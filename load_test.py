#!/usr/bin/env python3
"""
AWS WAF Token Load Tester

This script generates AWS WAF tokens using AwsSolver directly,
then uses those tokens to make requests to Zyte API.

Configuration: Edit the constants at the top of this file.

Environment variables:
    ZYTEAPI_APIKEY: Your Zyte API key (required)
"""

import asyncio
import base64
import os
import sys
import uuid
from typing import List
from datetime import datetime
import httpx
from rnet import Client, Impersonate, Method
from AWSSolver.Solver import AwsSolver


DEFAULT_TOKENS = 1
DEFAULT_REQUESTS_PER_TOKEN = 100
DEFAULT_TOKEN_GENERATION_URL = "https://www.amazon.com/"  # URL to generate tokens from (challenge page)
DEFAULT_ZYTE_TARGET_URL = "https://www.amazon.com/dp/B014DQGEH4"  # URL to test with Zyte API
DEFAULT_ZYTE_TARGET_PRICE = "$354.29"  # Expected price in response body for validation
DEFAULT_DOMAIN = "www.amazon.com"
DEFAULT_USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36"
TOKEN_GENERATION_DELAY = 0.5  # seconds between token generations
MAX_CONCURRENT_REQUESTS = 50  # max concurrent requests to Zyte API


class TokenGenerator:

    @staticmethod
    async def generate_token(target_url: str, user_agent: str, domain: str) -> str:
        client = Client(impersonate=Impersonate.Chrome137, cookie_store=True)

        try:
            response = await client.request(
                method=Method.GET,
                url=target_url,
                timeout=15,
                headers={"user-agent": user_agent},
            )
            print(f"[DEBUG] Response status: {response.status}, OK: {response.ok}")

            html = await response.text()

            # Validate that we got a challenge page
            if "window.gokuProps" not in html or "challenge.js" not in html:
                preview = html[:200] if len(html) > 200 else html
                raise ValueError(
                    f"No AWS WAF challenge found. "
                    f"Response ({len(html)} bytes): {preview}..."
                )

            solver = AwsSolver(user_agent=user_agent, domain=domain)
            token = await solver.solve(html)
            return token

        except Exception as e:
            print(f"[ERROR] generate_token failed: {e}")
            raise

    @staticmethod
    async def generate_tokens(
        count: int,
        target_url: str = DEFAULT_TOKEN_GENERATION_URL,
        user_agent: str = DEFAULT_USER_AGENT,
        domain: str = DEFAULT_DOMAIN,
        delay: float = TOKEN_GENERATION_DELAY
    ) -> List[str]:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Generating {count} tokens with {delay}s delay")

        tokens = []
        for i in range(count):
            try:
                token = await TokenGenerator.generate_token(target_url, user_agent, domain)
                tokens.append(token)
                if (i + 1) % 10 == 0:
                    print(f"  Progress: {i + 1}/{count} tokens generated")
            except Exception as e:
                tokens.append(e)

            if i < count - 1 and delay > 0:
                await asyncio.sleep(delay)

        valid_tokens = [t for t in tokens if isinstance(t, str)]
        errors = [t for t in tokens if not isinstance(t, str)]

        if errors:
            print(f"[WARNING] {len(errors)} token generation(s) failed")

            error_types = {}
            for error in errors:
                error_msg = str(error)
                if "No AWS WAF challenge found" in error_msg:
                    error_type = "No challenge page"
                elif "list index out of range" in error_msg:
                    error_type = "Parse error (malformed HTML)"
                elif "timeout" in error_msg.lower():
                    error_type = "Timeout"
                else:
                    error_type = type(error).__name__
                error_types[error_type] = error_types.get(error_type, 0) + 1

            for error_type, count in error_types.items():
                print(f"  {error_type}: {count}")

            if errors:
                print(f"  First error detail: {errors[0]}")

        print(f"[{datetime.now().strftime('%H:%M:%S')}] Successfully generated {len(valid_tokens)} tokens")

        if len(valid_tokens) == 0:
            print("\n[ERROR] No tokens were generated. The target URL may not be showing an AWS WAF challenge.")

        return valid_tokens


class ZyteAPIClient:

    def __init__(self, api_key: str, target_url: str, job_id: str):
        self.api_key = api_key
        self.target_url = target_url
        self.job_id = job_id
        self.zyte_api_url = "https://api.zyte.com/v1/extract"

    async def make_request(self, client: httpx.AsyncClient, token: str) -> dict:
        payload = {
            "url": self.target_url,
            "httpResponseBody": True,
            "jobId": self.job_id,
            "_smartBrowserFeatures": {
                # "ignore_ban_result": True,
                # "ignore_uncork_config": True,
                "disable_session": False,
                "disable_amazon_cookie": False,
                "browserless_log": True,
                "server_log": True
            },
            "requestCookies": [
                {
                    "name": "aws-waf-token",
                    "value": token,
                    "domain": ".amazon.com",
                    "path": "/"
                }
            ],
            "followRedirect": True
        }

        response = await client.post(
            self.zyte_api_url,
            json=payload,
            auth=(self.api_key, ""),
            timeout=60.0
        )

        result = response.json() if response.is_success else {}
        status_code = result.get("statusCode")

        contains_price = False
        if status_code == 200:
            http_response_body = result.get("httpResponseBody")
            if http_response_body:
                try:
                    decoded_body = base64.b64decode(http_response_body).decode('utf-8', errors='ignore')
                    contains_price = DEFAULT_ZYTE_TARGET_PRICE in decoded_body
                except Exception:
                    pass

        is_success = status_code == 200 and contains_price

        return {
            "status": response.status_code,
            "statusCode": status_code,
            "success": is_success,
            "contains_price": contains_price,
            "token": token[:20] + "...",
        }

    async def make_requests_with_tokens(
        self,
        tokens: List[str],
        requests_per_token: int,
        max_concurrent: int = 50
    ) -> dict:
        total_requests = len(tokens) * requests_per_token
        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Making {total_requests} requests "
              f"({len(tokens)} tokens × {requests_per_token} requests per token)...")

        stats = {
            "total": total_requests,
            "success": 0,
            "failed": 0,
            "by_status": {}
        }

        semaphore = asyncio.Semaphore(max_concurrent)

        async def limited_request(client, token):
            async with semaphore:
                return await self.make_request(client, token)

        async with httpx.AsyncClient() as client:
            tasks = []
            for token in tokens:
                for _ in range(requests_per_token):
                    tasks.append(limited_request(client, token))

            completed = 0
            results = []

            for coro in asyncio.as_completed(tasks):
                try:
                    result = await coro
                    results.append(result)

                    if result["success"]:
                        stats["success"] += 1
                    else:
                        stats["failed"] += 1

                    status_code = result.get("statusCode", "unknown")
                    stats["by_status"][status_code] = stats["by_status"].get(status_code, 0) + 1

                    completed += 1
                    if completed % 100 == 0:
                        print(f"[{datetime.now().strftime('%H:%M:%S')}] Progress: {completed}/{total_requests} "
                              f"(Success: {stats['success']}, Failed: {stats['failed']})")

                except Exception as e:
                    stats["failed"] += 1
                    completed += 1
                    print(f"[ERROR] Request failed: {e.message}")

        return stats


async def main():
    # Check for Zyte API key
    api_key = os.getenv("ZYTEAPI_APIKEY")
    if not api_key:
        print("ERROR: ZYTEAPI_APIKEY environment variable is not set", file=sys.stderr)
        print("Please set it with: export ZYTEAPI_APIKEY='your-api-key'", file=sys.stderr)
        sys.exit(1)

    # Generate unique job ID for this run
    job_id = str(uuid.uuid4())

    print("=" * 80)
    print("AWS WAF Token Load Tester")
    print("=" * 80)
    print(f"Job ID: {job_id}")
    print(f"Token generation URL: {DEFAULT_TOKEN_GENERATION_URL}")
    print(f"Zyte API target URL: {DEFAULT_ZYTE_TARGET_URL}")
    print(f"Domain: {DEFAULT_DOMAIN}")
    print(f"Tokens to generate: {DEFAULT_TOKENS}")
    print(f"Token generation delay: {TOKEN_GENERATION_DELAY}s")
    print(f"Requests per token: {DEFAULT_REQUESTS_PER_TOKEN}")
    print(f"Total requests: {DEFAULT_TOKENS * DEFAULT_REQUESTS_PER_TOKEN}")
    print(f"Max concurrent: {MAX_CONCURRENT_REQUESTS}")
    print("=" * 80)

    start_time = datetime.now()

    # Generate tokens
    tokens = await TokenGenerator.generate_tokens(
        count=DEFAULT_TOKENS,
        target_url=DEFAULT_TOKEN_GENERATION_URL,
        user_agent=DEFAULT_USER_AGENT,
        domain=DEFAULT_DOMAIN,
        delay=TOKEN_GENERATION_DELAY
    )

    if not tokens:
        print("\nERROR: No tokens were generated successfully", file=sys.stderr)
        sys.exit(1)

    # Make requests with tokens
    client = ZyteAPIClient(api_key, DEFAULT_ZYTE_TARGET_URL, job_id)
    stats = await client.make_requests_with_tokens(
        tokens,
        DEFAULT_REQUESTS_PER_TOKEN,
        MAX_CONCURRENT_REQUESTS
    )

    # Print summary
    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()

    print("\n" + "=" * 80)
    print("RESULTS")
    print("=" * 80)
    print(f"Duration: {duration:.2f}s")
    print(f"Total requests: {stats['total']}")
    print(f"Successful: {stats['success']} ({stats['success']/stats['total']*100:.1f}%)")
    print(f"Failed: {stats['failed']} ({stats['failed']/stats['total']*100:.1f}%)")
    print(f"Requests/second: {stats['total']/duration:.2f}")
    print("\nStatus code breakdown:")
    for status, count in sorted(stats['by_status'].items()):
        print(f"  {status}: {count} ({count/stats['total']*100:.1f}%)")
    print("=" * 80)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        sys.exit(0)
