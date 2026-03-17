from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from rnet import Client, Impersonate, Method
from AWSSolver.Solver import AwsSolver
from urllib.parse import urlparse

app = FastAPI()


class SolveRequest(BaseModel):
    url: str
    domain: str | None = None
    user_agent: str


def extract_domain(value: str) -> str:
    """Return domain with www. prefix (e.g. 'www.binance.com') from a URL or domain string."""
    raw = value.strip()
    if "://" not in raw:
        raw = "https://" + raw
    host = urlparse(raw).hostname or raw
    if not host.startswith("www."):
        host = "www." + host
    return host


@app.post("/solve")
async def solve(request: SolveRequest):
    domain = extract_domain(request.domain if request.domain else request.url)
    try:
        client = Client(impersonate=Impersonate.Chrome137, cookie_store=True)

        response = await client.request(
            method=getattr(Method, "GET"),
            url=request.url,
            timeout=15,
            headers={"user-agent": request.user_agent},
        )
        html = await response.text()

        solver = AwsSolver(user_agent=request.user_agent, domain=domain)
        token = await solver.solve(html)

        return {"token": token}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))