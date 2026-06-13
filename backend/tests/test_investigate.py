import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app


@pytest.mark.asyncio
async def test_health():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        r = await client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_detect_ip():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        r = await client.post("/api/detect", json={"value": "1.1.1.1"})
    assert r.status_code == 200
    assert r.json()["type"] == "ip"


@pytest.mark.asyncio
async def test_detect_domain():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        r = await client.post("/api/detect", json={"value": "cloudflare.com"})
    assert r.status_code == 200
    assert r.json()["type"] == "domain"


@pytest.mark.asyncio
async def test_investigate_unknown_fails():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        r = await client.post("/api/investigate", json={"value": "not_an_artifact!!!"})
    assert r.status_code == 422
