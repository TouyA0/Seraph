import hashlib
import json
import os

import redis.asyncio as aioredis

_client: aioredis.Redis | None = None
TTL = int(os.getenv("CACHE_TTL_SECONDS", "3600"))


def _get_client() -> aioredis.Redis:
    global _client
    if _client is None:
        url = os.getenv("REDIS_URL", "redis://redis:6379")
        _client = aioredis.from_url(url, decode_responses=True)
    return _client


def _cache_key(connector: str, artifact: str) -> str:
    h = hashlib.sha256(f"{connector}:{artifact}".encode()).hexdigest()[:16]
    return f"seraph:v1:{connector}:{h}"


async def get_cached(connector: str, artifact: str) -> dict | None:
    try:
        client = _get_client()
        raw = await client.get(_cache_key(connector, artifact))
        if raw:
            return json.loads(raw)
    except Exception:
        pass
    return None


async def set_cached(connector: str, artifact: str, data: dict) -> None:
    try:
        client = _get_client()
        await client.setex(_cache_key(connector, artifact), TTL, json.dumps(data))
    except Exception:
        pass


async def ping() -> bool:
    try:
        return await _get_client().ping()
    except Exception:
        return False
