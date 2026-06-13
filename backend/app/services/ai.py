import json
import os
from typing import AsyncIterator

import httpx

# Supporte Ollama (/v1/chat/completions via compatibilité OpenAI) ou tout endpoint OpenAI-compatible
_OLLAMA_URL = os.getenv("OLLAMA_BASE_URL", "http://ollama:11434")
_OPENAI_URL = os.getenv("OPENAI_COMPATIBLE_URL", "")
_MODEL = os.getenv("OLLAMA_MODEL", "mistral")
_ENABLED = os.getenv("AI_ENABLED", "true").lower() == "true"


def _base_url() -> str:
    if _OPENAI_URL:
        return _OPENAI_URL.rstrip("/")
    return f"{_OLLAMA_URL}/v1"


def _headers() -> dict:
    key = os.getenv("OPENAI_COMPATIBLE_KEY", "")
    if key:
        return {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
    return {"Content-Type": "application/json"}


async def is_available() -> bool:
    if not _ENABLED:
        return False
    try:
        async with httpx.AsyncClient(timeout=3) as client:
            if _OPENAI_URL:
                r = await client.get(f"{_base_url()}/models", headers=_headers())
            else:
                r = await client.get(f"{_OLLAMA_URL}/api/tags")
            return r.status_code == 200
    except Exception:
        return False


async def chat(messages: list[dict], temperature: float = 0.2) -> str:
    payload = {
        "model": _MODEL,
        "messages": messages,
        "temperature": temperature,
        "stream": False,
    }
    async with httpx.AsyncClient(timeout=120) as client:
        r = await client.post(
            f"{_base_url()}/chat/completions",
            json=payload,
            headers=_headers(),
        )
        r.raise_for_status()
        data = r.json()
        return data["choices"][0]["message"]["content"]


async def stream_chat(messages: list[dict], temperature: float = 0.3) -> AsyncIterator[str]:
    payload = {
        "model": _MODEL,
        "messages": messages,
        "temperature": temperature,
        "stream": True,
    }
    async with httpx.AsyncClient(timeout=120) as client:
        async with client.stream(
            "POST",
            f"{_base_url()}/chat/completions",
            json=payload,
            headers=_headers(),
        ) as r:
            r.raise_for_status()
            async for line in r.aiter_lines():
                if not line.startswith("data: "):
                    continue
                chunk = line[6:]
                if chunk.strip() == "[DONE]":
                    return
                try:
                    delta = json.loads(chunk)["choices"][0]["delta"].get("content", "")
                    if delta:
                        yield delta
                except Exception:
                    continue
