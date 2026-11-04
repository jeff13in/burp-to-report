"""Client for any OpenAI-compatible chat completions endpoint.

Default: Meta Model API (Muse Spark). Privacy mode: point LLM_BASE_URL at a local server
running a Meta open-weights model (Ollama, vLLM, llama.cpp all expose /v1/chat/completions),
so captured client traffic never leaves the machine.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
from dataclasses import dataclass

import httpx


@dataclass
class LLMConfig:
    base_url: str
    api_key: str
    model: str
    mode: str  # "cloud" | "local" | "off"
    timeout: float = 60.0
    max_retries: int = 2
    reasoning_effort: str | None = None

    @classmethod
    def from_env(cls) -> "LLMConfig":
        mode = os.getenv("B2R_MODE", "").lower()
        key = os.getenv("META_API_KEY", "")
        if not mode:
            mode = "cloud" if key else "off"
        if mode == "local":
            return cls(
                base_url=os.getenv("LLM_BASE_URL", "http://localhost:11434/v1"),
                api_key=os.getenv("LLM_API_KEY", "local"),
                model=os.getenv("LLM_MODEL", "llama3.1:8b"),
                mode="local",
                timeout=float(os.getenv("LLM_TIMEOUT", "120")),
            )
        return cls(
            base_url=os.getenv("LLM_BASE_URL", "https://api.meta.ai/v1"),
            api_key=key,
            model=os.getenv("LLM_MODEL", "muse-spark-1.3"),
            mode=mode,
            timeout=float(os.getenv("LLM_TIMEOUT", "60")),
            reasoning_effort=os.getenv("LLM_REASONING_EFFORT", "low") or None,
        )


class LLMError(RuntimeError):
    pass


def extract_json(text: str) -> dict:
    """Models sometimes wrap JSON in prose or code fences; take the first object."""
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start, end = text.find("{"), text.rfind("}")
        if start >= 0 and end > start:
            return json.loads(text[start:end + 1])
        raise


class LLMClient:
    def __init__(self, cfg: LLMConfig | None = None, transport: httpx.AsyncBaseTransport | None = None):
        self.cfg = cfg or LLMConfig.from_env()
        self._transport = transport

    @property
    def enabled(self) -> bool:
        return self.cfg.mode != "off"

    async def chat_json(self, system: str, user: str) -> dict:
        if not self.enabled:
            raise LLMError("LLM disabled (no META_API_KEY and B2R_MODE not set)")
        body: dict = {
            "model": self.cfg.model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "response_format": {"type": "json_object"},
            "temperature": 0.1,
        }
        if self.cfg.reasoning_effort and self.cfg.mode == "cloud":
            body["reasoning_effort"] = self.cfg.reasoning_effort
        headers = {"Authorization": f"Bearer {self.cfg.api_key}", "Content-Type": "application/json"}

        last: Exception | None = None
        async with httpx.AsyncClient(timeout=self.cfg.timeout, transport=self._transport) as client:
            for attempt in range(self.cfg.max_retries + 1):
                try:
                    r = await client.post(f"{self.cfg.base_url.rstrip('/')}/chat/completions", json=body, headers=headers)
                    if r.status_code == 400 and "response_format" in body:
                        body.pop("response_format")  # some local servers reject it; retry without
                        continue
                    if r.status_code in (429, 500, 502, 503, 504):
                        raise LLMError(f"retryable status {r.status_code}")
                    r.raise_for_status()
                    content = r.json()["choices"][0]["message"]["content"]
                    return extract_json(content)
                except (httpx.HTTPError, LLMError, KeyError, json.JSONDecodeError) as e:
                    last = e
                    await asyncio.sleep(min(2 ** attempt, 8))
        raise LLMError(f"LLM call failed after retries: {last}")
