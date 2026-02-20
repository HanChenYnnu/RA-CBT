"""Simple OpenAI-compatible HTTP client wrapper."""

from __future__ import annotations

import httpx


class OpenAICompatClient:
    def __init__(self, base_url: str, api_key: str, timeout: float = 30.0) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._timeout = timeout

    def chat_completions(self, payload: dict) -> dict:
        headers = {"Authorization": f"Bearer {self._api_key}"}
        endpoint = f"{self._base_url}/v1/chat/completions"
        with httpx.Client(timeout=self._timeout) as client:
            response = client.post(endpoint, json=payload, headers=headers)
            response.raise_for_status()
            return response.json()
