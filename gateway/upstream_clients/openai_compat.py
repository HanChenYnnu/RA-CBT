"""OpenAI-compatible upstream proxy client."""

from __future__ import annotations

from typing import Any

import httpx


class UpstreamProxyError(Exception):
    """Raised when upstream cannot be reached after retries."""


def post_chat_completions(
    *,
    base_url: str,
    api_key: str,
    payload: dict[str, Any],
    timeout: float,
    retries: int = 1,
) -> tuple[int, Any]:
    endpoint = f"{base_url.rstrip('/')}/v1/chat/completions"
    headers = {"Authorization": f"Bearer {api_key}"}

    attempt = 0
    last_error: Exception | None = None
    while attempt <= retries:
        try:
            with httpx.Client(timeout=timeout) as client:
                response = client.post(endpoint, json=payload, headers=headers)
            try:
                body: Any = response.json()
            except ValueError:
                body = {"raw": response.text}
            return response.status_code, body
        except httpx.RequestError as exc:
            last_error = exc
            attempt += 1

    raise UpstreamProxyError(str(last_error) if last_error else "upstream request failed")
