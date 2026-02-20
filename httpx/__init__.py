"""Lightweight local httpx compatibility shim for tests and simple runtime."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any


class RequestError(Exception):
    """Raised for upstream network failures."""


@dataclass
class _Request:
    method: str
    url: str
    headers: dict[str, str]
    json: Any


class Response:
    def __init__(self, status_code: int, body: Any, request: _Request) -> None:
        self.status_code = status_code
        self._body = body
        self.request = request
        self.text = body if isinstance(body, str) else json.dumps(body)

    def json(self) -> Any:
        if isinstance(self._body, (dict, list, int, float, bool)) or self._body is None:
            return self._body
        return json.loads(self._body)


_MOCKER: Any = None


class Client:
    def __init__(self, timeout: float = 10.0) -> None:
        self.timeout = timeout

    def __enter__(self) -> Client:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        return None

    def post(self, url: str, json: Any, headers: dict[str, str] | None = None) -> Response:
        request = _Request(method="POST", url=url, headers=headers or {}, json=json)
        if _MOCKER is not None:
            mocked = _MOCKER.dispatch(request)
            if mocked is not None:
                return mocked
        try:
            data = json and __import__("json").dumps(json).encode("utf-8") or b"{}"
            req = urllib.request.Request(url, method="POST", data=data)
            for key, value in (headers or {}).items():
                req.add_header(key, value)
            req.add_header("Content-Type", "application/json")
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                text = resp.read().decode("utf-8")
                try:
                    parsed = __import__("json").loads(text)
                except ValueError:
                    parsed = text
                return Response(status_code=resp.status, body=parsed, request=request)
        except urllib.error.URLError as exc:
            raise RequestError(str(exc)) from exc


class AsyncClient:
    """Minimal async client compatible with local tests/experiments."""

    def __init__(self, timeout: float = 10.0) -> None:
        self._client = Client(timeout=timeout)

    async def __aenter__(self) -> AsyncClient:
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None

    async def post(self, url: str, json: Any, headers: dict[str, str] | None = None) -> Response:
        return self._client.post(url=url, json=json, headers=headers)
