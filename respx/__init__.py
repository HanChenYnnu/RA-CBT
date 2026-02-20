"""Lightweight local respx compatibility shim."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx


@dataclass
class _Route:
    method: str
    url: str
    status_code: int = 200
    payload: Any = None
    calls: list[Any] = None

    def __post_init__(self) -> None:
        if self.calls is None:
            self.calls = []

    def respond(self, status_code: int = 200, json: Any = None) -> _Route:
        self.status_code = status_code
        self.payload = json
        return self

    @property
    def called(self) -> bool:
        return len(self.calls) > 0

    @property
    def call_count(self) -> int:
        return len(self.calls)


class _MockRouter:
    def __init__(self) -> None:
        self.routes: list[_Route] = []

    def post(self, url: str) -> _Route:
        route = _Route(method="POST", url=url)
        self.routes.append(route)
        return route

    def dispatch(self, request: Any) -> httpx.Response | None:
        for route in self.routes:
            if request.method == route.method and request.url == route.url:
                route.calls.append(type("Call", (), {"request": request}))
                return httpx.Response(route.status_code, route.payload, request)
        return None


class mock:
    def __enter__(self) -> _MockRouter:
        self.router = _MockRouter()
        httpx._MOCKER = self.router
        return self.router

    def __exit__(self, exc_type, exc, tb) -> None:
        httpx._MOCKER = None
