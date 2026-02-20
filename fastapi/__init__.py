"""Tiny local FastAPI compatibility shim for offline Stage 0 testing."""

from __future__ import annotations

from collections.abc import Callable
from types import SimpleNamespace
from typing import Any


class FastAPI:
    def __init__(self, title: str = "", version: str = "", lifespan: Any = None) -> None:
        self.title = title
        self.version = version
        self.lifespan = lifespan
        self.routes: dict[tuple[str, str], Callable[..., Any]] = {}
        self.state = SimpleNamespace()

    def get(self, path: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            self.routes[("GET", path)] = func
            return func

        return decorator

    def post(self, path: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            self.routes[("POST", path)] = func
            return func

        return decorator
