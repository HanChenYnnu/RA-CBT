"""Tiny local TestClient compatibility shim."""

from __future__ import annotations

import asyncio
import inspect
from dataclasses import dataclass
from typing import Any

from fastapi import FastAPI


@dataclass
class Response:
    status_code: int
    _payload: Any
    headers: dict[str, str]

    def json(self) -> Any:
        return self._payload


class TestClient:
    __test__ = False

    def __init__(self, app: FastAPI) -> None:
        self._app = app
        self._lifespan_cm = None
        if app.lifespan is not None:
            self._lifespan_cm = app.lifespan(app)
            asyncio.run(self._lifespan_cm.__aenter__())

    def _call(
        self,
        method: str,
        path: str,
        json: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> Response:
        handler = self._app.routes[(method, path)]
        try:
            sig = inspect.signature(handler)
            kwargs: dict[str, Any] = {}
            for name in sig.parameters:
                if name in {"payload", "body"}:
                    kwargs[name] = json or {}
            payload = handler(**kwargs)
            if hasattr(payload, "status_code") and hasattr(payload, "body"):
                return Response(
                    status_code=payload.status_code,
                    _payload=payload.body,
                    headers=getattr(payload, "headers", {}),
                )
            return Response(status_code=200, _payload=payload, headers={})
        except Exception as exc:  # noqa: BLE001
            status_code = getattr(exc, "status_code", 500)
            detail = getattr(exc, "detail", str(exc))
            return Response(status_code=status_code, _payload={"detail": detail}, headers={})

    def get(self, path: str, headers: dict[str, str] | None = None) -> Response:
        return self._call("GET", path, headers=headers)

    def post(
        self,
        path: str,
        json: dict[str, Any],
        headers: dict[str, str] | None = None,
    ) -> Response:
        return self._call("POST", path, json=json, headers=headers)
