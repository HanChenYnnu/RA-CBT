"""FastAPI app entrypoint for the RA-CBT gateway."""

from __future__ import annotations

import argparse
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any

from fastapi import FastAPI
from gateway.config import Settings, load_settings
from gateway.upstream_clients.openai_compat import UpstreamProxyError, post_chat_completions


@dataclass
class GatewayResponse:
    status_code: int
    body: Any
    headers: dict[str, str]


@asynccontextmanager
async def lifespan(app_obj: FastAPI):
    app_obj.state.settings = load_settings()
    yield


app = FastAPI(title="RA-CBT Gateway", version="0.3.0", lifespan=lifespan)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/chat/completions")
def chat_completions(payload: dict[str, Any]) -> GatewayResponse:
    settings: Settings = app.state.settings
    request_id = uuid.uuid4().hex
    response_headers = {"X-Request-ID": request_id}

    try:
        status_code, body = post_chat_completions(
            base_url=settings.upstream.base_url,
            api_key=settings.upstream.api_key,
            payload=payload,
            timeout=settings.request_timeout,
            retries=1,
        )
        return GatewayResponse(status_code=status_code, body=body, headers=response_headers)
    except UpstreamProxyError as exc:
        return GatewayResponse(
            status_code=502,
            body={"error": {"message": f"upstream unavailable: {exc}"}},
            headers=response_headers,
        )


@app.get("/config/summary")
def config_summary() -> dict[str, str | float]:
    settings: Settings = app.state.settings
    return {
        "upstream_base_url": settings.upstream.base_url,
        "request_timeout": settings.request_timeout,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="RA-CBT Gateway app module")
    parser.add_argument("--config", default="gateway/config.yaml", help="Path to config yaml")
    return parser


def main() -> None:
    parser = build_parser()
    parser.parse_args()


if __name__ == "__main__":
    main()
