"""FastAPI app entrypoint for the RA-CBT gateway."""

from __future__ import annotations

import argparse
import json
import math
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from fastapi import FastAPI
from gateway.auth_jwt import JWTError, mint_cbat, verify_jwt
from gateway.budget import BudgetManager, estimate_prompt_tokens
from gateway.config import Settings, load_settings
from gateway.context import compare_with_tolerance, hash_ctx, load_policy
from gateway.dpop import DPoPError, ReplayCache, verify_dpop
from gateway.risk_engine import RiskEngine, load_risk_policy
from gateway.upstream_clients.openai_compat import UpstreamProxyError, post_chat_completions


@dataclass
class Request:
    method: str
    url: str
    headers: dict[str, str]
    state: SimpleNamespace


@dataclass
class GatewayResponse:
    status_code: int
    body: Any
    headers: dict[str, str]


def _stub_asn_country(ip: str) -> tuple[str, str]:
    if ip.startswith("10."):
        return "AS64512", "US"
    if ip.startswith("11."):
        return "AS64512", "US"
    if ip.startswith("20."):
        return "AS64550", "DE"
    return "AS00000", "ZZ"


def _ctx_server_from_request(request: Request) -> dict[str, Any]:
    ip = request.headers.get("x-forwarded-for", "127.0.0.1").split(",")[0].strip()
    ua = request.headers.get("user-agent", "unknown/0.0")
    asn = request.headers.get("x-asn")
    country = request.headers.get("x-country")
    if not asn or not country:
        stub_asn, stub_country = _stub_asn_country(ip)
        asn = asn or stub_asn
        country = country or stub_country
    return {"ip": ip, "ua": ua, "asn": asn, "country": country}


def _ctx_client_from_header(request: Request) -> dict[str, Any]:
    raw = request.headers.get("x-ctx")
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def _log_request(
    *,
    sub: str,
    jti: str,
    risk: float,
    decision: str,
    reject_reason: str | None,
    precharge: int,
    usage: int,
    latency_ms: int,
    traffic: str,
) -> None:
    logs_path = Path("gateway/logs")
    logs_path.mkdir(parents=True, exist_ok=True)
    line = {
        "ts": int(time.time()),
        "sub": sub,
        "jti": jti,
        "risk": round(float(risk), 6),
        "decision": decision,
        "reject_reason": reject_reason,
        "precharge": precharge,
        "usage": usage,
        "latency_ms": latency_ms,
        "traffic": traffic,
    }
    with logs_path.joinpath("requests.jsonl").open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(line, separators=(",", ":")) + "\n")


@asynccontextmanager
async def lifespan(app_obj: FastAPI):
    app_obj.state.settings = load_settings()
    app_obj.state.replay_cache = ReplayCache(ttl_seconds=120)
    app_obj.state.ctx_policy = load_policy()
    app_obj.state.budget_manager = BudgetManager()
    app_obj.state.risk_engine = RiskEngine(load_risk_policy())
    yield


app = FastAPI(title="RA-CBT Gateway", version="0.7.0", lifespan=lifespan)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/auth/exchange")
def auth_exchange(payload: dict[str, Any], request: Request) -> GatewayResponse:
    settings: Settings = app.state.settings
    auth_header = request.headers.get("authorization", "")
    user_key = request.headers.get("x-api-key")
    if auth_header.lower().startswith("bearer "):
        user_key = auth_header.split(" ", 1)[1].strip()
    if not user_key:
        return GatewayResponse(401, {"error": {"message": "missing api key"}}, {})

    user = settings.auth.users.get(user_key)
    if user is None:
        return GatewayResponse(403, {"error": {"message": "api key not allowed"}}, {})

    client_jwk = payload.get("client_jwk")
    ctx_client_body = payload.get("ctx")
    if not isinstance(client_jwk, dict) or not isinstance(ctx_client_body, dict):
        return GatewayResponse(
            400,
            {"error": {"message": "client_jwk and ctx are required objects"}},
            {},
        )

    from gateway.auth_jwt import jwk_thumbprint

    ctx_server = _ctx_server_from_request(request)
    ctx_merged = dict(ctx_client_body)
    ctx_merged.update(_ctx_client_from_header(request))
    ctx_merged.update(ctx_server)

    token, claims = mint_cbat(
        user_id=user.user_id,
        issuer=settings.auth.issuer,
        ttl_seconds=settings.auth.ttl_seconds,
        scope=user.scope,
        model_allow=user.model_allow,
        tool_allow=user.tool_allow,
        budget=user.budget,
        ctx_hash_value=hash_ctx(ctx_merged, settings.ctx.secret),
        jkt=jwk_thumbprint(client_jwk),
        secret=settings.jwt.access_secret,
        audience=settings.auth.audience,
        extra_claims={"ctx": ctx_merged},
    )

    return GatewayResponse(
        200,
        {
            "access_token": token,
            "token_type": "DPoP",
            "expires_in": claims["exp"] - claims["iat"],
            "policy_applied": {"plan": user.plan, "scope": user.scope, "budget": user.budget},
        },
        {},
    )


def _verify_access_token(request: Request) -> tuple[str, dict[str, Any]]:
    settings: Settings = app.state.settings
    auth_header = request.headers.get("authorization", "")
    if not auth_header.lower().startswith("bearer "):
        raise JWTError("missing bearer token")
    token = auth_header.split(" ", 1)[1].strip()
    claims = verify_jwt(
        token,
        settings.jwt.access_secret,
        issuer=settings.auth.issuer,
        audience=settings.auth.audience,
    )
    request.state.auth = claims
    return token, claims


def _scaled_budget(base_budget: dict[str, int], risk: float, k: float) -> dict[str, int]:
    factor = float(math.exp(-k * max(0.0, min(1.0, risk))))
    return {
        "rpm": max(1, int(base_budget.get("rpm", 1) * factor)),
        "tpm": max(1, int(base_budget.get("tpm", 1) * factor)),
        "burst": max(1, int(base_budget.get("burst", 1) * factor)),
    }


@app.post("/v1/chat/completions")
def chat_completions(payload: dict[str, Any], request: Request) -> GatewayResponse:
    settings: Settings = app.state.settings
    request_id = uuid.uuid4().hex
    response_headers = {"X-Request-ID": request_id}
    started = time.perf_counter()
    traffic = request.headers.get("x-traffic-class", "unknown")

    try:
        access_token, claims = _verify_access_token(request)
    except JWTError as exc:
        return GatewayResponse(
            401,
            {"error": {"message": f"invalid token: {exc}"}},
            response_headers,
        )

    dpop_header = request.headers.get("dpop")
    if not dpop_header:
        return GatewayResponse(401, {"error": {"message": "missing DPoP proof"}}, response_headers)

    expected_jkt = str(dict(claims.get("cnf", {})).get("jkt", ""))
    sub = str(claims.get("sub", ""))
    token_jti = str(claims.get("jti", ""))
    try:
        verify_dpop(
            dpop_proof=dpop_header,
            method=request.method,
            htu=request.url,
            access_token=access_token,
            expected_jkt=expected_jkt,
            sub=sub,
            replay_cache=app.state.replay_cache,
        )
    except DPoPError as exc:
        return GatewayResponse(
            401,
            {"error": {"message": f"invalid DPoP: {exc}"}},
            response_headers,
        )

    ctx_server = _ctx_server_from_request(request)
    ctx_now = _ctx_client_from_header(request)
    ctx_now.update(ctx_server)
    ctx_hash_now = hash_ctx(ctx_now, settings.ctx.secret)
    ctx_hash_token = str(claims.get("ctx_hash", ""))

    if ctx_hash_now != ctx_hash_token:
        token_ctx = claims.get("ctx", {})
        ok, reason = compare_with_tolerance(
            token_ctx=token_ctx if isinstance(token_ctx, dict) else {},
            current_ctx=ctx_now,
            policy=app.state.ctx_policy,
        )
        if not ok:
            latency = int((time.perf_counter() - started) * 1000)
            _log_request(
                sub=sub,
                jti=token_jti,
                risk=1.0,
                decision="deny",
                reject_reason="ctx_mismatch",
                precharge=0,
                usage=0,
                latency_ms=latency,
                traffic=traffic,
            )
            return GatewayResponse(
                401,
                {"error": {"message": reason, "reason_code": "ctx_mismatch"}},
                response_headers,
            )

    base_budget = claims.get("budget", {}) if isinstance(claims.get("budget"), dict) else {}
    base_budget_int = {k: int(v) for k, v in base_budget.items()}
    raw_messages = payload.get("messages", [])
    messages = list(raw_messages) if isinstance(raw_messages, list) else []
    requested_max_tokens = int(payload.get("max_tokens", 16))
    est_prompt = estimate_prompt_tokens(messages)
    preview_pressure = app.state.budget_manager.bucket_pressure(
        sub=sub,
        key_id=expected_jkt,
        budget=base_budget_int,
    )
    risk, _features = app.state.risk_engine.score(
        sub=sub,
        token_ctx=claims.get("ctx", {}) if isinstance(claims.get("ctx"), dict) else {},
        current_ctx=ctx_now,
        current_rpm=1.0,
        current_tpm=float(est_prompt + requested_max_tokens),
        bucket_pressure=preview_pressure,
    )

    if risk >= app.state.risk_engine.policy.tau_deny:
        latency = int((time.perf_counter() - started) * 1000)
        _log_request(
            sub=sub,
            jti=token_jti,
            risk=risk,
            decision="deny",
            reject_reason="risk_deny",
            precharge=0,
            usage=0,
            latency_ms=latency,
            traffic=traffic,
        )
        return GatewayResponse(
            403,
            {"error": {"message": "risk_deny", "reason_code": "risk_deny"}},
            response_headers,
        )

    effective_budget = base_budget_int
    effective_payload = dict(payload)
    decision = "allow"
    if risk >= app.state.risk_engine.policy.tau_allow:
        decision = "throttle"
        effective_budget = _scaled_budget(base_budget_int, risk, app.state.risk_engine.policy.k)
        cap = max(1, int(requested_max_tokens * app.state.risk_engine.scale_factor(risk)))
        effective_payload["max_tokens"] = cap
    else:
        effective_payload["max_tokens"] = requested_max_tokens

    allowed, precharge, reject_reason = app.state.budget_manager.precharge(
        sub=sub,
        key_id=expected_jkt,
        budget=effective_budget,
        est_prompt_tokens=est_prompt,
        max_tokens=int(effective_payload.get("max_tokens", requested_max_tokens)),
    )
    if not allowed:
        latency = int((time.perf_counter() - started) * 1000)
        _log_request(
            sub=sub,
            jti=token_jti,
            risk=risk,
            decision="deny",
            reject_reason=reject_reason,
            precharge=precharge,
            usage=0,
            latency_ms=latency,
            traffic=traffic,
        )
        return GatewayResponse(429, {"error": {"message": "budget exceeded"}}, response_headers)

    try:
        status_code, body = post_chat_completions(
            base_url=settings.upstream.base_url,
            api_key=settings.upstream.api_key,
            payload=effective_payload,
            timeout=settings.request_timeout,
            retries=1,
        )
    except UpstreamProxyError as exc:
        latency = int((time.perf_counter() - started) * 1000)
        _log_request(
            sub=sub,
            jti=token_jti,
            risk=risk,
            decision="error",
            reject_reason="upstream_unavailable",
            precharge=precharge,
            usage=0,
            latency_ms=latency,
            traffic=traffic,
        )
        return GatewayResponse(
            status_code=502,
            body={"error": {"message": f"upstream unavailable: {exc}"}},
            headers=response_headers,
        )

    usage_total_tokens = 0
    if isinstance(body, dict):
        usage = body.get("usage")
        if isinstance(usage, dict):
            usage_total_tokens = int(usage.get("total_tokens", 0))
    app.state.budget_manager.refund_or_charge(
        sub=sub,
        key_id=expected_jkt,
        budget=effective_budget,
        precharge=precharge,
        usage_total_tokens=usage_total_tokens,
    )

    latency = int((time.perf_counter() - started) * 1000)
    _log_request(
        sub=sub,
        jti=token_jti,
        risk=risk,
        decision=decision,
        reject_reason=None,
        precharge=precharge,
        usage=usage_total_tokens,
        latency_ms=latency,
        traffic=traffic,
    )
    return GatewayResponse(status_code=status_code, body=body, headers=response_headers)


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
