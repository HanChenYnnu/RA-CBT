"""JWT signing/verification and CBAT utility helpers."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import uuid
from typing import Any


class JWTError(ValueError):
    """Raised when JWT verification fails."""


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def _json_compact(payload: dict[str, Any]) -> str:
    return json.dumps(payload, separators=(",", ":"), sort_keys=True)


def sign_jwt(claims: dict[str, Any], secret: str, algorithm: str = "HS256") -> str:
    if algorithm != "HS256":
        raise JWTError("only HS256 is supported in stage2 scaffold")
    header = {"alg": algorithm, "typ": "JWT"}
    encoded_header = _b64url_encode(_json_compact(header).encode("utf-8"))
    encoded_payload = _b64url_encode(_json_compact(claims).encode("utf-8"))
    signing_input = f"{encoded_header}.{encoded_payload}".encode()
    signature = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    return f"{encoded_header}.{encoded_payload}.{_b64url_encode(signature)}"


def verify_jwt(
    token: str,
    secret: str,
    issuer: str,
    audience: str | None = None,
    now: int | None = None,
) -> dict[str, Any]:
    try:
        encoded_header, encoded_payload, encoded_signature = token.split(".")
    except ValueError as exc:
        raise JWTError("malformed token") from exc

    signing_input = f"{encoded_header}.{encoded_payload}".encode()
    try:
        expected_sig = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
        actual_sig = _b64url_decode(encoded_signature)
        header = json.loads(_b64url_decode(encoded_header))
        claims = json.loads(_b64url_decode(encoded_payload))
    except Exception as exc:  # noqa: BLE001
        raise JWTError("malformed token payload") from exc

    if not hmac.compare_digest(expected_sig, actual_sig):
        raise JWTError("invalid signature")

    if header.get("alg") != "HS256":
        raise JWTError("unsupported algorithm")

    ts_now = int(time.time()) if now is None else now
    if int(claims.get("exp", 0)) < ts_now:
        raise JWTError("token expired")
    if claims.get("iss") != issuer:
        raise JWTError("invalid issuer")
    if audience and claims.get("aud") != audience:
        raise JWTError("invalid audience")
    return claims


def canonical_ctx_json(ctx: dict[str, Any]) -> str:
    return _json_compact(ctx)


def ctx_hash(ctx: dict[str, Any], ctx_secret: str) -> str:
    digest = hmac.new(
        ctx_secret.encode("utf-8"), canonical_ctx_json(ctx).encode("utf-8"), hashlib.sha256
    ).digest()
    return _b64url_encode(digest)


def jwk_thumbprint(jwk: dict[str, Any]) -> str:
    kty = jwk.get("kty")
    if kty == "RSA":
        subset = {"e": jwk.get("e", ""), "kty": "RSA", "n": jwk.get("n", "")}
    elif kty == "EC":
        subset = {
            "crv": jwk.get("crv", ""),
            "kty": "EC",
            "x": jwk.get("x", ""),
            "y": jwk.get("y", ""),
        }
    else:
        subset = {"k": jwk.get("k", ""), "kty": kty or "oct"}
    return _b64url_encode(hashlib.sha256(_json_compact(subset).encode("utf-8")).digest())


def mint_cbat(
    *,
    user_id: str,
    issuer: str,
    ttl_seconds: int,
    scope: str,
    model_allow: list[str],
    tool_allow: list[str],
    budget: dict[str, int],
    ctx_hash_value: str,
    jkt: str,
    secret: str,
    audience: str | None = None,
    extra_claims: dict[str, Any] | None = None,
) -> tuple[str, dict[str, Any]]:
    iat = int(time.time())
    claims: dict[str, Any] = {
        "iss": issuer,
        "sub": user_id,
        "iat": iat,
        "exp": iat + ttl_seconds,
        "jti": uuid.uuid4().hex,
        "scope": scope,
        "model_allow": model_allow,
        "tool_allow": tool_allow,
        "budget": budget,
        "ctx_hash": ctx_hash_value,
        "cnf": {"jkt": jkt},
    }
    if audience:
        claims["aud"] = audience
    if extra_claims:
        claims.update(extra_claims)
    return sign_jwt(claims, secret), claims
