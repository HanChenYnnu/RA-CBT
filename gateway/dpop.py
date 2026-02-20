"""DPoP proof creation/verification with replay protection (MVP)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import uuid
from typing import Any

from gateway.auth_jwt import jwk_thumbprint


class DPoPError(ValueError):
    """Raised when DPoP validation fails."""


class ReplayCache:
    """In-memory replay cache keyed by subject and jti with TTL."""

    def __init__(self, ttl_seconds: int = 120) -> None:
        self.ttl_seconds = ttl_seconds
        self._store: dict[str, dict[str, int]] = {}

    def _cleanup(self, now: int) -> None:
        for sub in list(self._store):
            self._store[sub] = {k: v for k, v in self._store[sub].items() if v > now}
            if not self._store[sub]:
                del self._store[sub]

    def seen(self, sub: str, jti: str, now: int | None = None) -> bool:
        ts = int(time.time()) if now is None else now
        self._cleanup(ts)
        return jti in self._store.get(sub, {})

    def add(self, sub: str, jti: str, now: int | None = None) -> None:
        ts = int(time.time()) if now is None else now
        self._cleanup(ts)
        bucket = self._store.setdefault(sub, {})
        bucket[jti] = ts + self.ttl_seconds


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def _json_compact(payload: dict[str, Any]) -> str:
    return json.dumps(payload, separators=(",", ":"), sort_keys=True)


def hash_access_token(access_token: str) -> str:
    return _b64url_encode(hashlib.sha256(access_token.encode("utf-8")).digest())


def create_dpop_proof(
    *,
    method: str,
    htu: str,
    access_token: str,
    jwk: dict[str, Any],
    iat: int | None = None,
    jti: str | None = None,
) -> str:
    # MVP note: uses HS256 with oct JWK for offline local testing.
    header = {"typ": "dpop+jwt", "alg": "HS256", "jwk": jwk}
    claims = {
        "htm": method.upper(),
        "htu": htu,
        "iat": int(time.time()) if iat is None else iat,
        "jti": uuid.uuid4().hex if jti is None else jti,
        "ath": hash_access_token(access_token),
    }
    encoded_header = _b64url_encode(_json_compact(header).encode("utf-8"))
    encoded_payload = _b64url_encode(_json_compact(claims).encode("utf-8"))
    signing_input = f"{encoded_header}.{encoded_payload}".encode()
    key = str(jwk.get("k", "")).encode("utf-8")
    signature = hmac.new(key, signing_input, hashlib.sha256).digest()
    return f"{encoded_header}.{encoded_payload}.{_b64url_encode(signature)}"


def verify_dpop(
    *,
    dpop_proof: str,
    method: str,
    htu: str,
    access_token: str,
    expected_jkt: str,
    sub: str,
    replay_cache: ReplayCache,
    now: int | None = None,
) -> dict[str, Any]:
    ts_now = int(time.time()) if now is None else now
    try:
        encoded_header, encoded_payload, encoded_signature = dpop_proof.split(".")
        header = json.loads(_b64url_decode(encoded_header))
        claims = json.loads(_b64url_decode(encoded_payload))
    except Exception as exc:  # noqa: BLE001
        raise DPoPError("malformed DPoP proof") from exc

    if header.get("typ") != "dpop+jwt":
        raise DPoPError("invalid DPoP typ")
    if header.get("alg") != "HS256":
        raise DPoPError("unsupported DPoP alg")
    jwk = header.get("jwk")
    if not isinstance(jwk, dict):
        raise DPoPError("missing DPoP jwk")

    signing_input = f"{encoded_header}.{encoded_payload}".encode()
    expected_sig = hmac.new(
        str(jwk.get("k", "")).encode("utf-8"), signing_input, hashlib.sha256
    ).digest()
    actual_sig = _b64url_decode(encoded_signature)
    if not hmac.compare_digest(expected_sig, actual_sig):
        raise DPoPError("invalid DPoP signature")

    required_claims = {"htm", "htu", "iat", "jti", "ath"}
    if not required_claims.issubset(set(claims)):
        raise DPoPError("missing required DPoP claims")

    if str(claims["htm"]).upper() != method.upper():
        raise DPoPError("DPoP htm mismatch")
    if str(claims["htu"]) != htu:
        raise DPoPError("DPoP htu mismatch")

    if abs(ts_now - int(claims["iat"])) > 60:
        raise DPoPError("DPoP iat outside allowed skew")

    if claims["ath"] != hash_access_token(access_token):
        raise DPoPError("DPoP ath mismatch")

    jkt = jwk_thumbprint(jwk)
    if jkt != expected_jkt:
        raise DPoPError("DPoP jwk thumbprint mismatch")

    jti = str(claims["jti"])
    if replay_cache.seen(sub, jti, now=ts_now):
        raise DPoPError("DPoP replay detected")
    replay_cache.add(sub, jti, now=ts_now)

    return claims
