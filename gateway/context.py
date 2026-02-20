"""Context canonicalization, hashing, and tolerance comparison."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _normalize_str(value: str) -> str:
    return " ".join(value.strip().split())


def _normalize_timestamp(value: Any) -> str:
    if isinstance(value, (int, float)):
        dt = datetime.fromtimestamp(value, tz=timezone.utc)
        return dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")
    if isinstance(value, str):
        text = value.strip()
        try:
            if text.endswith("Z"):
                dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
            else:
                dt = datetime.fromisoformat(text)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return (
                dt.astimezone(timezone.utc)
                .replace(microsecond=0)
                .isoformat()
                .replace("+00:00", "Z")
            )
        except ValueError:
            return _normalize_str(text)
    return str(value)


def canonicalize(ctx: dict[str, Any]) -> dict[str, Any]:
    def clean(value: Any, key: str = "") -> Any:
        if value is None:
            return None
        if isinstance(value, dict):
            cleaned = {}
            for k in sorted(value):
                v = clean(value[k], k)
                if v is not None:
                    cleaned[_normalize_str(str(k))] = v
            return cleaned
        if isinstance(value, list):
            return [v for v in (clean(v) for v in value) if v is not None]
        if isinstance(value, str):
            if key in {"timestamp", "ts", "time", "observed_at"}:
                return _normalize_timestamp(value)
            return _normalize_str(value)
        if isinstance(value, (int, float)) and key in {"timestamp", "ts", "time", "observed_at"}:
            return _normalize_timestamp(value)
        return value

    canonical = clean(ctx)
    return canonical if isinstance(canonical, dict) else {}


def canonical_json(ctx: dict[str, Any]) -> str:
    return json.dumps(canonicalize(ctx), sort_keys=True, separators=(",", ":"))


def hash_ctx(ctx: dict[str, Any], secret: str) -> str:
    digest = hmac.new(
        secret.encode("utf-8"),
        canonical_json(ctx).encode("utf-8"),
        hashlib.sha256,
    ).digest()
    return _b64url_encode(digest)


def _ua_major(ua: str) -> str:
    parts = ua.split("/")
    if len(parts) < 2:
        return ua
    ver = parts[1].split(".")[0]
    return f"{parts[0]}/{ver}"


@dataclass
class TolerancePolicy:
    allow_same_asn: bool = True
    allow_same_country: bool = True
    allow_ua_minor: bool = True
    require_geo: bool = False


def load_policy(path: str | Path | None = None) -> TolerancePolicy:
    policy_path = (
        Path(path) if path else Path(__file__).with_name("policy").joinpath("default.yaml")
    )
    data = {}
    section = None
    for raw in policy_path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.endswith(":"):
            section = line[:-1]
            data[section] = {}
            continue
        k, v = [p.strip() for p in line.split(":", 1)]
        parsed: Any = v.lower() == "true" if v.lower() in {"true", "false"} else v
        if section:
            data[section][k] = parsed
        else:
            data[k] = parsed
    tol = data.get("tolerance", {})
    return TolerancePolicy(
        allow_same_asn=bool(tol.get("allow_same_asn", True)),
        allow_same_country=bool(tol.get("allow_same_country", True)),
        allow_ua_minor=bool(tol.get("allow_ua_minor", True)),
        require_geo=bool(tol.get("require_geo", False)),
    )


def compare_with_tolerance(
    *,
    token_ctx: dict[str, Any],
    current_ctx: dict[str, Any],
    policy: TolerancePolicy,
) -> tuple[bool, str]:
    token = canonicalize(token_ctx)
    cur = canonicalize(current_ctx)

    if token == cur:
        return True, "match"

    token_asn = str(token.get("asn", ""))
    cur_asn = str(cur.get("asn", ""))
    token_country = str(token.get("country", ""))
    cur_country = str(cur.get("country", ""))

    if token.get("ip") != cur.get("ip"):
        if policy.allow_same_asn and token_asn and token_asn == cur_asn:
            pass
        elif policy.allow_same_country and token_country and token_country == cur_country:
            pass
        else:
            return False, "ctx_mismatch"

    token_ua = str(token.get("ua", ""))
    cur_ua = str(cur.get("ua", ""))
    if token_ua != cur_ua:
        if policy.allow_ua_minor and _ua_major(token_ua) == _ua_major(cur_ua):
            pass
        else:
            return False, "ctx_mismatch"

    if policy.require_geo and (not token_country or not cur_country):
        return False, "ctx_mismatch"

    return True, "tolerated"
