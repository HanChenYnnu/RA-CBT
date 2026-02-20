"""Configuration loading with environment variable overrides."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class UpstreamConfig:
    base_url: str
    api_key: str


@dataclass
class JwtConfig:
    access_secret: str
    refresh_secret: str


@dataclass
class CtxConfig:
    secret: str


@dataclass
class AuthUser:
    user_id: str
    plan: str
    scope: str
    model_allow: list[str]
    tool_allow: list[str]
    budget: dict[str, int]


@dataclass
class AuthConfig:
    issuer: str
    audience: str | None
    ttl_seconds: int
    users: dict[str, AuthUser]


@dataclass
class Settings:
    upstream: UpstreamConfig
    jwt: JwtConfig
    ctx: CtxConfig
    auth: AuthConfig
    request_timeout: float


def _parse_scalar(value: str) -> Any:
    cleaned = value.strip().strip('"').strip("'")
    if cleaned in {"true", "True"}:
        return True
    if cleaned in {"false", "False"}:
        return False
    if cleaned in {"null", "None", ""}:
        return None if cleaned in {"null", "None"} else ""
    if cleaned.startswith("[") and cleaned.endswith("]"):
        inner = cleaned[1:-1].strip()
        if not inner:
            return []
        return [_parse_scalar(part.strip()) for part in inner.split(",")]
    if cleaned.isdigit():
        return int(cleaned)
    if cleaned.replace(".", "", 1).isdigit() and cleaned.count(".") <= 1:
        return float(cleaned)
    return cleaned


def _parse_yaml_like(text: str) -> dict[str, Any]:
    root: dict[str, Any] = {}
    stack: list[tuple[int, dict[str, Any]]] = [(0, root)]

    for raw_line in text.splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        line = raw_line.strip()

        while len(stack) > 1 and indent < stack[-1][0]:
            stack.pop()

        current = stack[-1][1]

        if line.endswith(":"):
            key = line[:-1].strip()
            current[key] = {}
            stack.append((indent + 2, current[key]))
            continue

        key, value = [part.strip() for part in line.split(":", 1)]
        current[key] = _parse_scalar(value)

    return root


def _env_override(data: dict[str, Any], env_name: str, key_path: tuple[str, ...]) -> None:
    value = os.getenv(env_name)
    if value is None:
        return
    if len(key_path) == 1:
        data[key_path[0]] = _parse_scalar(value)
        return

    current: dict[str, Any] = data
    for key in key_path[:-1]:
        child = current.get(key)
        if not isinstance(child, dict):
            child = {}
            current[key] = child
        current = child
    current[key_path[-1]] = _parse_scalar(value)


def load_settings(config_path: str | Path | None = None) -> Settings:
    path = Path(config_path) if config_path else Path(__file__).with_name("config.yaml")
    data = _parse_yaml_like(path.read_text(encoding="utf-8"))

    env_map = {
        "RA_CBT_UPSTREAM_BASE_URL": ("upstream", "base_url"),
        "RA_CBT_UPSTREAM_API_KEY": ("upstream", "api_key"),
        "RA_CBT_JWT_ACCESS_SECRET": ("jwt", "access_secret"),
        "RA_CBT_JWT_REFRESH_SECRET": ("jwt", "refresh_secret"),
        "RA_CBT_CTX_SECRET": ("ctx", "secret"),
        "RA_CBT_AUTH_ISSUER": ("auth", "issuer"),
        "RA_CBT_AUTH_AUDIENCE": ("auth", "audience"),
        "RA_CBT_AUTH_TTL_SECONDS": ("auth", "ttl_seconds"),
        "RA_CBT_REQUEST_TIMEOUT": ("request_timeout",),
    }
    for env_name, key_path in env_map.items():
        _env_override(data, env_name, key_path)

    upstream = data.get("upstream", {})
    jwt = data.get("jwt", {})
    ctx = data.get("ctx", {})
    auth_data = data.get("auth", {})
    users_data = auth_data.get("users", {}) if isinstance(auth_data, dict) else {}

    users: dict[str, AuthUser] = {}
    for api_key, profile in users_data.items():
        if not isinstance(profile, dict):
            continue
        users[api_key] = AuthUser(
            user_id=str(profile.get("user_id", "")),
            plan=str(profile.get("plan", "free")),
            scope=str(profile.get("scope", "chat:completions")),
            model_allow=list(profile.get("model_allow", [])),
            tool_allow=list(profile.get("tool_allow", [])),
            budget={k: int(v) for k, v in dict(profile.get("budget", {})).items()},
        )

    auth_cfg = AuthConfig(
        issuer=str(auth_data.get("issuer", "ra-cbt-gateway")),
        audience=(None if not auth_data.get("audience") else str(auth_data.get("audience"))),
        ttl_seconds=int(auth_data.get("ttl_seconds", 600)),
        users=users,
    )

    return Settings(
        upstream=UpstreamConfig(
            base_url=str(upstream.get("base_url", "http://127.0.0.1:9000")),
            api_key=str(upstream.get("api_key", "dev-upstream-key")),
        ),
        jwt=JwtConfig(
            access_secret=str(jwt.get("access_secret", "dev-access-secret")),
            refresh_secret=str(jwt.get("refresh_secret", "dev-refresh-secret")),
        ),
        ctx=CtxConfig(secret=str(ctx.get("secret", "dev-ctx-secret"))),
        auth=auth_cfg,
        request_timeout=float(data.get("request_timeout", 10.0)),
    )
