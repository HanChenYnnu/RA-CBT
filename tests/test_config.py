import os
from pathlib import Path

from gateway.config import load_settings

CFG_TEXT = """
upstream:
  base_url: http://127.0.0.1:8080
  api_key: key1
jwt:
  access_secret: access
  refresh_secret: refresh
ctx:
  secret: ctx
auth:
  issuer: issuer1
  audience: aud1
  ttl_seconds: 300
  users:
    k1:
      user_id: u1
      plan: pro
      scope: chat:completions
      model_allow: [m1,m2]
      tool_allow: [t1]
      budget:
        rpm: 10
        tpm: 1000
        burst: 2
request_timeout: 5.0
""".strip()


def test_load_settings_from_yaml(tmp_path: Path) -> None:
    cfg = tmp_path / "config.yaml"
    cfg.write_text(CFG_TEXT, encoding="utf-8")

    settings = load_settings(cfg)
    assert settings.upstream.base_url == "http://127.0.0.1:8080"
    assert settings.request_timeout == 5.0
    assert settings.auth.issuer == "issuer1"
    assert settings.auth.users["k1"].budget["rpm"] == 10


def test_env_override(tmp_path: Path) -> None:
    cfg = tmp_path / "config.yaml"
    cfg.write_text(CFG_TEXT, encoding="utf-8")

    os.environ["RA_CBT_UPSTREAM_API_KEY"] = "override"
    os.environ["RA_CBT_REQUEST_TIMEOUT"] = "12"
    os.environ["RA_CBT_AUTH_ISSUER"] = "issuer2"
    try:
        settings = load_settings(cfg)
    finally:
        os.environ.pop("RA_CBT_UPSTREAM_API_KEY", None)
        os.environ.pop("RA_CBT_REQUEST_TIMEOUT", None)
        os.environ.pop("RA_CBT_AUTH_ISSUER", None)

    assert settings.upstream.api_key == "override"
    assert settings.request_timeout == 12.0
    assert settings.auth.issuer == "issuer2"
