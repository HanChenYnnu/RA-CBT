import json

import respx
from client.dpop import create_dpop_jwt
from client.keygen import generate_es256_keypair
from fastapi.testclient import TestClient
from gateway.app import app


def _exchange_token(client: TestClient, public_jwk: dict[str, str]) -> str:
    exchange = client.post(
        "/auth/exchange",
        json={"client_jwk": public_jwk, "ctx": {"tenant": "acme", "device_id": "devA"}},
        headers={
            "X-API-Key": "test-user-key",
            "X-Forwarded-For": "10.1.1.1",
            "User-Agent": "Browser/120.1",
        },
    )
    assert exchange.status_code == 200
    return exchange.json()["access_token"]


def _chat_request(
    client: TestClient,
    token: str,
    private_jwk: dict[str, str],
    *,
    max_tokens: int,
    ip: str = "10.1.1.1",
    ua: str = "Browser/120.1",
    x_ctx: dict | None = None,
    traffic: str = "benign",
):
    proof = create_dpop_jwt(
        method="POST",
        htu="/v1/chat/completions",
        access_token=token,
        private_jwk=private_jwk,
    )
    headers = {
        "Authorization": f"Bearer {token}",
        "DPoP": proof,
        "X-Forwarded-For": ip,
        "User-Agent": ua,
        "X-Traffic-Class": traffic,
    }
    if x_ctx is not None:
        headers["X-CTX"] = json.dumps(x_ctx)
    return client.post(
        "/v1/chat/completions",
        json={
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": "hi"}],
            "max_tokens": max_tokens,
        },
        headers=headers,
    )


def test_ctx_match_passes() -> None:
    client = TestClient(app)
    public_jwk, private_jwk = generate_es256_keypair()
    token = _exchange_token(client, public_jwk)

    with respx.mock() as router:
        router.post("http://127.0.0.1:9000/v1/chat/completions").respond(
            status_code=200,
            json={"ok": True},
        )
        response = _chat_request(client, token, private_jwk, max_tokens=5)
    assert response.status_code == 200


def test_ip_drift_within_same_asn_passes() -> None:
    client = TestClient(app)
    public_jwk, private_jwk = generate_es256_keypair()
    token = _exchange_token(client, public_jwk)

    with respx.mock() as router:
        router.post("http://127.0.0.1:9000/v1/chat/completions").respond(
            status_code=200,
            json={"ok": True},
        )
        response = _chat_request(
            client,
            token,
            private_jwk,
            max_tokens=5,
            ip="11.2.2.2",
            ua="Browser/120.9",
        )
    assert response.status_code == 200


def test_cross_country_or_cross_asn_denies() -> None:
    client = TestClient(app)
    public_jwk, private_jwk = generate_es256_keypair()
    token = _exchange_token(client, public_jwk)

    response = _chat_request(
        client,
        token,
        private_jwk,
        max_tokens=5,
        ip="20.1.1.1",
        ua="Browser/120.1",
    )
    assert response.status_code == 401
    assert response.json()["error"]["reason_code"] == "ctx_mismatch"


def test_precharge_consumes_tokens() -> None:
    client = TestClient(app)
    public_jwk, private_jwk = generate_es256_keypair()
    token = _exchange_token(client, public_jwk)

    with respx.mock() as router:
        router.post("http://127.0.0.1:9000/v1/chat/completions").respond(
            status_code=200,
            json={"ok": True, "usage": {"total_tokens": 10}},
        )
        first = _chat_request(client, token, private_jwk, max_tokens=9)
        second = _chat_request(client, token, private_jwk, max_tokens=9)

    assert first.status_code == 200
    assert second.status_code == 429


def test_refund_returns_tokens() -> None:
    client = TestClient(app)
    public_jwk, private_jwk = generate_es256_keypair()
    token = _exchange_token(client, public_jwk)

    with respx.mock() as router:
        router.post("http://127.0.0.1:9000/v1/chat/completions").respond(
            status_code=200,
            json={"ok": True, "usage": {"total_tokens": 2}},
        )
        first = _chat_request(client, token, private_jwk, max_tokens=9)
        second = _chat_request(client, token, private_jwk, max_tokens=7)

    assert first.status_code == 200
    assert second.status_code == 200


def test_over_budget_returns_429() -> None:
    client = TestClient(app)
    public_jwk, private_jwk = generate_es256_keypair()
    token = _exchange_token(client, public_jwk)

    response = _chat_request(client, token, private_jwk, max_tokens=100)
    assert response.status_code == 429


def test_throttle_path_caps_max_tokens() -> None:
    client = TestClient(app)
    app.state.risk_engine.policy.tau_allow = 0.1
    app.state.risk_engine.policy.tau_deny = 0.99

    public_jwk, private_jwk = generate_es256_keypair()
    token = _exchange_token(client, public_jwk)

    with respx.mock() as router:
        route = router.post("http://127.0.0.1:9000/v1/chat/completions").respond(
            status_code=200,
            json={"ok": True, "usage": {"total_tokens": 2}},
        )
        response = _chat_request(client, token, private_jwk, max_tokens=8)

    assert response.status_code == 200
    sent = route.calls[0].request
    assert sent.json["max_tokens"] < 8


def test_deny_path_triggers() -> None:
    client = TestClient(app)
    app.state.risk_engine.policy.tau_allow = 0.1
    app.state.risk_engine.policy.tau_deny = 0.2

    public_jwk, private_jwk = generate_es256_keypair()
    token = _exchange_token(client, public_jwk)

    with respx.mock() as router:
        router.post("http://127.0.0.1:9000/v1/chat/completions").respond(
            status_code=200,
            json={"ok": True},
        )
        response = _chat_request(
            client,
            token,
            private_jwk,
            max_tokens=20,
            ip="20.9.9.9",
            ua="EvilBot/9.0",
            traffic="attack",
        )

    assert response.status_code in {401, 403}
    if response.status_code == 403:
        assert response.json()["error"]["reason_code"] == "risk_deny"
