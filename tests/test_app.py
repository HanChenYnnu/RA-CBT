import json

import respx
from client.dpop import create_dpop_jwt
from client.keygen import generate_es256_keypair
from fastapi.testclient import TestClient
from gateway.app import app


def _exchange_token(
    client: TestClient,
    public_jwk: dict[str, str],
    *,
    ip: str = "10.1.1.1",
    ua: str = "Browser/120.1",
    ctx: dict | None = None,
) -> str:
    exchange = client.post(
        "/auth/exchange",
        json={"client_jwk": public_jwk, "ctx": ctx or {"tenant": "acme"}},
        headers={"X-API-Key": "test-user-key", "X-Forwarded-For": ip, "User-Agent": ua},
    )
    assert exchange.status_code == 200
    return exchange.json()["access_token"]


def _call_chat(
    client: TestClient,
    token: str,
    private_jwk: dict[str, str],
    *,
    ip: str,
    ua: str,
    x_ctx: dict | None = None,
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
    }
    if x_ctx is not None:
        headers["X-CTX"] = json.dumps(x_ctx)
    return client.post("/v1/chat/completions", json={"model": "gpt-4o-mini"}, headers=headers)


def test_health() -> None:
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200


def test_ctx_match_passes() -> None:
    client = TestClient(app)
    public_jwk, private_jwk = generate_es256_keypair()
    token = _exchange_token(client, public_jwk, ip="10.0.0.1", ua="Browser/120.1")

    with respx.mock() as router:
        router.post("http://127.0.0.1:9000/v1/chat/completions").respond(
            status_code=200,
            json={"ok": True},
        )
        response = _call_chat(client, token, private_jwk, ip="10.0.0.1", ua="Browser/120.1")

    assert response.status_code == 200


def test_ip_drift_within_same_asn_passes() -> None:
    client = TestClient(app)
    public_jwk, private_jwk = generate_es256_keypair()
    token = _exchange_token(client, public_jwk, ip="10.1.1.1", ua="Browser/120.1")

    with respx.mock() as router:
        router.post("http://127.0.0.1:9000/v1/chat/completions").respond(
            status_code=200,
            json={"ok": True},
        )
        response = _call_chat(client, token, private_jwk, ip="11.9.9.9", ua="Browser/120.9")

    assert response.status_code == 200


def test_cross_country_or_cross_asn_denies() -> None:
    client = TestClient(app)
    public_jwk, private_jwk = generate_es256_keypair()
    token = _exchange_token(client, public_jwk, ip="10.1.1.1", ua="Browser/120.1")

    response = _call_chat(client, token, private_jwk, ip="20.1.1.1", ua="Browser/120.3")
    assert response.status_code == 401
    assert response.json()["error"]["reason_code"] == "ctx_mismatch"
