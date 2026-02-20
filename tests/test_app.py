import respx
from client.dpop import create_dpop_jwt
from client.keygen import generate_es256_keypair
from fastapi.testclient import TestClient
from gateway.app import app


def _exchange_token(client: TestClient, public_jwk: dict[str, str]) -> str:
    exchange = client.post(
        "/auth/exchange",
        json={"client_jwk": public_jwk, "ctx": {"tenant": "acme"}},
        headers={"X-API-Key": "test-user-key"},
    )
    assert exchange.status_code == 200
    return exchange.json()["access_token"]


def test_health() -> None:
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_chat_proxy_dpop_success() -> None:
    client = TestClient(app)
    public_jwk, private_jwk = generate_es256_keypair()
    token = _exchange_token(client, public_jwk)
    proof = create_dpop_jwt(
        method="POST",
        htu="/v1/chat/completions",
        access_token=token,
        private_jwk=private_jwk,
    )

    with respx.mock() as router:
        route = router.post("http://127.0.0.1:9000/v1/chat/completions").respond(
            status_code=200,
            json={
                "id": "chatcmpl-123",
                "choices": [{"message": {"role": "assistant", "content": "hello"}}],
            },
        )
        response = client.post(
            "/v1/chat/completions",
            json={"model": "gpt-4o-mini"},
            headers={"Authorization": f"Bearer {token}", "DPoP": proof},
        )

    assert route.called
    sent = route.calls[0].request
    assert sent.headers["Authorization"] == "Bearer dev-upstream-key"
    assert response.status_code == 200
    assert response.headers.get("X-Request-ID")


def test_dpop_wrong_htu_rejected() -> None:
    client = TestClient(app)
    public_jwk, private_jwk = generate_es256_keypair()
    token = _exchange_token(client, public_jwk)
    proof = create_dpop_jwt(
        method="POST",
        htu="/wrong/path",
        access_token=token,
        private_jwk=private_jwk,
    )

    response = client.post(
        "/v1/chat/completions",
        json={"model": "gpt-4o-mini"},
        headers={"Authorization": f"Bearer {token}", "DPoP": proof},
    )
    assert response.status_code == 401
    assert "htu mismatch" in response.json()["error"]["message"]


def test_dpop_replay_jti_rejected() -> None:
    client = TestClient(app)
    public_jwk, private_jwk = generate_es256_keypair()
    token = _exchange_token(client, public_jwk)
    proof = create_dpop_jwt(
        method="POST",
        htu="/v1/chat/completions",
        access_token=token,
        private_jwk=private_jwk,
    )

    with respx.mock() as router:
        router.post("http://127.0.0.1:9000/v1/chat/completions").respond(
            status_code=200,
            json={"ok": True},
        )
        first = client.post(
            "/v1/chat/completions",
            json={"model": "gpt-4o-mini"},
            headers={"Authorization": f"Bearer {token}", "DPoP": proof},
        )
    assert first.status_code == 200

    second = client.post(
        "/v1/chat/completions",
        json={"model": "gpt-4o-mini"},
        headers={"Authorization": f"Bearer {token}", "DPoP": proof},
    )
    assert second.status_code == 401
    assert "replay" in second.json()["error"]["message"]


def test_dpop_wrong_ath_rejected() -> None:
    client = TestClient(app)
    public_jwk, private_jwk = generate_es256_keypair()
    token = _exchange_token(client, public_jwk)
    proof = create_dpop_jwt(
        method="POST",
        htu="/v1/chat/completions",
        access_token="different-token",
        private_jwk=private_jwk,
    )

    response = client.post(
        "/v1/chat/completions",
        json={"model": "gpt-4o-mini"},
        headers={"Authorization": f"Bearer {token}", "DPoP": proof},
    )
    assert response.status_code == 401
    assert "ath mismatch" in response.json()["error"]["message"]


def test_dpop_wrong_jkt_rejected() -> None:
    client = TestClient(app)
    public_jwk, _ = generate_es256_keypair()
    token = _exchange_token(client, public_jwk)
    _, wrong_private = generate_es256_keypair()
    proof = create_dpop_jwt(
        method="POST",
        htu="/v1/chat/completions",
        access_token=token,
        private_jwk=wrong_private,
    )

    response = client.post(
        "/v1/chat/completions",
        json={"model": "gpt-4o-mini"},
        headers={"Authorization": f"Bearer {token}", "DPoP": proof},
    )
    assert response.status_code == 401
    assert "thumbprint mismatch" in response.json()["error"]["message"]
