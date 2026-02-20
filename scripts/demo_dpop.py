"""Local demo: exchange API key for CBAT, then call chat with DPoP proof."""

from __future__ import annotations

import pathlib
import sys


def main() -> None:
    root = pathlib.Path(__file__).resolve().parents[1]
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))

    import respx
    from client.dpop import create_dpop_jwt
    from client.keygen import generate_es256_keypair
    from fastapi.testclient import TestClient
    from gateway.app import app

    client = TestClient(app)
    public_jwk, private_jwk = generate_es256_keypair()

    exchange = client.post(
        "/auth/exchange",
        json={"client_jwk": public_jwk, "ctx": {"tenant": "demo"}},
        headers={"X-API-Key": "test-user-key"},
    )
    token = exchange.json()["access_token"]

    proof = create_dpop_jwt(
        method="POST",
        htu="/v1/chat/completions",
        access_token=token,
        private_jwk=private_jwk,
    )

    with respx.mock() as router:
        router.post("http://127.0.0.1:9000/v1/chat/completions").respond(
            status_code=200,
            json={
                "id": "demo",
                "choices": [{"message": {"role": "assistant", "content": "ok"}}],
            },
        )
        response = client.post(
            "/v1/chat/completions",
            json={
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": "hi"}],
            },
            headers={"Authorization": f"Bearer {token}", "DPoP": proof},
        )

    print(response.status_code)
    print(response.json())


if __name__ == "__main__":
    main()
