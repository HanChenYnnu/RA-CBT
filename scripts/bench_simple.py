"""Simple local benchmark for success and 429 rates."""

from __future__ import annotations

import argparse
import json
import pathlib
import sys


def main() -> None:
    parser = argparse.ArgumentParser(description="RA-CBT simple budget benchmark")
    parser.add_argument("--n", type=int, default=20, help="Number of requests")
    parser.add_argument("--mode", choices=["benign", "attack"], default="benign")
    args = parser.parse_args()

    root = pathlib.Path(__file__).resolve().parents[1]
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))

    import respx
    from client.dpop import create_dpop_jwt
    from client.keygen import generate_es256_keypair
    from fastapi.testclient import TestClient
    from gateway.app import app

    client = TestClient(app)
    pub, priv = generate_es256_keypair()
    exchange = client.post(
        "/auth/exchange",
        json={"client_jwk": pub, "ctx": {"tenant": "bench", "device_id": "devA"}},
        headers={
            "X-API-Key": "test-user-key",
            "X-Forwarded-For": "10.1.1.1",
            "User-Agent": "Bench/1.0",
        },
    )
    token = exchange.json()["access_token"]

    success = 0
    throttled = 0
    other = 0

    with respx.mock() as router:
        router.post("http://127.0.0.1:9000/v1/chat/completions").respond(
            status_code=200,
            json={"id": "bench", "usage": {"total_tokens": 4}},
        )
        for i in range(args.n):
            proof = create_dpop_jwt(
                method="POST",
                htu="/v1/chat/completions",
                access_token=token,
                private_jwk=priv,
            )
            is_attack = args.mode == "attack"
            ip = "20.9.9.9" if is_attack and i % 2 == 0 else "10.1.1.1"
            ua = "EvilBot/9.0" if is_attack else "Bench/1.0"
            max_tokens = 18 if is_attack else 6
            resp = client.post(
                "/v1/chat/completions",
                json={
                    "model": "gpt-4o-mini",
                    "messages": [{"role": "user", "content": "hello"}],
                    "max_tokens": max_tokens,
                },
                headers={
                    "Authorization": f"Bearer {token}",
                    "DPoP": proof,
                    "X-Forwarded-For": ip,
                    "User-Agent": ua,
                    "X-CTX": json.dumps({"tenant": "bench", "device_id": "devA"}),
                    "X-Traffic-Class": args.mode,
                },
            )
            if resp.status_code == 200:
                success += 1
            elif resp.status_code == 429:
                throttled += 1
            else:
                other += 1

    total = max(1, args.n)
    print(
        f"mode={args.mode} requests={args.n} success={success} "
        f"throttled_429={throttled} other={other}"
    )
    print(f"success_rate={success / total:.2%} throttled_rate={throttled / total:.2%}")


if __name__ == "__main__":
    main()
