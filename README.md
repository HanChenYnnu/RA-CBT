# RA-CBT Stage Scaffold

Production-quality Python scaffold for the RA-CBT gateway project.

## Layout

- `gateway/`: FastAPI app, config, JWT/DPoP verification, and upstream proxy modules
- `client/`: local OpenAI-compatible client + DPoP helpers
- `scripts/`: scenario/benchmark script placeholders and `demo_dpop.py`
- `experiments/`: experiment assets and outputs
- `tests/`: pytest test suite

## Quickstart

```bash
make setup
make test
make lint
```

Run server:

```bash
make run
# or
uvicorn gateway.app:app --reload
```

## Configuration

Configuration lives in `gateway/config.yaml` and supports env var overrides:

- `RA_CBT_UPSTREAM_BASE_URL`
- `RA_CBT_UPSTREAM_API_KEY`
- `RA_CBT_JWT_ACCESS_SECRET`
- `RA_CBT_CTX_SECRET`
- `RA_CBT_AUTH_ISSUER`
- `RA_CBT_AUTH_AUDIENCE`
- `RA_CBT_AUTH_TTL_SECONDS`
- `RA_CBT_REQUEST_TIMEOUT`

## API examples

Exchange API key for CBAT:

```bash
curl -s -X POST http://127.0.0.1:8000/auth/exchange \
  -H 'X-API-Key: test-user-key' \
  -H 'Content-Type: application/json' \
  -d '{"client_jwk":{"kty":"oct","k":"demo-key"},"ctx":{"tenant":"acme"}}'
```

Call protected chat endpoint using CBAT + DPoP:

```bash
# see scripts/demo_dpop.py for end-to-end local flow
python scripts/demo_dpop.py
```
