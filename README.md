# RA-CBT Stage Scaffold

Production-quality Python scaffold for the RA-CBT gateway project.

## Layout

- `gateway/`: FastAPI app, config, JWT/DPoP verification, context binding, and proxy modules
- `client/`: local OpenAI-compatible client + DPoP helpers
- `scripts/`: scenario/benchmark placeholders and `demo_dpop.py`
- `experiments/`: experiment assets and outputs
- `tests/`: pytest test suite

## Quickstart

```bash
make setup
make test
make lint
```

## Context tolerance policy

Context policy is defined in `gateway/policy/default.yaml` (same ASN/country, UA minor tolerance).  
Server always binds observed fields (`ip`, `ua`, optional `asn/country`) and compares runtime context to CBAT `ctx_hash` with tolerance fallback.

## API examples

Exchange API key for CBAT:

```bash
curl -s -X POST http://127.0.0.1:8000/auth/exchange \
  -H 'X-API-Key: test-user-key' \
  -H 'X-Forwarded-For: 10.1.1.1' \
  -H 'User-Agent: Browser/120.1' \
  -H 'Content-Type: application/json' \
  -d '{"client_jwk":{"kty":"oct","k":"demo-key"},"ctx":{"tenant":"acme"}}'
```

Ctx drift example (allowed same-ASN drift):

```bash
# First token issued from 10.x (AS64512), then call from 11.x (also AS64512)
# with minor UA change; request remains accepted by tolerance policy.
```

End-to-end local demo:

```bash
python scripts/demo_dpop.py
```
