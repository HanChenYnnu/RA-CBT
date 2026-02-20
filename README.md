# RA-CBT Stage Scaffold

Production-quality Python scaffold for the RA-CBT gateway project.

## Layout

- `gateway/`: FastAPI app, config, and upstream proxy modules
- `client/`: local OpenAI-compatible client helper
- `scripts/`: scenario/benchmark script placeholders
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
- `RA_CBT_REQUEST_TIMEOUT`

## API examples

Health:

```bash
curl -s http://127.0.0.1:8000/health
```

OpenAI-compatible proxy call via local gateway:

```bash
curl -s -X POST http://127.0.0.1:8000/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}'
```
