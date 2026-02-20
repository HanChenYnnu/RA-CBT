import respx
from fastapi.testclient import TestClient
from gateway.app import app


def test_health() -> None:
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_chat_proxy_forwards_request_and_preserves_response() -> None:
    client = TestClient(app)
    payload = {"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hi"}]}
    upstream_response = {
        "id": "chatcmpl-123",
        "object": "chat.completion",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": "hello"}}],
    }

    with respx.mock() as router:
        route = router.post("http://127.0.0.1:9000/v1/chat/completions").respond(
            status_code=200,
            json=upstream_response,
        )
        response = client.post("/v1/chat/completions", json=payload)

    assert route.called
    assert route.call_count == 1
    sent = route.calls[0].request
    assert sent.url == "http://127.0.0.1:9000/v1/chat/completions"
    assert sent.headers["Authorization"] == "Bearer dev-upstream-key"
    assert sent.json == payload

    assert response.status_code == 200
    assert response.json() == upstream_response
    assert response.headers.get("X-Request-ID")


def test_chat_proxy_propagates_upstream_error() -> None:
    client = TestClient(app)
    with respx.mock() as router:
        router.post("http://127.0.0.1:9000/v1/chat/completions").respond(
            status_code=429,
            json={"error": {"message": "rate_limited"}},
        )
        response = client.post("/v1/chat/completions", json={"model": "gpt-4o-mini"})

    assert response.status_code == 429
    assert response.json() == {"error": {"message": "rate_limited"}}
    assert response.headers.get("X-Request-ID")
