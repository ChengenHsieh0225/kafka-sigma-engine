"""Unit tests for the Log Generator HTTP admin endpoint (ADR-0015).

Tests observable behavior via real HTTP requests to a local test server:
- GET /rate returns the current EPS as JSON
- POST /rate updates the EPS and returns the new value
- POST /rate with invalid payloads returns 400
"""

import http.client
import json
import threading
from http.server import HTTPServer

from src.log_generator.admin import LogAdminHandler
from src.log_generator.service import LogGeneratorService


class FakePublisher:
    """In-memory publisher stub."""

    async def send(
        self,
        topic: str,
        value: bytes | None = None,
        key: bytes | None = None,
    ) -> None:
        pass


def _make_service(eps: int = 100) -> LogGeneratorService:
    svc = LogGeneratorService(publisher=FakePublisher(), topic="raw-logs")
    svc.set_eps(eps)
    return svc


def _spin_server(
    service: LogGeneratorService, n_requests: int = 1
) -> tuple[int, threading.Thread]:
    """Start a local HTTPServer that handles exactly n_requests, then exits."""
    Handler = type("_H", (LogAdminHandler,), {"service": service})
    server = HTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]

    def _serve() -> None:
        for _ in range(n_requests):
            server.handle_request()

    thread = threading.Thread(target=_serve, daemon=True)
    thread.start()
    return port, thread


# ---------------------------------------------------------------------------
# LogGeneratorService EPS accessors
# ---------------------------------------------------------------------------


def test_service_set_eps_then_get_eps_returns_new_value() -> None:
    svc = LogGeneratorService(publisher=FakePublisher(), topic="raw-logs")
    svc.set_eps(300)
    assert svc.get_eps() == 300


def test_service_set_eps_updates_value() -> None:
    svc = LogGeneratorService(publisher=FakePublisher(), topic="raw-logs")
    svc.set_eps(100)
    svc.set_eps(200)
    assert svc.get_eps() == 200


# ---------------------------------------------------------------------------
# GET /rate
# ---------------------------------------------------------------------------


def test_get_rate_returns_current_eps() -> None:
    service = _make_service(eps=200)
    port, thread = _spin_server(service)

    conn = http.client.HTTPConnection(f"127.0.0.1:{port}")
    conn.request("GET", "/rate")
    resp = conn.getresponse()
    body = json.loads(resp.read())

    assert resp.status == 200
    assert body["eps"] == 200
    thread.join(timeout=2)


def test_get_rate_reflects_updated_eps() -> None:
    service = _make_service(eps=100)
    service.set_eps(750)
    port, thread = _spin_server(service)

    conn = http.client.HTTPConnection(f"127.0.0.1:{port}")
    conn.request("GET", "/rate")
    resp = conn.getresponse()
    body = json.loads(resp.read())

    assert resp.status == 200
    assert body["eps"] == 750
    thread.join(timeout=2)


# ---------------------------------------------------------------------------
# POST /rate
# ---------------------------------------------------------------------------


def test_post_rate_updates_eps_and_returns_new_value() -> None:
    service = _make_service(eps=100)
    port, thread = _spin_server(service)

    payload = json.dumps({"eps": 500}).encode()
    conn = http.client.HTTPConnection(f"127.0.0.1:{port}")
    conn.request(
        "POST",
        "/rate",
        body=payload,
        headers={"Content-Length": str(len(payload)), "Content-Type": "application/json"},
    )
    resp = conn.getresponse()
    body = json.loads(resp.read())

    assert resp.status == 200
    assert body["eps"] == 500
    assert service.get_eps() == 500
    thread.join(timeout=2)


def test_post_rate_non_json_body_returns_400() -> None:
    service = _make_service(eps=100)
    port, thread = _spin_server(service)

    payload = b"not-json"
    conn = http.client.HTTPConnection(f"127.0.0.1:{port}")
    conn.request("POST", "/rate", body=payload, headers={"Content-Length": str(len(payload))})
    resp = conn.getresponse()
    resp.read()

    assert resp.status == 400
    thread.join(timeout=2)


def test_post_rate_zero_eps_returns_400() -> None:
    service = _make_service(eps=100)
    port, thread = _spin_server(service)

    payload = json.dumps({"eps": 0}).encode()
    conn = http.client.HTTPConnection(f"127.0.0.1:{port}")
    conn.request("POST", "/rate", body=payload, headers={"Content-Length": str(len(payload))})
    resp = conn.getresponse()
    resp.read()

    assert resp.status == 400
    thread.join(timeout=2)


def test_post_rate_missing_eps_key_returns_400() -> None:
    service = _make_service(eps=100)
    port, thread = _spin_server(service)

    payload = json.dumps({"rate": 500}).encode()
    conn = http.client.HTTPConnection(f"127.0.0.1:{port}")
    conn.request("POST", "/rate", body=payload, headers={"Content-Length": str(len(payload))})
    resp = conn.getresponse()
    resp.read()

    assert resp.status == 400
    thread.join(timeout=2)
