"""HTTP admin endpoint for the Log Generator (ADR-0015).

Exposes GET /rate and POST /rate so the EPS can be inspected and adjusted
at runtime without restarting the container.
"""

import json
from http.server import BaseHTTPRequestHandler
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from src.log_generator.service import LogGeneratorService


class LogAdminHandler(BaseHTTPRequestHandler):
    """Handle GET /rate and POST /rate for runtime EPS control.

    Subclasses must set the ``service`` class attribute to a
    :class:`~src.log_generator.service.LogGeneratorService` instance before
    the server is started.
    """

    service: "LogGeneratorService"

    def do_GET(self) -> None:
        """Return the current EPS as ``{"eps": <int>}``."""
        if self.path == "/rate":
            self._send_json(200, {"eps": self.service.get_eps()})
        else:
            self.send_error(404)

    def do_POST(self) -> None:
        """Update the EPS from ``{"eps": <int>}`` body and return the new value."""
        if self.path != "/rate":
            self.send_error(404)
            return

        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw)
            eps = int(data["eps"])
            if eps < 1:
                self.send_error(400)
                return
            self.service.set_eps(eps)
            self._send_json(200, {"eps": eps})
        except (KeyError, ValueError, json.JSONDecodeError):
            self.send_error(400)

    def _send_json(self, status: int, data: dict[str, Any]) -> None:
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        pass
