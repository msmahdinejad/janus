"""A deliberately weak local target, for calibrating the pipeline.

Not a vulnerable app in the OWASP Juice Shop sense: it is a ~90-line stdlib
server with exactly the flaws the checks are supposed to catch, so you can
answer "does the scanner work on my machine, with my model, right now?"
without pointing anything at a real system.

    python examples/lab_app/server.py --port 8099

Flaws planted on purpose:
  * missing security headers, weak cookie flags
  * CORS reflects any Origin, with credentials
  * /static/app.js ships an AWS-shaped key and a Stripe publishable key
  * /api/orders/<id> returns another user's order with no authorization
  * /.git/config is served
  * /admin answers 401 (reachable, protected)
  * /api/health leaks a version string
"""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

APP_JS = """
const cfg = {api: "/api", region: "eu-west-1"};
const AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE";
const STRIPE_PUBLISHABLE = "pk_live_51NxExamplePublishableKey0001";
async function loadOrder(id) { return (await fetch(`/api/orders/${id}`)).json(); }
loadOrder(1).then(o => { document.body.innerText = JSON.stringify(o); });
"""

INDEX = """<!doctype html>
<html><head><title>LabShop</title><script src="/static/app.js"></script></head>
<body><h1>LabShop</h1><p>A deliberately weak local target for Janus calibration.</p></body></html>
"""

ORDERS = {
    "1": {"id": 1, "email": "alice@example.test", "total": 4200, "status": "paid"},
    "2": {"id": 2, "email": "bob@example.test", "total": 9900, "status": "pending"},
    "3": {"id": 3, "email": "carol@example.test", "total": 15000, "status": "paid"},
}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # keep the console readable
        pass

    def _send(self, status: int, body: bytes, content_type: str = "text/html; charset=utf-8"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Set-Cookie", "sid=lab-session-abc123; Path=/")
        origin = self.headers.get("Origin")
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_POST(self):  # noqa: N802
        # Deliberately unauthenticated create: this is what the deterministic
        # write checks are supposed to flag (WRITE-UNAUTH / mass assignment).
        length = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except Exception:  # noqa: BLE001
            body = {}
        created = {"id": 99, **body}
        self._send(201, json.dumps(created).encode(), "application/json")

    def do_GET(self):  # noqa: N802
        path = urlsplit(self.path).path

        if path in ("/", "/index.html"):
            self._send(200, INDEX.encode())
        elif path == "/static/app.js":
            self._send(200, APP_JS.encode(), "application/javascript")
        elif path == "/admin":
            self._send(401, b'{"detail":"authentication required"}', "application/json")
        elif path == "/.git/config":
            self._send(200, b"[core]\n\trepositoryformatversion = 0\n", "text/plain")
        elif path == "/api/health":
            self._send(200, json.dumps({"status": "ok", "version": "1.4.2"}).encode(), "application/json")
        elif path.startswith("/api/orders/"):
            order_id = path.rsplit("/", 1)[-1]
            order = ORDERS.get(order_id)
            if order is None:
                self._send(404, b'{"detail":"not found"}', "application/json")
            else:
                self._send(200, json.dumps(order).encode(), "application/json")
        else:
            self._send(404, b"not found", "text/plain")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8099)
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"lab target on http://{args.host}:{args.port}  (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
