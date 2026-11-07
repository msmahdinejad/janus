"""A tiny OpenAI-compatible shim for gateways that httpx cannot talk to.

The problem this solves is specific and real: some corporate LiteLLM-style
gateways complete a TLS handshake with curl/.NET/urllib but fails inside httpx with
`SSL: UNEXPECTED_EOF_WHILE_READING`. Tools that drive models through httpx
(Strix, litellm's own client, most agent frameworks) therefore cannot reach
it, even though the gateway is healthy.

The shim listens on localhost (which every client can reach) and forwards to
the real gateway over urllib. It is deliberately small: `/v1/models`, and
`/v1/chat/completions` with or without streaming. It never logs the key, and
it only listens on loopback.

    janus llm-shim --port 18081 --upstream https://llm-gateway.example.test/v1 \
        --api-key-env LLM_API_KEY

Then point the client at `http://127.0.0.1:18081/v1` with any placeholder key.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit

HOP_BY_HOP = {"connection", "keep-alive", "transfer-encoding", "upgrade", "proxy-connection"}


def _client_allowed(addr: str) -> bool:
    """Loopback and private ranges only (containers reach the host over a
    private bridge). Anything routable from the LAN is refused: this shim
    injects a real API key and must not become a free relay."""
    import ipaddress

    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return ip.is_loopback or ip.is_private


class _State:
    upstream: str
    api_key: str
    timeout: float

    def __init__(self, upstream: str, api_key: str, timeout: float = 900.0) -> None:
        self.upstream = upstream.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    state: _State

    def log_message(self, fmt: str, *args: Any) -> None:
        pass

    # -- helpers -------------------------------------------------------
    def _auth(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json", "Accept": "*/*"}
        if self.state.api_key:
            headers["Authorization"] = f"Bearer {self.state.api_key}"
        return headers

    def _json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _error(self, status: int, message: str) -> None:
        self._json(status, {"error": {"message": message, "type": "shim_error"}})

    # -- routes --------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802
        if not _client_allowed(self.client_address[0]):
            self._error(403, "client address not allowed")
            return
        if urlsplit(self.path).path.rstrip("/") not in ("/v1/models", "/models"):
            self._error(404, f"no route for {self.path}")
            return
        path = self.path if self.path.startswith("/v1") else "/v1" + self.path
        req = urllib.request.Request(self.state.upstream + path[len("/v1"):], headers=self._auth())
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                self._json(resp.status, json.loads(resp.read().decode()))
        except urllib.error.HTTPError as exc:
            self._error(exc.code, exc.read().decode(errors="replace")[:500])
        except Exception as exc:  # noqa: BLE001
            self._error(502, str(exc)[:300])

    def do_POST(self) -> None:  # noqa: N802
        if not _client_allowed(self.client_address[0]):
            self._error(403, "client address not allowed")
            return
        if urlsplit(self.path).path.rstrip("/") not in ("/v1/chat/completions", "/chat/completions"):
            self._error(404, f"no route for {self.path}")
            return
        length = int(self.headers.get("Content-Length") or 0)
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except Exception:  # noqa: BLE001
            self._error(400, "invalid JSON body")
            return

        stream = bool(payload.get("stream"))
        url = self.state.upstream + "/chat/completions"
        req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                     headers=self._auth(), method="POST")
        try:
            resp = urllib.request.urlopen(req, timeout=self.state.timeout)
        except urllib.error.HTTPError as exc:
            self._error(exc.code, exc.read().decode(errors="replace")[:800])
            return
        except Exception as exc:  # noqa: BLE001
            self._error(502, f"upstream: {exc}"[:300])
            return

        with resp:
            if not stream:
                body = resp.read()
                self.send_response(resp.status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

            self.send_response(resp.status)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "close")
            self.end_headers()
            try:
                while True:
                    chunk = resp.read(4096)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                return


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def serve(upstream: str, api_key: str, host: str = "127.0.0.1", port: int = 18081) -> None:
    state = _State(upstream, api_key)
    handler = type("BoundShim", (Handler,), {"state": state})
    server = _Server((host, port), handler)
    shown = f"http://{host}:{port}/v1"
    print(f"LLM shim: {shown}  ->  {upstream}  (key: {'set' if api_key else 'MISSING'})")
    print("  point clients at this base URL; the shim adds the real Authorization header")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def key_from_env(name: str) -> str:
    return os.environ.get(name, "").strip()
