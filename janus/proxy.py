"""An allowlist HTTP proxy — the egress boundary for external agents.

`janus proxy --scope scope.toml --port 8899` starts a local forward proxy
that:

  * authorizes every request destination against the same `Scope` the rest
    of the tool uses (`Scope.authorize`), deny-wins;
  * refuses every method outside GET/HEAD/OPTIONS, so a proxied agent cannot
    POST/PUT/DELETE even if it tries;
  * counts requests against the scope's `max_requests`;
  * logs every decision (allow and deny) to `proxy-audit.ndjson`.

Point an external agent at it with `HTTP_PROXY`/`HTTPS_PROXY` (Strix's
adapter does this automatically when `JANUS_AGENT_PROXY` is set).

Honest limitation: for HTTPS the proxy sees a CONNECT to `host:443` and then
an encrypted tunnel. It can enforce *which host* is reachable, not which path
inside it. Path-level scope only exists for plain HTTP, and for the in-process
`native` agent (which uses `ScopeClient` for every request). Do not describe
this as path-level enforcement for HTTPS.
"""

from __future__ import annotations

import json
import select
import socket
import socketserver
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx

from .core.http import RequestBudget
from .core.scope import Scope

_HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "proxy-connection",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class ProxyState:
    def __init__(self, scope: Scope, audit_path: Path,
                 rewrite: dict[str, str] | None = None) -> None:
        self.scope = scope
        self.budget = RequestBudget(scope.max_requests)
        self.audit_path = audit_path
        self.rewrite = dict(rewrite or {})
        self.lock = threading.Lock()
        self.counts = {"allowed": 0, "denied": 0}

    def forward_host(self, host: str) -> str:
        """Address to actually connect to.

        The proxy authorizes the *requested* host; this only changes where the
        socket goes. Needed when the proxy runs on the host and the client
        addresses it by a container-only alias such as host.docker.internal.
        """
        return self.rewrite.get(host.lower(), host)

    def decide(self, target: str, method: str) -> tuple[bool, list[str]]:
        decision = self.scope.authorize(target, method=method)
        with self.lock:
            if decision.allowed:
                try:
                    self.budget.spend()
                except Exception as exc:  # BudgetExceeded
                    decision.allowed = False
                    decision.reasons.append(str(exc))
            key = "allowed" if decision.allowed else "denied"
            self.counts[key] += 1
            self.audit({
                "at": _now(), "target": target, "method": method,
                "allowed": decision.allowed, "reasons": decision.reasons,
                "used": self.budget.used,
            })
        return decision.allowed, decision.reasons

    def audit(self, row: dict[str, Any]) -> None:
        try:
            with self.audit_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(row, ensure_ascii=False) + "\n")
        except OSError:
            pass


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    state: ProxyState  # injected per-server

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
        pass  # the audit log is the record, not stderr

    # -- helpers -------------------------------------------------------
    def _deny(self, reasons: list[str], code: int = 403) -> None:
        body = json.dumps({"error": "blocked by scope", "reasons": reasons}).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _target_url(self) -> str | None:
        # Origin-form requests (GET /path) are not proxy requests.
        if self.path.startswith("http://") or self.path.startswith("https://"):
            return self.path
        return None

    # -- methods -------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802
        self._forward("GET")

    def do_HEAD(self) -> None:  # noqa: N802
        self._forward("HEAD")

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._forward("OPTIONS")

    def do_POST(self) -> None:  # noqa: N802
        self._reject_method()

    def _reject_method(self) -> None:
        reason = f"method {self.command} is outside the hard-coded safe set (GET/HEAD/OPTIONS)"
        with self.state.lock:
            self.state.counts["denied"] += 1
            self.state.audit({
                "at": _now(), "target": self._target_url() or self.path,
                "method": self.command, "allowed": False, "reasons": [reason],
                "used": self.state.budget.used,
            })
        self._deny([reason], 405)

    do_PUT = do_PATCH = do_DELETE = do_POST  # noqa: N815

    def _forward(self, method: str) -> None:
        url = self._target_url()
        if url is None:
            self._deny(["not a forward-proxy request (absolute URL required)"], 400)
            return
        allowed, reasons = self.state.decide(url, method)
        if not allowed:
            self._deny(reasons)
            return
        headers = {k: v for k, v in self.headers.items() if k.lower() not in _HOP_BY_HOP}
        parts = urlsplit(url)
        target = f"{parts.scheme}://{self.state.forward_host(parts.hostname or '')}"
        target += f":{parts.port}" if parts.port else ""
        target += f"{parts.path}?{parts.query}" if parts.query else parts.path
        try:
            with httpx.Client(timeout=30, follow_redirects=False, trust_env=False) as c:
                resp = c.request(method, target, headers=headers)
        except httpx.HTTPError as exc:
            self._deny([f"upstream error: {exc}"], 502)
            return
        body = resp.content
        self.send_response(resp.status_code)
        for k, v in resp.headers.items():
            if k.lower() not in _HOP_BY_HOP and k.lower() != "content-length":
                self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if method != "HEAD":
            self.wfile.write(body)

    def do_CONNECT(self) -> None:  # noqa: N802
        host, _, port = self.path.partition(":")
        target = f"https://{host}:{port or 443}/"
        allowed, reasons = self.state.decide(target, "GET")
        if not allowed:
            self._deny(reasons)
            return
        connect_host = self.state.forward_host(host)
        try:
            upstream = socket.create_connection((connect_host, int(port or 443)), timeout=15)
        except OSError as exc:
            self._deny([f"cannot connect: {exc}"], 502)
            return
        self.send_response(200, "Connection established")
        self.end_headers()
        self._tunnel(upstream)

    def _tunnel(self, upstream: socket.socket) -> None:
        sockets = [self.connection, upstream]
        try:
            while True:
                readable, _, errored = select.select(sockets, [], sockets, 30)
                if errored or not readable:
                    break
                for sock in readable:
                    data = sock.recv(65536)
                    if not data:
                        return
                    (upstream if sock is self.connection else self.connection).sendall(data)
        finally:
            upstream.close()


class _Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


def make_server(scope: Scope, host: str = "127.0.0.1", port: int = 8899,
                audit_path: Path | None = None,
                rewrite: dict[str, str] | None = None) -> tuple[_Server, ProxyState]:
    """Build the server without serving it (so tests can bind port 0)."""
    state = ProxyState(scope, audit_path or Path("proxy-audit.ndjson"), rewrite)
    handler = type("BoundHandler", (_Handler,), {"state": state})
    return _Server((host, port), handler), state


def serve(scope: Scope, host: str = "127.0.0.1", port: int = 8899,
          audit_path: Path | None = None, rewrite: dict[str, str] | None = None) -> None:
    server, state = make_server(scope, host, port, audit_path, rewrite)
    host, port = server.server_address[0], server.server_address[1]
    print(f"Janus scope proxy on http://{host}:{port}  (audit: {state.audit_path})")
    print(f"  allow: {scope.allow}  deny: {scope.deny}  max_requests: {scope.max_requests}")
    print("  HTTPS: host-level enforcement only (CONNECT tunnel). GET/HEAD/OPTIONS only.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        print(f"stopped: {state.counts['allowed']} allowed, {state.counts['denied']} denied, "
              f"{state.budget.used}/{state.budget.max_requests} requests")
