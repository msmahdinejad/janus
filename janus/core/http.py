"""The only HTTP client the recon engine is allowed to use.

Every request goes through three checks, in this order, before a single byte
leaves the machine:

  1. `Scope.authorize()` — host/port/path/scheme/method, deny-wins.
  2. `RequestBudget` — the scope's `max_requests` is a real ceiling, shared by
     every probe, redirect hop and agent tool call in the run.
  3. redirects are followed *manually*: each hop is authorized again, so a
     302 to an out-of-scope host is refused instead of silently followed.

Why this module exists at all: the delivered version called `httpx` directly
from a dozen places. That made "is every request scope-checked?" a question
you answer by reading all of them, and it made redirects a hole — the client
was created with `follow_redirects=False`, but nothing stopped a caller from
flipping it, and nothing counted requests at all. One client, one gate.
"""

from __future__ import annotations

import json
import json as _json
from dataclasses import dataclass, field
from typing import Any, Callable, Protocol
from urllib.parse import urljoin, urlsplit

import httpx

from .scope import Decision, Scope

MAX_REDIRECTS = 3


class ScopeDenied(RuntimeError):
    """A request was refused by the scope gate. Carries the Decision so the
    caller can log the exact reasons without re-deriving them."""

    def __init__(self, decision: Decision) -> None:
        self.decision = decision
        super().__init__("; ".join(decision.reasons) or "denied by scope")


class BudgetExceeded(RuntimeError):
    """The run's request budget is spent. This is a stop condition, not an
    error to retry: it means the scope promised a ceiling and we hit it."""


class TransportFailure(RuntimeError):
    """The request was authorized and charged, but the network failed.

    Distinct from a denial: the target was in scope, it just did not answer
    (DNS, connect timeout, TLS). Callers record it as "not tested" instead of
    letting one unreachable host abort the whole scan.
    """


@dataclass
class RequestBudget:
    max_requests: int
    used: int = 0
    by_host: dict[str, int] = field(default_factory=dict)

    @property
    def remaining(self) -> int:
        return max(self.max_requests - self.used, 0)

    def spend(self, host: str = "", n: int = 1) -> None:
        if self.used + n > self.max_requests:
            raise BudgetExceeded(
                f"request budget exhausted ({self.used}/{self.max_requests}); "
                f"raise [limits].max_requests in the scope file only with authorization"
            )
        self.used += n
        if host:
            self.by_host[host] = self.by_host.get(host, 0) + n


@dataclass
class Response:
    """A deliberately small response shape: status, headers, bounded text.

    Bounded matters: a hostile or broken endpoint returning a 2 GB body must
    not become a 2 GB Python string. `truncated` says the body was cut.
    """

    status: int
    url: str
    headers: dict[str, str]
    raw_headers: list[tuple[str, str]]
    text: str
    truncated: bool = False

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)

    def header_list(self, name: str) -> list[str]:
        return [v for k, v in self.raw_headers if k.lower() == name.lower()]

    def json(self) -> Any:
        return _json.loads(self.text)


class Transport(Protocol):
    def send(self, method: str, url: str, headers: dict[str, str],
             body: bytes | None = None) -> Response: ...


class HttpxTransport:
    """One httpx client, no redirects, no cookies, bounded body reads."""

    def __init__(self, timeout: float = 15.0, max_body: int = 1_000_000) -> None:
        self.max_body = max_body
        self._client = httpx.Client(
            timeout=timeout,
            follow_redirects=False,
            # A scanner must not carry a victim's cookies around; recon is
            # anonymous by construction.
            cookies=None,
            trust_env=False,
        )

    def send(self, method: str, url: str, headers: dict[str, str],
             body: bytes | None = None) -> Response:
        with self._client.stream(method, url, headers=headers, content=body) as resp:
            chunks: list[bytes] = []
            total = 0
            truncated = False
            for chunk in resp.iter_bytes():
                if total + len(chunk) > self.max_body:
                    chunks.append(chunk[: self.max_body - total])
                    truncated = True
                    break
                chunks.append(chunk)
                total += len(chunk)
            body = b"".join(chunks)
            text = body.decode(resp.encoding or "utf-8", errors="replace")
            return Response(
                status=resp.status_code,
                url=str(resp.url),
                headers={k.lower(): v for k, v in resp.headers.items()},
                raw_headers=list(resp.headers.multi_items()),
                text=text,
                truncated=truncated,
            )

    def close(self) -> None:
        self._client.close()


class ScopeClient:
    """Scope-checked, budgeted, redirect-aware HTTP client."""

    def __init__(
        self,
        scope: Scope,
        transport: Transport | None = None,
        budget: RequestBudget | None = None,
        *,
        rate_limiter: Any | None = None,
        on_probe: Callable[[dict[str, Any]], None] | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        self.scope = scope
        self.transport = transport or HttpxTransport()
        self.budget = budget or RequestBudget(scope.max_requests)
        self.rate_limiter = rate_limiter
        self.on_probe = on_probe
        self.extra_headers = dict(extra_headers or {})
        self.log: list[dict[str, Any]] = []
        self.exhausted = False

    # -- internals -----------------------------------------------------
    def _record(self, url: str, method: str, status: int | None, allowed: bool,
                reasons: tuple[str, ...] = ()) -> None:
        row = {"url": url, "method": method, "status": status, "allowed": allowed,
               "reasons": list(reasons)}
        self.log.append(row)
        if self.on_probe:
            self.on_probe(row)

    def _host(self, url: str) -> str:
        return (urlsplit(url).hostname or "").lower()

    def get(self, url: str, headers: dict[str, str] | None = None, *,
            follow_redirects: bool = True) -> Response:
        return self.request("GET", url, headers=headers, follow_redirects=follow_redirects)

    def post(self, url: str, json_body: dict | None = None,
             headers: dict[str, str] | None = None, *, follow_redirects: bool = False) -> Response:
        """POST is only reachable when the scope opted in; the gate below
        enforces that, so this method existing is not itself a permission."""
        merged = {"Content-Type": "application/json", **(headers or {})}
        body = json.dumps(json_body).encode("utf-8") if json_body is not None else b""
        return self.request("POST", url, headers=merged, body=body,
                            follow_redirects=follow_redirects)

    def request(self, method: str, url: str, headers: dict[str, str] | None = None, *,
                body: bytes | None = None, follow_redirects: bool = True) -> Response:
        method = method.upper()
        merged = {**self.extra_headers, **(headers or {})}
        hops = 0
        while True:
            decision = self.scope.authorize(url, method=method)
            if not decision.allowed:
                self._record(url, method, None, False, tuple(decision.reasons))
                raise ScopeDenied(decision)

            try:
                self.budget.spend(host=self._host(url))
            except BudgetExceeded:
                self.exhausted = True
                self._record(url, method, None, False, ("budget exhausted",))
                raise

            if self.rate_limiter is not None:
                self.rate_limiter.wait()

            try:
                resp = self.transport.send(method, url, merged, body)
            except Exception as exc:  # noqa: BLE001 - network errors are data, not crashes
                self._record(url, method, None, True, (f"transport error: {exc}",))
                raise TransportFailure(f"{url}: {exc}") from exc
            self._record(url, method, resp.status, True)

            location = resp.header("location")
            if not (follow_redirects and location and resp.status in (301, 302, 303, 307, 308)):
                return resp
            if hops >= MAX_REDIRECTS:
                return resp
            hops += 1
            next_url = urljoin(url, location)
            next_decision = self.scope.authorize(next_url, method=method)
            if not next_decision.allowed:
                # Do not follow. The redirect itself is still observable and
                # the blocked hop is logged with the reason.
                self._record(next_url, method, None, False, tuple(next_decision.reasons))
                return resp
            url = next_url

    def close(self) -> None:
        close = getattr(self.transport, "close", None)
        if close:
            close()


def probe_summary(client: ScopeClient) -> dict[str, Any]:
    """Counts for the run report: what was allowed, what was denied, why."""
    denied = [r for r in client.log if not r["allowed"]]
    hosts = sorted({urlsplit(r["url"]).hostname or "" for r in client.log if r.get("url")})
    return {
        "requests": client.budget.used,
        "budget": client.budget.max_requests,
        "denied": len(denied),
        "denied_reasons": sorted({reason for r in denied for reason in r["reasons"]})[:20],
        "hosts": hosts,
    }

