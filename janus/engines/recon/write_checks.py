"""Deterministic checks for the write path.

The agent can improvise POST requests, but improvisation is not coverage. These
checks run the same three questions against every endpoint the operator listed
in `[[write.targets]]`:

  1. **Does a write work without authentication?** If the scope says the
     endpoint requires auth (`expect_auth = true`) and an anonymous POST returns
     2xx, that is a critical broken-access-control finding on its own.
  2. **Does the endpoint accept privileged fields it was not asked to accept?**
     The baseline body is replayed with one extra field at a time (`role`,
     `owner_id`, `price`, …). If the response echoes the injected value, the
     field reached the model — mass assignment.
  3. **Is the endpoint reachable with the wrong verb?** A GET that returns the
     same 2xx as the POST means the route is not method-constrained.

Everything here is bounded: only listed URLs, only the listed method, one
request per field, and the run's request budget applies. Nothing is deleted —
cleanup of created rows is the operator's job, and is stated in the report.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from ...core.http import ScopeClient, ScopeDenied
from ...core.model import Finding
from ...core.scope import Scope, WriteTarget

PROBE_MARKER = "janus-write-probe"

_NUMERIC_FIELDS = ("price", "total", "balance", "credit", "amount", "quantity", "qty")


def _probe_value(field_name: str) -> Any:
    name = field_name.lower()
    if name in _NUMERIC_FIELDS:
        return 1
    if name.startswith("is_") or name in ("approved", "verified", "staff", "admin"):
        return True
    if name in ("role", "type", "kind"):
        return "admin"
    return PROBE_MARKER


def _host(url: str) -> str:
    return urlsplit(url).hostname or url


@dataclass
class WriteResult:
    findings: list[Finding]
    checked: int = 0
    blocked: int = 0
    notes: list[str] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.notes is None:
            self.notes = []


def run(scope: Scope, client: ScopeClient) -> WriteResult:
    """Run the configured checks. Returns findings plus a small tally for the
    coverage section."""
    result = WriteResult(findings=[])
    for target in scope.write_targets:
        if not scope.authorize(target.url, method=target.method).allowed:
            result.blocked += 1
            continue
        result.checked += 1
        result.findings.extend(_check_target(scope, client, target))
    return result


def _post(client: ScopeClient, target: WriteTarget, body: dict) -> Any:
    try:
        return client.post(target.url, json_body=body)
    except ScopeDenied:
        return None
    except Exception as exc:  # noqa: BLE001 - network errors are data
        return exc


def _check_target(scope: Scope, client: ScopeClient, target: WriteTarget) -> list[Finding]:
    findings: list[Finding] = []
    host = _host(target.url)
    endpoint = urlsplit(target.url).path or "/"

    baseline = _post(client, target, target.body)
    if baseline is None or isinstance(baseline, Exception):
        return findings

    unauthenticated_write = target.expect_auth and 200 <= baseline.status < 300
    if unauthenticated_write:
        findings.append(Finding(
            title=f"Write accepted without authentication: {target.method} {endpoint}",
            severity="critical", category="access-control", engine="recon",
            tool="write-checks", rule_id="WRITE-UNAUTH", target=target.url, host=host,
            endpoint=endpoint, method=target.method,
            message=f"An unauthenticated {target.method} to this endpoint returned "
                    f"{baseline.status}. The scope declares expect_auth = true, so the write "
                    f"should have been rejected before touching business logic.",
            remediation="Require authentication (and authorization for the acting user) on the "
                        "write route itself, not only in the UI or at the gateway.",
            confidence="confirmed", cwe=("CWE-306",), owasp=("A01:2021",),
            extra={"evidence": f"{target.method} {endpoint} -> {baseline.status}",
                   "request_body": target.body},
            sources=("write-checks",),
        ))

    # Mass assignment is only meaningful when the write actually goes through.
    if 200 <= baseline.status < 300:
        for field_name in scope.mass_assignment_fields:
            if field_name in target.body:
                continue
            value = _probe_value(field_name)
            body = {**target.body, field_name: value}
            resp = _post(client, target, body)
            if resp is None or isinstance(resp, Exception) or resp.status >= 400:
                continue
            text = (resp.text or "")[:4000]
            echoed = f'"{field_name}"' in text and str(value).lower() in text.lower()
            if echoed:
                findings.append(Finding(
                    title=f"Mass assignment suspected: '{field_name}' accepted on {endpoint}",
                    severity="high", category="access-control", engine="recon",
                    tool="write-checks", rule_id="WRITE-MASS-ASSIGN", target=target.url,
                    host=host, endpoint=endpoint, method=target.method,
                    message=f"Sending an extra field '{field_name}' = {value!r} alongside the "
                            f"documented body returned {resp.status} and the response echoed the "
                            f"injected value, so the field reached the model. If this field is "
                            f"privileged (role, owner, price), the client controls it.",
                    remediation="Bind only an explicit allowlist of writable fields server-side "
                                "(serializer fields / DTO), never `**request.data`.",
                    confidence="needs-review", cwe=("CWE-915",), owasp=("A01:2021",),
                    extra={"evidence": text[:600], "injected_field": field_name,
                           "injected_value": value},
                    sources=("write-checks",),
                ))
                break  # one confirmed injection per endpoint is enough signal

    # Verb tampering: the same path answering a safe method.
    try:
        get_resp = client.get(target.url)
    except Exception:  # noqa: BLE001
        get_resp = None
    if get_resp is not None and 200 <= get_resp.status < 300 and 200 <= baseline.status < 300:
        findings.append(Finding(
            title=f"Endpoint answers both {target.method} and GET: {endpoint}",
            severity="medium", category="configuration", engine="recon",
            tool="write-checks", rule_id="WRITE-VERB-TAMPER", target=target.url, host=host,
            endpoint=endpoint, method="GET",
            message=f"{endpoint} returns {get_resp.status} to a GET and {baseline.status} to a "
                    f"{target.method}. That can be legitimate (a read route and a write route "
                    f"sharing a path), but it is also how method-based authorization gets "
                    f"bypassed. Needs a look.",
            remediation="Make the method part of the authorization decision, not just the route.",
            confidence="needs-review", cwe=("CWE-650",), owasp=("A01:2021",),
            sources=("write-checks",),
        ))
    return findings
