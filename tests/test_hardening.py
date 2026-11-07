"""Regression tests for the hardening pass.

Each test here corresponds to a specific failure mode found in review, so a
future refactor that reintroduces one fails loudly instead of quietly
widening the blast radius.
"""

from __future__ import annotations

import json
import sys
import textwrap
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from janus.core.http import BudgetExceeded, RequestBudget, Response, ScopeClient, ScopeDenied
from janus.core.model import Finding
from janus.core.providers import ProviderProfile
from janus.core.scope import ScopeError, load_scope
from janus.engines.code.scan import iter_files
from janus.engines.common import run_tool
from janus.engines.recon.agent import AgentBudget
from janus.engines.recon.native_agent import NativeAgent


def _scope(tmp_path: Path, *, limits: str = "", allow: str = '["app.test", "*.app.test"]',
           extra: str = "", roots: str = ".", ports: str = "[80, 443]"):
    body = f"""\
    [engagement]
    name = "t"
    authorized_by = "team"
    reference = "SEC-1"
    valid_from = "2020-01-01"
    valid_until = "2999-01-01"

    [targets]
    allow = {allow}
    allow_ports = {ports}
    {extra}

    [limits]
    {limits}

    [code]
    roots = [{json.dumps(str(Path(roots)))}]
    """
    p = tmp_path / "scope.toml"
    p.write_text(textwrap.dedent(body), encoding="utf-8")
    return load_scope(p)


class FakeTransport:
    def __init__(self, responses: dict[str, Response]) -> None:
        self.responses = responses
        self.calls: list[str] = []

    def send(self, method: str, url: str, headers: dict[str, str], body: bytes | None = None) -> Response:
        self.calls.append(url)
        return self.responses.get(url, Response(404, url, {}, [], "not found"))


def _resp(status: int = 200, url: str = "https://app.test/", headers: dict | None = None,
          text: str = "") -> Response:
    hdrs = {k.lower(): v for k, v in (headers or {}).items()}
    return Response(status, url, hdrs, list((headers or {}).items()), text)


# ---- scope validation -------------------------------------------------

def test_invalid_date_is_a_scope_error_not_a_traceback(tmp_path):
    body = textwrap.dedent("""\
        [engagement]
        name = "t"
        authorized_by = "x"
        reference = "r"
        valid_from = "not-a-date"
        valid_until = "2999-01-01"
    """)
    p = tmp_path / "scope.toml"
    p.write_text(body, encoding="utf-8")
    with pytest.raises(ScopeError, match="valid_from"):
        load_scope(p)


def test_invalid_forbidden_path_regex_is_a_scope_error(tmp_path):
    with pytest.raises(ScopeError, match="forbidden_paths"):
        _scope(tmp_path, extra='forbidden_paths = ["(unclosed"]')


def test_negative_budget_rejected(tmp_path):
    with pytest.raises(ScopeError, match="max_requests"):
        _scope(tmp_path, limits="max_requests = -5")


def test_private_ip_requires_explicit_opt_in(tmp_path):
    scope = _scope(tmp_path, allow='["127.0.0.1"]')
    assert not scope.authorize("http://127.0.0.1:8000/").allowed

    scope2 = _scope(tmp_path, allow='["127.0.0.1"]', limits="allow_private_targets = true", ports="[80, 443, 8000]")
    assert scope2.authorize("http://127.0.0.1:8000/").allowed


def test_metadata_ip_always_denied_even_with_private_allowed(tmp_path):
    scope = _scope(tmp_path, allow='["169.254.169.254"]',
                   limits="allow_private_targets = true")
    decision = scope.authorize("http://169.254.169.254/latest/meta-data/")
    assert not decision.allowed
    assert any("link-local" in r for r in decision.reasons)


def test_host_normalisation_matches_trailing_dot_and_case(tmp_path):
    scope = _scope(tmp_path)
    assert scope.authorize("https://APP.TEST./").allowed


# ---- ScopeClient: budget, redirects, denial ---------------------------

def test_request_budget_is_enforced(tmp_path):
    scope = _scope(tmp_path, limits="max_requests = 2")
    client = ScopeClient(scope, transport=FakeTransport({}), budget=RequestBudget(2))
    client.get("https://app.test/a")
    client.get("https://app.test/b")
    with pytest.raises(BudgetExceeded):
        client.get("https://app.test/c")
    assert client.budget.used == 2


def test_redirect_to_out_of_scope_host_is_not_followed(tmp_path):
    scope = _scope(tmp_path)
    transport = FakeTransport({
        "https://app.test/": _resp(302, "https://app.test/", {"Location": "https://evil.test/"}),
    })
    client = ScopeClient(scope, transport=transport)
    resp = client.get("https://app.test/")
    assert resp.status == 302
    assert transport.calls == ["https://app.test/"]  # evil.test never contacted
    assert any(not row["allowed"] for row in client.log)


def test_out_of_scope_request_raises(tmp_path):
    scope = _scope(tmp_path)
    client = ScopeClient(scope, transport=FakeTransport({}))
    with pytest.raises(ScopeDenied):
        client.get("https://evil.test/")


# ---- redaction --------------------------------------------------------

def test_redaction_covers_title_remediation_and_nested_extra():
    secret = "sk-live-abcdef1234567890"
    f = Finding(
        title=f"leaked key {secret}",
        severity="high", category="secrets", engine="code", tool="builtin",
        remediation=f"rotate {secret} now",
        extra={"nested": {"token": secret}, "urls": [f"https://u:{secret}@h/"]},
    )
    blob = json.dumps(f.to_dict())
    assert secret not in blob
    assert "sk-live" not in f.title or "*" in f.title


def test_short_secrets_are_fully_masked():
    from janus.core.model import mask_secret

    assert mask_secret("abc") == "***"
    f = Finding(title="x", severity="info", category="other", engine="code", tool="t",
                message="password=abcd")
    assert "abcd" not in f.message


# ---- external tool exit codes ----------------------------------------

def test_run_tool_does_not_reuse_stale_output(tmp_path):
    out = tmp_path / "raw.json"
    out.write_text('{"stale": true}', encoding="utf-8")
    run = run_tool(sys.executable, ["-c", "import sys; sys.exit(3)"], out_path=out)
    assert not run.ok
    assert run.returncode == 3
    assert run.output_path is None  # stale file removed, nothing written
    assert not out.exists()


# ---- native agent -----------------------------------------------------

def _provider() -> ProviderProfile:
    return ProviderProfile(name="fake", base_url="https://llm.test/v1", model="m", api_key_env="PATH")


def _responses_provider() -> ProviderProfile:
    return ProviderProfile(name="openai", base_url="https://api.openai.test/v1",
                           model="gpt-6-astra", api_key_env="PATH",
                           api_format="responses")


def _tool_call(call_id: str, name: str, args: dict) -> httpx.Response:
    return httpx.Response(200, json={"choices": [{"message": {
        "role": "assistant", "content": None,
        "tool_calls": [{"id": call_id, "type": "function",
                        "function": {"name": name, "arguments": json.dumps(args)}}],
    }}]})


def test_native_agent_uses_only_the_scope_client(tmp_path, monkeypatch):
    scope = _scope(tmp_path)
    target = FakeTransport({"https://app.test/": _resp(200, "https://app.test/", text="<html>hi</html>")})
    client = ScopeClient(scope, transport=target)
    monkeypatch.setenv("PATH", "test-key")

    responses = iter([
        _tool_call("1", "http_get", {"url": "https://evil.test/", "reason": "out of scope"}),
        _tool_call("2", "http_get", {"url": "https://app.test/", "reason": "entry point"}),
        _tool_call("3", "report_finding", {
            "title": "Missing auth", "severity": "high", "url": "https://app.test/admin",
            "evidence": "200 without auth", "confidence": "confirmed", "lens": "authz"}),
        httpx.Response(200, json={"choices": [{"message": {"role": "assistant", "content": "done"}}]}),
    ])

    def handler(request: httpx.Request) -> httpx.Response:
        return next(responses)

    result = NativeAgent().run(
        ["https://app.test/"], tmp_path / "out", AgentBudget(max_turns=6), _provider(),
        scope=scope, http=client, llm_transport=httpx.MockTransport(handler),
    )
    assert result.status == "ok"
    assert target.calls == ["https://app.test/"]  # the out-of-scope URL never left the process
    agent_findings = [f for f in result.findings if f.rule_id == "AGENT-FINDING"]
    assert agent_findings
    # The lens the model selected maps the finding onto OWASP for coverage.
    assert agent_findings[0].owasp == ("A01:2021",)


def test_native_agent_refuses_without_scope_client(tmp_path):
    result = NativeAgent().run(["https://app.test/"], tmp_path, AgentBudget(), _provider())
    assert result.status == "failed"
    assert "scope-bound" in result.detail


def test_native_agent_uses_responses_wire_format_for_responses_models(tmp_path, monkeypatch):
    scope = _scope(tmp_path)
    target = FakeTransport({"https://app.test/": _resp(200, "https://app.test/", text="ok")})
    client = ScopeClient(scope, transport=target)
    monkeypatch.setenv("PATH", "test-key")
    requests: list[httpx.Request] = []
    responses = iter([
        httpx.Response(200, json={"id": "resp_1", "output": [{
            "type": "function_call", "call_id": "c1", "name": "http_get",
            "arguments": json.dumps({"url": "https://app.test/", "reason": "entry point"}),
        }]}),
        httpx.Response(200, json={"id": "resp_2", "output": [{
            "type": "message", "content": [{"type": "output_text", "text": "done"}],
        }]}),
    ])

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return next(responses)

    result = NativeAgent().run(
        ["https://app.test/"], tmp_path / "out", AgentBudget(max_turns=4), _responses_provider(),
        scope=scope, http=client, llm_transport=httpx.MockTransport(handler),
    )
    assert result.status == "ok"
    assert [request.url.path for request in requests] == ["/v1/responses", "/v1/responses"]
    first = json.loads(requests[0].content)
    second = json.loads(requests[1].content)
    assert first["tools"][0]["name"] == "http_get"
    assert second["previous_response_id"] == "resp_1"
    assert second["input"][0]["type"] == "function_call_output"
    assert target.calls == ["https://app.test/"]


# ---- code engine: exclusion bug --------------------------------------

def test_repo_under_a_directory_named_build_is_still_scanned(tmp_path):
    repo = tmp_path / "build" / "repo"
    repo.mkdir(parents=True)
    (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
    scope = _scope(tmp_path, roots=str(repo))
    files = [p.name for p in iter_files(scope)]
    assert files == ["app.py"]


# ---- dashboard -------------------------------------------------------

def test_dashboard_requires_token_when_configured(tmp_path):
    from janus.dashboard.server import build_app
    register = tmp_path / "register.json"
    register.write_text("[]", encoding="utf-8")
    client = TestClient(build_app(register, token="s3cret"))
    assert client.get("/api/findings").status_code == 401
    ok = client.get("/api/findings", headers={"Authorization": "Bearer s3cret"})
    assert ok.status_code == 200


def test_dashboard_refuses_public_bind_without_token(tmp_path):
    from janus.dashboard.server import run_dashboard
    with pytest.raises(SystemExit):
        run_dashboard(tmp_path / "r.json", host="0.0.0.0", open_browser=False)




def test_checks_stop_cleanly_when_budget_is_exhausted(tmp_path):
    from janus.engines.recon import passive

    scope = _scope(tmp_path, limits="max_requests = 1")
    client = ScopeClient(scope, transport=FakeTransport({
        "https://app.test/": _resp(200, "https://app.test/", text="<html></html>"),
    }))
    passive.check_headers_and_cookies(client, "https://app.test/")
    assert client.exhausted is False
    # next check finds no budget left; it must return "nothing tested", not raise
    assert passive.check_cors(client, "https://app.test/") == []
    assert client.exhausted is True

def test_proxy_blocks_out_of_scope_and_state_changing_methods(tmp_path):
    import http.client
    import threading

    from janus.proxy import make_server

    scope = _scope(tmp_path)
    server, state = make_server(scope, port=0, audit_path=tmp_path / "audit.ndjson")
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def call(method: str, target: str) -> int:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        try:
            conn.request(method, target)
            resp = conn.getresponse()
            resp.read()
            return resp.status
        finally:
            conn.close()

    try:
        assert call("GET", "http://evil.test/steal") == 403
        assert call("POST", "http://app.test/") == 405
    finally:
        server.shutdown()
        server.server_close()

    rows = [json.loads(line) for line in (tmp_path / "audit.ndjson").read_text().splitlines()]
    assert any("evil.test" in r["target"] and not r["allowed"] for r in rows)
    assert state.counts["denied"] >= 2

def test_recon_findings_at_same_endpoint_do_not_collapse(tmp_path):
    from janus.core.model import dedupe

    base = dict(severity="medium", category="configuration", engine="recon", tool="passive-recon",
                target="https://app.test/", host="app.test", endpoint="/", method="GET")
    a = Finding(title="Missing CSP", rule_id="HEADER-MISSING", **base)
    b = Finding(title="Cookie without HttpOnly", rule_id="COOKIE-FLAGS", **base)
    kept = dedupe([a, b])
    assert {f.rule_id for f in kept} == {"HEADER-MISSING", "COOKIE-FLAGS"}


def test_transport_failure_is_reported_not_raised_to_the_caller(tmp_path):
    from janus.core.http import TransportFailure

    class FailingTransport:
        def send(self, method, url, headers, body=None):
            raise OSError("dns goes nowhere")

    scope = _scope(tmp_path, allow='["app.test"]', ports="[80, 443]")
    client = ScopeClient(scope, transport=FailingTransport())
    from janus.engines.recon import passive
    assert passive.check_headers_and_cookies(client, "https://app.test/") == []
    assert client.budget.used == 1
    assert any("transport error" in r["reasons"][0] for r in client.log if r["reasons"])

def test_strix_sarif_is_mapped_to_findings(tmp_path):
    from janus.engines.recon.agent import _parse_strix_sarif
    from janus.core.providers import ProviderProfile

    sarif = {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "strix", "rules": [
                {"id": "idor", "name": "Broken object level authorization",
                 "shortDescription": {"text": "IDOR on order endpoint"}}]}},
            "results": [{
                "ruleId": "idor", "level": "error",
                "message": {"text": "GET /api/orders/2 returns another customer's order"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": "http://lab.test/api/orders/2"},
                    "region": {"startLine": 1}}}],
            }],
        }],
    }
    p = tmp_path / "findings.sarif"
    p.write_text(json.dumps(sarif), encoding="utf-8")
    provider = ProviderProfile(name="p", base_url="http://x", model="m", api_key_env="PATH")
    findings = _parse_strix_sarif(p, "agent:strix:p", provider)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "high" and f.rule_id == "idor"
    assert f.target.endswith("/api/orders/2") and f.host == "lab.test"

def test_strix_sarif_drops_clean_area_verdicts(tmp_path):
    from janus.engines.recon.agent import _parse_strix_sarif
    from janus.core.providers import ProviderProfile

    def result(rule, msg):
        return {"ruleId": rule, "level": "note", "message": {"text": msg},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": "https://x.test/"}}}]}

    doc = {"runs": [{"tool": {"driver": {"rules": []}}, "results": [
        result("a", "No issue identified: headers"),
        result("b", "Ruled out: admin bypass"),
        result("c", "Requires further review: /api/orders/{id}"),
    ]}]}
    p = tmp_path / "f.sarif"
    p.write_text(json.dumps(doc), encoding="utf-8")
    provider = ProviderProfile(name="p", base_url="http://x", model="m", api_key_env="PATH")
    findings = _parse_strix_sarif(p, "agent:strix:p", provider)
    assert len(findings) == 1
    assert findings[0].message.startswith("Needs review")

def test_strix_coverage_notes_are_low_severity_and_clean_areas_are_dropped(tmp_path):
    from janus.engines.recon.agent import _parse_strix_sarif
    from janus.core.providers import ProviderProfile

    doc = {"runs": [{"tool": {"driver": {"rules": []}}, "results": [
        {"ruleId": "strix-coverage/authz", "level": "note",
         "message": {"text": "Requires further review: authz"},
         "locations": [{"physicalLocation": {"artifactLocation": {"uri": "https://x.test/"}}}]},
        {"ruleId": "CWE-527", "level": "warning",
         "message": {"text": "Exposed .git"},
         "locations": [{"physicalLocation": {"artifactLocation": {"uri": "https://x.test/.git/config"}}}]},
    ]}]}
    p = tmp_path / "f.sarif"
    p.write_text(json.dumps(doc), encoding="utf-8")
    provider = ProviderProfile(name="p", base_url="http://x", model="m", api_key_env="PATH")
    findings = _parse_strix_sarif(p, "agent:strix:p", provider)
    assert [f.rule_id for f in findings] == ["strix-coverage/authz", "CWE-527"]
    assert findings[0].severity == "low" and findings[0].confidence == "needs-review"

def test_scan_history_records_are_immutable_per_run(tmp_path):
    from janus.dashboard.history import list_scans, load_scan, record_scan
    from janus.core.model import Finding

    def f(title, sev="high"):
        return Finding(title=title, severity=sev, category="configuration",
                       engine="recon", tool="passive-recon", target="https://a.test/",
                       host="a.test", endpoint="/", method="GET")

    manifest = {"engagement": "e", "authorization_reference": "r", "scope_sha256_16": "abc"}
    record_scan(tmp_path, run_id="run1", command="scan all", scope_manifest=manifest,
                findings=[f("first")])
    record_scan(tmp_path, run_id="run2", command="scan all", scope_manifest=manifest,
                findings=[f("second"), f("third", "low")])
    scans = list_scans(tmp_path)
    assert {s["run_id"] for s in scans} == {"run1", "run2"}
    assert len(load_scan(tmp_path, "run1")["findings"]) == 1
    assert len(load_scan(tmp_path, "run2")["findings"]) == 2


def test_scan_report_endpoint_serves_markdown_not_html(tmp_path):
    from janus.dashboard.history import record_scan
    from janus.dashboard.server import build_app
    from janus.core.model import Finding
    from fastapi.testclient import TestClient

    out = tmp_path / "out"
    out.mkdir()
    (out / "register.json").write_text("[]", encoding="utf-8")
    record_scan(out, run_id="r1", command="scan", scope_manifest={},
                findings=[Finding(title="<script>alert(1)</script>", severity="low",
                                  category="other", engine="recon", tool="x",
                                  target="https://a.test/", host="a.test")])
    client = TestClient(build_app(out / "register.json"))
    text = client.get("/api/scans/r1/report").text
    assert "script" in text and text.lstrip().startswith("#")


def test_dashboard_serves_scan_history(tmp_path):
    from fastapi.testclient import TestClient
    from janus.dashboard.history import record_scan
    from janus.dashboard.server import build_app
    from janus.core.model import Finding

    out = tmp_path / "out"
    out.mkdir()
    (out / "register.json").write_text("[]", encoding="utf-8")
    record_scan(out, run_id="r1", command="scan all", scope_manifest={"engagement": "e"},
                findings=[Finding(title="t", severity="low", category="other", engine="recon",
                                  tool="x", target="https://a.test/", host="a.test")])
    client = TestClient(build_app(out / "register.json"))
    assert client.get("/api/scans").json()[0]["run_id"] == "r1"
    page = client.get("/scans", follow_redirects=False)
    assert page.status_code == 307 and page.headers["location"] == "/#/scans"
    detail = client.get("/scans/r1", follow_redirects=False)
    assert detail.headers["location"] == "/#/scans?id=r1"
    assert client.get("/api/scans/r1").json()["findings"][0]["title"] == "t"

def test_scan_delta_only_compares_same_kind_of_run(tmp_path):
    from janus.dashboard.history import list_scans, record_scan
    from janus.core.model import Finding

    def f(title):
        return Finding(title=title, severity="low", category="other", engine="recon",
                       tool="x", target="https://a.test/", host="a.test")

    record_scan(tmp_path, run_id="code1", command="scan code", scope_manifest={}, findings=[f("a")])
    record_scan(tmp_path, run_id="recon1", command="scan recon --mode passive",
                scope_manifest={}, findings=[f("b")])
    record_scan(tmp_path, run_id="code2", command="scan code", scope_manifest={}, findings=[f("a")])
    rows = {r["run_id"]: r for r in list_scans(tmp_path)}
    # code2 compares with code1 (same finding) -> no new, no fixed
    assert rows["code2"]["delta"] == {"new": 0, "fixed": 0, "same": 1}
    # recon1 has no earlier recon run -> treated as first of its kind
    assert rows["recon1"]["delta"] == {"new": 1, "fixed": 0, "same": 0}


def test_coverage_quality_and_engine_status_are_honest():
    from janus.core.coverage import build
    from janus.engines.common import ToolResult

    doc = build(
        scope_name="e", mode="code", findings=[],
        tool_results=[ToolResult("semgrep", "skipped", detail="not installed")],
        engines=[{"id": "code", "status": "ran"}], code_files=4,
    )
    assert doc["quality"] == "degraded"
    assert doc["engines"] == [{"id": "code", "status": "ran"}]
    assert any("semgrep" in gap for gap in doc["gaps"])


def test_coverage_does_not_claim_agent_gap_without_selected_lenses():
    from janus.core.coverage import build

    doc = build(scope_name="e", mode="code", findings=[], lenses=None, engines=[])
    assert doc["gaps"] == [] and doc["quality"] == "complete"


def test_coverage_marks_budget_exhaustion_at_or_above_limit():
    from janus.core.coverage import build

    doc = build(scope_name="e", mode="passive", findings=[],
                recon={"budget_used": 11, "budget_max": 10}, engines=[{"id": "recon", "status": "ran"}])
    assert any("budget" in gap for gap in doc["gaps"])

def _write_scope(tmp_path, write_block: str = "", fields: str = '["role", "price"]'):
    body = f"""\
    [engagement]
    name = "t"
    authorized_by = "team"
    reference = "SEC-1"
    valid_from = "2020-01-01"
    valid_until = "2999-01-01"

    [targets]
    allow = ["staging.app.test"]
    seeds = ["https://staging.app.test"]
    allow_ports = [80, 443]

    [limits]
    allow_state_changing   = true
    mutating_methods       = ["POST"]
    require_nonprod_marker = true
    max_requests           = 50

    [code]
    roots = ["."]

    [write]
    mass_assignment_fields = {fields}
    {write_block}
    """
    p = tmp_path / "scope.toml"
    p.write_text(textwrap.dedent(body), encoding="utf-8")
    return load_scope(p)


class ScriptedTransport:
    """Returns queued responses in order and records what was sent."""
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def send(self, method, url, headers, body=None):
        self.calls.append((method, url, body))
        return self.responses.pop(0) if self.responses else _resp(404)


def test_write_checks_flag_unauthenticated_write(tmp_path):
    from janus.engines.recon import write_checks

    write_block = """
[[write.targets]]
url = "https://staging.app.test/api/orders"
method = "POST"
body = { product = 1 }
"""
    scope = _write_scope(tmp_path, write_block=write_block)
    # first POST succeeds anonymously -> critical; mass-assign loop then GET
    transport = ScriptedTransport([_resp(201, "https://staging.app.test/api/orders"),
                                   _resp(201, "https://staging.app.test/api/orders"),
                                   _resp(404, "https://staging.app.test/api/orders")])
    client = ScopeClient(scope, transport=transport)
    result = write_checks.run(scope, client)
    assert any(f.rule_id == "WRITE-UNAUTH" for f in result.findings)
    assert transport.calls[0][0] == "POST"


def test_write_checks_detect_mass_assignment_echo(tmp_path):
    from janus.core.scope import Scope, WriteTarget
    from janus.engines.recon import write_checks

    scope = _write_scope(tmp_path)
    scope.write_targets = [WriteTarget("https://staging.app.test/api/orders", "POST",
                                       {"product": 1}, expect_auth=False)]
    transport = ScriptedTransport([
        _resp(201, "https://staging.app.test/api/orders", text='{"id": 5}'),
        _resp(201, "https://staging.app.test/api/orders", text='{"id": 5, "role": "admin"}'),
        _resp(404, "https://staging.app.test/api/orders"),
    ])
    client = ScopeClient(scope, transport=transport)
    result = write_checks.run(scope, client)
    assert any(f.rule_id == "WRITE-MASS-ASSIGN" for f in result.findings)


def test_write_targets_require_state_changing_opt_in(tmp_path):
    from janus.core.scope import ScopeError, load_scope
    body = textwrap.dedent('''\
        [engagement]
        name = "t"
        authorized_by = "x"
        reference = "r"
        valid_from = "2020-01-01"
        valid_until = "2999-01-01"
        [targets]
        allow = ["staging.app.test"]
        [code]
        roots = ["."]
        [[write.targets]]
        url = "https://staging.app.test/api/orders"
    ''')
    p = tmp_path / "scope.toml"
    p.write_text(body, encoding="utf-8")
    with pytest.raises(ScopeError, match="allow_state_changing"):
        load_scope(p)

def test_dedupe_keeps_distinct_rules_from_one_tool(tmp_path):
    from janus.core.model import dedupe
    base = dict(severity="high", category="supply-chain", engine="code", tool="trivy",
                path="uv.lock", line=0)
    a = Finding(title="CVE-1", rule_id="CVE-1", **base)
    b = Finding(title="CVE-2", rule_id="CVE-2", **base)
    assert {f.rule_id for f in dedupe([a, b])} == {"CVE-1", "CVE-2"}


def test_dedupe_still_merges_the_same_secret_across_tools(tmp_path):
    from janus.core.model import dedupe
    base = dict(severity="critical", category="secrets", engine="code",
                path="app.py", line=10)
    a = Finding(title="secret", tool="gitleaks", rule_id="aws", **base)
    b = Finding(title="secret", tool="builtin", rule_id="SECRET-AWS-ACCESS-KEY", **base)
    out = dedupe([a, b])
    assert len(out) == 1
    assert "builtin" in out[0].extra.get("also_reported_by", []) + [out[0].tool]

def test_discovery_separates_owned_nonprod_and_ignores_third_party(tmp_path):
    from janus.discovery import discover, scope_toml

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "settings.py").write_text(
        'SITE = "https://staging.example.com"\n'
        'API = "https://api.example.com"\n'
        'GRAFANA = "https://grafana.example.com"\n'
        'CDN = "https://cdn.other.com"\n', encoding="utf-8")
    result = discover(repo, ["example.com"])
    assert result.nonprod == ["staging.example.com"]
    assert result.prod == ["api.example.com"]
    assert result.infra == ["grafana.example.com"]
    assert "cdn.other.com" in result.third_party

    toml = scope_toml(result)
    assert '"staging.example.com"' in toml
    assert 'deny  = ["api.example.com"]' in toml
    assert "grafana.example.com" not in toml.split("[limits]")[0]

def test_wall_clock_budget_stops_a_run(tmp_path):
    from janus.core.http import BudgetExceeded
    scope = _scope(tmp_path, limits="max_seconds = 0.001")
    import time as _time
    client = ScopeClient(scope, transport=FakeTransport({}))
    _time.sleep(0.01)  # the clock starts when the client is built
    with pytest.raises(BudgetExceeded, match="wall-clock"):
        client.get("https://app.test/")
