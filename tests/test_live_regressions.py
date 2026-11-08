"""Failures observed during the Torob integration run, with no live traffic."""
import json
from types import SimpleNamespace

import httpx
import pytest

from janus.core.coverage import build
from janus.core.providers import ProviderProfile, probe_models
from janus.engines.recon.agent import AgentBudget, StrixAdapter
from janus.engines.recon.native_agent import NativeAgent
from tests.test_hardening import _scope, FakeTransport, _provider, _tool_call
from janus.core.http import ScopeClient


def test_native_turn_limit_is_partial(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", "dummy")
    scope = _scope(tmp_path)
    client = ScopeClient(scope, transport=FakeTransport({}))
    result = NativeAgent().run(
        ["https://app.test/"], tmp_path, AgentBudget(max_turns=1), _provider(),
        scope=scope, http=client,
        llm_transport=httpx.MockTransport(lambda req: _tool_call(
            "call1", "http_get", {"url": "https://app.test/"})),
    )
    assert result.status == "partial"
    assert json.loads((tmp_path / "findings.json").read_text()) == []
    assert build(scope_name="t", mode="agent", findings=[], tool_results=[result])["quality"] == "degraded"


def test_probe_models_understands_gateway_slugs(monkeypatch):
    monkeypatch.setenv("JANUS_TEST_KEY", "dummy")
    monkeypatch.setattr(httpx.Client, "get", lambda *a, **kw: httpx.Response(
        200, json={"models": [{"slug": "model-a"}, {"slug": "model-b"}]}))
    p = ProviderProfile("p", "https://gateway.test", "model-a", "JANUS_TEST_KEY")
    ids, error = probe_models(p)
    assert ids == ["model-a", "model-b"]
    assert not error


@pytest.mark.parametrize("returncode,stdout", [(1, "Not logged in"), (0, "Unable to review"), (0, '[{"oops": 1}]')])
def test_review_failure_does_not_become_clean(tmp_path, monkeypatch, returncode, stdout):
    from janus import review
    monkeypatch.setattr(review, "find_tool", lambda name: "fake")
    monkeypatch.setattr(review.subprocess, "run", lambda *a, **kw: SimpleNamespace(
        returncode=returncode, stdout=stdout, stderr=""))
    result = review.run(tmp_path, agent="codex", lenses=[])
    assert review.tool_result(result).status == "failed"


def test_review_valid_empty_array_is_clean(tmp_path, monkeypatch):
    from janus import review
    monkeypatch.setattr(review, "find_tool", lambda name: "fake")
    monkeypatch.setattr(review.subprocess, "run", lambda *a, **kw: SimpleNamespace(
        returncode=0, stdout="[]", stderr=""))
    assert review.tool_result(review.run(tmp_path, lenses=[])).status == "ok"


@pytest.mark.parametrize("summary", [
    "Assessment Status: Incomplete — No Findings Reported",
    "Actual execution: None beyond scope definition.",
    "The target should be treated as untested. No traffic was generated.",
])
def test_strix_empty_sarif_does_not_override_unassessed_report(tmp_path, monkeypatch, summary):
    run_dir = tmp_path / "strix_runs" / "current"
    def run(*a, **kw):
        run_dir.mkdir(parents=True)
        (run_dir / "findings.sarif").write_text(json.dumps({"runs": [{
            "results": [], "invocations": [{"executionSuccessful": True}]}]}))
        (run_dir / "penetration_test_report.md").write_text(summary, encoding="utf-8")
        return SimpleNamespace(returncode=0, stdout="", stderr="")
    monkeypatch.setattr("janus.engines.recon.agent.find_tool", lambda name: "fake")
    monkeypatch.setattr("janus.engines.recon.agent.subprocess.run", run)
    monkeypatch.setenv("JANUS_TEST_KEY", "dummy")
    p = ProviderProfile("p", "https://model.test", "m", "JANUS_TEST_KEY")
    result = StrixAdapter().run(["https://app.test"], tmp_path, AgentBudget(), p,
                               egress_proxy="http://127.0.0.1:8898")
    assert result.status == "failed"


def test_failed_dns_response_is_not_an_absent_record(monkeypatch):
    from janus.engines.recon.passive import _txt_records
    class Resolver:
        def get(self, *a, **kw):
            return httpx.Response(200, request=httpx.Request("GET", "https://dns.test"),
                                  json={"Status": 2, "Question": []})
    monkeypatch.setattr("janus.engines.recon.passive.subprocess.run", lambda *a, **kw:
                        SimpleNamespace(returncode=1, stdout="", stderr="timeout"))
    assert _txt_records("example.test", Resolver()) == ([], False)


def test_denied_parent_domain_is_not_used_for_email_findings(tmp_path, monkeypatch):
    from janus.engines.recon import scan, passive
    scope = _scope(tmp_path, allow='["staging.example.test"]', extra='deny = ["example.test"]')
    monkeypatch.setattr(passive, "discover_subdomains_crtsh", lambda *a: [])
    monkeypatch.setattr(passive, "group_by_ip", lambda *a: {})
    from janus.engines.common import ToolResult
    monkeypatch.setattr(scan.adapters, "run_subfinder", lambda *a: ([], ToolResult("subfinder", "skipped")))
    queried = []
    monkeypatch.setattr(passive, "check_email_auth", lambda domain, client: (queried.append(domain) or [], True))
    result = scan.run(scope, cache_dir=tmp_path / "cache")
    assert queried == []
    assert any(r.name == "email-auth" and r.status == "skipped" for r in result.tool_results)


def test_coverage_does_not_claim_skipped_tool_is_missing():
    from janus.engines.common import ToolResult
    doc = build(scope_name="t", mode="passive", findings=[], tool_results=[
        ToolResult("email-auth", "skipped", detail="parent domain outside scope")])
    assert "not installed" not in " ".join(doc["gaps"])
    assert "outside scope" in " ".join(doc["gaps"])


def test_selected_lens_is_not_proof_it_was_tested():
    from janus.lenses import select
    from janus.engines.common import ToolResult
    doc = build(scope_name="t", mode="agent", findings=[], lenses=select("authn"),
                tool_results=[ToolResult("agent:native:test", "ok")])
    assert doc["lenses"][0]["status"] == "requested (execution unverified)"
    assert doc["quality"] == "degraded"
    assert any("per-lens" in gap for gap in doc["gaps"])


def test_recon_persists_lenses_and_rejects_invalid_selection(tmp_path, monkeypatch):
    from janus import cli
    from janus.engines.recon.scan import ReconScanResult
    from janus.dashboard.history import list_scans
    _scope(tmp_path)
    calls = []
    def run(*a, **kw):
        calls.append(kw)
        return ReconScanResult([], [], [], [], [])
    monkeypatch.setattr(cli.recon_scan, "run", run)
    output = tmp_path / "out"
    args = ["scan", "recon", "--scope", str(tmp_path / "scope.toml"),
            "--out", str(output), "--lens"]
    assert cli.main([*args, "nonexistent"]) == 2
    assert calls == []
    assert cli.main([*args, "authn"]) == 0
    assert [lens.id for lens in calls[0]["lenses"]] == ["authn"]
    assert json.loads((output / "coverage.json").read_text())["lenses"][0]["id"] == "authn"
    assert list_scans(output)[0]["lenses"] == ["authn"]


def test_distinct_agent_findings_on_same_url_survive_merge_and_aggregation():
    from janus.core.model import Finding, dedupe, aggregate_repetitive
    rows = [Finding(title=f"Separate issue {i}", severity="low", category="other",
                    engine="recon", tool="agent:native:test", rule_id="AGENT-FINDING",
                    host="app.test", endpoint="/", method="GET") for i in range(12)]
    duplicate = Finding(**{k: v for k, v in rows[0].to_dict().items() if k != "fingerprint"})
    assert len(dedupe([*rows, duplicate])) == 12
    assert len(aggregate_repetitive(rows)) == 12


def test_native_http_tool_explains_redirect_and_returns_security_headers(tmp_path):
    from tests.test_hardening import _resp
    scope = _scope(tmp_path)
    client = ScopeClient(scope, transport=FakeTransport({
        "http://app.test/": _resp(302, "http://app.test/", {"location": "https://app.test/"}),
        "https://app.test/": _resp(200, "https://app.test/", {"strict-transport-security": "max-age=123"}),
    }))
    content, _ = NativeAgent()._http_get(client, {"url": "http://app.test/"})
    result = json.loads(content)
    assert result["requested_url"] == "http://app.test/"
    assert result["url"] == "https://app.test/"
    assert result["redirect_chain"] == [
        {"url": "http://app.test/", "status": 302},
        {"url": "https://app.test/", "status": 200},
    ]
    assert result["headers"]["strict-transport-security"] == "max-age=123"


def test_strix_synthetic_sarif_location_uses_target_metadata(tmp_path):
    from janus.engines.recon.agent import _parse_strix_sarif
    path = tmp_path / "findings.sarif"
    path.write_text(json.dumps({"runs": [{"results": [{
        "ruleId": "CWE-213", "level": "warning", "message": {"text": "Excess SSR fields"},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": "SECURITY.md"}}}],
        "properties": {"synthetic_location": True, "strix": {
            "target": "https://app.test/", "endpoint": "/shop/{id}/", "method": "GET",
            "technical_analysis": "Private fields in anonymous page props",
            "remediation_steps": "Use a public serializer allow-list",
        }},
    }]}]}), encoding="utf-8")
    finding = _parse_strix_sarif(path, "agent:strix:test", _provider())[0]
    assert finding.target == "https://app.test/"
    assert finding.host == "app.test"
    assert finding.endpoint == "/shop/{id}/"
    assert "anonymous page props" in finding.extra["evidence"]
    assert "allow-list" in finding.remediation
