from janus.core.model import Finding, dedupe, aggregate_repetitive, mask_secret, redact_text, summarize


def test_fingerprint_is_stable_for_identical_findings():
    f1 = Finding(title="X", severity="high", category="injection", engine="code", tool="builtin",
                 path="a.py", line=10)
    f2 = Finding(title="X", severity="high", category="injection", engine="code", tool="builtin",
                 path="a.py", line=10)
    assert f1.fingerprint == f2.fingerprint


def test_fingerprint_changes_with_line():
    f1 = Finding(title="X", severity="high", category="injection", engine="code", tool="builtin", path="a.py", line=10)
    f2 = Finding(title="X", severity="high", category="injection", engine="code", tool="builtin", path="a.py", line=11)
    assert f1.fingerprint != f2.fingerprint


def test_dedupe_keeps_more_severe_and_records_also_reported_by():
    low = Finding(title="X", severity="low", category="secrets", engine="code", tool="gitleaks", path="a.py", line=1)
    high = Finding(title="X", severity="critical", category="secrets", engine="code", tool="builtin", path="a.py", line=1)
    out = dedupe([low, high])
    assert len(out) == 1
    assert out[0].severity == "critical"
    assert "gitleaks" in out[0].extra["also_reported_by"]


def test_aggregate_collapses_repetitive_non_exempt_category():
    findings = [
        Finding(title="noisy", severity="low", category="container", engine="code", tool="trivy",
                rule_id="KSV-1", path=f"f{i}.yaml", line=1)
        for i in range(15)
    ]
    out = aggregate_repetitive(findings, threshold=10)
    assert len(out) == 1
    assert out[0].extra["occurrences"] == 15


def test_aggregate_never_collapses_secrets():
    findings = [
        Finding(title="secret", severity="critical", category="secrets", engine="code", tool="builtin",
                rule_id="S-1", path=f"f{i}.py", line=1)
        for i in range(15)
    ]
    out = aggregate_repetitive(findings, threshold=10)
    assert len(out) == 15


def test_mask_secret_keeps_prefix_suffix_only():
    masked = mask_secret("AKIAABCDEFGHIJKLMNOP")
    assert masked.startswith("AKIA")
    assert "ABCDEFGHIJKLMN" not in masked


def test_redact_text_scrubs_credentialed_url():
    text = "see postgres://admin:SuperSecret123@db.internal:5432/app for details"
    out = redact_text(text)
    assert "SuperSecret123" not in out
    assert "postgres://admin:" in out


def test_redact_text_scrubs_kv_assignment():
    text = 'api_key = "sk-abcdefghijklmnopqrstuvwxyz"'
    out = redact_text(text)
    assert "abcdefghijklmnopqrstuvwxyz" not in out


def test_finding_constructor_redacts_message_automatically():
    f = Finding(title="t", severity="low", category="secrets", engine="code", tool="builtin",
                message='token="verysecretvalue1234"')
    assert "verysecretvalue1234" not in f.message


def test_summarize_counts_by_severity_and_category():
    findings = [
        Finding(title="a", severity="critical", category="injection", engine="code", tool="builtin"),
        Finding(title="b", severity="low", category="configuration", engine="recon", tool="passive-recon"),
    ]
    s = summarize(findings)
    assert s["total"] == 2
    assert s["by_severity"]["critical"] == 1
    assert s["by_engine"]["code"] == 1
    assert s["by_engine"]["recon"] == 1
