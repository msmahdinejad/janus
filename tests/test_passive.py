"""Unit tests for the pure (no-network) parts of the recon engine's passive
checks: the JS-bundle secret scanner. Fixture secrets are built with
string multiplication rather than hand-typed literals specifically because
regex length requirements (e.g. AWS/Google key lengths) are easy to get
subtly wrong by eye — this bit the development of this file more than
once, so tests here lean on `len()`, not hand-counting."""

from janus.engines.recon.passive import _scan_js_text_for_secrets


def _rule_ids(findings):
    return {f.rule_id for f in findings}


def test_aws_key_in_js_bundle_detected_as_critical():
    key = "AKIA" + "A" * 16
    findings = _scan_js_text_for_secrets("https://x.test/chunk.js", "x.test", f'var k="{key}";')
    assert "JS-SECRET-AWS-ACCESS-KEY" in _rule_ids(findings)
    hit = next(f for f in findings if f.rule_id == "JS-SECRET-AWS-ACCESS-KEY")
    assert hit.severity == "critical"
    assert hit.engine == "recon" and hit.target == "https://x.test/chunk.js"


def test_stripe_secret_key_flagged_but_publishable_key_is_not():
    sk = "sk_live_" + "A" * 20
    pk = "pk_live_" + "A" * 20
    text = f'var a="{sk}"; var b="{pk}";'
    findings = _scan_js_text_for_secrets("https://x.test/chunk.js", "x.test", text)
    stripe_hits = [f for f in findings if f.rule_id == "JS-SECRET-STRIPE-LIVE"]
    assert len(stripe_hits) == 1
    assert sk[-6:] not in stripe_hits[0].message  # redacted, not echoed in full


def test_google_style_key_flagged_as_medium_not_critical():
    key = "AIza" + "A" * 35
    findings = _scan_js_text_for_secrets("https://x.test/chunk.js", "x.test", f'apiKey:"{key}"')
    google_hits = [f for f in findings if f.rule_id == "JS-GOOGLE-API-KEY"]
    assert len(google_hits) == 1
    assert google_hits[0].severity == "medium"  # not "critical" - routinely public-by-design


def test_repeated_identical_secret_reported_once_per_bundle():
    key = "AKIA" + "B" * 16
    text = f'var a="{key}"; var b="{key}"; var c="{key}";'
    findings = _scan_js_text_for_secrets("https://x.test/chunk.js", "x.test", text)
    aws_hits = [f for f in findings if f.rule_id == "JS-SECRET-AWS-ACCESS-KEY"]
    assert len(aws_hits) == 1  # distinct-value dedupe within one bundle, not one row per occurrence


def test_placeholder_value_not_flagged():
    findings = _scan_js_text_for_secrets("https://x.test/chunk.js", "x.test", 'api_key = "changeme"')
    assert not findings


def test_no_secrets_in_plain_bundle():
    findings = _scan_js_text_for_secrets(
        "https://x.test/chunk.js", "x.test",
        "function add(a,b){return a+b} module.exports={add};",
    )
    assert findings == []
