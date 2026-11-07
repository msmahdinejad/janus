import textwrap
from pathlib import Path

import pytest

from janus.core.scope import ScopeError, load_scope


def _write_scope(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "scope.toml"
    p.write_text(textwrap.dedent(body), encoding="utf-8")
    return p


VALID_BODY = """\
    [engagement]
    name = "t"
    authorized_by = "someone"
    reference = "SEC-1"
    valid_from = "2020-01-01"
    valid_until = "2999-01-01"

    [targets]
    allow = ["example.com", "*.example.com"]
    deny = ["pay.example.com"]
    allow_ports = [443]
    forbidden_paths = ["^/admin/delete"]

    [limits]
    allow_active_recon = false
    allow_agent = false

    [code]
    roots = ["."]
    """


def test_valid_scope_loads(tmp_path):
    scope = load_scope(_write_scope(tmp_path, VALID_BODY))
    assert scope.engagement.reference == "SEC-1"


def test_missing_reference_rejected(tmp_path):
    body = VALID_BODY.replace('reference = "SEC-1"', 'reference = ""')
    with pytest.raises(ScopeError):
        load_scope(_write_scope(tmp_path, body))


def test_missing_code_root_rejected(tmp_path):
    body = VALID_BODY.replace('roots = ["."]', 'roots = ["does-not-exist-xyz"]')
    with pytest.raises(ScopeError):
        load_scope(_write_scope(tmp_path, body))


def test_expired_window_denies(tmp_path):
    body = VALID_BODY.replace('valid_until = "2999-01-01"', 'valid_until = "2020-01-02"')
    scope = load_scope(_write_scope(tmp_path, body))
    decision = scope.authorize("https://example.com/")
    assert not decision.allowed
    assert any("outside the authorized window" in r for r in decision.reasons)


def test_allowed_subdomain(tmp_path):
    scope = load_scope(_write_scope(tmp_path, VALID_BODY))
    assert scope.authorize("https://api.example.com/").allowed


def test_apex_not_matched_by_wildcard_only_allow(tmp_path):
    body = VALID_BODY.replace('allow = ["example.com", "*.example.com"]', 'allow = ["*.example.com"]')
    scope = load_scope(_write_scope(tmp_path, body))
    assert not scope.authorize("https://example.com/").allowed
    assert scope.authorize("https://api.example.com/").allowed


def test_deny_wins_over_allow(tmp_path):
    scope = load_scope(_write_scope(tmp_path, VALID_BODY))
    decision = scope.authorize("https://pay.example.com/")
    assert not decision.allowed
    assert any("deny" in r for r in decision.reasons)


def test_out_of_scope_host_denied(tmp_path):
    scope = load_scope(_write_scope(tmp_path, VALID_BODY))
    assert not scope.authorize("https://evil.com/").allowed


def test_disallowed_port_denied(tmp_path):
    scope = load_scope(_write_scope(tmp_path, VALID_BODY))
    assert not scope.authorize("https://example.com:8443/").allowed


def test_forbidden_path_denied(tmp_path):
    scope = load_scope(_write_scope(tmp_path, VALID_BODY))
    assert not scope.authorize("https://example.com/admin/delete-everything").allowed


def test_state_changing_method_denied_by_default(tmp_path):
    scope = load_scope(_write_scope(tmp_path, VALID_BODY))
    decision = scope.authorize("https://example.com/", method="POST")
    assert not decision.allowed
    assert any("not allowed by this engagement" in r for r in decision.reasons)


def test_state_changing_requires_nonprod_marker(tmp_path):
    body = VALID_BODY.replace("allow_agent = false", "allow_agent = false\n    allow_state_changing = true")
    with pytest.raises(ScopeError, match="require_nonprod_marker"):
        load_scope(_write_scope(tmp_path, body))


def test_state_changing_opt_in_allows_only_listed_methods(tmp_path):
    body = VALID_BODY.replace(
        "allow_agent = false",
        "allow_agent = false\n    allow_state_changing = true\n    require_nonprod_marker = true\n"
        "    mutating_methods = [\"POST\"]")
    scope = load_scope(_write_scope(tmp_path, body))
    assert scope.authorize("https://api.staging.example.com/orders", method="POST").allowed
    assert not scope.authorize("https://api.staging.example.com/orders/1", method="DELETE").allowed
    assert not scope.authorize("https://www.example.com/", method="POST").allowed


def test_active_recon_requires_explicit_opt_in(tmp_path):
    scope = load_scope(_write_scope(tmp_path, VALID_BODY))
    with pytest.raises(ScopeError):
        scope.require_active_recon()


def test_agent_requires_explicit_opt_in_even_if_active_recon_allowed(tmp_path):
    body = VALID_BODY.replace("allow_active_recon = false", "allow_active_recon = true")
    scope = load_scope(_write_scope(tmp_path, body))
    scope.require_active_recon()  # should not raise
    with pytest.raises(ScopeError):
        scope.require_agent()  # separate opt-in, still false
