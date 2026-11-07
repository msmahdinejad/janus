"""Tests for --diff (changed_files) and --baseline (suppression), each
built on a disposable, local-only git repo rather than touching Janus's
own (deliberately uncommitted) repo."""

import subprocess
import textwrap
from pathlib import Path

import pytest

from janus.core.baseline import apply_baseline, load_baseline_fingerprints
from janus.core.model import Finding
from janus.core.scope import load_scope
from janus.engines.code.scan import changed_files, run


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=str(repo), check=True, capture_output=True, text=True)


@pytest.fixture
def tiny_git_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "test@test.local")
    _git(repo, "config", "user.name", "test")
    (repo / "a.py").write_text("x = 1\n", encoding="utf-8")
    (repo / "b.py").write_text("y = 2\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "base")
    # Now change one file and add a new, untracked one.
    (repo / "a.py").write_text("x = 1\neval('danger')\n", encoding="utf-8")
    (repo / "c.py").write_text("z = 3\n", encoding="utf-8")
    return repo


def test_changed_files_finds_modified_and_untracked(tiny_git_repo: Path):
    changed = changed_files(tiny_git_repo, "HEAD")
    assert (tiny_git_repo / "a.py").resolve() in changed
    assert (tiny_git_repo / "c.py").resolve() in changed
    assert (tiny_git_repo / "b.py").resolve() not in changed  # untouched since the base commit


def test_changed_files_returns_none_for_non_git_dir(tmp_path: Path):
    plain_dir = tmp_path / "not-a-repo"
    plain_dir.mkdir()
    assert changed_files(plain_dir, "HEAD") is None


def _scope_for(repo: Path, tmp_path: Path):
    scope_path = tmp_path / "scope.toml"
    scope_path.write_text(textwrap.dedent(f"""\
        [engagement]
        name = "t"
        authorized_by = "t"
        reference = "t"
        valid_from = "2020-01-01"
        valid_until = "2999-01-01"

        [targets]
        allow = ["example.com"]

        [code]
        roots = [{str(repo).replace(chr(92), '/')!r}]
    """), encoding="utf-8")
    return load_scope(scope_path)


def test_diff_mode_only_scans_changed_files(tiny_git_repo: Path, tmp_path: Path):
    scope = _scope_for(tiny_git_repo, tmp_path)
    result = run(scope, use_gitleaks=False, use_trivy=False, use_semgrep=False,
                 cache_dir=tmp_path / "cache", diff_base="HEAD")
    assert result.diff_applicable is True
    scanned_paths = {f.path for f in result.findings}
    # a.py has the eval() call and was changed; b.py is untouched and must
    # not appear even though it would also match PY-EVAL-EXEC if scanned.
    assert any("a.py" in p for p in scanned_paths)
    assert not any("b.py" in p for p in scanned_paths)


def test_diff_mode_falls_back_to_full_scan_when_not_a_git_repo(tmp_path: Path):
    plain_dir = tmp_path / "plain"
    plain_dir.mkdir()
    (plain_dir / "x.py").write_text("eval('x')\n", encoding="utf-8")
    scope = _scope_for(plain_dir, tmp_path)
    result = run(scope, use_gitleaks=False, use_trivy=False, use_semgrep=False,
                 cache_dir=tmp_path / "cache2", diff_base="HEAD")
    assert result.diff_applicable is False
    assert result.files_scanned == 1  # fell back to scanning everything


def test_load_baseline_fingerprints_from_list_and_dict_shapes(tmp_path: Path):
    p1 = tmp_path / "b1.json"
    p1.write_text('["fp1", "fp2"]', encoding="utf-8")
    assert load_baseline_fingerprints(p1) == {"fp1", "fp2"}

    p2 = tmp_path / "b2.json"
    p2.write_text('{"suppressed": ["fp3"]}', encoding="utf-8")
    assert load_baseline_fingerprints(p2) == {"fp3"}

    assert load_baseline_fingerprints(None) == set()
    assert load_baseline_fingerprints(tmp_path / "missing.json") == set()


def test_apply_baseline_sets_accepted_risk_only_for_open_findings():
    open_finding = Finding(title="x", severity="high", category="other", engine="code", tool="builtin",
                            path="a.py", line=1)
    already_fixed = Finding(title="y", severity="high", category="other", engine="code", tool="builtin",
                             path="b.py", line=1, status="fixed")
    findings = [open_finding, already_fixed]
    fps = {open_finding.fingerprint, already_fixed.fingerprint}
    count = apply_baseline(findings, fps)
    assert count == 1
    assert open_finding.status == "accepted-risk"
    assert already_fixed.status == "fixed"  # untouched - baseline never overrides a human triage
