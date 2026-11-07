"""Orchestration for `janus scan code`: walk the scope's roots, run the
zero-dependency builtin engine on every eligible file, run whichever of
gitleaks/trivy/semgrep are installed, then dedupe + aggregate the combined
result. See ARCHITECTURE.md for why this shape (deterministic tools produce
candidates; nothing here decides "is this a real bug", a human or the
optional AI layer does)."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from ...core.model import Finding, aggregate_repetitive, dedupe
from ...core.scope import Scope
from ..common import ToolResult
from . import adapters, builtin

TEXT_EXTS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".java", ".rb", ".php", ".c", ".cpp", ".h",
    ".cs", ".sh", ".bash", ".yml", ".yaml", ".json", ".toml", ".ini", ".env", ".md", ".rst", ".txt",
}
SPECIAL_FILENAMES = {
    "dockerfile", "docker-compose.yml", "docker-compose.yaml", ".env", "requirements.txt",
    "go.mod", "package.json", "pom.xml", "gemfile",
}
DEFAULT_EXCLUDE_DIRS = {
    "node_modules", ".git", "dist", "build", "target", "vendor", "__pycache__",
    ".venv", "venv", ".next", "coverage", ".tmp", ".mypy_cache", ".pytest_cache", ".ruff_cache",
}
SKIP_SUFFIXES = (".min.js", ".min.css", ".map", ".lock")
MAX_FILE_BYTES = 1_500_000


def changed_files(git_root: Path, base_ref: str) -> set[Path] | None:
    """Files changed vs. `base_ref`, as absolute resolved paths, plus
    untracked files (so a new file staged for this PR isn't invisible).
    Returns None — not an empty set — when `git_root` isn't a git repo (or
    git isn't available), so callers can tell "diff mode found nothing
    changed" apart from "diff mode isn't applicable here, fall back to a
    full scan" and warn accordingly instead of silently scanning zero files.

    Three attempts, same order the predecessor `codesec` pipeline used
    (merge-base diff, then a plain diff, then diff against HEAD) — a
    shallow checkout or a base_ref that isn't a real merge-base can break
    the first form.
    """

    def _git(args: list[str]) -> str | None:
        try:
            r = subprocess.run(["git", *args], cwd=str(git_root), capture_output=True,
                                text=True, timeout=30)
        except Exception:
            return None
        return r.stdout if r.returncode == 0 else None

    toplevel = _git(["rev-parse", "--show-toplevel"])
    if toplevel is None:
        return None
    toplevel_path = Path(toplevel.strip())

    out = (
        _git(["diff", "--name-only", f"{base_ref}...HEAD"])
        or _git(["diff", "--name-only", base_ref])
        or _git(["diff", "--name-only", "HEAD"])
        or ""
    )
    rel_paths = {line.strip() for line in out.splitlines() if line.strip()}

    untracked = _git(["ls-files", "--others", "--exclude-standard"]) or ""
    rel_paths.update(line.strip() for line in untracked.splitlines() if line.strip())

    return {(toplevel_path / rel).resolve() for rel in rel_paths}


def iter_files(scope: Scope, progress: Callable[[int], None] | None = None,
                only_paths: set[Path] | None = None):
    count = 0
    for root in scope.code_roots:
        for p in root.rglob("*"):
            if not p.is_file():
                continue
            # Compare only the path *relative to the root*. The delivered
            # version tested `p.parts` against the absolute path, so a repo
            # checked out under e.g. D:\build\... had every single file
            # silently excluded.
            try:
                rel_parts = p.relative_to(root).parts
            except ValueError:
                continue
            if any(part in DEFAULT_EXCLUDE_DIRS for part in rel_parts):
                continue
            if p.name.lower().endswith(SKIP_SUFFIXES):
                continue
            is_special = p.name.lower() in SPECIAL_FILENAMES
            if not is_special and p.suffix.lower() not in TEXT_EXTS:
                continue
            try:
                if p.stat().st_size > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            if not scope.authorize_path(p):
                continue
            if only_paths is not None and p.resolve() not in only_paths:
                continue
            count += 1
            if progress and count % 500 == 0:
                progress(count)
            yield p


GENERIC_NOISE_RULES = {
    ("gitleaks", "generic-api-key"),
    ("builtin", "SECRET-GENERIC-KV"),
}
NOISE_COLLAPSE_THRESHOLD = 50


def collapse_generic_noise(findings: list[Finding], threshold: int = NOISE_COLLAPSE_THRESHOLD) -> list[Finding]:
    """Collapse heuristic "maybe a secret" rules that fired across a whole
    dataset into one reviewable row.

    A JSON fixture corpus can produce thousands of `generic-api-key` hits that
    are all the same non-issue. Keeping 2,400 rows does not make the report
    more thorough; it makes it unreadable, and the one real secret in there
    gets lost. Specific provider rules (AWS/GitHub/Stripe/...) are never
    collapsed.
    """
    grouped: dict[tuple[str, str], list[Finding]] = {}
    rest: list[Finding] = []
    for f in findings:
        if (f.tool, f.rule_id) in GENERIC_NOISE_RULES:
            grouped.setdefault((f.tool, f.rule_id), []).append(f)
        else:
            rest.append(f)

    for (_tool, _rule), group in grouped.items():
        if len(group) < threshold:
            rest.extend(group)
            continue
        rep = group[0]
        files = sorted({g.path for g in group})
        rep.extra["occurrences"] = len(group)
        rep.extra["files"] = len(files)
        rep.extra["locations_sample"] = files[:10]
        rep.title = f"{rep.title} (x{len(group)} occurrences across {len(files)} files)"
        if rep.severity in ("critical", "high"):
            rep.severity = "medium"
        rep.notes = (
            "Collapsed heuristic hits: the same low-specificity rule fired across many "
            "data/fixture files. Review the sample paths, not each row."
        )
        rest.append(rep)
    return rest


@dataclass
class CodeScanResult:
    findings: list[Finding]
    tool_results: list[ToolResult]
    files_scanned: int
    diff_applicable: bool = True  # False = --diff was requested but no root was a git repo


def run(
    scope: Scope,
    use_gitleaks: bool = True,
    use_trivy: bool = True,
    use_semgrep: bool = True,
    allow_network: bool = True,
    semgrep_configs: tuple[str, ...] = ("p/security-audit",),
    cache_dir: Path | None = None,
    tool_dirs: tuple[Path, ...] = (),
    diff_base: str | None = None,
    baseline_fingerprints: set[str] | None = None,
) -> CodeScanResult:
    findings: list[Finding] = []
    files_scanned = 0

    # --diff: union the changed-files set across every code root (each may
    # be its own git repo); None from any one of them just means that
    # particular root isn't a git repo, not that nothing changed overall.
    diff_files: set[Path] | None = None
    diff_applicable = True
    if diff_base:
        diff_files = set()
        any_applicable = False
        for root in scope.code_roots:
            changed = changed_files(root, diff_base)
            if changed is not None:
                any_applicable = True
                diff_files.update(changed)
        diff_applicable = any_applicable
        if not any_applicable:
            diff_files = None  # fall back to a full scan rather than silently scanning zero files

    for path in iter_files(scope, only_paths=diff_files):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        findings.extend(builtin.scan_file(path, text))
        files_scanned += 1

    tool_results: list[ToolResult] = []
    out_dir = (cache_dir or Path(".cache/janus")) / "code"
    out_dir.mkdir(parents=True, exist_ok=True)

    def _keep(finding_path: str, root: Path) -> bool:
        # Adapters scan the whole root (none of the three support a clean
        # "only these files" input uniformly), so their findings are filtered
        # here: outside the roots, inside a noise directory, excluded by
        # `[code].exclude`, or untouched by the diff.
        p = Path(finding_path)
        if not p.is_absolute():
            p = root / p
        if not scope.authorize_path(p):
            return False
        if diff_files is None:
            return True
        return p.resolve() in diff_files

    for root in scope.code_roots:
        if use_gitleaks:
            r = adapters.run_gitleaks(root, out_dir, tool_dirs)
            tool_results.append(r)
            findings.extend(f for f in r.findings if _keep(f.path, root))
        if use_trivy:
            r = adapters.run_trivy(root, out_dir, allow_network, tool_dirs, cache_dir=out_dir / "trivy-cache")
            tool_results.append(r)
            findings.extend(f for f in r.findings if _keep(f.path, root))
        if use_semgrep:
            r = adapters.run_semgrep(root, out_dir, semgrep_configs, tool_dirs)
            tool_results.append(r)
            findings.extend(f for f in r.findings if _keep(f.path, root))

    findings = dedupe(findings)
    findings = aggregate_repetitive(findings)
    findings = collapse_generic_noise(findings)

    if baseline_fingerprints:
        from ...core.baseline import apply_baseline
        apply_baseline(findings, baseline_fingerprints)

    return CodeScanResult(
        findings=findings, tool_results=tool_results, files_scanned=files_scanned,
        diff_applicable=diff_applicable,
    )
