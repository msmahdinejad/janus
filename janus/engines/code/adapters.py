"""Optional external-tool adapters for the code engine: gitleaks (secrets),
trivy (deps/IaC/secrets/misconfig), semgrep (SAST with real data-flow).

Three rules every adapter here follows, and a test enforces:

  1. A missing tool is `skipped`, never an exception and never a silent
     "clean" result.
  2. The output file is deleted before the run and the exit code is
     inspected after it. "Crashed" and "found nothing" are different
     outcomes, and a stale file from a previous run is never re-reported.
  3. A tool's own non-zero "findings present" code (gitleaks 1, semgrep 1)
     is success-with-findings, not failure; anything else is `failed` with
     bounded diagnostics.
"""

from __future__ import annotations

import json
from pathlib import Path

from ...core.model import Finding
from ..common import ToolResult, find_tool, map_severity, run_tool

_CATEGORY_HINTS = (
    ("sql", "injection"), ("inject", "injection"), ("command", "injection"),
    ("xss", "xss"), ("cross-site", "xss"),
    ("secret", "secrets"), ("credential", "secrets"), ("password", "secrets"), ("token", "secrets"),
    ("tls", "crypto"), ("crypto", "crypto"), ("ssl", "crypto"),
    ("auth", "auth"), ("jwt", "auth"), ("csrf", "auth"),
    ("misconfig", "configuration"), ("config", "configuration"),
    ("ksv", "container"), ("docker", "container"), ("container", "container"),
    ("workflow", "ci-cd"), ("action", "ci-cd"), ("pipeline", "ci-cd"),
)



def _resolve_path(raw: str, root: Path) -> str:
    """Normalise a scanner-reported path to an absolute one.

    gitleaks reports paths relative to the *process* cwd, trivy relative to
    the scan root, semgrep absolute. Joining blindly to the root produced
    `root/root/file` and made every finding's location wrong (the file filter
    still accepted it, because the doubled path was technically inside the
    root). Try the plausible bases and keep the first that exists.
    """
    if not raw:
        return ""
    candidate = Path(raw)
    if candidate.is_absolute():
        return str(candidate.resolve())
    for base in (root, Path.cwd()):
        joined = (base / candidate)
        if joined.exists():
            return str(joined.resolve())
    return str((root / candidate).resolve())


def _guess_category(*texts: str) -> str:
    joined = " ".join(t or "" for t in texts).lower()
    for needle, cat in _CATEGORY_HINTS:
        if needle in joined:
            return cat
    return "other"


def run_gitleaks(root: Path, out_dir: Path, tool_dirs: tuple[Path, ...] = ()) -> ToolResult:
    exe = find_tool("gitleaks", tool_dirs)
    if not exe:
        return ToolResult("gitleaks", "skipped", detail="gitleaks not found on PATH")
    out_path = out_dir / "raw-gitleaks.json"
    run = run_tool(exe, [
        "detect", "--no-git", "--source", str(root), "--report-format", "json",
        "--report-path", str(out_path), "--exit-code", "0", "--no-banner", "--redact",
    ], out_path=out_path, timeout=600)
    # gitleaks --exit-code 0 makes 0 the only success code; anything else is
    # a real failure, not "leaks were found".
    if not run.ok:
        return ToolResult("gitleaks", "failed", detail=f"exit {run.returncode}: {run.diagnostics()}")
    if run.output_path is None:
        return ToolResult("gitleaks", "ok", detail="ran, no report file (zero findings)")
    try:
        rows = json.loads(run.output_path.read_text(encoding="utf-8") or "[]")
    except Exception as e:  # noqa: BLE001
        return ToolResult("gitleaks", "failed", detail=f"could not parse output: {e}")

    findings = []
    for r in rows:
        path = _resolve_path(r.get("File", ""), root)
        line = int(r.get("StartLine", 0) or 0)
        rule = r.get("RuleID", "")
        # `generic-api-key` is gitleaks' high-entropy catch-all: on data files
        # (fixtures, JSON dumps, eval corpora) it fires thousands of times on
        # values that are not credentials. Specific providers' rules stay
        # critical; the catch-all is review material, not a breach.
        if path.lower().endswith((".md", ".rst", ".txt")):
            severity = "low"
        elif rule == "generic-api-key":
            severity = "medium"
        else:
            severity = "critical"
        findings.append(Finding(
            title=f"Secret detected: {rule or 'unknown rule'}",
            severity=severity,
            category="secrets", engine="code", tool="gitleaks", rule_id=rule,
            path=path, line=line, end_line=int(r.get("EndLine", line) or line),
            message=r.get("Description", "Potential secret found by gitleaks."),
            remediation="Rotate the credential and remove it from git history (e.g. git filter-repo).",
            confidence="likely", cwe=("CWE-798",), owasp=("A07:2021",),
            snippet="[redacted by gitleaks --redact]", sources=("gitleaks",),
        ))
    return ToolResult("gitleaks", "ok", findings=findings, detail=f"{len(findings)} findings")


DEFAULT_SKIP_DIRS = ("node_modules", ".git", ".venv", "venv", "dist", "build", "target",
                     "vendor", "__pycache__", ".next", "coverage")


def run_trivy(root: Path, out_dir: Path, allow_network: bool = True, tool_dirs: tuple[Path, ...] = (),
              cache_dir: Path | None = None) -> ToolResult:
    exe = find_tool("trivy", tool_dirs)
    if not exe:
        return ToolResult("trivy", "skipped", detail="trivy not found on PATH")
    out_path = out_dir / "raw-trivy.json"
    scanners = "secret,misconfig" if not allow_network else "vuln,secret,misconfig"
    args = ["fs", "--quiet", "--format", "json", "--output", str(out_path),
            "--scanners", scanners, "--timeout", "20m"]
    for d in DEFAULT_SKIP_DIRS:
        args += ["--skip-dirs", f"**/{d}"]
    if cache_dir:
        args += ["--cache-dir", str(cache_dir)]
    args.append(str(root))
    run = run_tool(exe, args, out_path=out_path, timeout=1400)
    if not run.ok:
        detail = f"exit {run.returncode}: {run.diagnostics()}"
        blob = f"{run.stderr} {run.stdout}".lower()
        if any(k in blob for k in ("download vulnerability db", "403", "mirror.gcr.io", "oci repository")):
            detail += (
                " | hint: the vulnerability DB could not be downloaded. The default mirror is "
                "mirror.gcr.io; set TRIVY_DB_REPOSITORY=ghcr.io/aquasecurity/trivy-db:2 (and "
                "TRIVY_JAVA_DB_REPOSITORY=ghcr.io/aquasecurity/trivy-java-db:1), or run with "
                "--offline to skip dependency CVEs. Secrets/misconfig scanning does not need the DB."
            )
        return ToolResult("trivy", "failed", detail=detail)
    if run.output_path is None:
        return ToolResult("trivy", "ok", detail="ran, no report file (zero findings)")
    try:
        doc = json.loads(run.output_path.read_text(encoding="utf-8") or "{}")
    except Exception as e:  # noqa: BLE001
        return ToolResult("trivy", "failed", detail=f"could not parse output: {e}")

    findings = []
    for result in doc.get("Results", []) or []:
        target = result.get("Target", "")
        for v in result.get("Vulnerabilities", []) or []:
            findings.append(Finding(
                title=f"{v.get('VulnerabilityID', '?')}: {v.get('PkgName', '?')} {v.get('InstalledVersion', '')}",
                severity=map_severity(v.get("Severity")), category="supply-chain",
                engine="code", tool="trivy", rule_id=v.get("VulnerabilityID", ""),
                path=_resolve_path(target, root), line=0,
                message=v.get("Title") or (v.get("Description") or "")[:300],
                remediation=f"Upgrade to {v.get('FixedVersion')}" if v.get("FixedVersion") else "No fixed version published yet; track upstream.",
                confidence="confirmed", cwe=tuple(v.get("CweIDs", []) or ()), sources=("trivy",),
            ))
        for s in result.get("Secrets", []) or []:
            findings.append(Finding(
                title=f"Secret detected: {s.get('Title', s.get('RuleID', 'unknown'))}",
                severity="low" if target.lower().endswith((".md", ".rst", ".txt")) else map_severity(s.get("Severity"), "high"),
                category="secrets", engine="code", tool="trivy", rule_id=s.get("RuleID", ""),
                path=_resolve_path(target, root), line=int(s.get("StartLine", 0) or 0),
                message="Potential secret found by trivy.",
                remediation="Rotate the credential and remove it from history.",
                confidence="likely", cwe=("CWE-798",), sources=("trivy",),
            ))
        for m in result.get("Misconfigurations", []) or []:
            findings.append(Finding(
                title=m.get("Title", m.get("ID", "misconfiguration")),
                severity=map_severity(m.get("Severity")),
                category=_guess_category(m.get("ID", ""), m.get("Title", "")),
                engine="code", tool="trivy", rule_id=m.get("ID", ""),
                path=_resolve_path(target, root), line=0,
                message=m.get("Description") or m.get("Message", ""),
                remediation=m.get("Resolution", "See trivy documentation for this rule."),
                confidence="needs-review", sources=("trivy",),
            ))
    return ToolResult("trivy", "ok", findings=findings, detail=f"{len(findings)} findings")


def run_semgrep(root: Path, out_dir: Path, configs: tuple[str, ...] = ("p/security-audit",),
                tool_dirs: tuple[Path, ...] = ()) -> ToolResult:
    exe = find_tool("semgrep", tool_dirs)
    if not exe:
        return ToolResult("semgrep", "skipped", detail="semgrep not found on PATH")
    out_path = out_dir / "raw-semgrep.json"
    args = ["--json", "--output", str(out_path), "--quiet", "--metrics=off",
            "--timeout", "120", "--max-target-bytes", "2000000"]
    for d in DEFAULT_SKIP_DIRS:
        args += ["--exclude", d]
    for c in configs:
        args += ["--config", c]
    args.append(str(root))
    run = run_tool(exe, args, out_path=out_path, timeout=1200)
    # semgrep exits 1 when it has findings; that is success for our purposes.
    if run.returncode not in (0, 1) or run.output_path is None:
        return ToolResult("semgrep", "failed",
                          detail=f"exit {run.returncode}: {run.diagnostics() or 'no output file'}")
    try:
        doc = json.loads(run.output_path.read_text(encoding="utf-8") or "{}")
    except Exception as e:  # noqa: BLE001
        return ToolResult("semgrep", "failed", detail=f"could not parse output: {e}")

    findings = []
    for r in doc.get("results", []) or []:
        extra = r.get("extra", {}) or {}
        meta = extra.get("metadata", {}) or {}
        line = int((r.get("start") or {}).get("line", 0) or 0)
        end_line = int((r.get("end") or {}).get("line", line) or line)
        findings.append(Finding(
            title=(extra.get("message") or r.get("check_id", "semgrep finding"))[:140],
            severity=map_severity(extra.get("severity")),
            category=_guess_category(r.get("check_id", ""), extra.get("message", "")),
            engine="code", tool="semgrep", rule_id=r.get("check_id", ""),
            path=r.get("path", ""), line=line, end_line=end_line,
            message=extra.get("message", ""),
            remediation=meta.get("fix") or meta.get("remediation") or "See the semgrep rule's own references for the recommended fix.",
            confidence="likely",
            cwe=tuple(meta.get("cwe", []) if isinstance(meta.get("cwe"), list) else [meta.get("cwe")] if meta.get("cwe") else []),
            owasp=tuple(meta.get("owasp", []) if isinstance(meta.get("owasp"), list) else [meta.get("owasp")] if meta.get("owasp") else []),
            snippet=(extra.get("lines") or "")[:800], sources=("semgrep",),
        ))
    return ToolResult("semgrep", "ok", findings=findings, detail=f"{len(findings)} findings")
