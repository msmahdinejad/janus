"""Optional external-tool adapters for the recon engine: nuclei (template
scanning) and subfinder (extra passive subdomain sources).

Both are optional; `janus doctor` reports them missing rather than failing.
`run_nuclei` is only reachable after the caller has confirmed
`scope.allow_active_recon`, and it only receives targets that already passed
`scope.authorize()` for every host individually.

Nuclei note: it is an external process, so its egress cannot be *enforced*
here the way `ScopeClient` enforces the built-in checks. What this adapter
does do is constrain it hard: explicit target list, no interactsh, intrusive
tag classes excluded, a rate limit, one retry, and no redirect following.
For a stronger boundary put it behind `janus proxy`.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from ...core.model import Finding
from ..common import ToolResult, find_tool, map_severity, run_tool

DEFAULT_EXCLUDE_TAGS = ("intrusive", "dos", "fuzz", "bruteforce", "default-login", "headless")
DEFAULT_SEVERITIES = ("critical", "high", "medium")


def run_nuclei(
    targets: list[str], out_dir: Path, rate_limit: int = 10, concurrency: int = 15,
    templates_dir: Path | None = None, tool_dirs: tuple[Path, ...] = (),
) -> ToolResult:
    exe = find_tool("nuclei", tool_dirs)
    if not exe:
        return ToolResult("nuclei", "skipped", detail="nuclei not found on PATH")
    if not targets:
        return ToolResult("nuclei", "ok", detail="no targets to scan")

    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "raw-nuclei.jsonl"
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt", dir=out_dir, encoding="utf-8") as tf:
        tf.write("\n".join(targets))
        targets_file = tf.name

    args = [
        "-l", targets_file, "-jsonl", "-o", str(out_path),
        "-etags", ",".join(DEFAULT_EXCLUDE_TAGS),
        "-severity", ",".join(DEFAULT_SEVERITIES),
        "-rate-limit", str(rate_limit), "-c", str(concurrency),
        "-retries", "1", "-no-interactsh", "-silent",
    ]
    if templates_dir:
        args += ["-t", str(templates_dir)]
    try:
        run = run_tool(exe, args, out_path=out_path, timeout=3600)
    finally:
        Path(targets_file).unlink(missing_ok=True)

    if not run.ok:
        return ToolResult("nuclei", "failed", detail=f"exit {run.returncode}: {run.diagnostics()}")
    if run.output_path is None:
        return ToolResult("nuclei", "ok", detail="ran, no matches")

    findings = []
    for line in run.output_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = row.get("info", {}) or {}
        findings.append(Finding(
            title=info.get("name", row.get("template-id", "nuclei finding")),
            severity=map_severity(info.get("severity"), "medium"),
            category="exposure", engine="recon", tool="nuclei", rule_id=row.get("template-id", ""),
            target=row.get("matched-at", row.get("host", "")), host=row.get("host", ""),
            endpoint=row.get("matched-at", ""), method="GET",
            message=info.get("description", "") or "See the nuclei template for details.",
            remediation="See the nuclei template's own `reference` field and the CWE for remediation.",
            confidence="likely", cwe=tuple(info.get("classification", {}).get("cwe-id", []) or ()),
            sources=("nuclei",),
        ))
    return ToolResult("nuclei", "ok", findings=findings, detail=f"{len(findings)} findings")


def run_subfinder(domain: str, tool_dirs: tuple[Path, ...] = ()) -> tuple[list[str], ToolResult]:
    exe = find_tool("subfinder", tool_dirs)
    if not exe:
        return [], ToolResult("subfinder", "skipped", detail="subfinder not found on PATH")
    run = run_tool(exe, ["-d", domain, "-silent"], timeout=180)
    if not run.ok:
        return [], ToolResult("subfinder", "failed", detail=f"exit {run.returncode}: {run.diagnostics()}")
    hosts = sorted({line.strip().lower() for line in run.stdout.splitlines() if line.strip()})
    return hosts, ToolResult("subfinder", "ok", detail=f"{len(hosts)} hostnames")
