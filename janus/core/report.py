"""Three views of the same data: Markdown for a human, JSON for a machine or
the dashboard, SARIF for GitHub/GitLab's native code-scanning UI."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .model import summarize

_SEV_TO_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}


def to_json(scope_manifest: dict[str, Any], findings: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "meta": scope_manifest,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": summarize_dicts(findings),
        "findings": findings,
    }


def summarize_dicts(findings: list[dict[str, Any]]) -> dict[str, Any]:
    # Thin wrapper so callers with plain dicts (loaded back from the
    # register) don't need to round-trip through Finding objects.
    from .model import Finding

    objs = []
    for d in findings:
        d2 = {k: v for k, v in d.items() if k != "fingerprint"}
        try:
            objs.append(Finding(**d2))
        except TypeError:
            continue
    return summarize(objs)


def to_markdown(scope_manifest: dict[str, Any], findings: list[dict[str, Any]], max_findings: int = 150) -> str:
    summary = summarize_dicts(findings)
    lines: list[str] = []
    lines.append(f"# Janus security report — {scope_manifest.get('engagement', 'unknown engagement')}")
    lines.append("")
    lines.append(f"- Authorization reference: `{scope_manifest.get('authorization_reference', 'n/a')}`")
    lines.append(f"- Authorized by: {scope_manifest.get('authorized_by', 'n/a')}")
    lines.append(
        f"- Valid window: {scope_manifest.get('valid_from', '?')} .. {scope_manifest.get('valid_until', '?')}"
    )
    lines.append(f"- Generated: {datetime.now(timezone.utc).isoformat()}")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"Total findings: **{summary['total']}**")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|---|---|")
    for sev, count in summary["by_severity"].items():
        lines.append(f"| {sev} | {count} |")
    lines.append("")
    lines.append("| Category | Count |")
    lines.append("|---|---|")
    for cat, count in sorted(summary["by_category"].items(), key=lambda kv: -kv[1]):
        lines.append(f"| {cat} | {count} |")
    lines.append("")

    ordered = sorted(
        findings,
        key=lambda f: (["critical", "high", "medium", "low", "info"].index(f.get("severity", "info"))
                       if f.get("severity") in ["critical", "high", "medium", "low", "info"] else 5),
    )
    shown, rest = ordered[:max_findings], ordered[max_findings:]

    lines.append("## Findings")
    lines.append("")
    for f in shown:
        loc = f"{f.get('path')}:{f.get('line')}" if f.get("engine") == "code" else f"{f.get('host') or f.get('target')} {f.get('endpoint', '')}".strip()
        lines.append(f"### [{f.get('severity', 'info').upper()}] {f.get('title', '(untitled)')}")
        lines.append("")
        lines.append(f"- Status: `{f.get('status', 'open')}`  ·  Confidence: `{f.get('confidence', 'needs-review')}`")
        lines.append(f"- Location: `{loc}`")
        lines.append(f"- Tool / rule: `{f.get('tool')}` / `{f.get('rule_id') or '-'}`")
        if f.get("message"):
            lines.append(f"- Impact: {f['message']}")
        if f.get("remediation"):
            lines.append(f"- Remediation: {f['remediation']}")
        if f.get("snippet"):
            lines.append("")
            lines.append("  ```")
            for sline in str(f["snippet"]).splitlines():
                lines.append(f"  {sline}")
            lines.append("  ```")
        lines.append("")
    if rest:
        lines.append(f"...and {len(rest)} more findings (see findings.json / the dashboard for the full list).")
        lines.append("")

    lines.append("## Limitations")
    lines.append("")
    lines.append(
        "- This report reflects what the enabled engines/adapters actually ran — see the `tools` section of "
        "findings.json for which ones were skipped (not installed) vs. failed vs. ok. Absence of a finding "
        "in a skipped category means \"not tested\", not \"clean\"."
    )
    lines.append(
        "- Static analysis (the `code` engine) proves what the source says, not what happens in a running "
        "system. The `recon` engine proves what a given vantage point can observe, not what every possible "
        "attacker-controlled network path can reach."
    )
    return "\n".join(lines)


def to_sarif(findings: list[dict[str, Any]]) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results = []
    for f in findings:
        rule_key = f"{f.get('tool')}/{f.get('rule_id') or f.get('title')}"
        if rule_key not in rules:
            rules[rule_key] = {
                "id": rule_key,
                "name": f.get("title", rule_key),
                "shortDescription": {"text": f.get("title", rule_key)},
                "fullDescription": {"text": f.get("message") or f.get("title", "")},
                "properties": {
                    "tags": [f.get("category", "other"), *f.get("cwe", []), *f.get("owasp", [])],
                },
            }
        uri = f.get("path") or f.get("target") or f.get("host") or "unknown"
        line = max(int(f.get("line") or 1), 1)
        results.append({
            "ruleId": rule_key,
            "level": _SEV_TO_SARIF_LEVEL.get(f.get("severity", "info"), "note"),
            "message": {"text": f.get("message") or f.get("title", "")},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": line},
                }
            }],
            "partialFingerprints": {"janus/v1": f.get("fingerprint", "")},
        })
    return {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/Schemata/sarif-schema-2.1.0.json",
        "runs": [{
            "tool": {"driver": {"name": "janus", "rules": list(rules.values())}},
            "results": results,
        }],
    }
