"""Coverage accounting: what was actually attempted, and what was not.

A security report that lists findings without saying what was *not* tested
invites the reader to assume the silence is safety. This module answers the
two questions a reviewer asks first: which areas did this run exercise, and
which areas were skipped because a tool was missing, a mode was off, or the
budget ran out.

It also maps findings onto OWASP categories, which is how the pipeline
supports the claim that it covers at least what a free-form prompt would:
the prompt's implicit checklist is enumerated here, per lens.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable

from ..lenses import Lens

OWASP_NAMES = {
    "A01:2021": "Broken Access Control",
    "A02:2021": "Cryptographic Failures",
    "A03:2021": "Injection",
    "A04:2021": "Insecure Design",
    "A05:2021": "Security Misconfiguration",
    "A06:2021": "Vulnerable and Outdated Components",
    "A07:2021": "Identification and Authentication Failures",
    "A08:2021": "Software and Data Integrity Failures",
    "A09:2021": "Security Logging and Monitoring Failures",
    "A10:2021": "Server-Side Request Forgery",
}


def build(
    *,
    scope_name: str,
    mode: str,
    findings: Iterable[Any],
    tool_results: Iterable[Any] = (),
    lenses: list[Lens] | None = None,
    code_files: int | None = None,
    recon: dict[str, Any] | None = None,
    engines: Iterable[dict[str, Any]] = (),
) -> dict[str, Any]:
    findings = list(findings)
    lenses = lenses or []

    tools = []
    for r in tool_results:
        tools.append({
            "id": getattr(r, "name", "?"),
            "status": getattr(r, "status", "?"),
            "detail": getattr(r, "detail", ""),
            "findings": len(getattr(r, "findings", []) or []),
        })

    engine_rows = []
    for engine in engines:
        if not isinstance(engine, dict):
            continue
        row = dict(engine)
        row.setdefault("id", "unknown")
        row.setdefault("status", "unknown")
        engine_rows.append(row)

    lens_rows = []
    for lens in lenses:
        matched = [f for f in findings if any(t in (f.owasp or ()) for t in lens.owasp)]
        lens_rows.append({
            "id": lens.id,
            "title": lens.title,
            "status": "requested (execution unverified)" if mode == "agent" else "not-run (agent mode off)",
            "owasp": list(lens.owasp),
            "findings": len(matched),
        })

    by_owasp: dict[str, dict[str, int]] = {}
    untagged = 0
    for f in findings:
        tags = tuple(f.owasp or ())
        if not tags:
            untagged += 1
        for tag in tags:
            row = by_owasp.setdefault(tag, {"total": 0, "confirmed": 0})
            row["total"] += 1
            if f.confidence == "confirmed":
                row["confirmed"] += 1

    gaps: list[str] = []
    for tool in tools:
        if tool["status"] == "skipped":
            gaps.append(f"{tool['id']} skipped - {tool['detail']}")
        elif tool["status"] == "failed":
            gaps.append(f"{tool['id']} failed - {tool['detail'][:120]}")
        elif tool["status"] == "partial":
            gaps.append(f"{tool['id']} incomplete - {tool['detail'][:120]}")
    # Agent lenses are optional. Only say that they were not run when the
    # caller explicitly supplied a lens selection; a code-only coverage build
    # has no agent lens surface at all and must not claim a missing test.
    if lenses and mode != "agent":
        gaps.append("AI agent lenses were not run (`--mode agent` is off or the scope forbids it)")
    elif lenses:
        gaps.append("Selected lenses were included in agent instructions; per-lens execution is not attested")
    if recon and recon.get("budget_used") is not None and recon.get("budget_max") is not None \
            and recon.get("budget_used") >= recon.get("budget_max"):
        gaps.append("request budget was exhausted before every check finished")
    if untagged:
        gaps.append(f"{untagged} finding(s) carry no OWASP mapping (tool-native rules)")

    has_failed = any(str(row.get("status")) == "failed" for row in [*tools, *engine_rows])
    has_degraded = any(str(row.get("status")) in {"skipped", "unknown", "partial"} for row in [*tools, *engine_rows]) or bool(gaps)
    quality = "failed" if has_failed else "degraded" if has_degraded else "complete"

    return {
        "engagement": scope_name,
        "mode": mode,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "code": {"files_scanned": code_files} if code_files is not None else None,
        "recon": recon or None,
        "engines": engine_rows,
        "tools": tools,
        "lenses": lens_rows,
        "owasp": {tag: {"name": OWASP_NAMES.get(tag, tag), **row} for tag, row in sorted(by_owasp.items())},
        "gaps": gaps,
        "quality": quality,
    }


def to_markdown(coverage: dict[str, Any]) -> str:
    lines = ["## Coverage", ""]
    if coverage.get("quality"):
        lines.append(f"- Run quality: **{coverage['quality']}**.")
    if coverage.get("engines"):
        lines += ["", "| Engine | Status | Findings | Detail |", "|---|---|---:|---|"]
        for engine in coverage["engines"]:
            lines.append(
                f"| {engine.get('id', '?')} | {engine.get('status', 'unknown')} | "
                f"{engine.get('findings', 0)} | {engine.get('detail', '')} |"
            )
    code = coverage.get("code")
    if code:
        lines.append(f"- Code engine: **{code.get('files_scanned')} files** scanned.")
    recon = coverage.get("recon")
    if recon:
        lines.append(
            f"- External engine: **{recon.get('hosts_tested')} hosts** tested, "
            f"**{recon.get('budget_used')}/{recon.get('budget_max')}** requests used, "
            f"{recon.get('denied')} refused by scope."
        )

    if coverage.get("lenses"):
        lines += ["", "| Lens | Status | OWASP | Findings |", "|---|---|---|---|"]
        for lens in coverage["lenses"]:
            lines.append(
                f"| {lens['title']} | {lens['status']} | {', '.join(lens['owasp'])} | {lens['findings']} |"
            )

    if coverage.get("owasp"):
        lines += ["", "| OWASP | Area | Findings | Confirmed |", "|---|---|---|---|"]
        for tag, row in coverage["owasp"].items():
            lines.append(f"| {tag} | {row['name']} | {row['total']} | {row['confirmed']} |")

    if coverage.get("gaps"):
        lines += ["", "**Not covered / degraded:**", ""]
        for gap in coverage["gaps"]:
            lines.append(f"- {gap}")
    lines.append("")
    return "\n".join(lines)

