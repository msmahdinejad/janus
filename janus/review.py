"""Agent-driven source review: the layer that reads code for intent, not patterns.

The regex/SAST engines answer "does this line look dangerous?". They cannot
answer "is this callback actually bound to the order it claims to pay for?", and
that is exactly the class of bug a human reviewer (or a coding agent with a
prompt) finds and a pattern matcher never will.

This module hands a structured review protocol to a coding-agent CLI in its
read-only mode, asks for JSON findings with file:line evidence, and imports them
into the same register as everything else — so those findings get history,
coverage and triage instead of living in a chat transcript.

What it is not: it does not edit the repository (`--sandbox read-only` /
`--permission-mode plan`), it does not decide truth (every finding is
`needs-review`), and it cannot run if the CLI is absent.
"""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .core.model import Finding
from .engines.common import ToolResult, find_tool, map_severity
from .lenses import Lens, instruction as lens_instruction

JSON_BLOCK_RE = re.compile(r"\[[\s\S]*\]")

SYSTEM = """You are a senior application-security engineer performing a READ-ONLY
source review. Do not modify, create or delete files. Do not run commands that
change state.

You are reviewing the repository at {root}.

## What to look for

{lenses}

## How to prove a finding

Every finding needs a source location (file:line) and a short code excerpt that
shows the flaw, plus the precondition an attacker needs. If the impact depends
on something you cannot see (a URL pattern, a gateway rule, a deployment
config), say so in `impact` and set confidence to "needs-review".

Do NOT report: missing security headers, dependency versions, generic
"consider using parameterized queries" advice, or anything you cannot point at
in the code. No speculation dressed as fact.

## Output format

Return exactly one JSON array, no prose before or after:

[
  {{
    "title": "short, specific, e.g. 'Payment callback does not bind amount to order'",
    "severity": "critical|high|medium|low",
    "path": "relative/path.py",
    "line": 123,
    "evidence": "the 1-5 lines that prove it (no secrets, redact values)",
    "impact": "what an attacker gains, and the precondition",
    "remediation": "the concrete change, at the right layer",
    "confidence": "confirmed|likely|needs-review"
  }}
]

If you find nothing, return [].
"""


@dataclass
class ReviewResult:
    findings: list[Finding]
    agent: str
    detail: str
    raw: str


def _prompt(root: Path, lenses: list[Lens], extra: str = "") -> str:
    text = SYSTEM.format(root=root, lenses=lens_instruction(lenses))
    if extra.strip():
        text += "\n## Operator focus (does not override the rules above)\n" + extra.strip() + "\n"
    return text


def _extract_json(text: str) -> list[dict]:
    """Pull the JSON array out of an agent's reply, tolerating code fences."""
    if not text:
        return []
    cleaned = re.sub(r"```(?:json)?", "", text)
    match = JSON_BLOCK_RE.search(cleaned)
    if not match:
        return []
    try:
        data = json.loads(match.group(0))
    except json.JSONDecodeError:
        return []
    if not isinstance(data, list):
        return []
    return [row for row in data if isinstance(row, dict) and row.get("title")]


def _to_findings(rows: list[dict], agent: str, root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for row in rows:
        path = str(row.get("path", "")).strip()
        try:
            line = int(row.get("line") or 0)
        except (TypeError, ValueError):
            line = 0
        confidence = str(row.get("confidence", "needs-review")).lower()
        if confidence not in ("confirmed", "likely", "needs-review"):
            confidence = "needs-review"
        evidence = str(row.get("evidence", ""))[:1200]
        impact = str(row.get("impact", ""))
        findings.append(Finding(
            title=str(row.get("title"))[:180],
            severity=map_severity(row.get("severity"), "medium"),
            category="other", engine="code", tool=f"review:{agent}",
            rule_id="REVIEW",
            path=(root / path).as_posix() if path and not Path(path).is_absolute() else path,
            line=line,
            message=impact,
            remediation=str(row.get("remediation", "")),
            confidence=confidence,
            extra={"evidence": evidence, "reviewer": agent},
            sources=(f"review:{agent}",),
        ))
    return findings


def run(root: Path, *, agent: str = "codex", lenses: list[Lens],
        timeout: int = 1800, extra: str = "") -> ReviewResult:
    exe = find_tool(agent)
    if not exe:
        return ReviewResult([], agent, f"{agent} CLI not found on PATH", "")

    prompt = _prompt(root.resolve(), lenses, extra)
    # Always feed the prompt on stdin: a long multi-line argument gets mangled
    # by some shells/wrappers ("your message appears cut off"), and stdin also
    # avoids any command-line length limit.
    if agent == "codex":
        args = [exe, "exec", "--sandbox", "read-only", "--skip-git-repo-check", "-"]
    elif agent == "claude":
        args = [exe, "-p", "--permission-mode", "plan"]
    else:
        return ReviewResult([], agent, f"unsupported review agent {agent!r}", "")

    try:
        proc = subprocess.run(args, cwd=str(root), capture_output=True, text=True,
                              timeout=timeout, input=prompt,
                              encoding="utf-8", errors="replace")
    except subprocess.TimeoutExpired:
        return ReviewResult([], agent, "timed out", "")
    except Exception as exc:  # noqa: BLE001
        return ReviewResult([], agent, str(exc), "")

    rows = _extract_json(proc.stdout)
    findings = _to_findings(rows, agent, root.resolve())
    if proc.returncode != 0 and not findings:
        tail = (proc.stderr or proc.stdout or "").strip().replace("\n", " ")[-400:]
        return ReviewResult([], agent, f"exit {proc.returncode}: {tail}", proc.stdout)
    return ReviewResult(findings, agent, f"{len(findings)} findings from source review",
                        proc.stdout)


def tool_result(result: ReviewResult) -> ToolResult:
    return ToolResult(f"review:{result.agent}", "ok", findings=result.findings,
                      detail=result.detail)
