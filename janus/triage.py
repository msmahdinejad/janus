"""`janus triage`: hand TRIAGE.md's protocol to a real coding-agent CLI
instead of a human manually pasting it into a chat session.

This is deliberately the lightest-weight, safest-by-construction piece of
the "different AI agents with their own tools" concept (see
ARCHITECTURE.md's multi-model section): each backend here is invoked in
that CLI's own READ-ONLY / no-file-edit mode where one exists, specifically
so an experimental, loosely-verified integration like this one can't do
anything worse than produce a bad report. It writes ITS OWN output file
from the subprocess's stdout — it does not trust the invoked agent to
write files on disk, so "the agent ignored the instruction to only write
one file" isn't a failure mode here the way it would be with an unrestricted
`--full-auto`-style invocation.

Unverified: the exact CLI flags below are research-backed (Nov 2026), not
tested end-to-end against a live install in this environment (see
ARCHITECTURE.md "Honest gaps"). If a flag is wrong for your installed
version, the subprocess call fails and this reports that clearly — it
degrades to "skipped/failed," never silently.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .engines.common import ToolResult, find_tool

TRIAGE_PROMPT = (
    "Read the file TRIAGE.md in the current directory and follow its protocol exactly. "
    "Apply it to the findings in out/findings.json (adjust the path if it lives elsewhere "
    "in this repo) against the actual source in this repository. This is a READ-ONLY "
    "review: do not edit, create, or delete any file, and do not run any command that "
    "changes state. Produce your full triage output (one block per finding reviewed, "
    "per TRIAGE.md's format, ending with the summary section) as your final response."
)


@dataclass
class TriageBudget:
    timeout_seconds: int = 1800


class TriageAgent(Protocol):
    name: str

    def run(self, repo_root: Path, budget: TriageBudget) -> ToolResult: ...


class CodexTriageAgent:
    """OpenAI Codex CLI, invoked with an explicit read-only sandbox policy.

    The policy flag — not the prompt — is the control: `--sandbox read-only`
    is enforced by the CLI's own sandbox. If an older CLI rejects the flag,
    the run fails closed and says so.
    """

    name = "codex"

    def run(self, repo_root: Path, budget: TriageBudget) -> ToolResult:
        exe = find_tool("codex")
        if not exe:
            return ToolResult("triage:codex", "skipped", detail="codex CLI not found on PATH")
        args = [exe, "exec", "--sandbox", "read-only", "--skip-git-repo-check", TRIAGE_PROMPT]
        try:
            proc = subprocess.run(args, cwd=str(repo_root), capture_output=True, text=True, stdin=subprocess.DEVNULL,
                                   encoding="utf-8", errors="replace",
                                   timeout=budget.timeout_seconds)
        except subprocess.TimeoutExpired:
            return ToolResult("triage:codex", "failed", detail="timed out")
        except Exception as e:  # noqa: BLE001
            return ToolResult("triage:codex", "failed", detail=str(e))
        if proc.returncode != 0 and not proc.stdout.strip():
            return ToolResult("triage:codex", "failed",
                               detail=f"exit {proc.returncode}: {proc.stderr[:500]}")
        return _ok_with_text("triage:codex", proc.stdout)


class ClaudeCodeTriageAgent:
    """Claude Code's non-interactive mode, with the plan permission mode.

    `--permission-mode plan` keeps the session read-only (no edits, no
    commands that change state). As with Codex, the flag is the boundary and
    the prompt is only guidance.
    """

    name = "claude"

    def run(self, repo_root: Path, budget: TriageBudget) -> ToolResult:
        exe = find_tool("claude")
        if not exe:
            return ToolResult("triage:claude", "skipped", detail="claude CLI not found on PATH")
        args = [exe, "-p", "--permission-mode", "plan", TRIAGE_PROMPT]
        try:
            proc = subprocess.run(args, cwd=str(repo_root), capture_output=True, text=True, stdin=subprocess.DEVNULL,
                                   encoding="utf-8", errors="replace",
                                   timeout=budget.timeout_seconds)
        except subprocess.TimeoutExpired:
            return ToolResult("triage:claude", "failed", detail="timed out")
        except Exception as e:  # noqa: BLE001
            return ToolResult("triage:claude", "failed", detail=str(e))
        if proc.returncode != 0 and not proc.stdout.strip():
            return ToolResult("triage:claude", "failed",
                               detail=f"exit {proc.returncode}: {proc.stderr[:500]}")
        return _ok_with_text("triage:claude", proc.stdout)


def _ok_with_text(name: str, text: str) -> ToolResult:
    return ToolResult(name, "ok", detail=f"{len(text)} chars of output", output_text=text)


TRIAGE_AGENTS: dict[str, TriageAgent] = {
    "codex": CodexTriageAgent(),
    "claude": ClaudeCodeTriageAgent(),
}
