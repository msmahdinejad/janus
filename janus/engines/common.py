"""Shared plumbing for external-tool adapters (code and recon alike).

The rule every adapter in this project follows: if the tool isn't installed,
return status="skipped" and keep going. A missing scanner is a coverage gap
to report, never a crash. See ARCHITECTURE.md's "no mandatory dependency"
principle.
"""

from __future__ import annotations

import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ToolResult:
    name: str
    status: str  # "ok" | "partial" | "skipped" | "failed"
    findings: list = field(default_factory=list)
    detail: str = ""
    seconds: float = 0.0
    output_text: str = ""  # free-text output for adapters that don't produce Finding rows (e.g. janus/triage.py)


def find_tool(name: str, extra_dirs: tuple[Path, ...] = ()) -> str | None:
    found = shutil.which(name)
    if found:
        return found
    for d in extra_dirs:
        for candidate in (d / name, d / f"{name}.exe"):
            if candidate.is_file():
                return str(candidate)
    return None


def run_cli(args: list[str], timeout: int = 300, cwd: str | Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        args, capture_output=True, text=True, timeout=timeout, cwd=str(cwd) if cwd else None,
    )


@dataclass
class ToolRun:
    """Result of one external-tool invocation, including the exit code.

    Why this exists: the delivered adapters called `run_cli(...)` and then
    parsed whatever file happened to exist at the output path. Two failure
    modes followed — a crashed tool looked like "0 findings", and a file left
    over from a previous run was re-parsed and reported as fresh results.
    `out_path` is removed before the run and the return code is inspected
    afterwards, so "no output" and "failed" can no longer masquerade as "ok".
    """

    returncode: int
    stdout: str
    stderr: str
    output_path: Path | None = None

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    def diagnostics(self, limit: int = 400) -> str:
        text = (self.stderr or self.stdout or "").strip().replace("\n", " ")
        return text[:limit]


def run_tool(
    exe: str,
    args: list[str],
    *,
    out_path: Path | None = None,
    timeout: int = 300,
    cwd: str | Path | None = None,
    env: dict[str, str] | None = None,
) -> ToolRun:
    """Run an external scanner with a fresh output path and a checked exit code.

    A non-zero exit is not automatically a failure: gitleaks uses 1 for
    "secrets found", semgrep uses 1 for "findings found". Callers decide via
    `ToolRun.ok` and `ToolRun.output_path`; what they can no longer do is
    mistake a crash for a clean scan.
    """
    if out_path is not None:
        try:
            out_path.unlink(missing_ok=True)
        except OSError:
            pass
    try:
        proc = subprocess.run(
            [exe, *args], capture_output=True, text=True, timeout=timeout,
            cwd=str(cwd) if cwd else None, env=env,
        )
    except subprocess.TimeoutExpired:
        return ToolRun(returncode=124, stdout="", stderr=f"timed out after {timeout}s")
    except OSError as exc:
        return ToolRun(returncode=127, stdout="", stderr=str(exc))
    fresh = out_path if (out_path is not None and out_path.exists()) else None
    return ToolRun(returncode=proc.returncode, stdout=proc.stdout, stderr=proc.stderr, output_path=fresh)


_SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high", "ERROR": "high",
    "MEDIUM": "medium", "WARNING": "medium", "UNKNOWN": "medium", "MODERATE": "medium",
    "LOW": "low",
    "INFO": "info", "NOTE": "info", "UNIMPORTANT": "info",
}


def map_severity(value: str | None, default: str = "medium") -> str:
    return _SEVERITY_MAP.get(str(value or "").upper(), default)


class Timer:
    def __enter__(self):
        self._start = time.monotonic()
        return self

    def __exit__(self, *exc):
        self.seconds = time.monotonic() - self._start

    seconds: float = 0.0


class RateLimiter:
    """Dumb, deliberate token-less limiter: just enforces a minimum gap
    between calls. Good enough for a conservative recon pace; not meant to
    be a high-throughput scheduler."""

    def __init__(self, max_rps: float) -> None:
        self.min_interval = 1.0 / max_rps if max_rps > 0 else 0.0
        self._last = 0.0

    def wait(self) -> None:
        if self.min_interval <= 0:
            return
        now = time.monotonic()
        delta = now - self._last
        if delta < self.min_interval:
            time.sleep(self.min_interval - delta)
        self._last = time.monotonic()
