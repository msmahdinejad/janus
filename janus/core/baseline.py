"""Baseline suppression: a short, auditable way to say "these specific
findings are known and accepted, stop failing CI on them" without hand-
editing `register.json` or re-triaging through the dashboard every run.

A baseline file is just `{"suppressed": ["<fingerprint>", ...]}`. Applying
one does NOT delete or hide a finding — it sets that finding's `status` to
`accepted-risk` (a real, visible status, not a different code path), and
only for findings that are still `open`/`needs-review` in the register — a
finding a human has already explicitly marked `fixed`/`ruled-out` keeps
that status, and a baseline never re-opens one either.
"""

from __future__ import annotations

import json
from pathlib import Path


def load_baseline_fingerprints(path: str | Path | None) -> set[str]:
    if not path:
        return set()
    p = Path(path)
    if not p.is_file():
        return set()
    data = json.loads(p.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return set(data)
    return set(data.get("suppressed", []))


def apply_baseline(findings: list, fingerprints: set[str]) -> int:
    """Mutates `findings` (a list of Finding objects) in place, setting
    `status = "accepted-risk"` on any whose fingerprint is baselined and
    that don't already carry a human-set status. Returns how many were
    affected, for the CLI to report."""
    if not fingerprints:
        return 0
    count = 0
    for f in findings:
        if f.fingerprint in fingerprints and f.status in ("open", "needs-review"):
            f.status = "accepted-risk"
            f.notes = (f.notes + " " if f.notes else "") + "(suppressed via baseline file)"
            count += 1
    return count
