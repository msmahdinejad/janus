"""The findings register: one JSON file, one source of truth.

Re-running a scan should never create duplicate rows and should never wipe
out a human's triage decision on a finding that just didn't fire this time
(it might be fixed, or the scanner might have timed out on that one host —
the register can't tell the difference, so it keeps the row and leaves it to
a human to mark `fixed`). This mirrors the "register.json + REGISTER.md"
idea from the pipelines this project grew out of, generalized to be engine-
agnostic and given a proper merge function instead of a from-scratch
rebuild every run.
"""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any

from .model import SEVERITIES, Finding, utc_now_iso

_SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}

_LOCK_TIMEOUT = 10.0
_LOCK_STALE_AFTER = 60.0


class RegisterLocked(RuntimeError):
    """Another process held the register lock past the timeout."""


class _FileLock:
    """Cross-process lock built from an exclusive-create lock file.

    Why not msvcrt/fcntl: this has to behave the same on Windows and POSIX
    without a dependency, and the only writers are short read-modify-write
    transactions (a scan merge, a triage click). An O_EXCL lock file with a
    stale-after timeout covers that, including a crashed process leaving the
    file behind.
    """

    def __init__(self, target: Path, timeout: float = _LOCK_TIMEOUT) -> None:
        self.path = target.with_name(target.name + ".lock")
        self.timeout = timeout
        self._fd: int | None = None

    def __enter__(self) -> "_FileLock":
        deadline = time.monotonic() + self.timeout
        # A fresh --out directory does not exist yet on the very first scan.
        self.path.parent.mkdir(parents=True, exist_ok=True)
        while True:
            try:
                self._fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                os.write(self._fd, f"{os.getpid()} {time.time()}".encode())
                return self
            except FileExistsError:
                try:
                    age = time.time() - self.path.stat().st_mtime
                except OSError:
                    age = 0
                if age > _LOCK_STALE_AFTER:
                    with contextlib.suppress(OSError):
                        self.path.unlink()
                    continue
                if time.monotonic() > deadline:
                    raise RegisterLocked(
                        f"register is locked by another process ({self.path}); "
                        f"waited {self.timeout:.0f}s"
                    ) from None
                time.sleep(0.05)

    def __exit__(self, *exc) -> None:
        if self._fd is not None:
            with contextlib.suppress(OSError):
                os.close(self._fd)
            self._fd = None
        with contextlib.suppress(OSError):
            self.path.unlink()


class Register:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._by_fingerprint: dict[str, dict[str, Any]] = {}
        self.load_error: str = ""
        if self.path.exists():
            try:
                rows = json.loads(self.path.read_text(encoding="utf-8"))
                if not isinstance(rows, list):
                    raise ValueError("register must be a JSON array")
                self._by_fingerprint = {
                    row["fingerprint"]: row for row in rows
                    if isinstance(row, dict) and "fingerprint" in row
                }
            except Exception as exc:  # noqa: BLE001
                # A corrupt register must not take the dashboard or the CLI
                # down; it is reported instead of silently discarded.
                self.load_error = f"{self.path}: {exc}"
                self._by_fingerprint = {}

    def merge(self, findings: list[Finding]) -> dict[str, int]:
        """Merge freshly-scanned findings into the register. Returns a
        {"new": n, "updated": n, "unchanged": n} summary."""
        now = utc_now_iso()
        stats = {"new": 0, "updated": 0, "unchanged": 0}
        seen_this_run: set[str] = set()
        for f in findings:
            fp = f.fingerprint
            seen_this_run.add(fp)
            row = f.to_dict()
            existing = self._by_fingerprint.get(fp)
            if existing is None:
                row["first_seen"] = row["last_seen"] = now
                row["status"] = f.status
                self._by_fingerprint[fp] = row
                stats["new"] += 1
            else:
                if existing.get("status") in ("fixed", "ruled-out", "accepted-risk"):
                    # A human already triaged this; a re-scan hitting the
                    # same spot is a signal worth surfacing, but it should
                    # not silently flip the status back to "open" under the
                    # human's feet.
                    existing["last_seen"] = now
                    existing.setdefault("extra", {})["reappeared_at"] = now
                    stats["unchanged"] += 1
                else:
                    row["first_seen"] = existing["first_seen"]
                    row["last_seen"] = now
                    row["status"] = existing.get("status", f.status)
                    row["notes"] = existing.get("notes", "")
                    self._by_fingerprint[fp] = row
                    stats["updated"] += 1
        return stats

    def set_status(self, fingerprint: str, status: str, notes: str | None = None) -> bool:
        row = self._by_fingerprint.get(fingerprint)
        if row is None:
            return False
        row["status"] = status
        if notes is not None:
            row["notes"] = notes
        return True

    def all(self) -> list[dict[str, Any]]:
        return sorted(
            self._by_fingerprint.values(),
            key=lambda r: (_SEVERITY_RANK.get(r.get("severity"), len(SEVERITIES)), r.get("last_seen", "")),
        )

    # ---- persistence -------------------------------------------------
    def reload(self) -> None:
        """Re-read the file (call this inside a transaction, after locking)."""
        rows: list[dict[str, Any]] = []
        if self.path.exists():
            try:
                loaded = json.loads(self.path.read_text(encoding="utf-8"))
                if isinstance(loaded, list):
                    rows = [r for r in loaded if isinstance(r, dict) and "fingerprint" in r]
            except Exception as exc:  # noqa: BLE001
                self.load_error = f"{self.path}: {exc}"
        self._by_fingerprint = {r["fingerprint"]: r for r in rows}

    def _write(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Atomic-ish write: temp file + replace, so a crash mid-write can't
        # leave the register truncated.
        fd, tmp_path = tempfile.mkstemp(dir=self.path.parent, prefix=".register-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(list(self._by_fingerprint.values()), f, indent=2, ensure_ascii=False)
            os.replace(tmp_path, self.path)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    @contextlib.contextmanager
    def transaction(self):
        """Lock, re-read, let the caller mutate, write, unlock.

        This is the fix for the read-modify-write race: a scan merge and a
        dashboard triage click can no longer interleave, because both go
        through the same lock and both start from the file on disk rather
        than from a copy loaded earlier.
        """
        with _FileLock(self.path):
            self.reload()
            yield self
            self._write()

    def save(self) -> None:
        with _FileLock(self.path):
            self._write()
