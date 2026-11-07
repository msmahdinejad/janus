"""Immutable, atomic scan history records.

The live register answers what is true now. This module keeps one directory per
scan so the dashboard can explain what changed and what actually ran. Writers
build a complete directory beside the final path and rename it into place only
after every artifact is written.
"""
from __future__ import annotations

import json
import os
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from ..core import coverage as coverage_mod
from ..core import report as report_mod

SCANS_DIR = "scans"
_REQUIRED_ARTIFACTS = ("scan.json", "findings.json", "report.md", "findings.sarif", "coverage.json")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def _tool_rows(tool_results: Iterable[Any]) -> list[dict[str, Any]]:
    return [{
        "id": getattr(r, "name", "?"),
        "status": getattr(r, "status", "?"),
        "detail": getattr(r, "detail", ""),
        "findings": len(getattr(r, "findings", []) or []),
    } for r in tool_results]


def _fallback_coverage(scope_manifest: dict[str, Any], mode: str, tools: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "engagement": scope_manifest.get("engagement", ""),
        "mode": mode,
        "generated_at": _now(),
        "code": None,
        "recon": None,
        "engines": [],
        "tools": tools,
        "lenses": [],
        "owasp": {},
        "quality": "not-assessed",
        "gaps": ["coverage.json was not supplied by the scan runner; execution status is not assessed"],
    }


def _coverage_quality(coverage: dict[str, Any]) -> str:
    quality = str(coverage.get("quality", "")).lower()
    if quality in {"complete", "degraded", "failed", "not-assessed"}:
        return quality
    rows = [*coverage.get("engines", []), *coverage.get("tools", [])]
    if any(str(row.get("status")) == "failed" for row in rows if isinstance(row, dict)):
        return "failed"
    if coverage.get("gaps") or any(str(row.get("status")) in {"skipped", "unknown"} for row in rows if isinstance(row, dict)):
        return "degraded"
    return "complete"


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False), encoding="utf-8")


def record_scan(
    out_dir: str | Path,
    *,
    run_id: str,
    command: str,
    scope_manifest: dict[str, Any],
    findings: Iterable[Any],
    tool_results: Iterable[Any] = (),
    mode: str = "",
    lenses: list[str] | None = None,
    coverage: dict[str, Any] | None = None,
    extra: dict[str, Any] | None = None,
) -> Path:
    """Persist one immutable run and return its final directory.

    ``findings`` must contain only this run's findings. Existing final
    directories are never overwritten; a repeated run id is an immutable
    record collision and returns the original directory.
    """
    out_dir = Path(out_dir)
    root = out_dir / SCANS_DIR
    root.mkdir(parents=True, exist_ok=True)
    final_dir = root / run_id
    if final_dir.exists():
        return final_dir

    findings_list = [f.to_dict() if hasattr(f, "to_dict") else dict(f) for f in findings]
    tools = _tool_rows(tool_results)
    coverage_doc = dict(coverage) if isinstance(coverage, dict) else _fallback_coverage(scope_manifest, mode, tools)
    coverage_doc.setdefault("tools", tools)
    coverage_doc.setdefault("gaps", [])
    coverage_doc.setdefault("engines", [])
    coverage_doc.setdefault("quality", _coverage_quality(coverage_doc))

    by_sev: dict[str, int] = {}
    by_engine: dict[str, int] = {}
    by_tool: dict[str, int] = {}
    for f in findings_list:
        by_sev[f.get("severity", "info")] = by_sev.get(f.get("severity", "info"), 0) + 1
        by_engine[f.get("engine", "?")] = by_engine.get(f.get("engine", "?"), 0) + 1
        by_tool[f.get("tool", "?")] = by_tool.get(f.get("tool", "?"), 0) + 1

    quality = _coverage_quality(coverage_doc)
    meta = {
        "run_id": run_id,
        "finished_at": _now(),
        "command": command,
        "mode": mode,
        "engagement": scope_manifest.get("engagement", ""),
        "authorization_reference": scope_manifest.get("authorization_reference", ""),
        "scope_sha256_16": scope_manifest.get("scope_sha256_16", ""),
        "lenses": lenses or [],
        "total": len(findings_list),
        "by_severity": by_sev,
        "by_engine": by_engine,
        "by_tool": by_tool,
        "tools": tools,
        "engines": coverage_doc.get("engines", []),
        "gaps": coverage_doc.get("gaps", []),
        "quality": quality,
        "status": "complete",
        "files_scanned": (coverage_doc.get("code") or {}).get("files_scanned"),
        "recon": coverage_doc.get("recon"),
        **(extra or {}),
    }

    tmp_dir = root / f".{run_id}.tmp-{uuid.uuid4().hex}"
    try:
        tmp_dir.mkdir()
        _write_json(tmp_dir / "scan.json", meta)
        _write_json(tmp_dir / "findings.json", findings_list)
        _write_json(tmp_dir / "coverage.json", coverage_doc)
        report = report_mod.to_markdown(scope_manifest, findings_list)
        report += "\n" + coverage_mod.to_markdown(coverage_doc)
        (tmp_dir / "report.md").write_text(report, encoding="utf-8")
        _write_json(tmp_dir / "findings.sarif", report_mod.to_sarif(findings_list))
        os.replace(tmp_dir, final_dir)
    except Exception:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise
    return final_dir


def _read_json(path: Path) -> tuple[Any | None, bool]:
    try:
        return json.loads(path.read_text(encoding="utf-8")), True
    except (OSError, ValueError, TypeError):
        return None, False


def _entry(path: Path) -> tuple[dict[str, Any], bool, bool]:
    """Return (public row, complete artifacts?, valid findings?)."""
    meta_raw, meta_ok = _read_json(path / "scan.json")
    meta = dict(meta_raw) if isinstance(meta_raw, dict) else {}
    run_id = str(meta.get("run_id") or path.name)
    meta["run_id"] = run_id
    findings_ok = _findings_valid(path / "findings.json")
    missing = [name for name in _REQUIRED_ARTIFACTS if not (path / name).is_file()]
    # Old records predate per-run coverage. Keep them visible but unverified.
    if not (path / "coverage.json").is_file():
        missing = [name for name in missing if name != "coverage.json"]
        meta.setdefault("quality", "not-assessed")
        meta.setdefault("gaps", [])
        if "coverage.json was not recorded for this run" not in meta["gaps"]:
            meta["gaps"] = [*meta["gaps"], "coverage.json was not recorded for this run"]
    coverage_raw, coverage_ok = _read_json(path / "coverage.json")
    if isinstance(coverage_raw, dict):
        meta["coverage"] = coverage_raw
        meta["quality"] = coverage_raw.get("quality", meta.get("quality", "not-assessed"))
        meta["engines"] = coverage_raw.get("engines", meta.get("engines", []))
        meta["gaps"] = coverage_raw.get("gaps", meta.get("gaps", []))
    elif (path / "coverage.json").exists():
        missing.append("coverage.json (invalid JSON)")
        meta.setdefault("quality", "not-assessed")
    complete = meta_ok and findings_ok and not missing
    if not complete:
        meta["status"] = "partial"
        if meta.get("quality") == "complete":
            meta["quality"] = "not-assessed"
        gaps = list(meta.get("gaps") or [])
        detail = ", ".join(dict.fromkeys(missing)) or "invalid scan.json or findings.json"
        marker = f"scan record incomplete: {detail}"
        if marker not in gaps:
            gaps.append(marker)
        meta["gaps"] = gaps
    else:
        meta.setdefault("status", "complete")
        meta.setdefault("quality", "not-assessed")
    return meta, complete, findings_ok


def list_scans(out_dir: str | Path) -> list[dict[str, Any]]:
    """Newest first, including partial/corrupt records with an honest status."""
    root = Path(out_dir) / SCANS_DIR
    if not root.is_dir():
        return []
    entries: list[tuple[dict[str, Any], bool, bool, Path]] = []
    for path in root.iterdir():
        if not path.is_dir() or path.name.startswith("."):
            continue
        row, complete, findings_ok = _entry(path)
        entries.append((row, complete, findings_ok, path))
    entries.sort(key=lambda x: (x[0].get("finished_at", ""), x[0].get("run_id", "")), reverse=True)
    rows = [row for row, _complete, _findings_ok, _path in entries]
    valid = {row["run_id"]: complete and findings_ok for row, complete, findings_ok, _path in entries}
    for i, row in enumerate(rows):
        kind = _kind(row.get("command", ""))
        complete = valid.get(row["run_id"], False)
        older = next((r for r in rows[i + 1:] if valid.get(r.get("run_id"), False)
                      and _kind(r.get("command", "")) == kind), None)
        row["kind"] = kind
        row["previous_run_id"] = older["run_id"] if complete and older else None
        row["baseline"] = not bool(complete and older)
        row["delta"] = _delta(row["run_id"], older["run_id"] if complete and older else None, root) if complete else {"new": 0, "fixed": 0, "same": 0}
    return rows


def _kind(command: str) -> str:
    parts = str(command or "").split()
    return " ".join(parts[:2]) if len(parts) >= 2 else (parts[0] if parts else "scan")


_FP_CACHE: dict[str, tuple[tuple[int, int], frozenset[str]]] = {}
_FP_CACHE_MAX = 1024
_FINDINGS_VALID_CACHE: dict[str, tuple[tuple[int, int], bool]] = {}


def _fingerprints(root: Path, run_id: str) -> frozenset[str]:
    path = root / run_id / "findings.json"
    try:
        st = path.stat()
    except OSError:
        return frozenset()
    key = (st.st_mtime_ns, st.st_size)
    hit = _FP_CACHE.get(str(path))
    if hit and hit[0] == key:
        return hit[1]
    raw, ok = _read_json(path)
    if not ok or not isinstance(raw, list):
        return frozenset()
    fps = frozenset(str(r.get("fingerprint") or r.get("title", "")) for r in raw if isinstance(r, dict))
    if len(_FP_CACHE) >= _FP_CACHE_MAX:
        _FP_CACHE.clear()
    _FP_CACHE[str(path)] = (key, fps)
    return fps


def _findings_valid(path: Path) -> bool:
    """Validate findings once per file version; history list calls are hot."""
    try:
        st = path.stat()
    except OSError:
        return False
    key = (st.st_mtime_ns, st.st_size)
    cache_key = str(path)
    hit = _FINDINGS_VALID_CACHE.get(cache_key)
    if hit and hit[0] == key:
        return hit[1]
    raw, ok = _read_json(path)
    valid = ok and isinstance(raw, list)
    if len(_FINDINGS_VALID_CACHE) >= _FP_CACHE_MAX:
        _FINDINGS_VALID_CACHE.clear()
    _FINDINGS_VALID_CACHE[cache_key] = (key, valid)
    return valid


def _delta(run_id: str, previous_id: str | None, root: Path) -> dict[str, int]:
    current = _fingerprints(root, run_id)
    if previous_id is None:
        return {"new": len(current), "fixed": 0, "same": 0}
    previous = _fingerprints(root, previous_id)
    return {"new": len(current - previous), "fixed": len(previous - current), "same": len(current & previous)}


def _diff_findings(current: list[dict[str, Any]], previous: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    key = lambda f: str(f.get("fingerprint") or f.get("title", ""))
    cur_keys = {key(f) for f in current}
    prev_keys = {key(f) for f in previous}
    return ([f for f in current if key(f) not in prev_keys],
            [f for f in previous if key(f) not in cur_keys])


def load_scan(out_dir: str | Path, run_id: str) -> dict[str, Any] | None:
    # ``run_id`` comes from a URL. Keep it a single directory name so a deep
    # link cannot walk out of ``scans/`` (including ``.``/``..`` aliases).
    if not run_id or run_id in {".", ".."} or Path(run_id).name != run_id or any(c in run_id for c in ("/", "\\")):
        return None
    scan_dir = Path(out_dir) / SCANS_DIR / run_id
    if not scan_dir.is_dir() or scan_dir.name.startswith("."):
        return None
    meta, complete, findings_ok = _entry(scan_dir)
    raw, _ = _read_json(scan_dir / "findings.json")
    findings = raw if findings_ok and isinstance(raw, list) else []
    scans = list_scans(scan_dir.parent.parent)
    row = next((s for s in scans if s.get("run_id") == run_id), None)
    delta = row.get("delta", {"new": 0, "fixed": 0, "same": 0}) if row else {"new": 0, "fixed": 0, "same": 0}
    previous_id = row.get("previous_run_id") if row else None
    previous = []
    if previous_id:
        old_raw, old_ok = _read_json(scan_dir.parent / previous_id / "findings.json")
        if old_ok and isinstance(old_raw, list):
            previous = old_raw
    new_findings, fixed_findings = _diff_findings(findings, previous) if previous_id else ([], [])
    coverage, coverage_ok = _read_json(scan_dir / "coverage.json")
    return {
        "meta": meta,
        "findings": findings,
        "coverage": coverage if coverage_ok and isinstance(coverage, dict) else None,
        "delta": delta,
        "new_findings": new_findings,
        "fixed_findings": fixed_findings,
        "kind": row.get("kind", _kind(meta.get("command", ""))) if row else _kind(meta.get("command", "")),
        "previous_run_id": previous_id,
        "baseline": row.get("baseline", True) if row else True,
        "status": row.get("status", "complete" if complete else "partial") if row else ("complete" if complete else "partial"),
        "quality": row.get("quality", meta.get("quality", "not-assessed")) if row else meta.get("quality", "not-assessed"),
        "dir": str(scan_dir),
        "report": str(scan_dir / "report.md"),
        "sarif": str(scan_dir / "findings.sarif"),
    }
