"""Regression tests for the stale-register bug found during the UI/UX
redesign (see janus/dashboard/DESIGN_NOTES.md backend requirement #1):
the dashboard used to load register.json once at startup, so a `janus
scan` run while it was open was invisible to it, and the next triage
click would silently overwrite the file with the stale in-memory copy."""

import json
from pathlib import Path

from fastapi.testclient import TestClient

from janus.core.model import Finding
from janus.dashboard.server import build_app


def _write_register(path: Path, findings: list[Finding]) -> None:
    path.write_text(json.dumps([f.to_dict() for f in findings], indent=2), encoding="utf-8")


def test_findings_endpoint_picks_up_a_file_change_made_after_startup(tmp_path: Path):
    reg_path = tmp_path / "register.json"
    f1 = Finding(title="first", severity="low", category="other", engine="code", tool="builtin", path="a.py", line=1)
    _write_register(reg_path, [f1])

    app = build_app(reg_path)
    client = TestClient(app)

    assert len(client.get("/api/findings").json()) == 1

    # Simulate a `janus scan` finishing while the dashboard is already open.
    f2 = Finding(title="second", severity="high", category="other", engine="code", tool="builtin", path="b.py", line=1)
    _write_register(reg_path, [f1, f2])

    findings = client.get("/api/findings").json()
    assert len(findings) == 2, "a file change after startup must be visible without restarting the server"


def test_status_write_does_not_clobber_a_concurrent_scan(tmp_path: Path):
    reg_path = tmp_path / "register.json"
    f1 = Finding(title="first", severity="low", category="other", engine="code", tool="builtin", path="a.py", line=1)
    _write_register(reg_path, [f1])

    app = build_app(reg_path)
    client = TestClient(app)
    client.get("/api/findings")  # warm the in-memory copy, like a dashboard page load would

    # A scan completes and adds a second finding on disk, out-of-band from this client.
    f2 = Finding(title="second", severity="high", category="other", engine="code", tool="builtin", path="b.py", line=1)
    _write_register(reg_path, [f1, f2])

    resp = client.post(f"/api/findings/{f1.fingerprint}/status", json={"status": "fixed", "notes": None})
    assert resp.status_code == 200

    on_disk = json.loads(reg_path.read_text(encoding="utf-8"))
    assert len(on_disk) == 2, "the scan's new finding must survive a triage write that started before it landed"
    assert any(row["fingerprint"] == f2.fingerprint for row in on_disk)
    assert next(row for row in on_disk if row["fingerprint"] == f1.fingerprint)["status"] == "fixed"


def test_bulk_status_updates_multiple_findings(tmp_path: Path):
    reg_path = tmp_path / "register.json"
    f1 = Finding(title="a", severity="low", category="other", engine="code", tool="builtin", path="a.py", line=1)
    f2 = Finding(title="b", severity="low", category="other", engine="code", tool="builtin", path="b.py", line=1)
    _write_register(reg_path, [f1, f2])

    app = build_app(reg_path)
    client = TestClient(app)
    resp = client.post("/api/findings/status", json={
        "fingerprints": [f1.fingerprint, f2.fingerprint, "not-a-real-fingerprint"],
        "status": "ruled-out", "notes": "bulk-closed in a sweep",
    })
    assert resp.status_code == 200
    body = resp.json()
    assert body["updated"] == 2
    assert body["missing"] == ["not-a-real-fingerprint"]

    findings = {f["fingerprint"]: f for f in client.get("/api/findings").json()}
    assert findings[f1.fingerprint]["status"] == "ruled-out"
    assert findings[f2.fingerprint]["status"] == "ruled-out"


def test_meta_revision_changes_when_register_changes(tmp_path: Path):
    reg_path = tmp_path / "register.json"
    f1 = Finding(title="a", severity="low", category="other", engine="code", tool="builtin", path="a.py", line=1)
    _write_register(reg_path, [f1])

    app = build_app(reg_path)
    client = TestClient(app)
    rev1 = client.get("/api/meta").json()["revision"]

    import time
    time.sleep(0.01)
    f2 = Finding(title="b", severity="low", category="other", engine="code", tool="builtin", path="b.py", line=1)
    _write_register(reg_path, [f1, f2])

    rev2 = client.get("/api/meta").json()["revision"]
    assert rev1 != rev2
