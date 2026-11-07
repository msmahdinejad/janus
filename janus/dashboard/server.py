"""A deliberately small local dashboard: FastAPI + one static page.

Bound to 127.0.0.1 by default. Binding further is now an explicit decision:
`run_dashboard(..., allow_remote=True, token=...)` is refused unless a token
is configured, and every `/api/*` request then needs it. The delivered
version allowed `--host 0.0.0.0` with unauthenticated read *and write* access
to the findings register — a security tool should not open a writable
findings store to the network by accident.

The register itself is loaded lazily per request via `LiveRegister`, which
re-stats the file, so an external `janus scan` is visible immediately and a
triage click cannot overwrite a newer scan with a stale in-memory copy.
"""

from __future__ import annotations

import hashlib
import ipaddress
import threading
import webbrowser
import json
from pathlib import Path
from typing import Optional

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import (FileResponse, JSONResponse, PlainTextResponse,
                               RedirectResponse)
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from ..core.store import Register
from . import history

STATIC_DIR = Path(__file__).resolve().parent / "static"


class StatusUpdate(BaseModel):
    status: str
    notes: Optional[str] = None


class BulkStatusUpdate(BaseModel):
    fingerprints: list[str]
    status: str
    notes: Optional[str] = None


ALLOWED_STATUSES = {"open", "needs-review", "ruled-out", "fixed", "accepted-risk"}


def is_loopback(host: str) -> bool:
    if host in ("localhost", ""):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class LiveRegister:
    """Reloads `register.json` whenever its bytes change.

    An mtime check is not enough on filesystems with coarse timestamps: a
    scan that finishes inside the same tick as the previous read is invisible,
    and the next triage click writes the stale copy back. Content hashing is
    a few hundred microseconds for a register of this size and removes the
    whole class of race.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self._register: Register | None = None
        self._digest: str | None = None

    def _refresh_if_changed(self) -> Register:
        try:
            raw = self.path.read_bytes() if self.path.exists() else b""
        except OSError:
            raw = b""
        digest = hashlib.sha256(raw).hexdigest()
        if self._register is None or digest != self._digest:
            self._register = Register(self.path)
            self._digest = digest
        return self._register

    def all(self) -> list[dict]:
        return self._refresh_if_changed().all()

    def load_error(self) -> str:
        return self._refresh_if_changed().load_error

    def revision(self) -> str:
        self._refresh_if_changed()
        return (self._digest or "")[:16]

    def set_status(self, fingerprint: str, status: str, notes: str | None) -> bool:
        # Lock, re-read, mutate, write: the same transaction the CLI scan uses,
        # so a triage click and a finishing scan cannot lose each other.
        register = Register(self.path)
        with register.transaction() as reg:
            ok = reg.set_status(fingerprint, status, notes)
        if ok:
            try:
                self._digest = hashlib.sha256(self.path.read_bytes()).hexdigest()
            except OSError:
                self._digest = None
        return ok


def build_app(register_path: Path, token: str | None = None,
              scans_dir: Path | None = None) -> FastAPI:
    app = FastAPI(title="Janus dashboard")
    live = LiveRegister(register_path)
    scans_root = Path(scans_dir) if scans_dir else Path(register_path).parent

    if token:
        @app.middleware("http")
        async def require_token(request: Request, call_next):
            if request.url.path.startswith("/api/"):
                header = request.headers.get("authorization", "")
                if header != f"Bearer {token}":
                    return JSONResponse({"detail": "missing or invalid token"}, status_code=401)
            return await call_next(request)

    @app.get("/api/findings")
    def list_findings():
        return live.all()

    @app.post("/api/findings/{fingerprint}/status")
    def set_status(fingerprint: str, body: StatusUpdate):
        if body.status not in ALLOWED_STATUSES:
            raise HTTPException(400, f"status must be one of {sorted(ALLOWED_STATUSES)}")
        ok = live.set_status(fingerprint, body.status, body.notes)
        if not ok:
            raise HTTPException(404, "no finding with that fingerprint")
        return {"ok": True}

    @app.post("/api/findings/status")
    def set_status_bulk(body: BulkStatusUpdate):
        if body.status not in ALLOWED_STATUSES:
            raise HTTPException(400, f"status must be one of {sorted(ALLOWED_STATUSES)}")
        updated, missing = [], []
        for fp in body.fingerprints:
            (updated if live.set_status(fp, body.status, body.notes) else missing).append(fp)
        return {"updated": len(updated), "missing": missing}

    @app.get("/api/meta")
    def meta():
        from ..core.report import summarize_dicts
        findings = live.all()
        return {
            "register_path": str(register_path),
            "revision": live.revision(),
            "load_error": live.load_error(),
            "summary": summarize_dicts(findings),
        }

    @app.get("/scans")
    def scans_page():
        # One UI: /scans is a deep link into the SPA, not a second design.
        return RedirectResponse("/#/scans", status_code=307)

    @app.get("/scans/{run_id}")
    def scan_page(run_id: str):
        if history.load_scan(scans_root, run_id) is None:
            raise HTTPException(404, "no such scan")
        return RedirectResponse(f"/#/scans?id={run_id}", status_code=307)

    @app.get("/api/scans/{run_id}/report", response_class=PlainTextResponse)
    def scan_report(run_id: str):
        scan = history.load_scan(scans_root, run_id)
        if scan is None:
            raise HTTPException(404, "no such scan")
        try:
            return Path(scan["report"]).read_text(encoding="utf-8")
        except OSError:
            raise HTTPException(404, "report not written for this scan") from None

    @app.get("/api/scans/{run_id}/sarif")
    def scan_sarif(run_id: str):
        scan = history.load_scan(scans_root, run_id)
        if scan is None:
            raise HTTPException(404, "no such scan")
        try:
            return JSONResponse(json.loads(Path(scan["sarif"]).read_text(encoding="utf-8")))
        except (OSError, ValueError):
            raise HTTPException(404, "SARIF not written for this scan") from None

    @app.get("/api/scans")
    def api_scans():
        return history.list_scans(scans_root)

    @app.get("/api/scans/{run_id}")
    def api_scan(run_id: str):
        scan = history.load_scan(scans_root, run_id)
        if scan is None:
            raise HTTPException(404, "no such scan")
        return scan

    @app.get("/")
    def index():
        return FileResponse(STATIC_DIR / "index.html")

    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
    return app


def run_dashboard(register_path: Path, host: str = "127.0.0.1", port: int = 8787,
                  open_browser: bool = True, *, allow_remote: bool = False,
                  token: str | None = None) -> None:
    if not is_loopback(host) and not allow_remote:
        raise SystemExit(
            f"refusing to bind {host!r}: the dashboard has no authentication by default and "
            f"exposes read/write access to the findings register. Use --allow-remote with "
            f"--token, or keep it on 127.0.0.1."
        )
    if not is_loopback(host) and not token:
        raise SystemExit("--allow-remote requires --token (or JANUS_DASHBOARD_TOKEN)")

    app = build_app(register_path, token=token, scans_dir=register_path.parent)
    if open_browser:
        threading.Timer(1.0, lambda: webbrowser.open(f"http://{host}:{port}/")).start()
    shown = f"http://{host}:{port}/"
    print(f"Janus dashboard: {shown}  (register: {register_path})  - Ctrl+C to stop")
    if token:
        print("  token required: send `Authorization: Bearer <token>` on /api/* requests")
    uvicorn.run(app, host=host, port=port, log_level="warning")
