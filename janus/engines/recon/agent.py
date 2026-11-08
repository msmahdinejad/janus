"""The optional external-agent testing layer.

Gating (enforced by the caller — `engines/recon/scan.py` — before this module
is reached, and re-checked here where it is cheap):

  1. `scope.allow_active_recon` AND `scope.allow_agent` must both be true.
  2. The target list is the same pre-validated, scope-checked list used for
     nuclei — never raw user input.
  3. Egress: an external agent runs in its own process (and, for Strix, its
     own Docker container). It cannot be *made* to respect `scope.toml` by a
     prompt. This adapter therefore refuses to run unless an egress proxy is
     configured, and passes that proxy into the child environment. Use
     `janus proxy --scope ...` for the bundled allowlist proxy.
  4. Exit codes are inspected and artifacts are only accepted if this run
     produced them. A crashed agent is `failed`, not "0 findings".

`NativeAgent` (see native_agent.py) is the default backend precisely because
it needs none of this: it has no network stack of its own, only `ScopeClient`.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit
from typing import Any, Protocol

from ...core.http import ScopeClient
from ...core.model import Finding, dedupe
from ...core.providers import ProviderProfile
from ...core.scope import Scope
from ..common import ToolResult, find_tool, map_severity
from .native_agent import NativeAgent

BASE_POLICY = (
    "READ-ONLY authorized security assessment. Use only GET/HEAD/OPTIONS requests. "
    "Do not create, modify, or delete data. Do not register accounts, brute-force "
    "credentials, or send POST/PUT/PATCH/DELETE. Do not use any credential or secret "
    "you discover in a real request — report its existence and location only. Focus on "
    "BOLA/IDOR, auth weaknesses, information disclosure, misconfiguration, GET-reachable "
    "injection, and exposed internal endpoints. Prove each finding with the minimal "
    "reproducible, non-destructive request."
)


@dataclass
class AgentBudget:
    max_turns: int = 25
    max_budget_usd: float = 2.0
    scan_mode: str = "quick"  # quick | standard | deep (backend-specific meaning)
    timeout_seconds: int = 2700


class AgentAdapter(Protocol):
    name: str

    def run(self, targets: list[str], out_dir: Path, budget: AgentBudget,
            provider: ProviderProfile, extra_instruction: str = "", *,
            scope: Scope | None = None, http: ScopeClient | None = None) -> ToolResult: ...


class StrixAdapter:
    """Reference integration for github.com/usestrix/strix (external process).

    Refuses to run without `egress_proxy`. That is not a formality: Strix can
    resolve new hosts and run tools inside its container, so the proxy is the
    only part of this design that actually constrains where it goes.
    """

    name = "strix"

    def run(self, targets: list[str], out_dir: Path, budget: AgentBudget,
            provider: ProviderProfile, extra_instruction: str = "", *,
            scope: Scope | None = None, http: ScopeClient | None = None,
            egress_proxy: str | None = None) -> ToolResult:
        label = f"agent:strix:{provider.name}"
        exe = find_tool("strix")
        if not exe:
            return ToolResult(label, "skipped", detail="strix CLI not found on PATH")
        if not targets:
            return ToolResult(label, "ok", detail="no targets")
        proxy = egress_proxy or os.environ.get("JANUS_AGENT_PROXY", "")
        if not proxy:
            return ToolResult(
                label, "failed",
                detail="refused: external agent without an egress proxy. Start `janus proxy "
                       "--scope <file> --port 8899`, set JANUS_AGENT_PROXY=http://127.0.0.1:8899, "
                       "or use --agent-backend native. A prompt is not a network control.",
            )
        if not os.environ.get(provider.api_key_env, ""):
            return ToolResult(label, "skipped", detail=f"{provider.api_key_env} not set")

        out_dir.mkdir(parents=True, exist_ok=True)
        instruction = BASE_POLICY if not extra_instruction else f"{BASE_POLICY}\n\n{extra_instruction}"
        args = [exe, "-n", "--scan-mode", budget.scan_mode,
                "--max-turns", str(budget.max_turns), "--max-budget", str(budget.max_budget_usd),
                "--instruction", instruction]
        for t in targets:
            args += ["--target", t]

        run_env = {
            **os.environ,
            "STRIX_LLM": f"openai/{provider.model}",
            "LLM_API_BASE": provider.base_url,
            "LLM_API_KEY": os.environ[provider.api_key_env],
            # Strix's preflight defaults to 30s; a gateway that is merely slow
            # then looks like a dead endpoint.
            "LLM_PREFLIGHT_TIMEOUT": "120",
            "LLM_TIMEOUT": "300",
            "HTTP_PROXY": proxy,
            "HTTPS_PROXY": proxy,
            "http_proxy": proxy,
            "https_proxy": proxy,
            # The LLM endpoint is infrastructure, not a scan target: it must
            # not be routed through the scope proxy (which allows GET only and
            # would answer the model call with 405).
            "NO_PROXY": ",".join(filter(None, ["127.0.0.1", "localhost",
                                               urlsplit(provider.base_url).hostname or ""])),
            # litellm otherwise fetches its model price map from
            # raw.githubusercontent.com at startup; on a filtered network that
            # is a 3x timeout before the run even begins.
            "LITELLM_LOCAL_MODEL_COST_MAP": "True",
        }
        started = time.time()

        def _fresh(pattern: str) -> list[Path]:
            return sorted(
                (p for p in out_dir.rglob(pattern) if p.stat().st_mtime >= started - 60),
                key=lambda p: p.stat().st_mtime, reverse=True,
            )

        def _no_traffic_report() -> Path | None:
            reports = _fresh("penetration_test_report.md")
            if not reports:
                return None
            report = reports[0]
            report_text = report.read_text(encoding="utf-8", errors="replace").lower().replace("**", "")
            no_traffic_markers = (
                "no http requests were sent",
                "no http exchanges with the target",
                "no request was issued",
                "before a single request was issued",
                "before the first request was issued to the target",
                "no security assessment results are available",
                "assessment status: incomplete",
                "actual execution: none beyond scope definition",
                "no traffic was generated",
            )
            return report if any(marker in report_text for marker in no_traffic_markers) else None

        try:
            proc = subprocess.run(args, capture_output=True, text=True,
                                  encoding="utf-8", errors="replace",
                                  timeout=budget.timeout_seconds, cwd=str(out_dir), env=run_env)
        except subprocess.TimeoutExpired:
            return ToolResult(label, "failed", detail="timed out")
        except Exception as e:  # noqa: BLE001
            return ToolResult(label, "failed", detail=str(e))

        # Strix: 0 = completed with no findings, 2 = completed with findings
        # present (its documented signal), anything else = failure.
        if proc.returncode not in (0, 2):
            # Keep the whole log next to the run and surface its tail: the
            # useful line in a tool failure is almost always at the end.
            try:
                (out_dir / "stderr.log").write_text(proc.stderr or "", encoding="utf-8", errors="replace")
            except OSError:
                pass
            # A budget cap (MaxTurnsExceeded) is a stop condition, not a crash:
            # if the run still wrote its SARIF, that evidence is valid and is
            # imported as a partial result instead of being discarded.
            fresh = _fresh("findings.sarif")
            if fresh:
                report = _no_traffic_report()
                if report:
                    return ToolResult(
                        label,
                        "failed",
                        detail=(
                            "agent report says no requests reached the target; 0 findings is not a "
                            f"clean result (report: {report})"
                        ),
                    )
                try:
                    partial = _parse_strix_sarif(fresh[0], label, provider)
                except Exception:  # noqa: BLE001
                    partial = []
                if not partial:
                    return ToolResult(
                        label,
                        "failed",
                        detail=(
                            "partial agent artifact contains no findings and no report proves that "
                            "the target was tested; 0 findings is not a clean result"
                        ),
                    )
                tail = (proc.stderr or proc.stdout or "").strip().replace("\n", " ")
                why = "turn budget reached" if "MaxTurnsExceeded" in (proc.stderr or "") else f"exit {proc.returncode}"
                return ToolResult(label, "partial", findings=partial,
                                  detail=f"partial ({why}): {len(partial)} findings; "
                                         f"report: {fresh[0].parent / 'penetration_test_report.md'}")
            tail = (proc.stderr or proc.stdout or "").strip().replace("\n", " ")
            return ToolResult(label, "failed",
                              detail=f"exit {proc.returncode} (stderr.log saved): {tail[-700:]}")

        # Strix's artifact layout is its own to change, and it did: 1.7 writes
        # `findings.sarif` under `strix_runs/<target>_<id>/`, not the older
        # `vulnerabilities.json`. Accept both, newest first, and only artifacts
        # this run produced.
        sarif_files = _fresh("findings.sarif")
        legacy = _fresh("vulnerabilities.json")
        report = _no_traffic_report()
        if report:
            return ToolResult(
                label,
                "failed",
                detail=(
                    "agent report says no requests reached the target; 0 findings is not a "
                    f"clean result (report: {report})"
                ),
            )
        if sarif_files:
            try:
                findings = _parse_strix_sarif(sarif_files[0], label, provider)
            except Exception as e:  # noqa: BLE001
                return ToolResult(label, "failed", detail=f"could not parse {sarif_files[0]}: {e}")
            run_dir = sarif_files[0].parent
            report = run_dir / "penetration_test_report.md"
            extra = f"; report: {report}" if report.exists() else ""
            return ToolResult(label, "ok", findings=findings,
                              detail=f"{len(findings)} findings (model: {provider.model}){extra}")
        if legacy:
            try:
                rows = json.loads(legacy[0].read_text(encoding="utf-8"))
            except Exception as e:  # noqa: BLE001
                return ToolResult(label, "failed", detail=f"could not parse {legacy[0]}: {e}")
            findings = []
            for r in rows if isinstance(rows, list) else rows.get("vulnerabilities", []):
                findings.append(Finding(
                    title=r.get("title", r.get("name", "agent finding")),
                    severity=map_severity(r.get("severity"), "medium"),
                    category="other", engine="recon", tool=label, rule_id=r.get("id", ""),
                    target=r.get("url", r.get("target", "")), host=r.get("host", ""),
                    endpoint=r.get("endpoint", r.get("url", "")), method=r.get("method", "GET"),
                    message=r.get("impact", r.get("description", "")),
                    remediation=r.get("remediation", "See the agent's full markdown report for details."),
                    confidence="needs-review",
                    extra={"poc": r.get("poc", r.get("proof_of_concept", "")), "model": provider.model},
                    sources=(label,),
                ))
            return ToolResult(label, "ok", findings=findings,
                              detail=f"{len(findings)} findings (model: {provider.model})")

        return ToolResult(label, "failed",
                          detail=f"exit {proc.returncode}, no fresh SARIF/vulnerabilities.json; result unavailable")


def _parse_strix_sarif(path, label: str, provider) -> list[Finding]:
    """Map Strix's SARIF 2.1.0 output onto the shared Finding model."""
    doc = json.loads(path.read_text(encoding="utf-8"))
    runs = doc.get("runs") or []
    if not runs:
        return []
    run = runs[0]
    rules = {r.get("id"): r for r in (run.get("tool", {}).get("driver", {}).get("rules") or [])
             if isinstance(r, dict)}
    findings: list[Finding] = []
    for res in run.get("results") or []:
        if not isinstance(res, dict):
            continue
        rule_id = str(res.get("ruleId") or "")
        rule = rules.get(rule_id, {})
        message = (res.get("message") or {}).get("text") or rule.get("shortDescription", {}).get("text", "")
        # Strix emits one SARIF result per area. A "needs review" note is a
        # real observation (the agent saw something it could not prove) and
        # is imported as low/needs-review; "no issue"/"ruled out" is the
        # absence of a finding and must never become one.
        coverage_note = rule_id.startswith("strix-coverage/")
        lowered = message.lower()
        if coverage_note and not ("requires further review" in lowered or "needs review" in lowered):
            continue
        # Strix emits one SARIF result per coverage area, tagged with its own
        # triage verdict. "No issue identified" and "Ruled out" are the
        # absence of a finding, not findings; importing them would turn a
        # clean area into a false positive in every downstream report.
        if "ruled out" in message.lower() or "no issue identified" in message.lower() \
                or "not applicable" in message.lower():
            continue
        message = message.replace("Requires further review:", "Needs review:").strip()
        title = (rule.get("name") or message or rule_id or "agent finding")[:160]
        level = str(res.get("level") or "").lower()
        props = res.get("properties") or {}
        metadata = props.get("strix") if isinstance(props.get("strix"), dict) else {}
        severity = map_severity(props.get("severity") or metadata.get("severity") or {
            "error": "high", "warning": "medium", "note": "low",
        }.get(level, "medium"))
        loc = ((res.get("locations") or [{}])[0] or {}).get("physicalLocation", {})
        url = (loc.get("artifactLocation") or {}).get("uri", "")
        # Strix can use SECURITY.md as a synthetic SARIF location for a web
        # issue. Its target/endpoint metadata carries the actual affected URL.
        url = str(metadata.get("target") or url)
        remediation = metadata.get("remediation_steps")
        if isinstance(remediation, list):
            remediation = "\n".join(str(step) for step in remediation)
        line = (loc.get("region") or {}).get("startLine", 0) or 0
        if coverage_note:
            severity, confidence = "low", "needs-review"
        findings.append(Finding(
            title=title, severity=severity, category="other", engine="recon",
            tool=label, rule_id=rule_id or "strix",
            target=url, host=url.split("/")[2] if "//" in url else "",
            endpoint=str(metadata.get("endpoint") or url), method=str(metadata.get("method") or "GET"),
            message=message,
            remediation=str(remediation or "See the Strix report next to this run for reproduction steps and fixes."),
            confidence="needs-review",
            extra={"model": provider.model, "sarif_level": level,
                   "evidence": str(props.get("evidence") or metadata.get("technical_analysis") or "")[:2000]},
            sources=(label,),
        ))
    return findings


AGENT_BACKENDS: dict[str, Any] = {
    "native": NativeAgent(),
    "strix": StrixAdapter(),
}


def run_ensemble(
    backend: AgentAdapter, targets: list[str], out_dir: Path, budget: AgentBudget,
    providers: list[ProviderProfile], extra_instruction: str = "",
    *, scope: Scope | None = None, http: ScopeClient | None = None,
) -> tuple[list[Finding], list[ToolResult]]:
    """Run the backend once per provider, sequentially, and merge.

    Sequential on purpose: two LLM agents hammering the same target at once is
    load this project does not default to. Each provider gets its own output
    directory so artifacts cannot overwrite each other.
    """
    all_findings: list[Finding] = []
    results: list[ToolResult] = []
    for provider in providers:
        provider_dir = out_dir / provider.name
        result = backend.run(targets, provider_dir, budget, provider, extra_instruction,
                             scope=scope, http=http)
        results.append(result)
        all_findings.extend(result.findings)
    return dedupe(all_findings), results
