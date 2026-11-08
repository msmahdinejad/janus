"""The `janus` command line. Deliberately argparse + stdlib only for the
CLI itself (fastapi/uvicorn/httpx are the only real dependencies, and only
httpx is needed outside the dashboard) — see ARCHITECTURE.md on why minimal,
boring dependencies were chosen for "anyone, anywhere" portability.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from pathlib import Path

from .core import baseline as baseline_mod
from .core import coverage as coverage_mod
from .core import providers as providers_mod
from .core import report as report_mod
from .core.scope import ScopeError, load_scope, write_manifest
from .core.store import Register
from .engines.code import scan as code_scan
from .engines.recon import scan as recon_scan
from .engines.recon.agent import AgentBudget
from .triage import TRIAGE_AGENTS, TriageBudget

# Default ensemble when --mode agent is used without --agent-providers:
# try all three, `providers.resolve()` silently drops any whose API key
# env var isn't set, so this is safe to leave as the default even if the
# operator only has one or two keys configured.
DEFAULT_AGENT_PROVIDERS = ["deepseek", "glm", "openai"]

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

SCOPE_TEMPLATE = """\
[engagement]
name          = "{name}"
authorized_by = "CHANGE_ME — operator/team label, e.g. security-team"
reference     = "CHANGE_ME — local engagement reference or self-attested label"
valid_from    = "{today}"
valid_until   = "{later}"
enabled       = true

[targets]
# Exact hosts or "*.example.com" wildcards (subdomains only, not the apex).
allow = ["example.com", "*.example.com"]
deny  = []
allow_ports = [80, 443]
forbidden_paths = ["^/admin/(delete|purge|drop)", "^/internal/"]

[limits]
# Passive checks (headers/cookies/CORS/sensitive-path probing, all GET-only)
# run regardless. Set these to true when you choose active testing for this
# engagement — see README.md "Responsible use".
allow_active_recon   = false
allow_agent          = false   # also needs a ready LLM provider — see `janus doctor` and
                                # README "Multi-model agent ensemble" (DeepSeek/GLM/OpenAI, run
                                # `janus scan recon --mode agent --agent-providers deepseek,glm,openai`)
require_nonprod_marker = false
nonprod_markers = ["staging", "stage", "test", "dev", "sandbox", "qa", "demo"]
max_rps      = 3
max_requests = 20000

[code]
roots   = ["../path/to/your/repo"]
exclude = ["**/migrations/**", "**/*.min.js"]
"""


def _today_and_later():
    from datetime import datetime, timedelta, timezone
    today = datetime.now(timezone.utc).date()
    return today.isoformat(), (today + timedelta(days=30)).isoformat()


def _ask(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    try:
        answer = input(f"{prompt}{suffix}: ").strip()
    except EOFError:
        answer = ""
    return answer or default


def _ask_yes_no(prompt: str, default_no: bool = True) -> bool:
    suffix = "[y/N]" if default_no else "[Y/n]"
    try:
        answer = input(f"{prompt} {suffix}: ").strip().lower()
    except EOFError:
        answer = ""
    if not answer:
        return not default_no
    return answer in ("y", "yes")


def _toml_list(items: list[str]) -> str:
    return "[" + ", ".join(json.dumps(i) for i in items) + "]"


def _render_scope_toml(
    name: str, authorized_by: str, reference: str, valid_days: int,
    allow_hosts: list[str], deny_hosts: list[str], code_roots: list[str],
    allow_active_recon: bool, allow_agent: bool,
) -> str:
    from datetime import datetime, timedelta, timezone
    today = datetime.now(timezone.utc).date()
    later = today + timedelta(days=valid_days)
    return f"""\
[engagement]
name          = {json.dumps(name)}
authorized_by = {json.dumps(authorized_by)}
reference     = {json.dumps(reference)}
valid_from    = "{today.isoformat()}"
valid_until   = "{later.isoformat()}"
enabled       = true

[targets]
allow = {_toml_list(allow_hosts)}
deny  = {_toml_list(deny_hosts)}
allow_ports = [80, 443]
forbidden_paths = ["^/admin/(delete|purge|drop)", "^/internal/"]

[limits]
# Passive checks (headers/cookies/CORS/sensitive-path probing, all GET-only) run regardless.
# See README.md "Responsible use" before changing either of the two below to true.
allow_active_recon   = {str(allow_active_recon).lower()}
allow_agent          = {str(allow_agent).lower()}   # also needs a ready LLM provider - `janus doctor`
require_nonprod_marker = false
nonprod_markers = ["staging", "stage", "test", "dev", "sandbox", "qa", "demo"]
max_rps      = 3
max_requests = 20000

[code]
roots   = {_toml_list(code_roots)}
exclude = ["**/migrations/**", "**/*.min.js", "**/node_modules/**"]
"""


def cmd_init(args: argparse.Namespace) -> int:
    target_dir = Path(args.dir)
    target_dir.mkdir(parents=True, exist_ok=True)
    scope_path = target_dir / "scope.toml"
    if scope_path.exists() and not args.force:
        print(f"refusing to overwrite existing {scope_path} (pass --force to replace it)", file=sys.stderr)
        return 2

    if args.interactive:
        print("Janus setup - a few questions, Enter accepts the default shown in [brackets].")
        print()
        name = _ask("Engagement name", args.name)
        authorized_by = _ask("Operator or team label", "")
        while not authorized_by:
            print("  this is required as descriptive audit metadata.")
            authorized_by = _ask("Operator or team label", "")
        reference = _ask("Engagement reference or self-attested label", "")
        while not reference:
            print("  this is required as descriptive audit metadata.")
            reference = _ask("Engagement reference or self-attested label", "")
        valid_days = int(_ask("Valid for how many days", "30") or "30")
        allow_raw = _ask("Target domain(s) for the recon engine, comma-separated "
                          "(e.g. example.com, *.example.com) - leave blank to skip recon entirely", "")
        allow_hosts = [h.strip() for h in allow_raw.split(",") if h.strip()]
        deny_hosts: list[str] = []
        if allow_hosts:
            deny_raw = _ask("Any hosts to explicitly EXCLUDE even if they'd match above (comma-separated)", "")
            deny_hosts = [h.strip() for h in deny_raw.split(",") if h.strip()]
        code_raw = _ask("Repo path(s) for the code engine, comma-separated (relative or absolute)", ".")
        code_roots = [c.strip() for c in code_raw.split(",") if c.strip()]
        print()
        print("Active recon (nuclei template scanning) and the AI-agent layer are both left OFF by")
        print("default - read README.md 'Responsible use' first. You can flip them on later by")
        print("editing scope.toml directly; this wizard will only set them if you explicitly say yes now.")
        allow_active_recon = False
        allow_agent = False
        if allow_hosts:
            allow_active_recon = _ask_yes_no("Enable active recon (nuclei) now", default_no=True)
            if allow_active_recon:
                allow_agent = _ask_yes_no("Also enable the AI-agent layer now", default_no=True)
        content = _render_scope_toml(
            name, authorized_by, reference, valid_days, allow_hosts or ["example.com"], deny_hosts,
            code_roots or ["."], allow_active_recon, allow_agent,
        )
    else:
        today, later = _today_and_later()
        content = SCOPE_TEMPLATE.format(name=args.name, today=today, later=later)

    scope_path.write_text(content, encoding="utf-8")
    (target_dir / "out").mkdir(exist_ok=True)
    print()
    print(f"wrote {scope_path}")
    if not args.interactive:
        print("edit it - especially [engagement] authorized_by/reference and [targets]/[code] - before scanning.")
        print("(or re-run with --interactive for a guided setup)")
    else:
        print()
        print("Next:")
        print(f"  janus doctor                                          # see what's installed/ready")
        print(f"  janus scan code   --scope {scope_path} --out {target_dir / 'out'}")
        if allow_hosts:
            print(f"  janus scan recon  --scope {scope_path} --out {target_dir / 'out'}   # passive by default")
        print(f"  janus dashboard   --register {target_dir / 'out' / 'register.json'}")
    return 0


def _tool_dirs(path: str) -> tuple[Path, ...]:
    """Local tool directory (default .tools/bin). Keeping scanner binaries
    beside the project means no PATH surgery and no admin rights."""
    p = Path(path)
    return (p,) if p.is_dir() else ()


def _print_tool_results(results) -> None:
    for r in results:
        print(f"  [{r.status:7s}] {r.name:12s} {r.detail}")


def cmd_scan_code(args: argparse.Namespace) -> int:
    try:
        scope = load_scope(args.scope)
    except ScopeError as e:
        print(f"scope error: {e}", file=sys.stderr)
        return 2

    run_id = f"{uuid.uuid4().hex[:12]}"
    out_dir = Path(args.out)
    write_manifest(scope, run_id, out_dir, {"command": "scan code", "diff": args.diff or "", "baseline": args.baseline or ""})

    baseline_fps = baseline_mod.load_baseline_fingerprints(args.baseline)
    result = code_scan.run(
        scope,
        use_gitleaks=not args.no_gitleaks, use_trivy=not args.no_trivy, use_semgrep=not args.no_semgrep,
        allow_network=not args.offline, cache_dir=Path(args.cache),
        diff_base=args.diff, baseline_fingerprints=baseline_fps,
        tool_dirs=_tool_dirs(args.tools_dir),
    )
    if args.diff and not result.diff_applicable:
        print(f"  [warning] --diff {args.diff!r} requested but no [code].roots entry is a git repo "
              f"(or git isn't available) — ran a full scan instead", file=sys.stderr)
    print(f"scanned {result.files_scanned} files, {len(result.findings)} findings after dedupe/aggregate")
    _print_tool_results(result.tool_results)
    if baseline_fps:
        suppressed = sum(1 for f in result.findings if f.status == "accepted-risk" and "baseline file" in f.notes)
        print(f"  baseline: {suppressed} finding(s) auto-set to accepted-risk from {args.baseline}")

    register = Register(out_dir / "register.json")
    with register.transaction() as reg:
        merge_stats = reg.merge(result.findings)
    print(f"register: +{merge_stats['new']} new, {merge_stats['updated']} updated, {merge_stats['unchanged']} unchanged")

    coverage_doc = coverage_mod.build(
        scope_name=scope.engagement.name, mode="code", findings=result.findings,
        tool_results=result.tool_results, code_files=result.files_scanned,
        engines=[{"id": "code", "status": "ran", "findings": len(result.findings),
                   "detail": f"{result.files_scanned} files scanned"}],
    )
    (out_dir / "coverage.json").write_text(json.dumps(coverage_doc, indent=2), encoding="utf-8")
    _record_scan(out_dir, run_id, scope, "scan code", result.findings, result.tool_results,
                 mode="code", coverage=coverage_doc)
    _write_reports(scope, register, out_dir, run_id)
    with (out_dir / "report.md").open("a", encoding="utf-8") as fh:
        fh.write("\n" + coverage_mod.to_markdown(coverage_doc))
    return _exit_code_for([f.to_dict() for f in result.findings], args.fail_on or "high")


def cmd_scan_recon(args: argparse.Namespace) -> int:
    try:
        scope = load_scope(args.scope)
    except ScopeError as e:
        print(f"scope error: {e}", file=sys.stderr)
        return 2

    lenses = _selected_lenses(args.lens)
    if lenses is None:
        return 2
    run_id = f"{uuid.uuid4().hex[:12]}"
    out_dir = Path(args.out)
    write_manifest(scope, run_id, out_dir, {
        "command": f"scan recon --mode {args.mode}", "lenses": [lens.id for lens in lenses],
    })

    agent_providers = []
    if args.mode == "agent":
        all_providers = providers_mod.load_providers(args.providers_file)
        requested = [p.strip() for p in args.agent_providers.split(",") if p.strip()]
        agent_providers, problems = providers_mod.resolve(requested, all_providers)
        for p in problems:
            print(f"  [provider skipped] {p}", file=sys.stderr)
        if agent_providers:
            print(f"agent ensemble: {', '.join(p.name for p in agent_providers)}")

    try:
        result = recon_scan.run(
            scope, mode=args.mode, nuclei_rate_limit=args.rate_limit,
            nuclei_templates_dir=Path(args.nuclei_templates) if args.nuclei_templates else None,
            skip_passive=getattr(args, "skip_passive", False),
            agent_backend=args.agent_backend,
            agent_budget=AgentBudget(max_turns=args.agent_max_turns,
                                     max_budget_usd=args.agent_max_budget),
            agent_providers=agent_providers,
            cache_dir=Path(args.cache),
            tool_dirs=_tool_dirs(args.tools_dir),
            lenses=lenses,
        )
    except ScopeError as e:
        print(f"refused: {e}", file=sys.stderr)
        return 2

    print(f"discovered {len(result.hosts_discovered)} hostnames, tested {len(result.hosts_tested)} "
          f"(after scope filtering + wildcard-IP sampling)")
    print(f"request budget: {result.budget_used}/{result.budget_max} used, "
          f"{result.denied} request(s) refused by scope")
    for reason in result.denied_reasons:
        print(f"  [denied] {reason}", file=sys.stderr)
    print(f"{len(result.findings)} findings after dedupe/aggregate")
    _print_tool_results(result.tool_results)

    register = Register(out_dir / "register.json")
    with register.transaction() as reg:
        merge_stats = reg.merge(result.findings)
    print(f"register: +{merge_stats['new']} new, {merge_stats['updated']} updated, {merge_stats['unchanged']} unchanged")

    (out_dir / f"{run_id}.probe_log.json").write_text(json.dumps(result.probe_log, indent=2), encoding="utf-8")
    coverage_doc = coverage_mod.build(
        scope_name=scope.engagement.name, mode=args.mode, findings=result.findings,
        tool_results=result.tool_results, lenses=lenses, recon={
            "hosts_discovered": len(result.hosts_discovered),
            "hosts_tested": len(result.hosts_tested),
            "budget_used": result.budget_used,
            "budget_max": result.budget_max,
            "denied": result.denied,
        },
        engines=[{"id": "recon", "status": "ran", "findings": len(result.findings),
                   "detail": f"{len(result.hosts_tested)} hosts tested"}],
    )
    (out_dir / "coverage.json").write_text(json.dumps(coverage_doc, indent=2), encoding="utf-8")
    _record_scan(out_dir, run_id, scope, f"scan recon --mode {args.mode}", result.findings,
                 result.tool_results, mode=args.mode, lenses=[l.id for l in lenses], coverage=coverage_doc)
    _write_reports(scope, register, out_dir, run_id)
    with (out_dir / "report.md").open("a", encoding="utf-8") as fh:
        fh.write("\n" + coverage_mod.to_markdown(coverage_doc))
    return _exit_code_for([f.to_dict() for f in result.findings], args.fail_on or "high")


def _resolve_providers(args) -> tuple[list, dict]:
    all_providers = providers_mod.load_providers(args.providers_file)
    requested = [p.strip() for p in args.agent_providers.split(",") if p.strip()]
    ready, problems = providers_mod.resolve(requested, all_providers)
    for p in problems:
        print(f"  [provider skipped] {p}", file=sys.stderr)
    if ready:
        print(f"agent ensemble: {', '.join(p.name for p in ready)}")
    return ready, all_providers


def _selected_lenses(raw: str):
    from .lenses import select

    try:
        return select(raw)
    except ValueError as exc:
        print(f"lens error: {exc}", file=sys.stderr)
        return None


def cmd_scan_all(args: argparse.Namespace) -> int:
    """One command, one register, one report: source engine + external engine
    (+ agent lenses), instead of the operator stitching five tools and
    several prompts together by hand."""
    try:
        scope = load_scope(args.scope)
    except ScopeError as e:
        print(f"scope error: {e}", file=sys.stderr)
        return 2

    lenses = _selected_lenses(args.lens)
    if lenses is None:
        return 2
    if args.mode == "agent" and lenses:
        print(f"lenses: {', '.join(lens.id for lens in lenses)}")

    run_id = f"{uuid.uuid4().hex[:12]}"
    out_dir = Path(args.out)
    write_manifest(scope, run_id, out_dir, {
        "command": "scan all", "mode": args.mode,
        "lenses": [lens.id for lens in lenses], "diff": args.diff or "",
    })

    all_findings: list = []
    tool_results: list = []
    code_files: int | None = None
    recon_summary: dict | None = None

    if scope.code_roots:
        code_result = code_scan.run(
            scope,
            use_gitleaks=not args.no_gitleaks, use_trivy=not args.no_trivy,
            use_semgrep=not args.no_semgrep, allow_network=not args.offline,
            cache_dir=Path(args.cache), diff_base=args.diff,
            baseline_fingerprints=baseline_mod.load_baseline_fingerprints(args.baseline),
            tool_dirs=_tool_dirs(args.tools_dir),
        )
        all_findings.extend(code_result.findings)
        tool_results.extend(code_result.tool_results)
        code_files = code_result.files_scanned
        print(f"code: {code_result.files_scanned} files, {len(code_result.findings)} findings")
    else:
        print("code: skipped (no [code].roots in scope)")

    if scope.allow:
        providers: list = []
        if args.mode == "agent":
            providers, _ = _resolve_providers(args)
        try:
            recon_result = recon_scan.run(
                scope, mode=args.mode, nuclei_rate_limit=args.rate_limit,
            nuclei_templates_dir=Path(args.nuclei_templates) if args.nuclei_templates else None,
            skip_passive=getattr(args, "skip_passive", False),
                agent_backend=args.agent_backend,
                agent_budget=AgentBudget(max_turns=args.agent_max_turns,
                                         max_budget_usd=args.agent_max_budget),
                agent_providers=providers, cache_dir=Path(args.cache),
                tool_dirs=_tool_dirs(args.tools_dir), lenses=lenses,
            )
        except ScopeError as e:
            print(f"recon refused: {e}", file=sys.stderr)
            return 2
        all_findings.extend(recon_result.findings)
        tool_results.extend(recon_result.tool_results)
        recon_summary = {
            "hosts_discovered": len(recon_result.hosts_discovered),
            "hosts_tested": len(recon_result.hosts_tested),
            "budget_used": recon_result.budget_used,
            "budget_max": recon_result.budget_max,
            "denied": recon_result.denied,
        }
        print(f"recon: {len(recon_result.hosts_tested)} hosts tested, "
              f"{len(recon_result.findings)} findings, budget "
              f"{recon_result.budget_used}/{recon_result.budget_max}")
        (out_dir / f"{run_id}.probe_log.json").write_text(
            json.dumps(recon_result.probe_log, indent=2), encoding="utf-8")
    else:
        print("recon: skipped (no [targets].allow in scope)")

    print(f"combined: {len(all_findings)} findings before merge")
    _print_tool_results(tool_results)

    register = Register(out_dir / "register.json")
    with register.transaction() as reg:
        merge_stats = reg.merge(all_findings)
    print(f"register: +{merge_stats['new']} new, {merge_stats['updated']} updated, "
          f"{merge_stats['unchanged']} unchanged")

    engines = [{
        "id": "code", "status": "ran" if scope.code_roots else "skipped",
        "findings": len(code_result.findings) if scope.code_roots else 0,
        "detail": f"{code_files} files scanned" if scope.code_roots else "no [code].roots configured",
    }, {
        "id": "recon", "status": "ran" if scope.allow else "skipped",
        "findings": len(recon_result.findings) if scope.allow else 0,
        "detail": f"{len(recon_result.hosts_tested)} hosts tested" if scope.allow else "no [targets].allow configured",
    }]
    coverage_doc = coverage_mod.build(
        scope_name=scope.engagement.name, mode=args.mode, findings=all_findings,
        tool_results=tool_results, lenses=lenses, code_files=code_files, recon=recon_summary,
        engines=engines,
    )
    (out_dir / "coverage.json").write_text(json.dumps(coverage_doc, indent=2), encoding="utf-8")
    _record_scan(out_dir, run_id, scope, "scan all", all_findings, tool_results,
                 mode=args.mode, lenses=[l.id for l in lenses], coverage=coverage_doc)
    _write_reports(scope, register, out_dir, run_id)
    with (out_dir / "report.md").open("a", encoding="utf-8") as fh:
        fh.write("\n" + coverage_mod.to_markdown(coverage_doc))
    print(f"wrote {out_dir / 'coverage.json'} and appended the coverage section to report.md")

    return _exit_code_for([f.to_dict() for f in all_findings], args.fail_on or "high")


def _record_scan(out_dir: Path, run_id: str, scope, command: str, findings, tool_results,
                 mode: str = "", lenses=None, coverage=None) -> None:
    """Write this run's immutable history entry (see dashboard/history.py)."""
    from .dashboard.history import record_scan

    try:
        record_scan(
            out_dir, run_id=run_id, command=command, scope_manifest=scope.manifest(run_id),
            findings=findings, tool_results=tool_results, mode=mode, lenses=lenses,
            coverage=coverage,
        )
    except Exception as exc:  # noqa: BLE001 - history must never fail a scan
        print(f"  [warning] could not record scan history: {exc}", file=sys.stderr)


def _write_reports(scope, register: Register, out_dir: Path, run_id: str) -> None:
    findings = register.all()
    manifest = scope.manifest(run_id)
    (out_dir / "findings.json").write_text(
        json.dumps(report_mod.to_json(manifest, findings), indent=2, ensure_ascii=False), encoding="utf-8")
    (out_dir / "findings.sarif").write_text(json.dumps(report_mod.to_sarif(findings), indent=2), encoding="utf-8")
    (out_dir / "report.md").write_text(report_mod.to_markdown(manifest, findings), encoding="utf-8")
    print(f"wrote {out_dir / 'findings.json'}, findings.sarif, report.md")


def _exit_code_for(findings: list[dict], fail_on: str) -> int:
    if fail_on == "none":
        return 0
    threshold = SEVERITY_ORDER.index(fail_on) if fail_on in SEVERITY_ORDER else SEVERITY_ORDER.index("high")
    for f in findings:
        if f.get("status") in ("fixed", "ruled-out", "accepted-risk"):
            continue
        sev = f.get("severity", "info")
        if sev in SEVERITY_ORDER and SEVERITY_ORDER.index(sev) <= threshold:
            return 1
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    register = Register(args.register)
    findings = register.all()
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest = {"engagement": "(rebuilt from register)", "authorization_reference": "", "authorized_by": ""}
    (out_dir / "findings.json").write_text(
        json.dumps(report_mod.to_json(manifest, findings), indent=2, ensure_ascii=False), encoding="utf-8")
    (out_dir / "findings.sarif").write_text(json.dumps(report_mod.to_sarif(findings), indent=2), encoding="utf-8")
    (out_dir / "report.md").write_text(report_mod.to_markdown(manifest, findings), encoding="utf-8")
    print(f"wrote reports to {out_dir}")
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    from .engines.common import find_tool
    tools = ["semgrep", "gitleaks", "trivy", "nuclei", "subfinder", "strix", "docker", "codex", "claude"]
    local = _tool_dirs(getattr(args, "tools_dir", ".tools/bin"))
    print("tool availability (missing ones are skipped gracefully, never fatal):")
    for t in tools:
        path = find_tool(t, local)
        print(f"  [{'FOUND  ' if path else 'MISSING'}] {t:10s} {path or ''}")

    if any(t == "trivy" for t in tools) and find_tool("trivy", local) \
            and not os.environ.get("TRIVY_DB_REPOSITORY"):
        print("  hint: trivy downloads a vulnerability DB from mirror.gcr.io by default. If that is")
        print("        blocked, set TRIVY_DB_REPOSITORY=ghcr.io/aquasecurity/trivy-db:2")

    print()
    print("LLM provider availability for --mode agent (checked via API-key env vars; a key's")
    print("VALUE is never read here or printed anywhere in janus, only whether it's set):")
    all_providers = providers_mod.load_providers(getattr(args, "providers_file", None))
    for name, profile in sorted(all_providers.items()):
        state = "READY  " if profile.available else "no key "
        print(f"  [{state}] {name:12s} needs ${profile.api_key_env:<20s} -> {profile.base_url}")
    print("  (edit janus/core/providers.py defaults, or pass --providers-file a-custom.toml,")
    print("   to change base_url/model/api_key_env per provider)")

    print()
    print("agent backends:")
    print("  [DEFAULT] native  in-process, scope-checked HTTP only (no shell, no raw sockets)")
    from .engines.common import find_tool as _ft
    strix = _ft("strix", local)
    proxy = os.environ.get("JANUS_AGENT_PROXY", "")
    print(f"  [{'READY  ' if strix and proxy else 'NOT SET'}] strix   "
          f"cli={'found' if strix else 'missing'}, egress_proxy={proxy or 'unset'}  "
          f"(needs both; run `janus proxy`)")

    if getattr(args, "check_models", False):
        print()
        print("live model check (GET /models per provider; no key material is printed):")
        for _name, profile in sorted(all_providers.items()):
            if not profile.available:
                continue
            ids, err = providers_mod.probe_models(profile)
            if ids is None:
                print(f"  {profile.name:12s} unavailable: {err}")
                continue
            reachable = "yes" if profile.model in ids else "NO - override model in providers.toml"
            sample = ", ".join(ids[:6]) + (" ..." if len(ids) > 6 else "")
            print(f"  {profile.name:12s} default={profile.model} reachable={reachable}")
            print(f"  {'':12s} {len(ids)} models, e.g. {sample}")
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    import shutil
    demo_dir = Path(__file__).resolve().parent.parent / "examples" / "demo-fixture"
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    seed = demo_dir / "seed_findings.json"
    register_path = out_dir / "register.json"
    if not register_path.exists() or args.force:
        shutil.copy(seed, register_path)
    print(f"demo register ready at {register_path} (synthetic data about a fake 'Example Corp' - "
          f"see examples/demo-fixture/README.md). Launching dashboard...")
    return cmd_dashboard(argparse.Namespace(register=str(register_path), host=args.host,
                                            port=args.port, no_open=False,
                                            allow_remote=False, token=None))


def cmd_triage(args: argparse.Namespace) -> int:
    agent = TRIAGE_AGENTS.get(args.agent)
    if agent is None:
        print(f"unknown --agent {args.agent!r}; available: {sorted(TRIAGE_AGENTS)}", file=sys.stderr)
        return 2
    repo_root = Path(args.repo).resolve()
    result = agent.run(repo_root, TriageBudget(timeout_seconds=args.timeout))
    if result.status == "skipped":
        print(f"skipped: {result.detail}")
        print(f"install the {args.agent!r} CLI, or run TRIAGE.md's protocol yourself in any agent session.")
        return 0
    if result.status == "failed":
        print(f"triage run failed: {result.detail}", file=sys.stderr)
        print("the exact CLI flags used here are research-backed, not verified against a live "
              "install (see ARCHITECTURE.md 'Honest gaps') - check `codex exec --help` / `claude --help` "
              "against your installed version if this looks like a flag mismatch.", file=sys.stderr)
        return 1
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(result.output_text, encoding="utf-8")
    print(f"wrote {out_path} ({result.detail})")
    return 0


def cmd_dashboard(args: argparse.Namespace) -> int:
    from .dashboard.server import run_dashboard
    run_dashboard(Path(args.register), host=args.host, port=args.port,
                  open_browser=not args.no_open, allow_remote=args.allow_remote,
                  token=args.token)
    return 0




def cmd_review_code(args: argparse.Namespace) -> int:
    """Hand a structured review protocol to a coding agent and import findings."""
    from .core import coverage as coverage_mod
    from .lenses import select as select_lenses
    from .review import run as review_run, tool_result

    repo = Path(args.repo)
    if not repo.is_dir():
        print(f"not a directory: {repo}", file=sys.stderr)
        return 2
    try:
        lenses = select_lenses(args.lens)
    except ValueError as exc:
        print(f"lens error: {exc}", file=sys.stderr)
        return 2

    run_id = f"{uuid.uuid4().hex[:12]}"
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{run_id}.review-manifest.json").write_text(
        json.dumps({"run_id": run_id, "command": "review code", "repo": str(repo),
                    "agent": args.agent, "lenses": [l.id for l in lenses]}, indent=2),
        encoding="utf-8")

    print(f"reviewing {repo} with {args.agent} (lenses: {', '.join(l.id for l in lenses)})")
    result = review_run(repo.resolve(), agent=args.agent, lenses=lenses,
                        timeout=args.timeout, extra=args.instruction or "")
    findings = result.findings
    if result.raw:
        (out_dir / f"{run_id}.review-response.txt").write_text(result.raw, encoding="utf-8")
    print(f"{len(findings)} findings — {result.detail}")
    if not findings and result.raw and "[" not in result.raw:
        print("  (the agent replied without a JSON array; raw response saved next to the run)",
              file=sys.stderr)

    register = Register(out_dir / "register.json")
    with register.transaction() as reg:
        stats = reg.merge(findings)
    print(f"register: +{stats['new']} new, {stats['updated']} updated")

    cov = coverage_mod.build(scope_name=f"review:{repo.name}", mode="review",
                             findings=findings, tool_results=[tool_result(result)],
                             lenses=lenses)
    (out_dir / "coverage.json").write_text(json.dumps(cov, indent=2), encoding="utf-8")
    _record_scan(out_dir, run_id, _ReviewScope(repo), "review code", findings,
                 [tool_result(result)], mode="review",
                 lenses=[l.id for l in lenses], coverage=cov)
    _write_reports_for(out_dir, run_id, cov)
    if result.status != "ok":
        return 2
    return _exit_code_for([f.to_dict() for f in findings], args.fail_on or "high")


class _ReviewScope:
    """Minimal manifest provider so history/report writers work for reviews."""

    def __init__(self, repo: Path) -> None:
        self.repo = repo

    def manifest(self, run_id: str) -> dict:
        return {"engagement": f"review:{self.repo.name}", "authorized_by": "operator",
                "authorization_reference": f"review-{run_id}", "valid_from": "", "valid_until": "",
                "run_id": run_id}


def _write_reports_for(out_dir: Path, run_id: str, coverage_doc: dict) -> None:
    from .core import report as report_mod
    from .core.store import Register

    register = Register(out_dir / "register.json")
    findings = register.all()
    manifest = {"engagement": out_dir.name, "authorization_reference": f"review-{run_id}"}
    (out_dir / "findings.json").write_text(
        json.dumps(report_mod.to_json(manifest, findings), indent=2, ensure_ascii=False),
        encoding="utf-8")
    (out_dir / "findings.sarif").write_text(
        json.dumps(report_mod.to_sarif(findings), indent=2), encoding="utf-8")
    (out_dir / "report.md").write_text(report_mod.to_markdown(manifest, findings), encoding="utf-8")
    print(f"wrote {out_dir / 'report.md'}")

def cmd_discover(args: argparse.Namespace) -> int:
    """Derive candidate targets from a repository's own configuration."""
    from .discovery import discover, scope_toml

    root = Path(args.repo)
    if not root.is_dir():
        print(f"not a directory: {root}", file=sys.stderr)
        return 2
    owned = [s.strip() for s in args.owned.split(",") if s.strip()]
    if not owned:
        print("--owned is required (the domains you actually own, e.g. example.com,example.org)",
              file=sys.stderr)
        return 2

    result = discover(root, owned)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "discovery.json").write_text(
        json.dumps(result.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"scanned {result.files_scanned} text files under {root}")
    print(f"  owned, non-production : {len(result.nonprod)}")
    for h in result.nonprod[:20]:
        print(f"      {h}")
    print(f"  owned, production     : {len(result.prod)} (written to deny)")
    print(f"  owned, internal tools : {len(result.infra)} (excluded)")
    print(f"  third-party           : {len(result.third_party)} (ignored)")

    if args.write_scope:
        target = Path(args.write_scope)
        target.write_text(scope_toml(result, engagement=args.name, reference=args.reference),
                          encoding="utf-8")
        print(f"wrote {target} — review it, then run `janus scan recon --mode passive`")
    print("reminder: discovery is evidence, not authorization. Confirm the hosts.")
    return 0

def cmd_llm_shim(args: argparse.Namespace) -> int:
    from .llm_shim import key_from_env, serve

    upstream = args.upstream or os.environ.get("LLM_API_BASE", "")
    if not upstream:
        print("no upstream: pass --upstream or set LLM_API_BASE", file=sys.stderr)
        return 2
    key = key_from_env(args.api_key_env)
    if not key:
        print(f"warning: ${args.api_key_env} is empty; upstream calls will be unauthenticated",
              file=sys.stderr)
    serve(upstream, key, host=args.host, port=args.port)
    return 0


def cmd_proxy(args: argparse.Namespace) -> int:
    from .core.scope import load_scope
    from .proxy import serve

    if args.host not in ("127.0.0.1", "localhost", "::1") and not args.allow_remote:
        print("refusing to bind the proxy on a non-loopback address (use --allow-remote if you "
              "really need it; the scope file is still enforced per request)", file=sys.stderr)
        return 2
    try:
        scope = load_scope(args.scope)
    except ScopeError as e:
        print(f"scope error: {e}", file=sys.stderr)
        return 2
    rewrite: dict[str, str] = {}
    for pair in (args.rewrite or "").split(","):
        if "=" in pair:
            src, dst = pair.split("=", 1)
            rewrite[src.strip().lower()] = dst.strip()
    serve(scope, host=args.host, port=args.port, audit_path=Path(args.audit), rewrite=rewrite)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="janus", description="Two-faced, authorization-gated security pipeline.")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("init", help="scaffold a new engagement (scope.toml + out/)")
    s.add_argument("--dir", default=".", help="directory to scaffold into")
    s.add_argument("--name", default="my-engagement")
    s.add_argument("--force", action="store_true")
    s.add_argument("--interactive", "-i", action="store_true",
                    help="ask a few questions and generate a ready-to-use scope.toml "
                         "(fastest path to a working setup; see README.md Quickstart)")
    s.set_defaults(func=cmd_init)

    scan = sub.add_parser("scan", help="run an engine")
    scan_sub = scan.add_subparsers(dest="engine", required=True)

    sc = scan_sub.add_parser("code", help="source-code engine: SAST + secrets + SCA")
    sc.add_argument("--scope", required=True)
    sc.add_argument("--out", default="out")
    sc.add_argument("--cache", default=".cache/janus")
    sc.add_argument("--no-semgrep", action="store_true")
    sc.add_argument("--no-trivy", action="store_true")
    sc.add_argument("--no-gitleaks", action="store_true")
    sc.add_argument("--offline", action="store_true", help="skip CVE DB downloads (secrets/misconfig only)")
    sc.add_argument("--fail-on", choices=[*SEVERITY_ORDER, "none"], default="high")
    sc.add_argument("--diff", default=None, metavar="BASE_REF",
                     help="only scan files changed vs. this git ref (e.g. origin/main); falls back to "
                          "a full scan with a warning if a [code].roots entry isn't a git repo")
    sc.add_argument("--baseline", default=None, metavar="FILE",
                     help="JSON file of fingerprints ({\"suppressed\": [...]}) to auto-mark accepted-risk "
                          "so CI stays green on known/accepted findings without re-triaging every run")
    sc.add_argument("--tools-dir", default=".tools/bin",
                    help="directory with locally installed scanner binaries (default: .tools/bin)")
    sc.set_defaults(func=cmd_scan_code)

    sr = scan_sub.add_parser("recon", help="external engine: passive recon, optional active/agent")
    sr.add_argument("--scope", required=True)
    sr.add_argument("--out", default="out")
    sr.add_argument("--cache", default=".cache/janus")
    sr.add_argument("--mode", choices=["passive", "active", "agent"], default="passive")
    sr.add_argument("--rate-limit", type=int, default=10, help="nuclei requests/sec (active mode only)")
    sr.add_argument("--agent-backend", default="native",
                     choices=["native", "strix"],
                     help="native = in-process agent limited to the scope-checked HTTP client "
                          "(no shell, no raw network); strix = external agent, requires an egress "
                          "proxy (see `janus proxy`)")
    sr.add_argument("--agent-providers", default=",".join(DEFAULT_AGENT_PROVIDERS),
                     help="comma-separated provider names to ensemble over in --mode agent "
                          "(default: deepseek,glm,openai - any without an API key set are skipped "
                          "automatically; see `janus doctor` and README 'Multi-model agent ensemble')")
    sr.add_argument("--providers-file", default=None,
                     help="providers.toml overriding/extending the built-in provider defaults")
    sr.add_argument("--agent-max-turns", type=int, default=25)
    sr.add_argument("--lens", default="all",
                    help="comma-separated review lenses for agent mode (authz,authn,injection,secrets,"
                         "business,files,client,infra) or 'all'")
    sr.add_argument("--skip-passive", action="store_true",
                    help="agent-only run: do not send the passive checks")
    sr.add_argument("--nuclei-templates", default=None,
                    help="template directory or single template (default: nuclei own set)")
    sr.add_argument("--agent-max-budget", type=float, default=2.0)
    sr.add_argument("--fail-on", choices=[*SEVERITY_ORDER, "none"], default="high")
    sr.add_argument("--tools-dir", default=".tools/bin",
                    help="directory with locally installed scanner binaries (default: .tools/bin)")
    sr.set_defaults(func=cmd_scan_recon)

    sa = scan_sub.add_parser(
        "all", help="one run: code engine + external engine (+ agent lenses), one register and report")
    sa.add_argument("--scope", required=True)
    sa.add_argument("--out", default="out")
    sa.add_argument("--cache", default=".cache/janus")
    sa.add_argument("--mode", choices=["passive", "active", "agent"], default="passive")
    sa.add_argument("--lens", default="all")
    sa.add_argument("--rate-limit", type=int, default=10)
    sa.add_argument("--agent-backend", default="native", choices=["native", "strix"])
    sa.add_argument("--agent-providers", default=",".join(DEFAULT_AGENT_PROVIDERS))
    sa.add_argument("--providers-file", default=None)
    sa.add_argument("--agent-max-turns", type=int, default=25)
    sa.add_argument("--skip-passive", action="store_true")
    sa.add_argument("--nuclei-templates", default=None)
    sa.add_argument("--agent-max-budget", type=float, default=2.0)
    sa.add_argument("--no-semgrep", action="store_true")
    sa.add_argument("--no-trivy", action="store_true")
    sa.add_argument("--no-gitleaks", action="store_true")
    sa.add_argument("--offline", action="store_true")
    sa.add_argument("--diff", default=None, metavar="BASE_REF")
    sa.add_argument("--baseline", default=None, metavar="FILE")
    sa.add_argument("--tools-dir", default=".tools/bin")
    sa.add_argument("--fail-on", choices=[*SEVERITY_ORDER, "none"], default="high")
    sa.set_defaults(func=cmd_scan_all)

    rp = sub.add_parser("report", help="rebuild md/json/sarif reports from a register.json")
    rp.add_argument("--register", required=True)
    rp.add_argument("--out", default="out")
    rp.set_defaults(func=cmd_report)

    dd = sub.add_parser("doctor", help="show which optional external tools and LLM providers are available")
    dd.add_argument("--providers-file", default=None, help="providers.toml overriding the built-in defaults")
    dd.add_argument("--tools-dir", default=".tools/bin")
    dd.add_argument("--check-models", action="store_true",
                    help="call each configured provider's /models endpoint to verify the model id")
    dd.set_defaults(func=cmd_doctor)

    db = sub.add_parser("dashboard", help="launch the local findings dashboard")
    db.add_argument("--register", default="out/register.json")
    db.add_argument("--host", default="127.0.0.1")
    db.add_argument("--port", type=int, default=8787)
    db.add_argument("--no-open", action="store_true", help="do not launch a browser")
    db.add_argument("--allow-remote", action="store_true",
                    help="allow binding a non-loopback address (requires --token)")
    db.add_argument("--token", default=None,
                    help="bearer token required on /api/* (or set JANUS_DASHBOARD_TOKEN)")
    db.set_defaults(func=cmd_dashboard)

    rv = sub.add_parser("review", help="agent-driven read-only source review")
    rv_sub = rv.add_subparsers(dest="target", required=True)
    rvc = rv_sub.add_parser("code", help="review a repository with a coding agent")
    rvc.add_argument("--repo", required=True)
    rvc.add_argument("--agent", choices=["codex", "claude"], default="codex")
    rvc.add_argument("--lens", default="authz,business,injection")
    rvc.add_argument("--instruction", default=None)
    rvc.add_argument("--out", default="out/review")
    rvc.add_argument("--timeout", type=int, default=1800)
    rvc.add_argument("--fail-on", choices=[*SEVERITY_ORDER, "none"], default="high")
    rvc.set_defaults(func=cmd_review_code)

    dv = sub.add_parser("discover", help="derive candidate targets from a repo's config/URLs")
    dv.add_argument("--repo", required=True)
    dv.add_argument("--owned", required=True,
                    help="comma-separated domains you own (e.g. example.com,example.org)")
    dv.add_argument("--out", default="out/discovery")
    dv.add_argument("--write-scope", default=None, help="path to write a draft scope.toml")
    dv.add_argument("--name", default="discovered")
    dv.add_argument("--reference", default="REVIEW-ME")
    dv.set_defaults(func=cmd_discover)

    sh = sub.add_parser("llm-shim", help="localhost OpenAI-compatible shim for gateways httpx cannot reach")
    sh.add_argument("--upstream", default=None, help="real base URL (default: $LLM_API_BASE)")
    sh.add_argument("--api-key-env", default="LLM_API_KEY")
    sh.add_argument("--host", default="127.0.0.1")
    sh.add_argument("--port", type=int, default=18081)
    sh.set_defaults(func=cmd_llm_shim)

    px = sub.add_parser("proxy", help="allowlist egress proxy for external agents (GET/HEAD/OPTIONS)")
    px.add_argument("--scope", required=True)
    px.add_argument("--host", default="127.0.0.1")
    px.add_argument("--port", type=int, default=8899)
    px.add_argument("--audit", default="proxy-audit.ndjson")
    px.add_argument("--allow-remote", action="store_true")
    px.add_argument("--rewrite", default="",
                    help="comma-separated host=address pairs for the outbound socket, e.g. "
                         "host.docker.internal=127.0.0.1 (authorization still uses the original host)")
    px.set_defaults(func=cmd_proxy)

    dm = sub.add_parser("demo", help="load synthetic example findings and open the dashboard - no setup needed")
    dm.add_argument("--out", default="examples/demo-fixture/out")
    dm.add_argument("--host", default="127.0.0.1")
    dm.add_argument("--port", type=int, default=8787)
    dm.add_argument("--force", action="store_true")
    dm.set_defaults(func=cmd_demo)

    tr = sub.add_parser("triage", help="hand TRIAGE.md's protocol to a coding-agent CLI (codex/claude)")
    tr.add_argument("--agent", choices=sorted(TRIAGE_AGENTS), default="codex")
    tr.add_argument("--repo", default=".", help="repo root to triage in (must contain TRIAGE.md and out/findings.json)")
    tr.add_argument("--out", default="out/triage-report.md")
    tr.add_argument("--timeout", type=int, default=1800)
    tr.set_defaults(func=cmd_triage)

    return p


def main(argv: list[str] | None = None) -> int:
    # A Windows console defaults to cp1252; any tool output containing a
    # non-Latin glyph would crash the report printer mid-scan. Reports are
    # written as UTF-8 files regardless, so only the console needs this.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            pass
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)

