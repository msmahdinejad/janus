"""Orchestration for `janus scan recon`.

This is the one place that decides whether active probing (nuclei) or the
agent layer may run at all: it calls `scope.require_active_recon()` /
`scope.require_agent()` before constructing any target list for them.

Everything that touches a target goes through one `ScopeClient`, which is
also the object passed to the agent. That is the structural fix for the
"agent mode has no egress control" finding: the agent's only way to make a
request is the same budgeted, authorized client the passive checks use.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from ...core.http import RequestBudget, ScopeClient
from ...core.model import Finding, aggregate_repetitive, dedupe
from ...core.providers import ProviderProfile
from ...core.scope import Scope, ScopeError
from ..common import RateLimiter, ToolResult
from . import adapters, passive, write_checks
from .agent import AGENT_BACKENDS, AgentBudget, run_ensemble


@dataclass
class ReconScanResult:
    findings: list[Finding]
    tool_results: list[ToolResult]
    hosts_discovered: list[str]
    hosts_tested: list[str]
    probe_log: list[dict]
    budget_used: int = 0
    budget_max: int = 0
    denied: int = 0
    denied_reasons: list[str] = field(default_factory=list)


def _primary_domains(scope: Scope) -> list[str]:
    """Bare domains for CT-log discovery, derived from the allow list.

    IP addresses are skipped: `crt.sh` has nothing for them and an SPF/DMARC
    lookup against `127.0.0.1` is meaningless.
    """
    domains = {pat[2:] if pat.startswith("*.") else pat for pat in scope.allow}
    out = []
    for d in sorted(domains):
        if not d or "*" in d:
            continue
        try:
            ipaddress.ip_address(d)
            continue
        except ValueError:
            out.append(d)
    return out


def run(
    scope: Scope,
    mode: str = "passive",  # "passive" | "active" | "agent"
    max_hosts_per_ip: int = 3,
    nuclei_rate_limit: int = 10,
    nuclei_templates_dir: Path | None = None,
    agent_backend: str = "native",
    agent_budget: AgentBudget | None = None,
    agent_providers: list[ProviderProfile] | None = None,
    cache_dir: Path | None = None,
    tool_dirs: tuple[Path, ...] = (),
    lenses: list | None = None,
    skip_passive: bool = False,
) -> ReconScanResult:
    if not scope.allow:
        raise ScopeError("this scope file has no [targets].allow entries - nothing to test")

    out_dir = (cache_dir or Path(".cache/janus")) / "recon"
    out_dir.mkdir(parents=True, exist_ok=True)
    findings: list[Finding] = []
    tool_results: list[ToolResult] = []

    discovery_client = passive.http_client()
    client = ScopeClient(
        scope,
        budget=RequestBudget(scope.max_requests),
        rate_limiter=RateLimiter(scope.max_rps),
    )

    try:
        # ---- discovery: third-party sources only, never the target ------
        discovered: set[str] = set(scope.allow)
        for domain in _primary_domains(scope):
            discovered.update(passive.discover_subdomains_crtsh(domain, discovery_client))
        for domain in _primary_domains(scope):
            hosts, r = adapters.run_subfinder(domain, tool_dirs)
            if r.status != "skipped":
                tool_results.append(r)
            discovered.update(hosts)
        discovered = {h for h in discovered if not h.startswith("*")}

        groups = passive.group_by_ip(sorted(discovered), discovery_client)
        sampled: list[str] = []
        for _ip, hosts in groups.items():
            sampled.extend(sorted(hosts)[:max_hosts_per_ip])

        # Explicit seeds first: they are the only way to express a port other
        # than 443 (a bare host in `allow` has no port).
        target_urls: list[str] = []
        for seed in scope.seeds:
            if scope.authorize(seed, method="GET").allowed:
                target_urls.append(seed)
        seeded_hosts = {(urlsplit(u).hostname or "") for u in target_urls}
        for host in sampled:
            if host in seeded_hosts:
                continue
            target_urls.append(host if "://" in host else f"https://{host}")

        # ---- passive checks, one budgeted client -------------------------
        hosts_tested: list[str] = []
        for base_url in target_urls:
            decision = scope.authorize(base_url, method="GET")
            if not decision.allowed:
                continue
            hosts_tested.append(base_url)
            if skip_passive:
                continue
            findings.extend(passive.check_headers_and_cookies(client, base_url))
            findings.extend(passive.check_cors(client, base_url))
            findings.extend(passive.check_sensitive_paths(client, base_url))
            findings.extend(passive.check_js_bundle_secrets(client, base_url))
            findings.extend(passive.check_infra_exposure(client, base_url))

        if not skip_passive:
            for domain in _primary_domains(scope):
                findings.extend(passive.check_email_auth(domain, discovery_client))

        # ---- active: nuclei, only with its own opt-in --------------------
        if mode in ("active", "agent") and not skip_passive:
            scope.require_active_recon()
            r = adapters.run_nuclei(hosts_tested, out_dir, rate_limit=nuclei_rate_limit,
                                    templates_dir=nuclei_templates_dir, tool_dirs=tool_dirs)
            tool_results.append(r)
            findings.extend(r.findings)

        # ---- deterministic write checks (listed endpoints only) ----------
        if scope.write_targets and mode in ("active", "agent"):
            wr = write_checks.run(scope, client)
            findings.extend(wr.findings)
            tool_results.append(ToolResult(
                "write-checks", "ok" if wr.checked else "skipped",
                findings=wr.findings,
                detail=f"{wr.checked} endpoint(s) checked, {wr.blocked} refused by scope",
            ))
            if wr.checked:
                print(f"write-checks: {wr.checked} endpoint(s), {len(wr.findings)} findings")

        # ---- agent: needs both opt-ins -----------------------------------
        if mode == "agent":
            scope.require_agent()
            backend = AGENT_BACKENDS.get(agent_backend)
            if backend is None:
                raise ScopeError(
                    f"unknown agent backend {agent_backend!r}; available: {sorted(AGENT_BACKENDS)}")
            if not agent_providers:
                raise ScopeError(
                    "--mode agent needs at least one available LLM provider (check the API key "
                    "env vars; `janus doctor` shows which are ready)")
            targets = [h if "://" in h else f"https://{h}" for h in hosts_tested]
            from ...lenses import instruction as lens_instruction

            extra = lens_instruction(lenses) if lenses else ""
            agent_findings, agent_results = run_ensemble(
                backend, targets, out_dir / "agent", agent_budget or AgentBudget(), agent_providers,
                extra_instruction=extra, scope=scope, http=client,
            )
            tool_results.extend(agent_results)
            findings.extend(agent_findings)
    finally:
        client.close()
        discovery_client.close()

    findings = dedupe(findings)
    findings = aggregate_repetitive(findings)

    denied = [row for row in client.log if not row.get("allowed")]
    return ReconScanResult(
        findings=findings,
        tool_results=tool_results,
        hosts_discovered=sorted(discovered),
        hosts_tested=hosts_tested,
        probe_log=client.log,
        budget_used=client.budget.used,
        budget_max=client.budget.max_requests,
        denied=len(denied),
        denied_reasons=sorted({r for row in denied for r in row.get("reasons", [])})[:20],
    )
