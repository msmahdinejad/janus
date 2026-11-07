"""The zero-dependency half of the recon engine.

Everything here works with nothing installed beyond Python + httpx, and every
request to a real target goes through one gate: `ScopeClient` (see
`janus/core/http.py`), which authorizes the URL, charges it against the run's
request budget, and refuses to follow a redirect out of scope.

Design notes:

  * Asset discovery is passive: Certificate Transparency logs via crt.sh.
    That is a third-party aggregator, not the target, so it uses its own
    plain client.
  * DNS resolution tries the stdlib resolver first and falls back to DNS-over-
    HTTPS when a corporate/stuck resolver returns nothing.
  * Every probe identifies itself honestly. Spoofing a browser to get past a
    WAF is detection evasion, which this project does not do; a WAF block is
    reported as "not tested", not routed around.
  * `_scan_js_text_for_secrets` reuses the code engine's secret patterns, so
    one list covers source on disk and shipped bundles.
  * "Passive" here means *non-state-changing*: GET/HEAD only, no payloads, no
    login, no writes. It is still real traffic, which is why it is budgeted
    and rate-limited rather than described as inert.
"""

from __future__ import annotations

import re
import socket
import subprocess
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

import httpx

from ...core.http import BudgetExceeded, Response, ScopeClient, ScopeDenied, TransportFailure
from ...core.model import Finding, shannon_entropy

USER_AGENT = "Janus-Recon/0.2 (+authorized security assessment; see scope.toml for contact)"

SENSITIVE_PATHS = (
    "/.git/config", "/.env", "/robots.txt", "/.well-known/security.txt",
    "/server-status", "/actuator/health", "/swagger", "/swagger.json", "/api-docs",
    "/graphql", "/admin", "/admin/", "/debug", "/metrics", "/console",
    "/phpmyadmin/", "/phpMyAdmin/", "/.aws/credentials",
)

SECRET_PATHS = {"/.git/config", "/.env", "/.aws/credentials"}

SECURITY_HEADERS = (
    "content-security-policy", "strict-transport-security", "x-frame-options",
    "x-content-type-options", "referrer-policy", "permissions-policy",
)

# Bounds. A hostile endpoint must not turn one check into an unbounded run.
MAX_JS_CHUNKS = 40
MAX_SOURCEMAP_CHECKS = 25
MAX_BUNDLE_FINDINGS = 25


def http_client(timeout: float = 15.0) -> httpx.Client:
    """Plain client for third-party passive sources (crt.sh, DoH).

    Never used against a target: targets go through ScopeClient.
    """
    return httpx.Client(
        timeout=timeout, follow_redirects=False,
        headers={"User-Agent": USER_AGENT}, trust_env=False,
    )


# ---- passive asset discovery ------------------------------------------

def discover_subdomains_crtsh(domain: str, client: httpx.Client) -> list[str]:
    try:
        resp = client.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=30)
        resp.raise_for_status()
        rows = resp.json()
    except Exception:
        return []
    names: set[str] = set()
    for row in rows:
        for name in str(row.get("name_value", "")).split("\n"):
            name = name.strip().lower().lstrip("*.")
            if name and "*" not in name:
                names.add(name)
    return sorted(names)


def resolve_host(host: str, client: httpx.Client | None = None) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None)
        return sorted({info[4][0] for info in infos})
    except socket.gaierror:
        pass
    if client is None:
        return []
    try:
        resp = client.get(
            "https://cloudflare-dns.com/dns-query",
            params={"name": host, "type": "A"},
            headers={"Accept": "application/dns-json"},
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
        return sorted({a["data"] for a in data.get("Answer", []) if a.get("type") == 1})
    except Exception:
        return []


def group_by_ip(hosts: list[str], client: httpx.Client) -> dict[str, list[str]]:
    groups: dict[str, list[str]] = {}
    for h in hosts:
        ips = resolve_host(h, client)
        key = ips[0] if ips else "unresolved"
        groups.setdefault(key, []).append(h)
    return groups


# ---- helpers ----------------------------------------------------------

def _get(client: ScopeClient, url: str, headers: dict[str, str] | None = None) -> Response | None:
    """One scope-checked GET. A refusal or an exhausted budget is logged by
    the client and turned into None here, so the remaining checks report
    "not tested" instead of aborting the run with a traceback."""
    try:
        return client.get(url, headers=headers)
    except (ScopeDenied, BudgetExceeded, TransportFailure):
        return None


def _host(url: str) -> str:
    return urlsplit(url).hostname or url


# ---- checks -----------------------------------------------------------

def check_headers_and_cookies(client: ScopeClient, base_url: str) -> list[Finding]:
    findings: list[Finding] = []
    resp = _get(client, base_url)
    if resp is None:
        return findings

    host = _host(base_url)
    headers = resp.headers
    missing = [h for h in SECURITY_HEADERS if h not in headers]
    https = urlsplit(base_url).scheme == "https"
    if https and "strict-transport-security" in missing:
        missing.remove("strict-transport-security")
        findings.append(Finding(
            title="Missing Strict-Transport-Security (HSTS)", severity="medium",
            category="configuration", engine="recon", tool="passive-recon",
            rule_id="HEADER-HSTS-MISSING", target=base_url, host=host,
            endpoint="/", method="GET",
            message="No HSTS header: the first request of a session can be downgraded to plain HTTP.",
            remediation="Send `Strict-Transport-Security: max-age=31536000; includeSubDomains` "
                        "on every HTTPS response.",
            confidence="confirmed", sources=("passive-recon",),
        ))
    if missing:
        findings.append(Finding(
            title=f"Missing security headers: {', '.join(missing)}", severity="low",
            category="configuration", engine="recon", tool="passive-recon",
            rule_id="HEADER-MISSING", target=base_url, host=host, endpoint="/", method="GET",
            message=f"Response is missing: {', '.join(missing)}.",
            remediation="Set these headers at the edge (CDN/reverse proxy) or in the app framework.",
            confidence="confirmed", sources=("passive-recon",),
        ))

    hsts = resp.header("strict-transport-security")
    if hsts and "includesubdomains" not in hsts.lower():
        findings.append(Finding(
            title="HSTS without includeSubDomains", severity="low", category="configuration",
            engine="recon", tool="passive-recon", rule_id="HEADER-HSTS-WEAK",
            target=base_url, host=host, endpoint="/", method="GET",
            message=f"Strict-Transport-Security is set ({hsts!r}) but does not include subdomains.",
            remediation="Add includeSubDomains (and consider preload) once every subdomain supports HTTPS.",
            confidence="confirmed", sources=("passive-recon",),
        ))

    server = resp.header("server")
    if server and any(c.isdigit() for c in server):
        findings.append(Finding(
            title=f"Server banner discloses version: {server}", severity="low", category="exposure",
            engine="recon", tool="passive-recon", rule_id="HEADER-SERVER-VERSION",
            target=base_url, host=host, endpoint="/", method="GET",
            message="A versioned Server header makes it trivial to match the stack against known CVEs.",
            remediation="Strip or generalize the Server header at the reverse proxy.",
            confidence="confirmed", sources=("passive-recon",),
        ))

    for cookie_header in resp.header_list("set-cookie"):
        lc = cookie_header.lower()
        name = cookie_header.split("=", 1)[0].strip()
        issues = [flag for flag in ("secure", "httponly") if flag not in lc]
        if issues:
            findings.append(Finding(
                title=f"Cookie '{name}' missing {', '.join(issues)}", severity="medium",
                category="configuration", engine="recon", tool="passive-recon",
                rule_id="COOKIE-FLAGS", target=base_url, host=host, endpoint="/", method="GET",
                message=f"Cookie is missing: {', '.join(issues)}. Without Secure it can be sent over "
                        f"plain HTTP; without HttpOnly, JavaScript (and so XSS) can read it.",
                remediation="Set Secure; HttpOnly on every cookie that isn't deliberately meant for JS.",
                confidence="confirmed", sources=("passive-recon",),
            ))
        if "samesite" not in lc:
            findings.append(Finding(
                title=f"Cookie '{name}' has no SameSite attribute", severity="low",
                category="configuration", engine="recon", tool="passive-recon",
                rule_id="COOKIE-NO-SAMESITE", target=base_url, host=host, endpoint="/", method="GET",
                message="No SameSite attribute set. Browsers default this to Lax, but an explicit "
                        "value documents intent and protects older/embedded clients.",
                remediation="Set SameSite=Lax (or Strict for sensitive session cookies).",
                confidence="confirmed", sources=("passive-recon",),
            ))
        elif "samesite=none" in lc and "secure" not in lc:
            findings.append(Finding(
                title=f"Cookie '{name}' sets SameSite=None without Secure", severity="medium",
                category="configuration", engine="recon", tool="passive-recon",
                rule_id="COOKIE-SAMESITE-NONE-INSECURE", target=base_url, host=host,
                endpoint="/", method="GET",
                message="SameSite=None without Secure is invalid per spec (most browsers reject the "
                        "cookie outright) and usually means the Secure flag was forgotten.",
                remediation="Add Secure alongside SameSite=None, or drop SameSite=None.",
                confidence="confirmed", sources=("passive-recon",),
            ))
    return findings


def check_cors(client: ScopeClient, base_url: str) -> list[Finding]:
    probe_origin = "https://janus-cors-probe.invalid"
    resp = _get(client, base_url, headers={"Origin": probe_origin})
    if resp is None:
        return []

    acao = resp.header("access-control-allow-origin")
    acac = resp.header("access-control-allow-credentials").lower() == "true"
    host = _host(base_url)
    findings: list[Finding] = []
    reflected = acao.rstrip("/") == probe_origin
    if reflected:
        findings.append(Finding(
            title="CORS reflects an arbitrary Origin", severity="high" if acac else "medium",
            category="configuration", engine="recon", tool="passive-recon",
            rule_id="CORS-REFLECTED", target=base_url, host=host, endpoint="/", method="GET",
            message=f"Access-Control-Allow-Origin echoed back our made-up probe origin "
                    f"({probe_origin!r}){' together with Allow-Credentials: true' if acac else ''}, "
                    f"meaning any website can read {'authenticated' if acac else 'unauthenticated'} "
                    f"responses from this origin via a victim's browser.",
            remediation="Validate Origin against an explicit allowlist server-side; never reflect it verbatim.",
            confidence="confirmed", cwe=("CWE-942",), owasp=("A05:2021",), sources=("passive-recon",),
        ))
    elif acao == "*" and acac:
        findings.append(Finding(
            title="CORS wildcard combined with credentials", severity="high",
            category="configuration", engine="recon", tool="passive-recon",
            rule_id="CORS-WILDCARD-CREDENTIALS", target=base_url, host=host, endpoint="/", method="GET",
            message="Access-Control-Allow-Origin: * with Allow-Credentials: true is invalid in most "
                    "browsers, but where honored it allows any origin to read credentialed responses.",
            remediation="Never pair a wildcard origin with Allow-Credentials: true.",
            confidence="confirmed", cwe=("CWE-942",), owasp=("A05:2021",), sources=("passive-recon",),
        ))
    return findings


def check_sensitive_paths(client: ScopeClient, base_url: str) -> list[Finding]:
    base_url = base_url.rstrip("/")
    findings: list[Finding] = []
    host = _host(base_url)

    # Baseline a definitely-nonexistent path first, so an SPA/catch-all
    # fallback (same HTML for every path) isn't reported as N separate hits.
    baseline = _get(client, f"{base_url}/janus-probe-does-not-exist-9f3c")
    baseline_sig = (baseline.status, len(baseline.text)) if baseline is not None else None

    for path in SENSITIVE_PATHS:
        resp = _get(client, base_url + path)
        if resp is None:
            continue
        sig = (resp.status, len(resp.text))
        if baseline_sig is not None and sig == baseline_sig:
            continue  # generic fallback page, not a real hit
        if resp.status == 200:
            findings.append(Finding(
                title=f"Potentially exposed path: {path}",
                severity="high" if path in SECRET_PATHS else "medium",
                category="exposure", engine="recon", tool="passive-recon", rule_id="SENSITIVE-PATH",
                target=base_url + path, host=host, endpoint=path, method="GET",
                message=f"GET {path} returned 200 with a body that differs from the baseline 404/"
                        f"fallback, so this looks like a real, reachable endpoint.",
                remediation="Confirm intent; if unintentional, remove public access or put it behind auth.",
                confidence="needs-review", sources=("passive-recon",),
            ))
        elif resp.status in (401, 403):
            # The delivered version dropped these entirely. An admin/login
            # endpoint answering 401 is still a reachable endpoint that
            # confirms the surface; it belongs in the report at low severity.
            findings.append(Finding(
                title=f"Auth-protected path confirmed reachable: {path}", severity="low",
                category="exposure", engine="recon", tool="passive-recon",
                rule_id="SENSITIVE-PATH-PROTECTED", target=base_url + path, host=host,
                endpoint=path, method="GET",
                message=f"GET {path} returned {resp.status}: the path exists and is protected by "
                        f"authentication. This is expected for admin surfaces; it is reported so the "
                        f"inventory is complete, not as a break-in.",
                remediation="Confirm the auth layer is intentional and that no weaker path bypasses it.",
                confidence="confirmed", sources=("passive-recon",),
            ))
        elif resp.status in (301, 302, 303, 307, 308) and "login" in resp.header("location").lower():
            findings.append(Finding(
                title=f"Login-gated endpoint found: {path}", severity="medium", category="exposure",
                engine="recon", tool="passive-recon", rule_id="SENSITIVE-PATH-LOGIN",
                target=base_url + path, host=host, endpoint=path, method="GET",
                message=f"GET {path} redirects to a login page ({resp.header('location')}), confirming "
                        f"a staff/admin surface is reachable from the public internet.",
                remediation="Put staff surfaces behind VPN/SSO/IP allowlist, not just a login form.",
                confidence="confirmed", sources=("passive-recon",),
            ))
    return findings


def _txt_records(domain: str, client: httpx.Client) -> tuple[list[str], bool]:
    """Return (records, lookup_succeeded).

    The distinction matters: a failed lookup is not an absent record. On this
    network both Cloudflare and Google DoH time out, which previously produced
    "No SPF record" findings for domains that do publish SPF. Failure is now
    reported as "not assessed", never as a finding.
    """
    providers = (
        ("https://cloudflare-dns.com/dns-query", {"name": domain, "type": "TXT"}),
        ("https://dns.google/resolve", {"name": domain, "type": "TXT"}),
    )
    for url, params in providers:
        try:
            resp = client.get(url, params=params,
                              headers={"Accept": "application/dns-json"}, timeout=8)
            resp.raise_for_status()
            data = resp.json()
        except Exception:  # noqa: BLE001
            continue
        return [str(a.get("data", "")) for a in data.get("Answer", []) or []], True

    # Last resort: the system resolver. Works on Windows and POSIX and uses the
    # same DNS the host already trusts (corporate resolvers included).
    try:
        proc = subprocess.run(["nslookup", "-type=TXT", domain], capture_output=True,
                              text=True, timeout=10, encoding="utf-8", errors="replace")
        if proc.returncode == 0:
            return re.findall(r'"([^"]+)"', proc.stdout or ""), True
    except Exception:  # noqa: BLE001
        pass
    return [], False


def check_email_auth(domain: str, client: httpx.Client) -> tuple[list[Finding], bool]:
    findings: list[Finding] = []
    spf_raw, spf_ok = _txt_records(domain, client)
    dmarc_raw, dmarc_ok = _txt_records(f"_dmarc.{domain}", client)

    spf = [t for t in spf_raw if "spf1" in t.lower()]
    dmarc = [t for t in dmarc_raw if "dmarc1" in t.lower()]

    if spf_ok and not spf:
        findings.append(Finding(
            title=f"No SPF record for {domain}", severity="medium", category="configuration",
            engine="recon", tool="passive-recon", rule_id="EMAIL-NO-SPF",
            target=domain, host=domain, endpoint="TXT", method="GET",
            message="No SPF TXT record found, making it easier to spoof mail \"From\" this domain.",
            remediation="Publish an SPF record scoped to your actual sending infrastructure.",
            confidence="confirmed", sources=("passive-recon",),
        ))
    if dmarc_ok and not dmarc:
        findings.append(Finding(
            title=f"No DMARC record for {domain}", severity="medium", category="configuration",
            engine="recon", tool="passive-recon", rule_id="EMAIL-NO-DMARC",
            target=domain, host=domain, endpoint="TXT", method="GET",
            message="No DMARC record found, so receivers have no policy for mail that fails SPF/DKIM.",
            remediation="Publish a DMARC record, starting at p=none to observe before enforcing.",
            confidence="confirmed", sources=("passive-recon",),
        ))
    return findings, (spf_ok and dmarc_ok)


# ---- JS bundle + sourcemap scanning ------------------------------------

_SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', re.IGNORECASE)
_BUILD_MANIFEST_RE = re.compile(r'/_next/static/[^"\'\s]+/_buildManifest\.js')
_JS_PATH_IN_MANIFEST_RE = re.compile(r'["\']((?:/_next/|/static/)[^"\']+?\.js)["\']')

# Key types routinely meant to reach the browser, restricted at the provider
# by referrer/API/IP rather than kept secret. Reported at low severity with
# guidance, instead of either "critical" (wrong) or nothing at all.
_EXPECTED_CLIENT_SIDE_PREFIXES: dict[str, tuple[str, ...]] = {
    "SECRET-STRIPE-LIVE": ("pk_live_",),
}


def check_js_bundle_secrets(client: ScopeClient, base_url: str) -> list[Finding]:
    findings: list[Finding] = []
    host = _host(base_url)

    resp = _get(client, base_url)
    if resp is None or "html" not in resp.header("content-type").lower():
        return findings

    chunk_urls: set[str] = set()
    for m in _SCRIPT_SRC_RE.finditer(resp.text):
        chunk_urls.add(urljoin(base_url, m.group(1)))

    manifest_match = _BUILD_MANIFEST_RE.search(resp.text)
    if manifest_match:
        manifest_url = urljoin(base_url, manifest_match.group(0))
        mresp = _get(client, manifest_url)
        if mresp is not None and mresp.status == 200:
            for m in _JS_PATH_IN_MANIFEST_RE.finditer(mresp.text):
                chunk_urls.add(urljoin(base_url, m.group(1)))

    seen_values: set[str] = set()
    for i, chunk_url in enumerate(sorted(chunk_urls)[:MAX_JS_CHUNKS]):
        cresp = _get(client, chunk_url)
        if cresp is None or cresp.status != 200:
            continue
        findings.extend(_scan_js_text_for_secrets(chunk_url, host, cresp.text, seen=seen_values))

        if i >= MAX_SOURCEMAP_CHECKS:
            continue
        map_url = chunk_url + ".map"
        mresp2 = _get(client, map_url)
        if mresp2 is None or mresp2.status != 200:
            continue
        try:
            map_doc = mresp2.json()
        except Exception:
            continue
        sources_content = map_doc.get("sourcesContent") or []
        if any(s for s in sources_content if s and str(s).strip()):
            findings.append(Finding(
                title="Exposed sourcemap leaks original source", severity="medium",
                category="exposure", engine="recon", tool="passive-recon",
                rule_id="SOURCEMAP-EXPOSED", target=map_url, host=host,
                endpoint=urlsplit(map_url).path, method="GET",
                message=f"{map_url} is publicly reachable with populated sourcesContent: the full, "
                        f"unminified original source is downloadable by anyone.",
                remediation="Stop shipping .map files in production builds, or put them behind auth.",
                confidence="confirmed", sources=("passive-recon",),
            ))
    return findings


def _scan_js_text_for_secrets(url: str, host: str, text: str,
                              seen: set[str] | None = None) -> list[Finding]:
    from ..code.builtin import _GENERIC_KV_RE, _PLACEHOLDER_RE, _SECRET_PATTERNS

    findings: list[Finding] = []
    seen = seen if seen is not None else set()
    endpoint = urlsplit(url).path or url

    for rule_id, title, pattern in _SECRET_PATTERNS:
        # Google-style keys get the dedicated, lower-severity treatment
        # below: they are client-side by design far more often than not.
        if rule_id == "SECRET-GOOGLE-API-KEY":
            continue
        for value in {m.group(0) for m in pattern.finditer(text)}:
            if value in seen:
                continue
            seen.add(value)
            expected_prefixes = _EXPECTED_CLIENT_SIDE_PREFIXES.get(rule_id, ())
            if expected_prefixes and value.startswith(expected_prefixes):
                findings.append(Finding(
                    title=f"Publishable key shipped in JS bundle: {title}", severity="low",
                    category="secrets", engine="recon", tool="passive-recon",
                    rule_id=f"JS-CLIENT-KEY-{rule_id}", target=url, host=host,
                    endpoint=endpoint, method="GET",
                    message=f"{title} with a publishable-key prefix is present in client JS. That is "
                            f"expected for this key type, but it must be restricted at the provider "
                            f"(allowed referrers, allowed APIs) or it can be abused for quota/billing.",
                    remediation="Confirm HTTP-referrer and API restrictions on this publishable key.",
                    confidence="needs-review", sources=("passive-recon",),
                ))
                continue
            findings.append(Finding(
                title=f"{title} found in shipped JS bundle", severity="critical",
                category="secrets", engine="recon", tool="passive-recon", rule_id=f"JS-{rule_id}",
                target=url, host=host, endpoint=endpoint, method="GET",
                message=f"{title} is embedded in a publicly served JS bundle: shipped to every "
                        f"visitor's browser and trivially extractable. Treat as compromised.",
                remediation="Rotate the credential immediately. Anything that must reach the browser "
                            "needs its OWN scope restriction at the provider.",
                confidence="confirmed", cwe=("CWE-798",), owasp=("A07:2021",),
                sources=("passive-recon",),
            ))

    for m in re.finditer(r"\bAIza[0-9A-Za-z_\-]{35}\b", text):
        value = m.group(0)
        if value in seen:
            continue
        seen.add(value)
        findings.append(Finding(
            title="Google-style API key found in shipped JS bundle (verify restrictions)",
            severity="medium", category="secrets", engine="recon", tool="passive-recon",
            rule_id="JS-GOOGLE-API-KEY", target=url, host=host, endpoint=endpoint, method="GET",
            message="A Google-style API key (AIza...) is present in client JS. This is routinely "
                    "intentional (Firebase config, Maps JS API) and safe IF restricted by HTTP "
                    "referrer / API / IP at the provider — unrestricted it can be abused for billing.",
            remediation="In Google Cloud / Firebase console, confirm application restrictions "
                        "(HTTP referrers) and API restrictions (only the APIs it needs).",
            confidence="needs-review", sources=("passive-recon",),
        ))
        break  # one key is enough signal; the same config key repeats across chunks

    generic_seen = 0
    for m in _GENERIC_KV_RE.finditer(text):
        value = m.group(2)
        if value in seen or _PLACEHOLDER_RE.match(value) or value.startswith("$") or "${" in value:
            continue
        if shannon_entropy(value) < 3.5:  # minified JS is noisier than source
            continue
        seen.add(value)
        findings.append(Finding(
            title=f"Possible hardcoded {m.group(1).lower()} in shipped JS bundle",
            severity="high", category="secrets", engine="recon", tool="passive-recon",
            rule_id="JS-SECRET-GENERIC-KV", target=url, host=host, endpoint=endpoint, method="GET",
            message="A high-entropy value sits next to a sensitive-looking key name inside a publicly "
                    "served bundle — could be a real credential, a client-safe key, or a build artifact.",
            remediation="If meant to be public, confirm it's scope-restricted at the provider. If not, "
                        "rotate it and stop shipping it to the client.",
            confidence="needs-review", cwe=("CWE-798",), sources=("passive-recon",),
        ))
        generic_seen += 1
        if generic_seen >= 5:  # one noisy bundle must not flood the report
            break
    return findings[:MAX_BUNDLE_FINDINGS]


# ---- infra/devops-tool exposure fingerprinting -------------------------

_INFRA_JSON_FINGERPRINTS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("/v1/sys/seal-status", "HashiCorp Vault", ("sealed", "initialized")),
    ("/api/health", "Grafana", ("version", "commit")),
    ("/api/session/properties", "Metabase", ("version",)),
)

_INFRA_PAGE_SIGNATURES: tuple[tuple[str, str], ...] = (
    ("GitLab", "GitLab"),
    ("Argo CD", "ArgoCD"),
    ("RabbitMQ Management", "RabbitMQ management UI"),
    ("JupyterLab", "JupyterLab"),
    ("Jupyter Notebook", "Jupyter Notebook"),
)


def check_infra_exposure(client: ScopeClient, base_url: str) -> list[Finding]:
    findings: list[Finding] = []
    host = _host(base_url)
    base_url = base_url.rstrip("/")

    for path, label, json_keys in _INFRA_JSON_FINGERPRINTS:
        resp = _get(client, base_url + path)
        if resp is None or resp.status != 200:
            continue
        try:
            body = resp.json()
        except Exception:
            continue
        if not isinstance(body, dict) or not all(k in body for k in json_keys):
            continue

        if label == "HashiCorp Vault":
            if body.get("sealed") is False:
                findings.append(Finding(
                    title="HashiCorp Vault is UNSEALED and publicly reachable", severity="critical",
                    category="exposure", engine="recon", tool="passive-recon",
                    rule_id="INFRA-VAULT-UNSEALED", target=base_url + path, host=host,
                    endpoint=path, method="GET",
                    message="This Vault instance responds to the public seal-status endpoint AND reports "
                            "sealed=false — an unsealed Vault with any network reachability is a direct "
                            "path to every secret it holds if auth is also weak.",
                    remediation="Put Vault's listener behind a private network/VPN immediately.",
                    confidence="confirmed", sources=("passive-recon",),
                ))
            else:
                findings.append(Finding(
                    title="HashiCorp Vault status endpoint is publicly reachable (sealed)",
                    severity="medium", category="exposure", engine="recon", tool="passive-recon",
                    rule_id="INFRA-VAULT-EXPOSED", target=base_url + path, host=host,
                    endpoint=path, method="GET",
                    message="Vault's seal-status endpoint is public by design and reports sealed=true "
                            "(the safe state) — but its reachability confirms a Vault lives here.",
                    remediation="Restrict network access to Vault's listener to only what needs it.",
                    confidence="confirmed", sources=("passive-recon",),
                ))
        else:
            version = {k: body.get(k) for k in json_keys}
            findings.append(Finding(
                title=f"{label} is publicly reachable", severity="medium", category="exposure",
                engine="recon", tool="passive-recon", rule_id="INFRA-TOOL-EXPOSED",
                target=base_url + path, host=host, endpoint=path, method="GET",
                message=f"{path} responds with a {label}-shaped health/info payload, confirming "
                        f"{label} is reachable from the open internet (version info: {version}).",
                remediation=f"Put {label} behind a VPN/SSO proxy/allowlist rather than relying on its "
                            f"own login alone, and consider whether this endpoint needs to be public.",
                confidence="confirmed", sources=("passive-recon",),
            ))

    resp = _get(client, base_url + "/")
    if resp is not None and resp.status == 200:
        body_sample = resp.text[:20000]
        for signature, label in _INFRA_PAGE_SIGNATURES:
            if signature in body_sample:
                findings.append(Finding(
                    title=f"{label} login/landing page is publicly reachable", severity="medium",
                    category="exposure", engine="recon", tool="passive-recon",
                    rule_id="INFRA-LOGIN-EXPOSED", target=base_url + "/", host=host,
                    endpoint="/", method="GET",
                    message=f"The page at this host contains {signature!r}, consistent with a {label} "
                            f"instance — reachability of a staff tool's login page is the finding, "
                            f"independent of whether login itself is secure.",
                    remediation=f"Put {label} behind a VPN/SSO proxy/IP allowlist.",
                    confidence="needs-review", sources=("passive-recon",),
                ))
                break
    return findings


@dataclass
class ReconCoverage:
    """What the passive pass actually covered, for the report's honesty
    section. Counts come from the ScopeClient's own log."""

    hosts: list[str] = field(default_factory=list)
    requests: int = 0
    denied: int = 0
    denied_reasons: list[str] = field(default_factory=list)

