#!/usr/bin/env python3
"""Generates seed_findings.json: synthetic example findings about a fake
"Example Corp" (example.com — IANA's reserved documentation domain), used
by `janus demo` to populate the dashboard with zero setup and zero network
access. Every value here is invented for illustration; run this script
again any time the Finding schema changes.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from janus.core.model import Finding  # noqa: E402

FINDINGS = [
    Finding(
        title="Hardcoded database credential in settings.py", severity="critical", category="secrets",
        engine="code", tool="builtin", rule_id="SECRET-DB-URL",
        path="example-app/settings.py", line=42,
        message="A database connection string with an embedded password is committed to the repo.",
        remediation="Rotate the credential, move it to a secret manager / env var, and purge git history.",
        confidence="confirmed", cwe=("CWE-798",), owasp=("A07:2021",),
        snippet='DATABASE_URL = "postgres://app:****@db.internal.example.com:5432/app"',
    ),
    Finding(
        title="SQL built with f-string in order lookup", severity="critical", category="injection",
        engine="code", tool="semgrep", rule_id="python.django.security.injection.sql",
        path="example-app/orders/views.py", line=118,
        message="order_id is interpolated directly into a raw SQL string via an f-string.",
        remediation="Use the ORM or parameterized queries; never interpolate request data into SQL.",
        confidence="confirmed", cwe=("CWE-89",), owasp=("A03:2021",),
        snippet='cursor.execute(f"SELECT * FROM orders WHERE id = {order_id}")',
    ),
    Finding(
        title="JWT decoded without signature verification", severity="critical", category="auth",
        engine="code", tool="builtin", rule_id="PY-JWT-NOVERIFY",
        path="example-app/auth/tokens.py", line=27,
        message="jwt.decode(..., verify=False) accepts a token with any (or no) signature.",
        remediation="Always verify the signature against a known key/JWKS and pin the algorithm.",
        confidence="confirmed", cwe=("CWE-347",), owasp=("A07:2021",),
    ),
    Finding(
        title="IDOR on /api/invoices/{id} — no ownership check", severity="high", category="access-control",
        engine="recon", tool="agent:strix", rule_id="",
        target="https://api.example.com/api/invoices/1042", host="api.example.com",
        endpoint="/api/invoices/{id}", method="GET",
        message="Incrementing the invoice id as a second, synthetic test account returned another "
                "account's invoice (status/amount/line items), with no ownership check server-side.",
        remediation="Check request.user owns the invoice before returning it; prefer non-sequential ids.",
        confidence="needs-review", cwe=("CWE-639",), owasp=("A01:2021",),
        extra={"poc": "GET /api/invoices/1042 as user B returned user A's invoice (both synthetic test accounts)."},
    ),
    Finding(
        title="CORS reflects an arbitrary Origin", severity="high", category="configuration",
        engine="recon", tool="passive-recon", rule_id="CORS-REFLECTED",
        target="https://api.example.com/", host="api.example.com", endpoint="/", method="GET",
        message="Access-Control-Allow-Origin echoed back a made-up probe origin, together with "
                "Access-Control-Allow-Credentials: true.",
        remediation="Validate Origin against an explicit allowlist server-side; never reflect it verbatim.",
        confidence="confirmed", cwe=("CWE-942",), owasp=("A05:2021",),
    ),
    Finding(
        title="Publicly reachable admin login", severity="high", category="exposure",
        engine="recon", tool="passive-recon", rule_id="SENSITIVE-PATH",
        target="https://admin.example.com/admin/login/", host="admin.example.com",
        endpoint="/admin/login/", method="GET",
        message="A staff admin panel is reachable from the public internet with no network-level "
                "restriction (it may still require valid credentials — reachability itself is the finding).",
        remediation="Put staff panels behind a VPN/allowlist or SSO proxy; don't rely on credentials alone.",
        confidence="confirmed", cwe=("CWE-284",), owasp=("A01:2021",),
    ),
    Finding(
        title="Outdated jinja2 with known CVE", severity="high", category="supply-chain",
        engine="code", tool="trivy", rule_id="CVE-2024-EXAMPLE",
        path="example-app/requirements.txt", line=0,
        message="jinja2 2.11.2 is affected by a sandbox-escape CVE (illustrative).",
        remediation="Upgrade to the fixed version in requirements.txt and re-run the SCA scan.",
        confidence="confirmed", cwe=(),
    ),
    Finding(
        title="No SPF record for example.com", severity="medium", category="configuration",
        engine="recon", tool="passive-recon", rule_id="EMAIL-NO-SPF",
        target="example.com", host="example.com", endpoint="TXT", method="GET",
        message="No SPF TXT record found, making it easier to spoof mail \"From\" this domain.",
        remediation="Publish an SPF record scoped to your actual sending infrastructure.",
        confidence="confirmed",
    ),
    Finding(
        title="No DMARC record for example.com", severity="medium", category="configuration",
        engine="recon", tool="passive-recon", rule_id="EMAIL-NO-DMARC",
        target="example.com", host="example.com", endpoint="TXT", method="GET",
        message="No DMARC record found — no policy for mail that fails SPF/DKIM.",
        remediation="Publish a DMARC record, starting at p=none to observe before enforcing.",
        confidence="confirmed",
    ),
    Finding(
        title="Session cookie missing Secure/HttpOnly", severity="medium", category="configuration",
        engine="recon", tool="passive-recon", rule_id="COOKIE-FLAGS",
        target="https://www.example.com/", host="www.example.com", endpoint="/", method="GET",
        message="session_id cookie is missing Secure and HttpOnly.",
        remediation="Set Secure; HttpOnly on every cookie not deliberately meant for JS to read.",
        confidence="confirmed",
    ),
    Finding(
        title="Container runs as root", severity="medium", category="container",
        engine="code", tool="builtin", rule_id="DOCKER-ROOT-USER",
        path="example-app/Dockerfile", line=1,
        message="No USER directive — the process runs as root inside the container.",
        remediation="Add `USER <non-root>` after installing dependencies.",
        confidence="confirmed", cwe=("CWE-250",), owasp=("A05:2021",),
    ),
    Finding(
        title="HSTS without includeSubDomains", severity="low", category="configuration",
        engine="recon", tool="passive-recon", rule_id="HEADER-HSTS-WEAK",
        target="https://www.example.com/", host="www.example.com", endpoint="/", method="GET",
        message="Strict-Transport-Security is set but does not include subdomains.",
        remediation="Add includeSubDomains (and consider preload) once every subdomain supports HTTPS.",
        confidence="confirmed",
    ),
    Finding(
        title="Server banner discloses version", severity="low", category="exposure",
        engine="recon", tool="passive-recon", rule_id="HEADER-SERVER-VERSION",
        target="https://blog.example.com/", host="blog.example.com", endpoint="/", method="GET",
        message="Server: nginx/1.24.0 — a versioned banner narrows the search for known CVEs.",
        remediation="Strip or generalize the Server header at the reverse proxy.",
        confidence="confirmed",
    ),
    Finding(
        title="Base image unpinned (:latest)", severity="low", category="supply-chain",
        engine="code", tool="builtin", rule_id="DOCKER-UNPINNED-BASE",
        path="example-app/Dockerfile", line=1,
        message="FROM python (no tag) can change contents between builds with no signal.",
        remediation="Pin to a specific tag, ideally a digest.",
        confidence="confirmed", cwe=("CWE-1104",),
    ),
    Finding(
        title="Dependency scanner coverage note", severity="info", category="other",
        engine="code", tool="trivy", rule_id="",
        path="example-app/", line=0,
        message="This is an illustrative info-level row so the dashboard's 'info' stat card isn't always "
                "zero in the demo — not a real finding.",
        remediation="—", confidence="confirmed", status="ruled-out",
    ),
]

if __name__ == "__main__":
    out_path = Path(__file__).resolve().parent / "seed_findings.json"
    out_path.write_text(json.dumps([f.to_dict() for f in FINDINGS], indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"wrote {len(FINDINGS)} synthetic findings to {out_path}")
