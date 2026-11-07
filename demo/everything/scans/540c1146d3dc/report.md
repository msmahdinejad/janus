# Janus security report — janus-full-demo

- Authorization reference: `demo-full-2026-11-06`
- Authorized by: local operator (own machine)
- Valid window: 2026-11-01T00:00:00+00:00 .. 2026-12-31T23:59:59+00:00
- Generated: 2026-11-07T12:03:10.648573+00:00

## Summary

Total findings: **11**

| Severity | Count |
|---|---|
| critical | 3 |
| high | 2 |
| medium | 1 |
| low | 5 |
| info | 0 |

| Category | Count |
|---|---|
| secrets | 4 |
| configuration | 4 |
| exposure | 3 |

## Findings

### [CRITICAL] AWS access key ID

- Status: `open`  ·  Confidence: `confirmed`
- Location: `D:/Janus/examples/lab_app/server.py:29`
- Tool / rule: `builtin` / `SECRET-AWS-ACCESS-KEY`
- Impact: AWS access key ID found in source. Treat as compromised: rotate it, then remove it from history.
- Remediation: Rotate the credential immediately, move it to a secret manager / env var injected at runtime, and purge it from git history.

  ```
  APP_JS = """
  const cfg = {api: "/api", region: "eu-west-1"};
  const AWS_ACCESS_KEY_ID = "AKIA************LE";
  const STRIPE_PUBLISHABLE = "pk_live_51NxExamplePublishableKey0001";
  async function loadOrder(id) { return (await fetch(`/api/orders/${id}`)).json(); }
  ```

### [CRITICAL] Stripe live key

- Status: `open`  ·  Confidence: `confirmed`
- Location: `D:/Janus/examples/lab_app/server.py:30`
- Tool / rule: `builtin` / `SECRET-STRIPE-LIVE`
- Impact: Stripe live key found in source. Treat as compromised: rotate it, then remove it from history.
- Remediation: Rotate the credential immediately, move it to a secret manager / env var injected at runtime, and purge it from git history.

  ```
  const cfg = {api: "/api", region: "eu-west-1"};
  const AWS_ACCESS_KEY_ID = "AKIA************LE";
  const STRIPE_PUBLISHABLE = "pk_live_51NxExamplePublishableKey0001";
  async function loadOrder(id) { return (await fetch(`/api/orders/${id}`)).json(); }
  loadOrder(1).then(o => { document.body.innerText = JSON.stringify(o); });
  ```

### [CRITICAL] AWS access key ID found in shipped JS bundle

- Status: `open`  ·  Confidence: `confirmed`
- Location: `127.0.0.1 /static/app.js`
- Tool / rule: `passive-recon` / `JS-SECRET-AWS-ACCESS-KEY`
- Impact: AWS access key ID is embedded in a publicly served JS bundle: shipped to every visitor's browser and trivially extractable. Treat as compromised.
- Remediation: Rotate the credential immediately. Anything that must reach the browser needs its OWN scope restriction at the provider.

### [HIGH] CORS reflects an arbitrary Origin

- Status: `open`  ·  Confidence: `confirmed`
- Location: `127.0.0.1 /`
- Tool / rule: `passive-recon` / `CORS-REFLECTED`
- Impact: Access-Control-Allow-Origin echoed back our made-up probe origin ('https://janus-cors-probe.invalid') together with Allow-Credentials: true, meaning any website can read authenticated responses from this origin via a victim's browser.
- Remediation: Validate Origin against an explicit allowlist server-side; never reflect it verbatim.

### [HIGH] Potentially exposed path: /.git/config

- Status: `open`  ·  Confidence: `needs-review`
- Location: `127.0.0.1 /.git/config`
- Tool / rule: `passive-recon` / `SENSITIVE-PATH`
- Impact: GET /.git/config returned 200 with a body that differs from the baseline 404/fallback, so this looks like a real, reachable endpoint.
- Remediation: Confirm intent; if unintentional, remove public access or put it behind auth.

### [MEDIUM] Cookie 'sid' missing secure, httponly

- Status: `open`  ·  Confidence: `confirmed`
- Location: `127.0.0.1 /`
- Tool / rule: `passive-recon` / `COOKIE-FLAGS`
- Impact: Cookie is missing: secure, httponly. Without Secure it can be sent over plain HTTP; without HttpOnly, JavaScript (and so XSS) can read it.
- Remediation: Set Secure; HttpOnly on every cookie that isn't deliberately meant for JS.

### [LOW] Missing security headers: content-security-policy, strict-transport-security, x-frame-options, x-content-type-options, referrer-policy, permissions-policy

- Status: `open`  ·  Confidence: `confirmed`
- Location: `127.0.0.1 /`
- Tool / rule: `passive-recon` / `HEADER-MISSING`
- Impact: Response is missing: content-security-policy, strict-transport-security, x-frame-options, x-content-type-options, referrer-policy, permissions-policy.
- Remediation: Set these headers at the edge (CDN/reverse proxy) or in the app framework.

### [LOW] Server banner discloses version: BaseHTTP/0.6 Python/3.14.7

- Status: `open`  ·  Confidence: `confirmed`
- Location: `127.0.0.1 /`
- Tool / rule: `passive-recon` / `HEADER-SERVER-VERSION`
- Impact: A versioned Server header makes it trivial to match the stack against known CVEs.
- Remediation: Strip or generalize the Server header at the reverse proxy.

### [LOW] Cookie 'sid' has no SameSite attribute

- Status: `open`  ·  Confidence: `confirmed`
- Location: `127.0.0.1 /`
- Tool / rule: `passive-recon` / `COOKIE-NO-SAMESITE`
- Impact: No SameSite attribute set. Browsers default this to Lax, but an explicit value documents intent and protects older/embedded clients.
- Remediation: Set SameSite=Lax (or Strict for sensitive session cookies).

### [LOW] Auth-protected path confirmed reachable: /admin

- Status: `open`  ·  Confidence: `confirmed`
- Location: `127.0.0.1 /admin`
- Tool / rule: `passive-recon` / `SENSITIVE-PATH-PROTECTED`
- Impact: GET /admin returned 401: the path exists and is protected by authentication. This is expected for admin surfaces; it is reported so the inventory is complete, not as a break-in.
- Remediation: Confirm the auth layer is intentional and that no weaker path bypasses it.

### [LOW] Publishable key shipped in JS bundle: Stripe live key

- Status: `open`  ·  Confidence: `needs-review`
- Location: `127.0.0.1 /static/app.js`
- Tool / rule: `passive-recon` / `JS-CLIENT-KEY-SECRET-STRIPE-LIVE`
- Impact: Stripe live key with a publishable-key prefix is present in client JS. That is expected for this key type, but it must be restricted at the provider (allowed referrers, allowed APIs) or it can be abused for quota/billing.
- Remediation: Confirm HTTP-referrer and API restrictions on this publishable key.

## Limitations

- This report reflects what the enabled engines/adapters actually ran — see the `tools` section of findings.json for which ones were skipped (not installed) vs. failed vs. ok. Absence of a finding in a skipped category means "not tested", not "clean".
- Static analysis (the `code` engine) proves what the source says, not what happens in a running system. The `recon` engine proves what a given vantage point can observe, not what every possible attacker-controlled network path can reach.
## Coverage

- Run quality: **failed**.

| Engine | Status | Findings | Detail |
|---|---|---:|---|
| code | ran | 2 | 34 files scanned |
| recon | ran | 9 | 1 hosts tested |
- Code engine: **34 files** scanned.
- External engine: **1 hosts** tested, **28/120** requests used, 0 refused by scope.

| Lens | Status | OWASP | Findings |
|---|---|---|---|
| Broken access control | not-run (agent mode off) | A01:2021 | 0 |
| Authentication and session | not-run (agent mode off) | A07:2021 | 3 |
| Injection and server-side execution | not-run (agent mode off) | A03:2021 | 0 |
| Secrets and data exposure | not-run (agent mode off) | A02:2021, A05:2021 | 1 |
| Business logic and payments | not-run (agent mode off) | A04:2021 | 0 |
| File handling and uploads | not-run (agent mode off) | A03:2021, A01:2021 | 0 |
| Client-side and browser trust | not-run (agent mode off) | A03:2021, A05:2021 | 1 |
| Write-path authorization and integrity | not-run (agent mode off) | A01:2021, A04:2021 | 0 |
| Edge, platform and configuration | not-run (agent mode off) | A05:2021, A06:2021 | 1 |

| OWASP | Area | Findings | Confirmed |
|---|---|---|---|
| A05:2021 | Security Misconfiguration | 1 | 1 |
| A07:2021 | Identification and Authentication Failures | 3 | 3 |

**Not covered / degraded:**

- semgrep failed - exit 2: no output file
- semgrep failed - exit 2: no output file
- AI agent lenses were not run (`--mode agent` is off or the scope forbids it)
- 7 finding(s) carry no OWASP mapping (tool-native rules)
