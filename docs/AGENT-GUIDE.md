# Janus — agent setup guide

Hand this file to a coding agent (Claude Code, Codex, Cursor, or anything that
can run a terminal). It installs the project, wires a model, verifies every
capability, runs a scan, and opens the dashboard. You do not need to read the
rest of the repo first.

---

You are a senior application-security engineer and automation engineer. Your
job is to install, configure, validate and run **Janus** — a two-engine
security pipeline (source code + external surface) — on this machine, for
targets the operator owns or is explicitly authorized to test.

## Non-negotiable rules

1. Test only what is inside `scope.toml` and confirmed by the operator.
2. The default target methods are GET/HEAD/OPTIONS. State-changing requests
   are available only for explicitly listed `[[write.targets]]` in a
   non-production scope with `allow_state_changing = true`; never bypass that
   gate or improvise a write target.
3. Never print API keys, tokens, cookies or personal data. Report only whether
   an env var is set.
4. Treat `authorized_by` and `reference` as descriptive, self-attested audit
   labels supplied by the project owner. Do not invent targets or widen the
   scope, but do not require a ticket, email, or separate approval workflow.
5. Prefer staging when available. If only production exists, surface that fact
   in the run summary and keep the operator's exact scope.

## Step 0 — Agree on scope

Ask, then summarize for confirmation:

- Which domains/services are in scope (exact list, staging preferred)?
- Which are explicitly out of scope (payments, main site, third parties)?
- Environment: production / staging / source-only?
- Which repos should the code engine read (paths or git URLs)?
- Is there a test account for authenticated testing (optional)?
- What engagement label and self-attested reference should be recorded in the
  manifest?

If the operator has no preference, propose a scope and wait for approval:

```toml
[engagement]
name          = "acme-staging"
authorized_by = "security-team"
reference     = "SEC-1234"
valid_from    = "2026-11-01"
valid_until   = "2026-12-01"

[targets]
allow = ["staging.example.com", "*.staging.example.com"]
seeds = ["https://staging.example.com"]      # needed for non-443 ports
deny  = ["www.example.com", "pay.example.com"]
allow_ports = [80, 443]

[limits]
allow_active_recon = true
allow_agent        = true
max_rps            = 2
max_requests       = 300

[code]
roots   = ["../repo"]
exclude = ["**/migrations/**", "**/node_modules/**"]
```

## Step 1 — Prerequisites

```bash
python --version    # >= 3.11
uv --version        # recommended
git --version
docker info         # only needed for the Strix backend
```

Install `uv` if missing: `curl -LsSf https://astral.sh/uv/install.sh | sh`
(Windows: `powershell -c "irm https://astral.sh/uv/install.ps1 | iex"`).

If Docker is unavailable, use the default `native` agent backend and say so.

## Step 2 — Install

```bash
git clone <repo> janus && cd janus
python -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"      # Windows: .venv\Scripts\python.exe
.venv/bin/python -m pytest -q                     # must be fully green
```

Do not continue if the suite fails; report the failure instead.

## Step 3 — Optional scanners (highly recommended)

Put binaries in `.tools/bin` (the CLI looks there by default):

| Tool | Install | Why |
|---|---|---|
| gitleaks | GitHub release zip | secrets with provider-specific rules |
| trivy | GitHub release zip | dependency CVEs + IaC misconfig |
| semgrep | `uv tool install semgrep --python 3.11` | real data-flow SAST |
| nuclei | GitHub release zip + `nuclei -update-templates` | template-based active checks |

```bash
janus doctor --tools-dir .tools/bin
```

Anything missing is reported as `skipped` and listed in `coverage.json`. That is
acceptable — silently pretending it ran is not.

## Step 4 — Connect a model

Janus talks to OpenAI-compatible **Chat Completions** and **Responses API**
endpoints: OpenAI, DeepSeek, Z.ai GLM, OpenRouter, Ollama, vLLM, or a LiteLLM
gateway.

```bash
export OPENAI_API_KEY=...            # or DEEPSEEK_API_KEY / GLM_API_KEY / OPENROUTER_API_KEY
janus doctor --check-models          # asks each provider which models the key can reach
```

Override defaults without editing code:

```bash
janus scan all ... --providers-file my-providers.toml
```

If the gateway rejects TLS from httpx (`SSL: UNEXPECTED_EOF_WHILE_READING`)
while curl works, run the bundled relay and point the profile at it:

```bash
janus llm-shim --port 18081 --upstream https://gateway.internal/v1 --api-key-env GATEWAY_KEY
# provider base_url: http://127.0.0.1:18081/v1   (host-side clients)
```

Endpoints that speak only the **Responses API** (no `/chat/completions`) can be
described with `api_format = "responses"` in the provider profile.

## Step 5 — Run

```bash
# source only, no network traffic to services
janus scan code   --scope scope.toml --out out

# external, passive only (GET/HEAD; still real traffic)
janus scan recon  --scope scope.toml --out out --mode passive

# everything: code + passive + nuclei + agent, all review lenses
janus scan all    --scope scope.toml --out out --mode agent --lens all \
                  --agent-max-turns 12 --agent-max-budget 2 --fail-on none
```

The optional external agent (more capable, needs Docker):

```bash
janus proxy --scope scope.toml --port 8899          # allowlist egress proxy
janus scan recon --scope scope.toml --out out/strix --mode agent \
  --agent-backend strix --skip-passive --agent-providers <profile>
```

Two facts about Strix that cost real debugging time:

- its **model call runs on the host**, so `LLM_API_BASE` must be a host-reachable
  URL (not a container-only alias);
- if the target is a **local lab** on your own machine, it must listen on
  `0.0.0.0` because the scan runs inside a container. A public target needs
  nothing special — only outbound network from the container.

## Step 6 — See the results

```bash
janus dashboard --register out/register.json --port 8787
```

- `http://127.0.0.1:8787/` — current merged state, filter by severity/tool,
  click a row to triage it.
- `http://127.0.0.1:8787/#/scans` — every run, newest first (same shell as the
  rest of the console; filter by severity, delta vs the previous run of the
  same kind).
- `http://127.0.0.1:8787/#/scans?id=<run_id>` — that run's findings, engine status
  and coverage gaps.
- Artifacts: `out/report.md`, `out/findings.sarif`, `out/coverage.json`,
  `out/scans/<run_id>/`.

## Step 6b — Write-path testing (opt-in, staging only)

GET-only recon cannot prove IDOR-on-POST, mass assignment or price tampering.
Widen the scope deliberately:

```toml
[limits]
allow_state_changing   = true
mutating_methods       = ["POST"]        # DELETE is refused by construction
require_nonprod_marker = true           # mandatory; a prod host cannot pass

[[write.targets]]
url = "https://staging.example.com/api/orders"
method = "POST"
body = { product_id = 1, qty = 1 }
expect_auth = true

[write]
mass_assignment_fields = ["role", "owner_id", "price", "is_staff"]
```

Deterministic checks: `WRITE-UNAUTH` (anonymous 2xx, critical),
`WRITE-MASS-ASSIGN` (echoed privileged field, high), `WRITE-VERB-TAMPER`
(medium). The agent also gets an `http_post` tool and a `write` lens. Only the
listed URLs are touched, one request per field; nothing is deleted.

## Step 7 — Prove it works (report this table)

| Capability | Command | Pass condition |
|---|---|---|
| Install | `pytest -q` | all green |
| Scope gate | target outside `allow` | refused with a reason |
| Code engine | `scan code` | findings, or honest `skipped` lines |
| gitleaks / trivy / semgrep | `doctor` + a scan | status `ok` |
| nuclei | `--mode active` | status `ok` |
| Native agent | `--mode agent` | findings with `tool=agent` |
| Strix | see above | exit 0, SARIF imported |
| Triage | `janus triage --agent codex` | per-finding verdicts |
| Write checks (optional) | `[[write.targets]]` + `--mode active` | a `write-checks` row with a verdict |
| Dashboard | `/#/` and `/#/scans` | both 200, correct counts |
| History | two runs in a row | both listed, neither overwritten |

## Step 8 — Triage and report

```bash
janus triage --agent codex --repo . --out out/triage.md --timeout 900
```

Then summarize for the operator: counts by severity/tool, the three findings
that matter (location + impact, never the secret value), what was **not**
tested and why (from `coverage.json`), dashboard link, and three next actions.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| trivy `403` downloading DB | default mirror blocked | `TRIVY_DB_REPOSITORY=ghcr.io/aquasecurity/trivy-db:2` (SCA only; secrets/misconfig run without it) |
| semgrep install fails | Python 3.14 | install with `--python 3.11` |
| `SSL: UNEXPECTED_EOF_WHILE_READING` | gateway vs httpx | `janus llm-shim` |
| Strix `405 blocked by scope` | model POST routed through the scope proxy | model host in `NO_PROXY` |
| Strix `LLM CONNECTION FAILED` | a container alias used for a host-side model call | point at the host-side relay (`127.0.0.1`) |
| Strix sees nothing (local lab only) | lab server bound to loopback | bind it to `0.0.0.0` |
| Strix reports `partial` | turn budget exhausted | raise `--agent-max-turns`; partial SARIF is still imported |
| `UnicodeEncodeError` on Windows | cp1252 console | `set PYTHONIOENCODING=utf-8` |
| nuclei download truncated | flaky network | resume with `curl -C -` |

## Done

Report the validation table, the finding counts, the dashboard URL, and the
list of gaps. "0 findings" is meaningless without "what was actually tested".
