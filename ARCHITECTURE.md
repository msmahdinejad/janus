# Architecture & tool research

This document is the review this project was built to produce: what the
predecessor pipelines (one source-code pipeline, one black-box/agentic
external pipeline) got right, what the current tooling landscape (researched
November 2026) suggests changing, and the reasoning behind every non-obvious
decision in `janus/`. If you're deciding whether to adopt or extend Janus,
read this before the code.

## Design principles

1. **No mandatory dependency.** `janus scan code` and `janus scan recon
   --mode passive` both produce real, useful output with *nothing* installed
   beyond Python. Every external tool (Semgrep, Gitleaks, Trivy, nuclei,
   subfinder, an AI agent) is an adapter that reports `skipped` if missing —
   never a crash, never a silently-empty report. This was the single best
   idea in the predecessor `codesec` pipeline; it's now the rule for both
   engines, not just one.
2. **The authorization gate can't be bypassed, including by its own
   operator.** `janus/core/scope.py` hard-codes the allowed HTTP methods as
   a Python constant, requires a named engagement + authorization reference
   + validity window before anything runs, and makes active scanning and
   the AI-agent layer each need their own explicit opt-in. See that file's
   docstring for the full reasoning — this is the difference between a
   security tool and an attack script, and it's deliberately the most
   over-engineered file in the repo.
3. **One Finding model, three report formats.** Every tool's native output
   (wildly different JSON shapes) gets normalized into one dataclass before
   it's deduplicated, aggregated, or rendered. Markdown for a human, JSON for
   the dashboard/CI, SARIF for GitHub/GitLab's native code-scanning UI.
4. **Honest about what wasn't tested.** "Zero findings" from a skipped tool,
   a WAF-blocked scan, or a `quick`-mode agent run is not the same claim as
   "clean," and the report says so explicitly (see README "Known
   limitations"). The predecessor recon pipeline ran nuclei's full template
   set against a production domain for 6.5 hours and got 0 findings with a
   36% request-error rate — almost certainly a WAF eating most of the
   traffic, not a clean bill of health. That distinction is now structural
   (per-tool `status: ok|skipped|failed` in every report), not a footnote.

## The `code` engine: tool research

| Tool | Role here | Why |
|---|---|---|
| **builtin (this repo)** | Always-on baseline: ~20 regex/entropy rules across injection, deserialization, crypto, auth, config, secrets, CI/CD, containers | Zero dependency; the predecessor `codesec` pipeline proved this is worth keeping even once real scanners are available, because it never reports a coverage gap as a clean scan |
| **Semgrep (CE)** | Primary SAST when installed | Fastest OSS option for CI feedback and custom rules. **Caveat found in research:** multiple 2026 sources describe Semgrep CE's cross-file/taint analysis as having moved behind Semgrep's paid platform, with **OpenGrep** (a 2025 community fork) cited as restoring that cross-file analysis while staying drop-in rule-compatible. If cross-file taint matters for your codebase, evaluate OpenGrep as a swap-in before assuming Semgrep CE alone is sufficient — the adapter (`janus/engines/code/adapters.py::run_semgrep`) just shells out to whatever `semgrep`-named binary is on PATH, so this is a one-line substitution, not a code change. [AppSec Santa – Semgrep alternatives](https://appsecsanta.com/semgrep-alternatives) |
| **Gitleaks** | Primary secrets scanner | Research consensus: fastest, simplest, good default CI gate; it pattern-matches only (no live-credential verification), which is exactly the property this project wants, since the engagement rules forbid ever testing whether a found credential is live |
| **Trivy** | SCA + IaC + extra secrets layer | Broadest single OSS scanner (most-starred security scanner on GitHub per one 2026 source) covering containers/filesystem/IaC/K8s in one tool — matches the breadth the predecessor pipeline already depended on, including its `--offline` mode for CVE-DB-free secrets/misconfig-only runs | [lucaberton.com – Trivy vs Grype 2026](https://lucaberton.com/blog/trivy-vs-grype-2026/) |
| CodeQL | Not wired as a default adapter (documented, not implemented) | Deeper interprocedural analysis, GitHub-native; heavier (compiles a DB first) and license/usage terms are narrower outside GitHub-hosted repos. Worth adding as an opt-in adapter for critical repos following the same `ToolResult`-returning pattern as the others |
| TruffleHog | **Deliberately not added**, despite being a common Gitleaks pairing in research | Its headline feature — verifying a found credential is live by actually using it — directly conflicts with this project's own engagement rule (never use a discovered secret). If you add it, keep `--no-verify` as the hard default and gate `--verify` behind the same kind of explicit, audited opt-in `scope.py` uses for active recon |

Sources consulted: [AppSec Santa SAST tools](https://appsecsanta.com/sast-tools), [Greptile – best SAST tools](https://www.greptile.com/content-library/best-sast-tools), [Cyber Security News – top SAST tools](https://cybersecuritynews.com/best-sast-tools-2/amp/), [AppSec Santa – Gitleaks vs TruffleHog](https://appsecsanta.com/secret-scanning-tools/gitleaks-vs-trufflehog), [jit.io – TruffleHog vs Gitleaks](https://www.jit.io/resources/appsec-tools/trufflehog-vs-gitleaks-a-detailed-comparison-of-secret-scanning-tools), [AppSec Santa – open source SCA tools](https://appsecsanta.com/sca-tools/open-source-sca-tools), [toolradar – Trivy vs Grype](https://toolradar.com/compare/trivy-vs-grype).

## The `recon` engine: tool research

| Tool / technique | Role here | Why |
|---|---|---|
| **Certificate Transparency (crt.sh)** | Primary passive asset discovery | Unchanged from the predecessor pipeline — it's genuinely the right default: zero traffic to the target, every historically-issued TLS cert is permanently logged |
| **DNS-over-HTTPS fallback for resolution** | New in this project | The predecessor pipeline documented real pain here: the local/corporate resolver on its network simply would not resolve certain hostnames, forcing a manual multi-DNS-server retry loop. `janus/engines/recon/passive.py::resolve_host` tries the stdlib resolver first and falls back to Cloudflare's DoH JSON API — no admin rights, no extra binary, no `/etc/hosts` surgery |
| **Passive header/cookie/CORS/sensitive-path checks (builtin)** | Always-on baseline | Zero dependency, GET-only, and — per the project's own engagement rules — this category (missing headers, CORS misconfig, cookie flags, SPF/DMARC, a handful of well-known exposed paths with SPA-fallback detection) is exactly what's safe to check before any written active-testing authorization exists |
| **nuclei** | Optional active scanning (`--mode active`, needs `allow_active_recon = true`) | Still the right template-driven scanner for known-CVE/misconfig signature matching — Apache/MIT-licensed-CLI-with-paid-cloud-tier per research, thousands of community templates. Kept at a conservative default (`-etags intrusive,dos,fuzz,bruteforce,default-login,headless`, severity `critical,high,medium`) matching the predecessor's own conservative settings |
| **OWASP ZAP** | **Recommended addition, not yet implemented** | Research gap identified: nuclei is template-driven (matches *known* patterns) and never actually crawls or fuzzes an application the way a human pentester would. ZAP's active crawl + authenticated-session + fuzzer fills exactly that gap and is the most-cited open-source complement to a nuclei-only setup. Next adapter to add, following the same `ToolResult` pattern |
| **subfinder / OWASP Amass** | Optional passive-source enrichment | `subfinder` is wired as an optional adapter (same graceful-skip pattern). Amass is the more complete option per research (chains more sources, graph-based asset mapping) but adds real complexity (brute-force/permutation modes need to stay off by default here) — documented as a future adapter rather than rushed in |
| **Strix** | Optional AI-agent layer (`--mode agent`, needs both `allow_active_recon` and `allow_agent = true`) | Confirmed current (Nov 2026 research) as an actively maintained, Apache-2.0, sandboxed autonomous pentest agent — validates that the predecessor pipeline's choice was and still is reasonable, not a stale pick. Reference adapter in `janus/engines/recon/agent.py` |
| PentestGPT / PentAGI | Documented alternatives, not wired by default | PentestGPT is a reasoning layer better suited to human-in-the-loop use than unattended runs; PentAGI is a credible self-hosted multi-agent alternative if Strix's Docker-sandbox model doesn't fit your infrastructure. Swapping either in means implementing `AgentAdapter` (one method) and registering it in `AGENT_BACKENDS` |
| CAI | **Deliberately not adopted** | Multiple October/November 2026 sources flag its maintenance status as uncertain (possibly archived/relicensed); verify the repository directly before building anything on it |

Sources consulted: [dev.to – open source autonomous AI pentesting tools 2026](https://dev.to/darkmoonx/open-source-autonomous-ai-pentesting-tools-in-2026-an-honest-field-guide-3ad0), [Strobes – 10 best open source agentic pentesting tools 2026](https://strobes.co/blog/open-source-agentic-pentesting-tools/), [Security Boulevard – same](https://securityboulevard.com/2026/07/10-best-open-source-agentic-pentesting-tools-in-2026/), [github.com/usestrix/strix](https://github.com/usestrix/strix), [blog.ostorlab.co – 9 open source AI pentest tools compared](https://blog.ostorlab.co/9-open-source-ai-pentest-tools-2026.html), [AppSec Santa – nuclei alternatives](https://appsecsanta.com/dast-tools/nuclei-alternatives), [dev.to – Nuclei vs traditional scanners 2026](https://dev.to/delmar_olivier_155f48bed1/nuclei-vs-traditional-vulnerability-scanners-in-2026-223k), [CloudSEK – open source attack surface management](https://www.cloudsek.com/knowledge-base/open-source-attack-surface-management), [OWASP Amass](https://github.com/owasp-amass), [OWASP ASM Top 10](https://owasp.org/www-project-attack-surface-management-top-10/).

## Dashboard: why embedded instead of DefectDojo/Faraday

Both are real, more capable platforms:

- **DefectDojo** — free, self-hosted, BSD-3-Clause, mature. Research caveat:
  the open-source edition's own comparison page states it cannot pull
  results from another tool's API directly — findings have to be exported
  from the scanner and imported — and its dashboard is comparatively basic
  (7-day counts, severity breakdown, a monthly trend). [docs.defectdojo.com](https://docs.defectdojo.com/get_started/about/defectdojo_versions/)
- **Faraday** — GPL-3.0 community edition, aimed at offensive teams,
  orchestrates 80+ tools. [appsecsanta.com – Faraday](https://www.appsecsanta.com/faraday-security)

Both need their own standing infrastructure (a database at minimum). For
"clone the repo, run one command, see your findings" — the portability this
project's brief explicitly asked for — a zero-infra, embedded dashboard
(`janus/dashboard/`: FastAPI + one static page, reads/writes the same
`register.json` the CLI uses, no build step) is the better default. It is
not a replacement for either platform at organizational scale: `janus
report` still emits SARIF, so a team already running DefectDojo, Faraday, or
GitHub/GitLab code scanning can feed those too, instead of this dashboard
being the only way to look at the data.

## What changed from the predecessor pipelines, concretely

- **Two separate ad-hoc findings registers → one shared `Finding` model and
  one `Register`.** Both engines used to invent their own JSON shape and
  their own merge logic; `janus/core/model.py` + `janus/core/store.py` are
  now engine-agnostic, so the dashboard, SARIF export, and CI gating all
  work identically regardless of which engine produced a row.
- **PowerShell-and-Windows-specific orchestration → a Python core with an
  optional Docker image.** The predecessor pipeline's own documentation
  lists real, time-consuming friction specific to that environment: a
  broken registry proxy, Windows `%APPDATA%`/`%TEMP%` write restrictions
  forcing environment-variable redirection for nuclei, a `ghcr.io` pull
  that reliably died after ~600MB–1.1GB requiring a mirror + manual image
  pinning against a Docker prune. None of that is specific to the actual
  *security* work — it's packaging friction. `janus/` runs on whatever runs
  Python 3.10+; `docker/Dockerfile` is the "don't fight your OS" option.
- **A config flag for "is active testing allowed" → a file-level, audited
  opt-in that's structurally separate from "is the agent allowed."** The
  predecessor prompts encoded engagement rules as *instructions to the
  model* ("do not brute-force," "do not use found secrets"). Janus encodes
  the hard constraints as code in `scope.py` instead — a prompt is advice
  an LLM can be talked out of; `SAFE_HTTP_METHODS` is not.
- **Ungrouped subdomain lists → wildcard-DNS-aware sampling.** The
  predecessor pipeline manually discovered that ~70% of one domain's
  "discovered" subdomains resolved to a single shared IP (a wildcard entry,
  not 140 independent services) and hand-built a one-off sampling script.
  `janus/engines/recon/passive.py::group_by_ip` + the CLI's
  `--max-hosts-per-ip` generalize that into the default discovery path.

## Multi-model agent ensemble + harness-agnostic setup

Added after the first review pass, at the user's explicit request for two
things: (1) the agent layer shouldn't depend on one single model/vendor,
and (2) setup should be easy enough to hand to a team that doesn't want to
learn a new CLI — "give it to a coding agent and let the agent run it."

**Why an ensemble, not a single configurable backend.** The original ask
was specifically DeepSeek + GLM + OpenAI/Codex together, not "pick one."
That maps to a real, documented phenomenon, not just vendor-coverage for
its own sake: different models have different blind spots on the same
code/target, so running the same agent step through several models and
merging results finds more than any single model does alone. Implementation:
`janus/core/providers.py` defines named provider profiles (base_url, model,
api_key_env — never the key itself), and `janus/engines/recon/agent.py::run_ensemble`
runs the configured backend once per *available* provider (whichever has
its API key env var set — none are required), merging findings through the
same dedupe/fingerprint machinery every other adapter uses. Two providers
flagging the identical spot collapse into one row with both cited in
`extra.also_reported_by` — convergence across models becomes a visible
signal instead of silent duplication.

**Provider research (verified 2026-11-06 — defaults remain overrideable because
provider catalogues can change):**

- **DeepSeek**: the documented OpenAI-compatible base URL is
  `https://api.deepseek.com`, and `deepseek-flash` is the current stable alias
  for DeepSeek V4.1 Flash. The OpenRouter default pins the dated
  `deepseek/deepseek-v4.1-flash-1017` slug. ([DeepSeek API quick start](https://api-docs.deepseek.com/quick_start/agent_integrations/))
- **GLM / Zhipu / Z.ai**: Z.AI's current public docs list GLM-5.3 and
  GLM-5.3-FLASH and show the international endpoint
  `https://api.z.ai/api/paas/v4`. Mainland accounts can override to
  `open.bigmodel.cn`. ([Z.AI documentation index](https://docs.z.ai/llms.txt))
- **OpenAI / Codex**: the current OpenAI model catalogue recommends
  `gpt-6-astra` for complex reasoning and coding. The native agent selects
  OpenAI's Responses API for its tool calls; `providers.toml` can override the
  model and wire format for an account-specific deployment.
  ([OpenAI model catalogue](https://developers.openai.com/api/docs/models))

**Why `AGENTS.md`, not three hardcoded per-vendor integrations.** The
original ask was "pick one of three agents, hand it an address/file/guide,
it sets up and runs the whole pipeline." Research found a real, confirmed
product for one leg of that — **OpenAI's Codex CLI** auto-discovers an
`AGENTS.md` at the repo root (now stewarded by the Linux Foundation's
Agentic AI Foundation as a cross-tool convention) and has a documented
headless mode (`codex exec --full-auto`) suited to exactly this use. [OpenAI Codex CLI docs guide (codex.danielvaughan.com)](https://codex.danielvaughan.com/2026/04/19/openai-codex-cli-official-documentation-guide/)
Research did **not** find an equivalently dominant, official "DeepSeek CLI"
or "GLM CLI" product — what exists for GLM is a handful of community
terminal agents (`@guizmo-ai/zai-cli`, OpenCode wired to GLM, Claude Code
via GLM's Anthropic-compatible endpoint) rather than one obvious choice.
[Best Agentic CLI Coding Tools for GLM (slashdot.org)](https://slashdot.org/software/agentic-cli-coding-tools/for-glm-5/), [zai-cli (pkgstats.com)](https://www.pkgstats.com/pkg:@guizmo-ai/zai-cli)

Given that, hardcoding three special-cased integrations would mean building
two of them against unverified, possibly-wrong product assumptions. Instead,
`AGENTS.md` is written **harness-agnostic**: the actual instructions (check
environment, ask the human for scope rather than inventing it, write
`scope.toml`, run both engines, confirm before enabling active/agent mode,
report back) don't depend on which specific CLI product is reading them.
Codex CLI gets this for free via auto-discovery; point any other capable
coding agent — one you've wired to DeepSeek or GLM through whatever CLI you
use — at the same file explicitly. This is more honest than three
integrations built on research this uncertain, and it's one file to
maintain instead of three.

## Honest gaps / roadmap

- **OWASP ZAP adapter**: researched and recommended above, not yet
  implemented.
- **Amass adapter**: documented as the more-complete alternative to
  `subfinder`, not yet implemented (its brute-force/permutation modes need
  careful default-off handling before they are).
- **CodeQL adapter**: documented, not yet implemented (needs a DB-build step
  the other adapters don't).
- **`janus triage` (`janus/triage.py`) — partially verified.** It bridges
  TRIAGE.md to a real coding-agent CLI (Codex or Claude Code) instead of a
  human manually pasting the protocol into a chat session — the concrete
  answer to "different AI agents, with their own tools, doing a complete
  review," for the source-code side specifically. What's actually
  confirmed: both `codex` and `claude` were found correctly via
  `find_tool()` on a machine that has them installed (the detection/
  gating logic is real, not assumed). What's NOT confirmed: an actual
  `codex exec --skip-git-repo-check "<prompt>"` invocation was started for
  real against this repo and deliberately stopped a few seconds in, rather
  than let an unbounded, costly, speculative agent run continue
  unsupervised during a build/review task — so the exact flags, the
  read-only-by-default behavior they're relying on, and the output shape
  are research-backed, not end-to-end proven. Treat this command as
  "try it, read what comes back" rather than "trust it blind" until you've
  run it once yourself; a wrong flag fails loudly (`status: "failed"`
  with the subprocess's stderr), it does not fail silently.
- **Provider defaults (`janus/core/providers.py`) are unverified against
  live API calls** — no real API key was available to test an actual
  request against DeepSeek/GLM/OpenAI during development (and doing so
  wasn't in scope for a review/build task). The provider-resolution logic
  itself (which providers are "available," env var checking, overrides via
  `providers.toml`) is unit-tested; the `base_url`/`model` defaults are
  research-backed best-effort, explicitly labeled as such in the same file
  and in USAGE.md — confirm the exact model name against each provider's
  current docs before relying on one in CI.
- **Agent output parsing (`StrixAdapter`) is defensive but unverified
  against a live run in this environment** — Strix's own JSON/SARIF shape is
  a moving target across versions; treat a parse mismatch as "update the
  adapter," not "the agent found nothing," and verify against your
  installed version before relying on it in CI.
- **`docker/Dockerfile` pulls each external tool from that project's own
  official image via multi-stage `COPY --from`**, which is more durable than
  hand-built download URLs but still depends on each project keeping its
  binary at the path this Dockerfile expects. Verification status, built
  live against this Dockerfile in the sandboxed environment Janus was
  developed in: the four `COPY --from` stages (trivy, gitleaks, nuclei,
  subfinder) all succeeded on the first attempt — those paths are confirmed
  correct, not guessed. The two `pip install` layers (`semgrep`, then
  `janus` itself and its runtime dependencies) could **not** be verified:
  that sandbox's Docker *build* containers cannot reach PyPI at all (DNS/
  connection errors, retried and still failing even with
  `docker build --network=host`), while the *host's* own `docker pull` of
  the five base images above worked fine seconds earlier — a container-
  network-vs-host-network split specific to that sandbox, not evidence of
  a Dockerfile bug. The predecessor pipelines' own documentation describes
  the same host having unusual general-internet egress (a system proxy on
  a non-standard port, `ghcr.io` pulls that needed a mirror), so this looks
  like the same class of issue, now showing up as "containers can't reach
  `pypi.org`" instead. This is an ordinary two-line `pip install`; it
  should work in a normal dev machine or CI runner. The `semgrep` line is
  already wrapped in `|| echo ... ` so a PyPI-restricted build still
  produces a working image (without semgrep) rather than failing outright
  — the final `RUN pip install --no-cache-dir .` is not wrapped that way on
  purpose, since a Janus image without `janus` itself installed isn't a
  usable image. If you hit the same restriction, point `pip` at an internal
  index (`--index-url`) or a wheel cache baked into an earlier layer.
- **No scheduled/continuous mode yet** — research on attack-surface
  management consistently recommends re-running discovery on a cadence to
  catch drift; today you'd cron `janus scan recon` yourself. A `--since`
  / baseline-diff mode (skip re-reporting findings already triaged) is the
  natural next step and the `Register.merge()` semantics already support it
  (a finding not seen this run keeps its last known status rather than
  disappearing).
