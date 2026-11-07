# Using Janus - the complete guide

This is the full walkthrough. For a 30-second version see README.md
"Quickstart"; for the design reasoning behind any of this see
ARCHITECTURE.md. If you want a coding agent (Codex CLI, or another CLI
pointed at DeepSeek/GLM) to do all of this for you automatically, see
"Letting an agent run this for you" near the end - but read at least
"Which parts actually use AI" first, since that section answers the
question people usually have before handing this to anyone or anything.

## 1. Install

```bash
pip install -e .
janus doctor   # shows which optional external tools AND which LLM providers are available
```

That's the whole native install. `janus doctor` never fails - it just
tells you what you have. Nothing in Janus requires any of the optional
tools or any LLM provider to produce useful output; see the coverage table
below.

Prefer not to install anything natively? `docker build -t janus -f
docker/Dockerfile .` builds an image with every optional external tool
preinstalled (semgrep/gitleaks/trivy/nuclei/subfinder) - see
`docker/Dockerfile`'s comments for its one known gap (the image can't be
built on a network that blocks PyPI from inside a Docker build context;
unrelated to Janus's own logic, see ARCHITECTURE.md "Honest gaps").

## 2. Set up an engagement (`scope.toml`)

Nothing scans anything without a `scope.toml` - see README.md "Responsible
use" for why this file is mandatory and what it enforces. Two ways to get
one:

**Guided (fastest, recommended):**

```bash
janus init --dir my-engagement --interactive
```

Answers a handful of questions (operator label, which domains, which
repo paths, whether to turn on active/agent recon right now) and writes a
ready-to-use `scope.toml`. Say no to active/agent recon if you're not sure
yet - you can flip those on later by editing the file.

**Manual:**

```bash
janus init --dir my-engagement
```

Writes a template with `CHANGE_ME` placeholders; open `my-engagement/scope.toml`
and fill them in. Every field is commented.

## 3. Run the engines

```bash
janus scan code  --scope my-engagement/scope.toml --out my-engagement/out
janus scan recon --scope my-engagement/scope.toml --out my-engagement/out
```

`scan code` always runs fully (it only reads files you already have access
to). `scan recon` defaults to `--mode passive` - low-impact, GET-only, no
scope.toml flag needed beyond the host being in `targets.allow`. Two
further modes need an explicit opt-in **in scope.toml itself**, not just a
CLI flag (see README "Responsible use" for why it's split this way):

```bash
# needs [limits] allow_active_recon = true in scope.toml
janus scan recon --scope my-engagement/scope.toml --out my-engagement/out --mode active

# needs allow_active_recon = true AND allow_agent = true in scope.toml,
# plus at least one LLM provider's API key set (see section 4)
janus scan recon --scope my-engagement/scope.toml --out my-engagement/out --mode agent \
  --agent-providers deepseek,glm,openai
```

Either run exits `0` (nothing at/above `--fail-on`, default `high`), `1`
(something is - the thing to gate CI on), or `2` (the scope file itself is
invalid/expired/disabled - a setup problem, not a finding).

## 4. Which parts actually use AI - and which models

This is the question to answer before you decide what you need configured.

| Piece | Uses AI? | What it actually is |
|---|---|---|
| `code` engine - builtin rules | **No** | Regex/entropy pattern matching, zero dependencies |
| `code` engine - Semgrep/Gitleaks/Trivy adapters | **No** | Deterministic static-analysis tools, if installed |
| `recon` engine - passive checks (headers, CORS, cookies, sensitive paths, SPF/DMARC, discovery) | **No** | Plain HTTP requests + DNS/CT-log lookups |
| `recon` engine - `--mode active` (nuclei) | **No** | Template/signature matching, if nuclei is installed |
| `recon` engine - `--mode agent` | **Yes** | An LLM-driven pentesting agent (Strix by default) forms hypotheses and verifies them with live requests |
| `janus triage` (optional, separate command) | **Yes** | Hands TRIAGE.md's review protocol to a coding-agent CLI (Codex/Claude Code) for deep source-level review |

So: everything except `--mode agent` and the separate, optional `janus triage`
command runs with **zero** LLM calls and **zero** API keys. If you only ever
run `scan code` and `scan recon` in passive/active mode, no AI is involved
anywhere in the pipeline, period.

### The `--mode agent` layer, specifically

`--mode agent` drives an agent backend (Strix, github.com/usestrix/strix,
is the one wired in `janus/engines/recon/agent.py`) with an LLM you choose.
Four provider profiles ship built in (`janus/core/providers.py`), each
needing one environment variable:

| Provider name | Env var | Default endpoint |
|---|---|---|
| `deepseek` | `DEEPSEEK_API_KEY` | DeepSeek's own API |
| `glm` | `GLM_API_KEY` | Zhipu/Z.ai GLM |
| `openai` | `OPENAI_API_KEY` | OpenAI (GPT-6 Astra) |
| `openrouter` | `OPENROUTER_API_KEY` | OpenRouter - one key, many providers/models |

`janus doctor` shows exactly which of these are ready right now (by
checking whether the env var is set - it never reads or prints the value).

**Why a list of providers, not just one:** `--agent-providers deepseek,glm,openai`
(the default) runs the SAME agent backend once per provider that actually
has a key configured, and merges the findings - this is a real coverage
gain, not just flexibility for its own sake: different models have
different blind spots, so three runs with three models surface things one
model misses. Only set one key? It silently runs with just that one -
nothing breaks, nothing is required to be "complete." Findings two
providers both flag on the same spot merge into one row and say so (see
`extra.also_reported_by` in a finding), so convergence across models is
visible, not hidden.

Set only the keys you actually have:

```bash
export DEEPSEEK_API_KEY=...     # pick any subset
export GLM_API_KEY=...
export OPENAI_API_KEY=...
# or just:
export OPENROUTER_API_KEY=...   # and point providers at openrouter instead - see below
```

Using OpenRouter instead of (or alongside) direct provider keys: pass
`--agent-providers openrouter` (or add it to the list), and set the model
OpenRouter should route to by overriding it in a small `providers.toml`:

```toml
[providers.openrouter]
model = "deepseek/deepseek-v4.1-flash-1017"   # any OpenRouter model slug
```

then `janus scan recon ... --mode agent --agent-providers openrouter --providers-file providers.toml`.

The built-in defaults are verified against the current public catalogues, but
model access is account-specific. Run `janus doctor --check-models` to ask
each configured provider which IDs your key can reach; override a model with
`--providers-file` without touching code. OpenAI's GPT-6 Astra profile uses
the Responses API for tool calls, while the other built-ins use the
OpenAI-compatible Chat Completions endpoint.

### What the agent layer is NOT

It is not required for anything else in Janus to work, it is not a general
"make Janus smarter" switch, and it is not the same thing as "letting an
AI coding agent run Janus for you" (that's a different layer - an
orchestrator OUTSIDE Janus driving the `janus` CLI itself, covered next).
You can use neither, either, or both.

## 5. The dashboard

```bash
janus dashboard --register my-engagement/out/register.json
# or, with zero setup, synthetic example data:
janus demo
```

Opens `http://127.0.0.1:8787`, binds to localhost only. Filter/search/sort
findings, expand one for the full detail, change its status (open /
needs-review / fixed / ruled-out / accepted-risk) and add a note - saved
straight back to `register.json`. No AI involved here either; it's a plain
FastAPI app reading/writing a JSON file.

## 5b. Deep triage with a coding-agent CLI

The deterministic tools produce candidates; deciding which `critical`/`high`
rows are real needs someone (or something) reading the actual source/target
and tracing source to sink. `TRIAGE.md` is that protocol, written to be
followed by any capable AI agent - and `janus triage` is a thin bridge that
hands it to a real coding-agent CLI instead of you pasting it into a chat
session by hand:

```bash
janus triage --agent codex  --repo . --out out/triage-report.md
janus triage --agent claude --repo . --out out/triage-report.md
```

Each backend is invoked in that CLI's safer, read-only(-by-default) mode
(`codex exec` without `--full-auto`) specifically so this can't do anything
worse than produce a bad report - it writes its OWN output file from the
subprocess's stdout rather than trusting the invoked agent to write files
on disk itself. Skips cleanly (`status: skipped`) if neither CLI is
installed. **This is the newest, least-tested piece of Janus** - the exact
flags are research-backed, not proven against every version; see
ARCHITECTURE.md "Honest gaps" before relying on it in CI. Worth running
with a *different* model/agent than whatever drove the scan itself - a
second opinion from a different model is the point, not redundant effort.

## 6. Letting an agent run this for you

If you'd rather hand the whole setup-and-run loop to an AI coding agent
instead of typing the commands above yourself: open a session in
whichever agent CLI you have (OpenAI's Codex CLI reads `AGENTS.md` from
the repo root automatically; point any other agent - one you've configured
against DeepSeek or GLM - at the same file explicitly, e.g. "read
AGENTS.md and follow it"), and tell it what you want scanned. `AGENTS.md`
walks it through: checking the environment, asking YOU for scope details
(it is instructed not to invent target domains or source roots), writing
`scope.toml`, running both engines, and reporting back. Active and agent modes
remain explicit operator-selected options rather than assumptions.

This is a separate concern from section 4's "agent ensemble": that's an
AI model being used *inside* one scan step; this is an AI coding agent
*driving the whole CLI* as your operator. You can use either without the
other - run `janus` by hand with `--mode agent` fully configured and never
touch a coding-agent CLI, or have Codex (or a DeepSeek/GLM-backed agent)
run everything in passive-only mode and never touch an LLM provider key.

## Troubleshooting

- **"scope error: ..." and exit code 2.** The scope file itself is the
  problem (expired window, missing `authorized_by`/`reference`, a `[code].roots`
  path that doesn't exist) - fix the file, this isn't a scan result.
- **"refused: ..." on `scan recon --mode active/agent`.** `scope.toml` doesn't
  have `allow_active_recon`/`allow_agent` set to `true` - that's enforced on
  purpose, see README "Responsible use."
- **A tool/provider shows up as skipped/missing.** Expected if you haven't
  installed it or set its key - `janus doctor` is the source of truth; the
  report also says which tools ran vs. were skipped so "0 findings" is
  never confused with "clean, fully tested."
- **Non-ASCII characters look garbled in an old Windows console.** Shouldn't
  happen in `janus`'s own CLI output (checked during development); if you
  see it in a report file instead, that's just your terminal's pager/viewer,
  not the file - the files themselves are UTF-8.
