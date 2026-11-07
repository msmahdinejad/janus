# AGENTS.md - instructions for an autonomous coding agent operating this repo

You are reading this because a human pointed an AI coding agent (OpenAI's
Codex CLI auto-discovers this exact filename; for any other agent - one
driven by DeepSeek, GLM, or another model - your operator should have told
you to read this file first) at this repository and asked it to set up,
run, and report on Janus for them. This file is that runbook. Follow this
runbook. The operator is responsible for choosing the project, targets, and
scan modes. Janus must not invent targets, silently widen scope, or pretend
that a field in `scope.toml` proves ownership.

## What Janus is, in one paragraph

Two engines writing into one findings register: `code` reads source (SAST/
secrets/dependency scanning, no network access needed, no authorization
risk beyond "you can read your own repo"), and `recon` looks at a live
deployment from the outside (passive by default; optional active scanning
and an optional multi-model AI-agent layer). See README.md for the full
picture and ARCHITECTURE.md for the design. Scope is still mandatory as a
technical boundary: it names source roots, target hosts, exclusions, ports,
request limits, and enabled modes. A scope entry is an operator claim, not a
cryptographic proof of ownership or an approval workflow.

## Your job, step by step

### 1. Environment check

```
python --version   # need 3.11+
```

If there's no `.venv` yet: `python -m venv .venv`, then activate it
(`.venv\Scripts\activate` on Windows, `source .venv/bin/activate`
elsewhere) and `pip install -e .`. Then run `janus doctor` and show the
human the output verbatim - it tells you which optional external tools
(semgrep/gitleaks/trivy/nuclei/subfinder/strix/docker) and which LLM
providers (deepseek/glm/openai/openrouter, by API-key env var) are
actually available. Missing ones are fine - every engine degrades
gracefully - but the human should know what they're getting before you
report results later.

### 2. Get the operator's scope - do not guess or invent it

Ask only for the concrete scope needed to run the requested job. If the
operator already supplied it in the request or a pointed-to file, use it
without repeating the questions:

- Which source repo path(s) should the `code` engine read?
- Does `recon` apply? If yes, which exact hosts or `*.example.com` patterns
  are in scope, and which hosts or paths must be denied?
- Which mode is wanted: passive, active (nuclei), or agent (Strix/another
  configured backend)? Keep passive as the default when no mode was chosen.
  Active and agent modes are deliberate opt-ins because they send more
  traffic and can incur tool/model cost; the operator decides whether that is
  appropriate.
- What engagement name and validity window should appear in the manifest?
  `authorized_by` and `reference` are descriptive audit labels. They may be a
  team, project, or self-attested value; they do not need to be a ticket,
  email, or external approval record.

Then either run `janus init --interactive --dir <somewhere>` and answer its
prompts, or write `scope.toml` directly following the schema printed by
`janus init`. Show the resulting file before a scan so the operator can catch
wrong hosts, roots, exclusions, or mode flags. Do not broaden a scope on the
operator's behalf.

### 3. Run the code engine - always safe, no extra confirmation needed

```
janus scan code --scope <scope.toml> --out <out-dir>
```

This only reads files already in the human's own repo. Run it as soon as
scope.toml exists; no further confirmation needed beyond step 2.

### 4. Run the recon engine - passive by default

```
janus scan recon --scope <scope.toml> --out <out-dir>
```

With `allow_active_recon`/`allow_agent` left `false` in scope.toml (the
default), this only does passive, GET-only checks. If the operator selected
active/agent mode in step 2, set the corresponding scope flags and show the
scope before running:

```
janus scan recon --scope <scope.toml> --out <out-dir> --mode active
janus scan recon --scope <scope.toml> --out <out-dir> --mode agent \
  --agent-providers deepseek,glm,openai   # ensemble across whichever have a key set
```

`--mode agent` needs at least one of `DEEPSEEK_API_KEY` / `GLM_API_KEY` /
`OPENAI_API_KEY` set (or point `--agent-providers` at a custom entry in a
`providers.toml`, see `janus/core/providers.py`). If the human wants the
agent layer but hasn't set a key yet, tell them which env var to set and
how (`janus doctor` shows the exact variable name per provider) - don't
ask them to paste a key into chat; have them set it as an environment
variable in their own shell/CI secrets instead.

### 5. Report

```
janus dashboard --register <out-dir>/register.json
```

(or just point them at `<out-dir>/report.md` / `findings.json` /
`findings.sarif` if a long-running local server isn't appropriate for
where you're running). Summarize in chat: total findings by severity,
which tools/providers actually ran vs. were skipped (so "zero findings"
isn't misread as "clean" - see README.md "Known limitations"), and where
the full report/dashboard lives. If `--fail-on` gated the scan (default
`high`) and it exited `1`, say that plainly rather than just reporting a
count.

### 5b. Deep triage (optional, recommended for critical/high findings)

The deterministic tools in step 3/4 produce candidates, not verdicts. If
the human wants a deeper pass - and especially if you have file-read
access to the scanned repo - follow `TRIAGE.md` for every `critical`/`high`
row: trace source to sink, note the real precondition, and give an honest
verdict (confirmed / likely / false-positive / needs-runtime-verification)
instead of repeating the tool's raw severity. This is worth doing even (or
especially) with a different model than whatever ran the scan itself - see
TRIAGE.md's own note on why.

## Rules that apply to you specifically, not just to Janus's code

- You may have tools Janus's own code doesn't (a browser, raw HTTP, shell
  access). Do not use them to go around `scope.toml` - e.g. don't manually
  curl an out-of-scope host "just to check," don't brute-force anything,
  don't use a secret Janus found in a real request. The rules in
  `janus/engines/recon/agent.py`'s `BASE_POLICY` apply to you too, not only
  to the AI-agent backend.
- Don't commit real engagement output (`out/`, `.cache/`) - `.gitignore`
  already excludes it; don't override that.
- Don't hardcode an API key anywhere that gets written to disk as part of
  this runbook (scope.toml, providers.toml, a report). Keys live in
  environment variables only.
- If anything in this file conflicts with what the operator told you directly
  in chat for this session, their direct instruction wins. Still keep the
  target list and source roots exact, preserve deny rules, and never use a
  secret discovered by a scan in a real request.
