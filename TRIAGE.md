# TRIAGE.md - deep review protocol for an AI agent

Janus's deterministic tools (builtin rules, Semgrep, Gitleaks, Trivy, nuclei,
the passive recon checks) produce **candidates**, not verdicts — that split
is deliberate (see ARCHITECTURE.md principle #1: "deterministic tools, agent
interpreter"). This file is the protocol for the interpreter half: an AI
agent reading `findings.json` plus the actual source/target and deciding,
for each `critical`/`high` row, whether it's real.

This is a harness-agnostic protocol, the same way `AGENTS.md` is — it
doesn't matter whether the agent running it is Claude Code, OpenAI's Codex
CLI, or something driven by DeepSeek/GLM. What matters is that it has
file-read access to the scanned repo (and, for recon findings, the ability
to make the same GET requests Janus itself made) and follows this
structure. Point any capable agent at this file explicitly ("triage the
findings in out/findings.json using TRIAGE.md") when you want a second,
deeper pass beyond what the deterministic tools alone produced — including
running it with a **different model/agent than whatever drove the scan
itself**, which is real signal, not redundant effort: a different model
reading the same code catches different false positives and different
real bugs, the same reasoning behind the multi-provider ensemble in
`janus/engines/recon/agent.py` (see USAGE.md "Which parts actually use AI").

## Before you start

- Read the `scope.toml` this run used (named in `findings.json`'s `meta`).
  Triage within that scope; do not widen it, fetch anything outside
  `targets.allow`, or send anything beyond GET/HEAD to a recon target —
  you're reviewing evidence, not re-running the scan.
- Load `out/findings.json`. Treat every row's `confidence` field as a
  starting point, not a conclusion — `needs-review` rows are exactly what
  this protocol exists for; `confirmed` rows from a deterministic tool
  (e.g. a cookie flag check) usually don't need deep triage, spend your
  time on the ambiguous ones.

## For each `critical`/`high` finding

Answer these, in order, and stop early if an earlier answer already rules
it out:

1. **Where does the input come from?** Trace backward from the `sink`
   (the dangerous call/line the tool flagged) to its `source`. Is it
   actually attacker-reachable, or is it a constant, a config value, or
   something only an already-trusted caller controls?
2. **What sits between source and sink?** Validation, an allowlist, an
   auth check, a framework-level escaping step. A rule firing on `eval()`
   next to a hardcoded dispatch table is not the same finding as `eval()`
   on a raw request body.
3. **Who can trigger it, and what do they need?** Anonymous internet
   user? An authenticated user acting on another user's data (the IDOR
   shape)? A staff account only? Note the precondition explicitly — it
   changes severity more than almost anything else.
4. **What's the actual impact if it fires?** Read/write which data, which
   scope (one record, one tenant, everything)? Code execution, or just an
   error message? Be as narrow and literal as the evidence supports —
   "theoretical RCE path, unconfirmed" is a legitimate, useful output; it
   is not the same claim as "RCE."
5. **For recon findings specifically**: do NOT re-fetch the target to
   "confirm" anything beyond what the original GET/HEAD already showed,
   and never use a credential/secret the scan found. If confirming would
   require a request Janus's own `scope.py` wouldn't allow (state-
   changing, out of scope, non-GET), don't send it — note what would be
   needed to confirm and mark the finding accordingly instead.

## Output format (one block per finding you reviewed)

```
### [fingerprint-prefix] <title> — <your severity> — <your verdict>

- Verdict: confirmed / likely / false-positive / needs-runtime-verification
- Source -> sink: <concrete trace, file:line or request path>
- Precondition: <what an attacker needs - auth, role, network position, nothing>
- Impact: <specific, bounded by what you actually traced>
- Why the tool's original severity was right / should change: <one line>
- Fix: <one or two concrete actions, prioritized>
```

Then update that finding's `status` via the dashboard or
`POST /api/findings/{fingerprint}/status` (`ruled-out` for a confirmed
false positive, leave `needs-review` -> you'd set it to `open` with a note
if you're escalating confirmed-real, or `accepted-risk` only if a human
operator explicitly tells you to accept it — don't set that one
yourself).

## Calibration — don't inflate severity

- A `.git/config` or `/admin` route returning 200 is **reachability**, not
  a breach. Don't call it "confirmed compromise"; call it "confirmed
  reachable, unauthenticated" and let the actual content (or lack of it)
  of the response decide the rest.
- A credential/key found in source or a JS bundle is **confirmed exposure**
  of that credential — but "confirmed exposure" and "confirmed this key
  currently has write access to production" are different claims; don't
  make the second one without evidence, and never test it by actually
  using the key (see Janus's own engagement rules in `janus/engines/recon/agent.py`'s
  `BASE_POLICY` — they apply to you too).
- A code pattern that LOOKS like it should be exploitable but needs a
  precondition that isn't actually reachable in this codebase (an internal-
  only endpoint, a value that's always a constant in practice) is a
  `false-positive` for THIS codebase, even if the same regex match would
  be real somewhere else — note the precondition so the next person
  doesn't have to re-derive it.

## When you're done

Summarize once, at the end, not per-finding: total findings reviewed, how
many confirmed vs. ruled-out vs. still needs-runtime-verification, and the
3 fixes with the best impact-to-effort ratio. Be honest about coverage —
"I reviewed the 8 critical/high findings; I did not review medium/low" is
a more useful sentence than silence on the question.
