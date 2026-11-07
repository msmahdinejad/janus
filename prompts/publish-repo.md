# Publish brief — turn Janus into a credible public repository

Paste this into a fresh Claude session with repository access to `D:\Janus`.
It assumes the product review is already done (`prompts/review-project.md`);
this brief is about **presentation, assets and publishing**, not redesigning
features.

---

You are an open-source maintainer preparing a security tool for public release.
The code works and is tested. Your job: make the repository look and read like a
project a security engineer would trust in five minutes, then publish it.

## Product facts (do not invent beyond these)

- Two engines: source scanning (builtin rules + gitleaks/trivy/semgrep) and
  scoped external recon (passive checks, JS-bundle secrets, infra fingerprints,
  optional nuclei, optional AI agents).
- One normalized finding model → one register → Markdown / JSON / SARIF, plus
  `coverage.json` that states what was **not** tested.
- `scope.toml` is the authorization gate: allow/deny, ports, forbidden paths,
  validity window, private-IP opt-in. GET/HEAD/OPTIONS by default; write-path
  testing is opt-in, staging-only, with `DELETE` refused by construction.
- Agents: `native` (in-process, scope-bound HTTP only) and `strix` (external
  container behind an allowlist proxy).
- Local dashboard, no build step, no telemetry, no cloud: current findings,
  triage, and per-run history at `#/scans`.
- 113 tests, CI workflow present.

## What to produce

### 1. Assets (from real runs only)

```bash
python examples/lab_app/server.py --port 8099
janus scan all --scope engagements/lab-full/scope.toml --out demo/everything \
  --mode agent --lens all --fail-on none
janus dashboard --register demo/everything/register.json
```

- `docs/assets/dashboard-overview.png` (≥1600px)
- `docs/assets/scan-history.png` (the `#/scans` list, with deltas visible)
- `docs/assets/scan-detail.png` (one run: KPIs, engine status, findings)
- `docs/assets/demo.gif` (10–15s: overview → scans → detail → triage)
- `docs/assets/architecture.svg` (engines → register → reports → dashboard)

Sanitize: no internal hostnames, no keys, no personal data. `example.test` and
the lab target are safe to show. If an asset cannot be produced from a real run,
do not fake it — omit it and say so.

### 2. README (the shop window)

Order: name + one-line value proposition + hero screenshot → badges (CI,
Python, license) → "why this exists" (five prompts and a spreadsheet is not a
pipeline; a findings list without coverage is not a report) → **two-minute
quickstart** with demo data → feature tour using the assets (code engine,
external engine, agents, coverage contract, **scan history**) → authorization
model (prominent, non-negotiable) → provider matrix → CLI/scope reference →
architecture → FAQ (false positives, cost, CI, air-gapped) → contributing,
security policy, license.

Tone: precise, dry, no hype. Every claim must map to a command that works.
Keep the existing `docs/QUICKSTART.fa.md` and `docs/AGENT-GUIDE.md` links.

### 3. Repository hygiene

- `SECURITY.md` (how to report; explicit "authorized targets only" statement),
  `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `CHANGELOG.md` with a `0.2.0` entry
  (hardening, write-path, scan history, Strix support).
- CI: matrix Python 3.11/3.12/3.13, `pytest -q`, and a job that runs
  `janus scan code` on `examples/demo-fixture` to prove the CLI end to end.
- Issue templates: bug, feature, false positive; PR template with a checklist
  (tests, docs, no secrets in fixtures).
- `.gitattributes` for LF normalisation (developed on Windows).
- Topics: `security`, `sast`, `dast`, `penetration-testing`, `ai-agents`,
  `sarif`, `llm`, `bug-bounty`, `python`.
- Description: "Two-engine security pipeline: source scanning + scoped external
  recon, one register, SARIF out."

### 4. Publish

1. Full suite green and a demo scan run before publishing.
2. `git tag v0.2.0` with notes grouped Added / Changed / Fixed / Security.
3. `gh repo create <owner>/janus --private --source . --push`; verify the
   rendered README and images; then flip public.
4. Social preview (1200×630) from the overview screenshot.
5. Open one issue per deferred UI item and one "good first issue" for docs.

## Acceptance checklist (report pass/fail for each)

- [ ] `pytest -q` green; CI green on the pushed commit.
- [ ] Quickstart works from a clean clone in under two minutes (Linux + Windows;
      note platform caveats).
- [ ] `#/`, `#/scans`, `#/scans?id=<run>` render correctly with real data.
- [ ] A 5,000-finding register stays interactive.
- [ ] Every image in the README exists and matches the current UI.
- [ ] No secret, internal hostname or personal data anywhere (`git grep` for key
      shapes; inspect fixtures).
- [ ] Every README command was actually run.
- [ ] `SECURITY.md` and the authorization section are unambiguous.
- [ ] Release `v0.2.0` exists with notes and assets.

## What to hand back

The public URL, the release URL, the CI run URL, every file added/modified, and
anything you could not verify.
