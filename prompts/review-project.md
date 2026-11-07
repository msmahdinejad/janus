# Review brief — UI/UX + architecture (fix, don't shrink)

Give this to a fresh Claude session with repository access to `D:\Janus`.
It is self-contained.

---

You are a senior product designer **and** staff engineer reviewing a finished
security tool. Your job is to make it *work well and look intentional* — not to
make it more cautious, smaller, or more "minimal". **Do not remove capabilities,
do not weaken the authorization model, do not turn features off to make the UI
simpler.** Fix what is broken, finish what is half-done, and keep every test
green.

## The product in one paragraph

Janus is a two-engine security pipeline for teams testing their own systems.
The **code engine** does SAST + secrets + dependency/IaC scanning. The
**external engine** does scoped recon: headers/cookies/CORS, sensitive paths,
JS-bundle secrets, sourcemaps, infra fingerprints, SPF/DMARC, optional nuclei,
and optional AI agents (`native` in-process, or `strix` in a container behind an
allowlist proxy). A scope file gates every request; findings land in one
register with Markdown/JSON/SARIF exports plus a `coverage.json` that states
what was **not** tested. A local dashboard shows current state, triage, and a
per-run scan history. Write-path testing is opt-in and staging-only
(`[[write.targets]]` + `allow_state_changing`).

Current state you must preserve: **113 passing tests**, `janus` CLI with
`scan code|recon|all`, `doctor`, `dashboard`, `proxy`, `llm-shim`, `triage`,
`report`, `demo`. The dashboard is vanilla JS (no build step, no external
requests, no telemetry).

## Part 1 — The scan history UI is the weakest surface. Fix it properly.

The history lives at `#/scans` and `#/scans?id=<run_id>` inside the same SPA
shell. It works, but it is thin. Redesign it inside the existing design system
(do not build a second visual language, do not add a framework):

**List view**
- Make "what changed since last time" the headline, not a side column: a
  visible delta (`+N new / −N fixed / N same`) and a compact severity bar per
  run. Compare only runs of the same kind (code vs recon vs all).
- Group or filter by engagement; the current flat list will not survive 200
  runs. Add sorting (newest, most findings, most new) and pagination or
  virtualization.
- Empty state: explain how to produce the first run, with the exact command.
- Distinguish a clean run from a run where engines were `skipped` — a green
  "0 findings" that actually means "semgrep was not installed" is a lie.

**Detail view**
- Lead with the delta and the engine-status table; a run's credibility depends
  on what actually executed.
- Make findings filterable (severity, tool, confidence, status), sortable, and
  keyboard-navigable; expanding a row should reveal evidence/remediation
  without losing scroll position.
- Link out to `report.md` and SARIF (APIs exist). Show the coverage gaps as a
  first-class block, not a footnote.
- Add "compare with previous run of the same kind" (new/fixed lists), even if
  only as a filter preset.

**Craft**
- Contrast ≥ 4.5:1 in both themes; visible focus rings; no keyboard traps.
- Responsive to 768px: tables become cards or scroll deliberately.
- 5,000 findings in a historical run must not freeze the tab.
- Every dynamic string is untrusted: confirm `J.esc` is used on every path
  (history data comes from scan artifacts, which contain target-controlled text).
- Keep the existing nav/keyboard conventions (`g s` to reach scans).

## Part 2 — Architecture and correctness review

Read `janus/core/{scope,http,model,store}.py`, both engines, `dashboard/`, and
`cli.py`, then report and fix:

- **Authorization**: any path where a request can leave without
  `Scope.authorize()`? Any place that assumes a redirect stays in scope?
- **State**: register transaction/lock correctness; history immutability;
  what happens when two scans finish at once; partial writes.
- **Error handling**: tool failures that could look like "clean"; transport
  errors; corrupt artifacts; the dashboard when a file disappears.
- **Coverage honesty**: does `coverage.json` match what actually ran? Are
  skipped engines, missing lenses and exhausted budgets all visible?
- **CLI ergonomics**: consistent flags, exit codes, `--help` text, sensible
  defaults, no dead flags.
- **Tests**: the riskiest paths without coverage; add tests for every fix.
- **Docs accuracy**: README/QUICKSTART/AGENT-GUIDE statements must match the
  code. Fix the docs where they drifted.

Rank everything P0 (breaks or lies) / P1 (hurts trust or usability) / P2
(nice-to-have). Implement P0 and P1. Put P2 in `docs/UI-BACKLOG.md`.

## Constraints

- No new runtime dependencies, no build step, no external network calls from
  the dashboard.
- No feature removal and no new "safety" restrictions. If you think something
  is dangerous, document the trade-off; do not silently disable it.
- Keep `pytest -q` at 113+ and add tests for every behavioural change.
- Do not reformat unrelated files; keep diffs reviewable.

## Deliverables

1. The prioritized review (what you found, why it matters, file:line).
2. The patches, with tests.
3. Three screenshots (overview, scans list, scan detail) rendered from real
   data in `demo/everything`, saved under `docs/assets/`.
4. A short note in `docs/UI-BACKLOG.md` for what you deliberately left.
5. Anything you could not verify, stated plainly.
