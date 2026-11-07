# Scans UI — audit, what shipped, and the backlog

Scope: the scan-history surface of the dashboard (`#/scans`, `#/scans?id=<run>`).
Screenshots from a real run against the bundled lab target: [overview](assets/dashboard-overview.png),
[scan history](assets/scan-history.png), [scan detail](assets/scan-detail.png).

## What was wrong (ranked)

Line numbers refer to the version at commit `8133e88`.

### P0 — broken or misleading (fixed)

| # | Problem | Where | Why it matters |
|---|---|---|---|
| 1 | Deep link / first visit to `#/scans` crashes: `paint()` reads `S.scans.length` while `S.scans` is `null`. The exception escapes `render()` and, on a cold load, aborts the shell's boot (`J.load()` never runs). | `scans.js:89`, `:225` | The page is blank; with `#/scans` as the landing URL the whole console is dead. |
| 2 | A first-of-its-kind run is shown as "+9 new" (the server's `delta` for a baseline is *everything*). The list never shows "first run" because `d` is always truthy. | `scans.js:52-58`, `history.py:142` | Presents a starting point as a regression. |
| 3 | "0 findings" and a run whose engines were skipped/unrecorded look identical. The list shows no engine status at all; the detail table styles only `ok`/`failed` (`skipped` is unstyled) and says "No tools recorded" without saying what that implies. | `scans.js:111-113`, `:195-197` | A green-looking "0" that means "semgrep wasn't installed" is a lie. All three real runs in `demo/everything` record no engine status. |
| 4 | Findings table: `tr.frow` collides with the Findings explorer's `.frow { display: grid }`, so the table renders as a broken grid. | `scans.js:150`, `views.css` | Detail page is visibly corrupted. |
| 5 | Every finding renders two `<tr>`s with its detail HTML built eagerly and a `tabindex="0"` each. | `scans.js:140-159`, `:202` | 5,000 findings → ~10,000 rows, 5,000 tab stops: the tab freezes. |
| 6 | Late fetches write into the shared `#page` after you've navigated away (no route check). | `scans.js:164-217`, `:225` | Detail of run A overwrites the Findings page you just opened. |
| 7 | No grouping, sorting or pagination; every run is one table row. | `scans.js:98-117` | Unusable at 200 runs. |
| 8 | Detail has no way to filter/sort findings and no compare view. | `scans.js:199-203` | Can't answer "what's new since last time". |

### P1 — usability and craft (fixed)

* Severity chips in the list toolbar and the per-run severity pills have no visible styling or pressed state (`pill sev-*` / `chip sev-*` only set custom properties) — state was invisible (`scans.js:48,77`).
* `.delta.down` falls back to `#3fb950`, ≈2.3:1 on white; several `.muted` pairings sat on `surface-2` at the edge of 4.5:1 (`views.css`).
* The 7-column table has no narrow layout, so at 768 px the page scrolls sideways (`scans.js:100`).
* Gaps rendered as a footnote below a 5,000-row table (`scans.js:204`); engine detail truncated at 160 chars with no way to read the rest (`:196`).
* List is fetched once and never revalidated; the shell's 45 s poll re-rendered the whole view (wiping filters and expansions) on every register change (`scans.js:225`, `app.js` data handler).
* No keyboard model beyond Enter on a row; `/` jumped to the Findings search; no help entry for scans.
* Empty state used a placeholder command (`--scope …`) instead of an exact one.
* The history API re-read and re-parsed every run's `findings.json` on every call (`history.py:117-146`, and again inside `load_scan`).

### What shipped

* **List**: "Since the previous run" headline cards (newest run per engagement × kind with +new / −fixed / same, severity bar, engine verdict), then runs grouped by engagement (toggle), filters (engagement, kind, engine status incl. "needs attention"), sort (newest / most findings / most new — baselines never outrank real regressions), per-group and flat pagination, exact empty-state command with the dashboard's own output folder and a copy button.
* **Run verdict** (`C.health`, `scans-core.js`): complete / partial / degraded / unverified, derived from engine + tool status and recorded gaps — never from the finding count. `0 findings` is only called "Clean" when everything recorded ran ok.
* **Detail**: verdict + delta + severity first; "What actually ran" table and "Not covered / degraded" as first-class cards; compare presets (All / New / Fixed / Unchanged) against the previous run of the same kind (fixed findings are shown struck-through from the previous run); search, severity chips with live counts, tool / confidence / status filters, sortable headers (and a select on narrow screens); inline expansion that replaces only the one row, so scroll and focus are untouched; incremental rendering (100 rows, auto-loads on scroll) with `content-visibility` on rows; roving tabindex so the table is one tab stop.
* **Keyboard**: `g s` (unchanged), `/` focus filter, `j`/`k` or arrows move between runs / findings, `Enter`/`Space` open / expand, `Esc` collapse, shortcuts documented in `?`.
* **Backend (additive, small)**: `/api/scans` rows and `/api/scans/<id>` now carry `kind`, `previous_run_id`, `baseline`; fingerprint sets cached by `(mtime_ns, size)`; every new `scan.json` persists `engines` and `quality`, and every run has a per-run `coverage.json`.
* **Tests**: `tests/test_dashboard_scans_ui.py` (history fields, cache invalidation, escaping of every builder, run-health and delta semantics, sort/filter/diff logic via node, WCAG contrast of every colour pair `scans.css` uses in both themes).

## Backlog (P2 — deliberately left)

1. **Persist fingerprints in `scan.json` at record time.** The first `/api/scans` call after server start still parses every run's `findings.json`; later calls are cached. Storing the fingerprint list (or just the delta vs. the previous run) when the run is written removes the cold cost entirely.
2. **Server-side compare endpoint** — `GET /api/scans/<id>/compare` → `{previous_run_id, new:[fp], fixed:[finding…], same: n}`. The UI currently fetches the previous run's full findings (a second multi-MB payload for 5,000-finding runs) the first time a compare preset is used.
3. **Paged findings endpoint** for historical runs (`?offset=&limit=&severity=&q=`), so a 50,000-finding record never ships whole.
4. **Cheap detail**: `load_scan` still lists every run to find its delta (O(runs) small reads). Cache per-run rows keyed by directory mtime.
5. **Record per-engine duration, target counts and tool versions** in `scan.json` so the engine table can say how long and over what each engine ran.
6. **Trend strip** on the list (findings and new-per-run sparkline per engagement/kind) and a run-to-run "diff two arbitrary runs" picker.
7. **Download buttons** (`download` attribute) for `report.md` / SARIF; open-in-new-tab only today.
8. **Per-finding history across runs** ("first seen in run X, absent in Y, back in Z") and linking a finding in the run view to its triage state in the merged register.
9. A Playwright smoke suite (list → detail → compare → expand → keyboard) would catch regressions the node-vm unit tests can't (focus, scroll, layout).
10. Group headers don't yet show a mini trend or latest-run health beyond the "N need attention" chip.
11. **DNS rebinding pinning** — `Scope.authorize()` validates the requested
    hostname and the proxy enforces its host allowlist, but the pipeline does
    not pin a hostname to one resolved address for the lifetime of a run. This
    remains an infrastructure-hardening item for a future release.

## Could not be verified

* Complete/degraded verdict styling beyond the runs in the screenshots was exercised with synthetic records and unit tests.
* 5,000-finding behaviour was measured on a generated record (first paint ≈0.6 s including fetch; filter/sort/search ≈10 ms; scroll auto-load confirmed by real wheel scrolling) — not on an organically produced scan.
* Screen-reader behaviour (NVDA/VoiceOver) was not tested; ARIA roles/labels, roving tabindex and `aria-expanded` are in place but unheard.
* Visual checks were done in Chromium only (Chrome headless + the app's browser pane); Firefox/Safari untested (`content-visibility`, `color-mix` and `:focus-visible` are all supported there but not exercised).
* The `tests/test_dashboard_scans_ui.py` JS-logic tests need `node` and are skipped without it.
