# Janus dashboard — design notes

A redesign of the findings dashboard (UI/UX only). No Python, schema, or
endpoint changed: the frontend still talks to exactly `GET /api/findings`,
`GET /api/meta` and `POST /api/findings/{fingerprint}/status`, served by the
unchanged `server.py` (`/` → `index.html`, `/static` → `static/`).

## What it is now

A single-page console with a sidebar and five views, all hash-routed
(`#/overview`, `#/findings?…`, `#/assets`, `#/coverage`, `#/timeline`) so every
number on the dashboard is a link into the data and the back button works.

| View | Job |
|---|---|
| **Overview** | Posture at a glance: active / critical+high / untriaged / % resolved, the two engines side by side, severity donut, "needs attention first" queue, riskiest assets, top categories, triage pipeline. Every tile deep-links into a pre-filtered explorer. |
| **Findings** | The workhorse. Preset tabs (Active · Critical & high · Needs review · Resolved · All) with live counts, free-text search, six facet filters with live counts, group-by (severity / asset / category / tool / status / engine), sort + reverse, bulk triage, CSV export, incremental rendering (120 rows at a time, auto-loads on scroll). Filters live in the URL. |
| **Assets** | The same findings pivoted by *what is affected*: hosts (outward face) and files (inward face), ranked by severity-weighted remaining risk, expandable in place. |
| **Coverage** | Which tools/standards have produced evidence: per-engine summary, tool matrix, OWASP Top 10 and CWE tallies, evidence-quality (confidence) bar, category × engine heatmap. Deliberately honest about what it can't know (see below). |
| **Timeline** | First-seen trend (hour/day/week buckets, stacked by severity, cumulative line), age of active findings, a "possibly fixed" heuristic list, and an activity feed. |

### Triage — the repeated interaction — is faster, not slower

Old flow: expand row → pick status in a `<select>` → type note → click Save.
New flow, any of:

* **Row**: click the status pill → pick a status (1 click + 1 click; row updates instantly, toast with **Undo**).
* **Keyboard**: `j`/`k` to move, `1`–`5` to set Open / Needs review / Fixed / Ruled out / Accepted risk. Zero mouse.
* **Drawer**: the finding opens in a docked side panel (list stays visible and in context). Triage sits directly under the title: five one-click status buttons + a note field (`Ctrl+Enter` to save). Optional "advance to next after status change" turns triage into a queue.
* **Bulk**: tick rows (shift-click for ranges, group checkboxes, header "select all matching") → a floating bar applies a status to all of them.

Writes are optimistic and **serialised through one client queue** so two quick
clicks can never land out of order at the server; a failed write rolls back that
row and says so. Unsaved notes are flushed when you move to another finding.

### Interaction details worth knowing

* `Ctrl/⌘ K` command palette: jump to views, apply presets, run actions, or search findings by title/path/host/CWE.
* `g` then `o f a c t` to navigate, `/` search, `r` refresh, `t` theme, `?` shortcut sheet.
* Silent background refresh every 45 s (and on tab refocus) — only repaints, with a toast, if the register actually changed.
* Real loading (skeleton), empty ("no findings yet" with the commands to run), no-results (with *Clear all filters*), "inbox zero", and error-with-retry states.
* Responsive: full sidebar → icon rail (≤980 px) → off-canvas drawer + card rows (≤700 px). The finding drawer docks beside the list on wide screens and becomes a full-height overlay below 1360 px.

## Visual system

* **Quiet chrome, loud meaning.** Neutral ink-on-paper surfaces; colour is reserved for *data*: severity (red → orange → amber → blue → grey), triage status, and the two engine faces. Primary buttons are ink (inverts in dark mode), not a brand colour.
* **Janus as identity, not decoration.** The mark is one disc split down the middle: **teal = inward** (source code engine), **violet = outward** (live-surface recon engine). That two-tone coding is reused consistently — engine tags, the Overview "Two faces" panel, Coverage panels, asset icons, the category × engine heatmap — so the metaphor *does work* (tells you which engine a thing came from) rather than just sitting in a logo.
* Tokens in `static/css/tokens.css` (surfaces, text, severity solid/fg/bg triples, status, engine, radius, shadow, type). Dark mode follows `prefers-color-scheme` and a three-state manual toggle (auto → light → dark, persisted), matching the original `data-theme` pattern. Severity/status tints are separate fg/bg/solid tokens per theme so contrast holds in both.
* Type: system UI stack + system monospace (no web-font fetch), tabular numerals on every figure.
* Charts are hand-rolled SVG/CSS (`js/charts.js`, ~100 lines) and read the same CSS variables, so they re-theme instantly and **the dashboard now makes zero external requests** — the Chart.js CDN dependency is gone, which matters for a security tool that's often run on a locked-down workstation.

## Code layout (no build step)

```
static/
  index.html              shell; loads CSS/JS with a per-load cache-buster
  style.css               @import manifest of css/* (kept so the old URL still resolves)
  app.js                  router, nav, theme, command palette, keyboard
  css/  tokens base layout components views
  js/   util icons ui charts store drawer
  js/views/ shared overview explorer assets coverage timeline
```

Classic `<script>`s sharing one `J` namespace rather than ES modules: no
dependence on the server sending a JS MIME type (Python's `mimetypes` can
misreport `.js` on Windows), no bundler, trivially debuggable. Everything user-
or tool-supplied is HTML-escaped before it reaches `innerHTML`; CSV export
neutralises formula-injection prefixes (`= + - @`).

The cache-buster (`?v=<timestamp>` appended by an inline loader) is deliberate:
after upgrading Janus, a stale cached script must never meet a newer API.

## Decisions & trade-offs

* **No framework.** The brief ruled out a build pipeline; at this size vanilla modules with event delegation are fast and have no moving parts. The cost is hand-written re-render functions; views re-render wholesale (cheap at hundreds of rows) except the explorer, which repaints only the list so search focus and scroll survive.
* **Pagination = "render 120, load more on scroll"**, not true virtualization. Verified smooth at 435 findings; a few thousand should still be fine (untested), tens of thousands would want windowing (see next steps).
* **Coverage is honest, not impressive.** The API exposes findings, not run logs, so it can say *which tools produced findings* but not *which ran clean vs were skipped*. A "No findings" pill says exactly that instead of implying coverage. This is the single biggest gap between "looks like a product" and "is one" — see backend requirement 1.
* **"Possibly fixed" is a heuristic** (active finding not re-detected in its engine's latest scan, > 2 h older). It's labelled as one.
* **Bulk = N sequential POSTs.** Fine locally and keeps the existing contract; a bulk endpoint is requested below.

## What I'd do next with more time

1. True list virtualization + server-side filtering once registers pass ~5k rows.
2. Saved/named views (persisted filters), user-configurable columns.
3. Per-finding history and "diff between two scans" (needs backend requirement 2).
4. SLA / due dates and owner assignment on findings (schema change — out of scope here).
5. Focus trap + `inert` background when the drawer is an overlay; a screen-reader pass; high-contrast theme.
6. A Playwright smoke suite (load → filter → triage → undo) wired into CI; there is none for the UI today.
7. Print/PDF-friendly executive summary view of Overview.
8. Show the Janus "two faces" idea on a per-asset basis — a combined host + repo view for the same service.

## Verification performed

Run against a 15-row demo register and a generated 435-row register, in dark
and light at desktop width (plus Overview, Findings and the drawer at 390 px): every view renders with no console
errors; search, filters, group-by, sort/reverse, row expand (drawer), status
change, note save (`Ctrl+Enter`), undo, bulk bar, keyboard triage, command
palette, refresh, empty and error states all exercised; status/notes changes
confirmed persisted in `register.json`; `janus demo` launches and serves the
page, assets and API; existing test-suite (52 tests) passes unchanged.

Known quirks (not caused by this change): the shipped demo `register.json`
under `examples/demo-fixture/out/` is a stale 10-finding scan result, so
`janus demo` shows that unless run with `--force` (which copies the richer
15-row `seed_findings.json`); and `generate_seed.py` emits some non-ASCII
characters that can mojibake depending on the writer's default encoding.

## Backend requirements for the next step

None of these were implemented here (UI-only brief). In priority order:

1. **Stale in-memory register (correctness).** `build_app()` constructs `Register(register_path)` once at startup and serves/saves from that copy. A `janus scan` that updates `register.json` while the dashboard is running is invisible to it — and the next triage click rewrites the file from the stale copy, **silently discarding the scan's new findings**. Needed: reload on change (compare `st_mtime_ns`, or re-read per request) and a file lock / atomic merge on write. The UI's 45 s background refresh already exists and will pick this up with no frontend change.

2. **Scan-run / tool-status endpoint** — `GET /api/runs` →
   ```json
   [{ "run_id": "a21e2b6f5c72", "command": "scan code", "engagement": "…",
      "started_at": "…Z", "finished_at": "…Z",
      "tools": [{ "name": "semgrep", "engine": "code",
                  "status": "ran | skipped | failed | not-installed | out-of-scope",
                  "reason": "binary not found", "duration_ms": 8120,
                  "targets": 35, "findings": 71 }] }]
   ```
   Source: the existing `*.manifest.json` / `audit.ndjson` plus each adapter's `ToolResult`. Lets Coverage show *ran clean* vs *skipped* vs *failed* instead of inferring from findings, and lets Timeline mark scan boundaries.

3. **Status history + trend** — record `{fingerprint, at, from, to, by}` on every status change (append-only; `audit.ndjson` is a natural home), then expose
   `GET /api/findings/{fingerprint}/history` and
   `GET /api/trend?bucket=day|week&from=&to=` →
   `[{ "t": "2026-11-03", "new": 12, "resolved": 4, "reopened": 1, "active": {"critical": 3, "high": 9, "medium": 20, "low": 8, "info": 2} }]`.
   Today Timeline can only chart *first-seen* and cannot say when anything was resolved, so there is no burn-down / MTTR. Adding `triaged_by` / `triaged_at` to the stored row would also let the drawer show who closed a finding and when.

4. **Bulk status** — `POST /api/findings/status` with
   `{ "fingerprints": ["…"], "status": "fixed", "notes": null }` → `{ "updated": 40, "missing": [] }`, one load+save instead of N. (Bulk currently issues N sequential single POSTs.)

5. **Cheap change detection for polling** — include a `revision` (or the register's mtime / content hash) in `/api/meta`, or send an `ETag` on `/api/findings` and honour `If-None-Match`, so the background poll doesn't re-download the whole list every 45 s.

6. **Server-side query for large registers** (only if registers exceed a few thousand rows) — `GET /api/findings?limit=&cursor=&severity=&status=&engine=&q=&sort=` with a total-count header, plus `GET /api/facets` returning per-facet counts so filter popovers don't need the full list.
