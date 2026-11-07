# Changelog

All notable changes are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [0.2.0] - 2026-11-07

Hardening release. It closes the release blockers found in an independent
review, adds write-path testing and per-run scan history, and adds Strix as an
external agent backend behind an egress allowlist.

### Added

- **Scan history.** Every run writes an immutable record to
  `out/scans/<run_id>/` (`scan.json`, `findings.json`, `coverage.json`,
  `report.md`, `findings.sarif`). The dashboard's `#/scans` view lists runs
  newest first with severity chips and a delta against the previous run of the
  same kind; `#/scans?id=<run_id>` shows one run's KPIs, engine status,
  findings and coverage gaps.
- **Write-path testing** (opt-in, staging only). Deterministic checks for
  endpoints listed in `[[write.targets]]` (`WRITE-UNAUTH`,
  `WRITE-MASS-ASSIGN`, `WRITE-VERB-TAMPER`) plus a `write` review lens for the
  agent. Requires `allow_state_changing`, `require_nonprod_marker` and an
  explicit `mutating_methods` list; `DELETE`, `TRACE` and `CONNECT` are refused
  by construction.
- **Strix agent backend** (`--agent-backend strix`), refused unless an egress
  proxy is configured. New `janus proxy`: an allowlist, scope-checked and
  audited proxy for external agents. New `janus llm-shim` for gateways that
  `httpx` cannot reach.
- **Native agent backend** (`--agent-backend native`, default): in-process,
  its only capabilities are the scope-checked `http_get`, `report_finding` and
  `finish` tools.
- **`janus scan all`** runs both engines and, with `--mode agent`, the built-in
  review lenses (`--lens all` or a comma-separated list) in one run, one
  register and one report.
- **`coverage.json`** and a Coverage section in `report.md`: every tool that
  was skipped or failed and every lens that did not run.
- `--diff BASE_REF`, `--baseline FILE`, `--fail-on` for CI use; request budgets
  (`max_requests`) enforced by the scope gate.
- Dashboard: Scans view, keyboard triage, command palette, CSV export.
- Community files: `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`,
  issue and pull request templates, CI on Python 3.11-3.13.

### Changed

- Agent egress is a boundary (scope-checked client or allowlist proxy), not an
  instruction in a prompt.
- Heuristic rules that fire many times in one file are collapsed into a single
  finding with a count.
- Minimum Python is now 3.11 (the tested range is 3.11-3.13).
- The example GitHub Actions workflow moved to
  `docs/ci/github-actions.example.yml`; `.github/workflows/ci.yml` is the
  project's own CI.
- `janus llm-shim --api-key-env` now defaults to `LLM_API_KEY`.

### Fixed

- A tool that crashed or exited non-zero could be reported as zero findings;
  it is now `failed` in the run's tool status and in `coverage.json`.
- `scan code` crashed with `FileNotFoundError` on the first run into an
  `--out` directory that did not exist yet (the register lock file was created
  before the directory).
- Redaction now covers every free-text finding field, not only the snippet.
- `--fail-on` evaluates the current run only, not old rows in the register.
- The built wheel omitted the dashboard's static files, so a wheel install had no
  working dashboard.

### Security

- `max_requests` is enforced by the scope gate instead of being advisory.
- The dashboard refuses a non-loopback bind without `--allow-remote` and a
  bearer `--token`.
- The triage bridge passes explicit read-only flags to the coding-agent CLI.
- Cloud metadata addresses stay refused even with `allow_private_targets`.

[0.2.0]: https://github.com/msmahdinejad/janus/releases/tag/v0.2.0
