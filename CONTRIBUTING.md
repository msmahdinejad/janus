# Contributing to Janus

Thanks for looking. Janus is a security tool, so the bar for changes that touch
the authorization gate is higher than for the rest of the code.

## Set up

```bash
git clone https://github.com/msmahdinejad/janus.git && cd janus
python -m venv .venv
. .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest -q
```

Python 3.11, 3.12 and 3.13 are tested in CI. Optional scanners (semgrep,
gitleaks, trivy, nuclei) are not required to run the tests; `janus doctor`
shows which ones you have.

The dashboard's pure-logic JavaScript is exercised from
`tests/test_dashboard_scans_ui.py` through Node (`tests/js/`); those tests are
skipped when `node` is not installed, so Node is optional locally.

## Ground rules

1. **Scope is a hard boundary.** Anything that sends a request must go through
   `janus/core/scope.py` and the scope-checked HTTP client. A change that adds
   a second way to reach the network needs a test showing the scope still
   refuses what it should (see `tests/test_scope.py`, `tests/test_hardening.py`).
2. **Never widen the safe method set** (`GET`/`HEAD`/`OPTIONS`) and never make
   `DELETE`, `TRACE` or `CONNECT` reachable. Write-path testing stays opt-in and
   staging-only.
3. **A failed tool must not look like a clean scan.** New adapters report
   `ok` / `skipped` / `failed` and the gap shows up in `coverage.json`.
4. **No real secrets, hostnames or engagement output in fixtures.** Use
   `example.com`, `example.test`, `localhost`, and obviously fake values.
   Real scan output belongs in `out/` (gitignored), not in the repository.
5. **Add a test** for behaviour you change. A rule change needs a positive and
   a negative case; a new finding needs a stable `rule_id`.
6. **Update docs** (README, USAGE, CHANGELOG) when a command, flag or scope key
   changes.

## Pull requests

- Keep them focused; one behaviour change per PR.
- `pytest -q` must pass. CI also runs `janus scan code` on
  `examples/demo-fixture` as an end-to-end check.
- Fill in the PR template checklist.
- For false positives in a built-in rule, use the *False positive* issue
  template and include the smallest snippet that triggers it.

## Reporting security issues

Not here: see [SECURITY.md](SECURITY.md).
