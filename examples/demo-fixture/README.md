# Demo fixture

Everything in this directory is synthetic, generated for `janus demo` and
for the test suite. None of it is real:

- `example.com` / `*.example.com` is IANA's reserved documentation domain —
  not a real company, and `scope.demo.toml` never actually sends it traffic
  (the recon-looking rows in `seed_findings.json` are hand-authored example
  data, not the output of a live scan).
- Every "secret" (`AKIAFAKEEXAMPLE00000`, `not-a-real-password`, etc.) is an
  obviously-fake placeholder, not a credential that was ever valid.

## Files

- `vulnerable_app/` — a tiny, deliberately-vulnerable Python/Docker/YAML
  fixture that the `code` engine's builtin rules (and the test suite) run
  against for real. Try it yourself:

  ```bash
  janus scan code --scope examples/demo-fixture/scope.demo.toml --out examples/demo-fixture/out
  ```

- `scope.demo.toml` — a valid, always-non-expiring scope file pointed at
  `vulnerable_app/` for the code engine. `allow_active_recon` and
  `allow_agent` are both `false` — this fixture never needs them.
- `generate_seed.py` — (re)generates `seed_findings.json` from actual
  `janus.core.model.Finding` objects, so the demo data always matches the
  current schema. Run it again after changing `Finding`'s fields.
- `seed_findings.json` — synthetic example findings covering both engines
  and a range of severities, loaded by `janus demo` so the dashboard has
  something worth looking at with zero setup and zero network access.
