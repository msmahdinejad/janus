# Security policy

## Authorized targets only

Janus probes whatever its `scope.toml` names. **Run it only against systems you
own or have explicit written permission to test.** Scanning third-party systems
without permission is illegal in most jurisdictions, and "the tool let me" is
not a defence. `scope.toml` is a technical boundary the operator writes; Janus
cannot verify ownership from a config file. The operator is responsible for the
targets they enter.

Do not use this repository's issue tracker to ask for help scanning a target
you are not authorized to test, and do not report findings about third-party
systems here.

## Reporting a vulnerability in Janus itself

Use GitHub's private reporting: **Security → Report a vulnerability** on this
repository. Please do not open a public issue for a vulnerability.

Include: the Janus version or commit, the command you ran (with the scope file,
secrets removed), what you expected, and what happened.

Things we treat as security bugs in Janus:

- anything that lets a scan send a request the scope would have refused
  (out-of-scope host, port, forbidden path, non-allowed method, expired scope,
  private/metadata address without the opt-in);
- a way to make `DELETE`, `TRACE` or `CONNECT` leave the process;
- an agent backend reaching the network outside the scope-checked client or the
  allowlist proxy;
- secrets surviving redaction into `register.json`, reports, SARIF or logs;
- the dashboard accepting unauthenticated remote access, or any path traversal
  or injection in its API or UI;
- a tool failure that is reported as a clean scan.

This project has no bug-bounty program and no SLA; reports are handled on a
best-effort basis and credited if you want credit.

Supported versions: the latest release on `main`.

## Secrets hygiene within this project

- `janus/core/model.py::redact_text` scrubs secret-shaped substrings
  (credentialed URLs, `password=` / `token=` / `api_key=` assignments) from
  every free-text `Finding` field before it is stored or rendered. It is
  deliberately conservative: it over-redacts rather than risk leaving a real
  value in a report.
- Provider API keys are read from environment variables only. Janus reports
  whether a key is set, never its value, and never writes one to disk.
- `examples/demo-fixture/`, `examples/lab_app/` and `tests/` use only
  obviously fake values (`not-a-real-password`, AWS's documented example key
  IDs, the reserved `example.com` / `example.test` names). If you add a
  fixture, keep it that way: a realistic-looking fake secret still makes a
  scanner or a human skimming a report stop and evaluate it.
- `.gitignore` excludes `runs/`, `out/`, `.cache/`, `*.db`, `.env` and anything
  named `*.real.*`. Real engagement output must never be committed to a
  repository that also holds this tool's source.
