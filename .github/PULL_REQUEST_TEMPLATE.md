## What and why

<!-- One behaviour change per PR. Link the issue if there is one. -->

## Checklist

- [ ] `pytest -q` passes locally
- [ ] Tests added or updated for the behaviour I changed
- [ ] Docs updated (README / USAGE / CHANGELOG) if a command, flag or scope key changed
- [ ] No secrets, real hostnames or real engagement output in fixtures or docs (use `example.com`, `example.test`, obviously fake values)
- [ ] Nothing here lets a request bypass `scope.toml`, widens the safe method set, or makes a tool failure look like a clean scan (or, if it touches the scope gate, a test proves it)
