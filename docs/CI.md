# Running Janus in CI

Short answer to "do I need this in the quickstart?": **no — but you do need it
eventually.** The quickstart is about seeing your first finding in ten minutes;
CI is about not regressing afterwards. This page is the copy-paste version.

## What CI is good for (and what it is not)

| Good in CI | Bad in CI |
|---|---|
| `janus scan code` on every merge request, scoped to changed files | `scan recon` against a live target |
| secrets + dependency checks on the default branch | active/agent scanning from a shared runner |
| SARIF as a build artifact | storing scope files with production hosts in a repo |

Recon belongs on an operator's machine (or a dedicated, access-controlled
pipeline) because it sends real traffic to a real system, and authorization is
a human decision that a YAML file makes too easy to skip.

## Exit codes

| Code | Meaning | What CI should do |
|---|---|---|
| `0` | nothing at/above `--fail-on` | pass |
| `1` | findings at/above the threshold **in this run** | fail the job, keep artifacts |
| `2` | the scope file itself is invalid/expired/disabled | fail loudly: this is a setup bug, not a security result |

`--fail-on` only looks at the findings produced by the current run, so an
accepted finding from last month does not keep the pipeline red forever. Use
`--baseline <file>` when you want to suppress a known, accepted finding without
changing its status.

## GitLab CI

```yaml
stages: [security]

janus-code:
  stage: security
  image: python:3.12-slim
  variables:
    GIT_DEPTH: "0"                 # --diff needs history
    SEMGREP_SEND_METRICS: "off"
    TRIVY_DB_REPOSITORY: "ghcr.io/aquasecurity/trivy-db:2"
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
  before_script:
    - pip install --quiet -e .
    - pip install --quiet semgrep
    # pin tool versions; do not pipe a remote script into a shell
    - apt-get update -qq && apt-get install -y -qq curl tar >/dev/null
    - curl -sSL -o /tmp/gl.tgz https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz
    - tar -xzf /tmp/gl.tgz -C /usr/local/bin gitleaks
  script:
    - |
      if [ "$CI_PIPELINE_SOURCE" = "merge_request_event" ]; then
        janus scan code --scope scope.toml --out out \
          --diff "origin/$CI_MERGE_REQUEST_TARGET_BRANCH_NAME" --fail-on high
      else
        janus scan code --scope scope.toml --out out --fail-on high
      fi
  artifacts:
    when: always
    expire_in: 30 days
    paths: [out/]
```

Notes that matter:

- `--diff` scans only changed files; it falls back to a full scan (with a
  warning) if the root is not a git repo or the ref is unavailable.
- GitLab's native SAST report expects GitLab's own schema, not SARIF. Upload
  `out/findings.sarif` as an artifact (and feed it to whatever consumes SARIF);
  do not set `reports: sast:` to it.
- `scope.toml` in the repo should contain **code roots only** (`[targets]`
  empty). Keep any recon scope file out of version control.
- Cache `.cache/janus/` if the job is slow; the trivy DB cache is the bulk of it.

## GitHub Actions

The bundled `.github/workflows/janus.yml` is a working starting point: install,
scan, upload SARIF to code scanning, upload the report as an artifact.

## Air-gapped runners

`janus scan code --offline` skips the vulnerability DB download (secrets and
misconfiguration still run). Ship the binaries in the image and point
`--tools-dir` at them; no network is required at scan time.

## The one thing to avoid

Do not wire `scan recon --mode agent` into a shared pipeline. Two reasons:
the agent sends real requests to a real host, and the runner's IP is usually
not the one you scoped. Run it from a workstation with the same `scope.toml`
you reviewed.

## What is `TRIVY_DB_REPOSITORY`?

Trivy is the dependency/IaC scanner. To match installed packages against known
CVEs it downloads a compiled **vulnerability database** — a ~100 MB OCI
artifact published at `ghcr.io/aquasecurity/trivy-db:2`. By default Trivy pulls
it from a mirror (`mirror.gcr.io`). On networks where that mirror answers 403,
the download fails and Trivy exits with an error.

`TRIVY_DB_REPOSITORY` is Trivy's own environment variable for "where to fetch
that database". Pointing it at the canonical source fixes the failure:

```powershell
$env:TRIVY_DB_REPOSITORY = "ghcr.io/aquasecurity/trivy-db:2"
$env:TRIVY_JAVA_DB_REPOSITORY = "ghcr.io/aquasecurity/trivy-java-db:1"   # Java only
```

Notes:

- It is **not** a Janus setting and not a secret; it changes nothing about how
  the scan works, only where the data comes from.
- Secrets and misconfiguration checks do **not** need the DB. `--offline` skips
  the download entirely and still runs those two.
- If the database is already cached (`--cache-dir`), `--skip-db-update`
  (Trivy flag) avoids the network on later runs.
- On a locked-down network, mirror the artifact internally once and point the
  variable at your mirror; do not disable the check silently.
