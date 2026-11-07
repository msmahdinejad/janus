# syntax=docker/dockerfile:1
#
# "Anyone, anywhere" mode: one image with every optional external tool
# already installed, so `docker run janus ...` works identically on
# Windows/macOS/Linux/CI without six separate native installs.
#
# Each scanner is pulled from ITS OWN project's official image via a
# multi-stage COPY --from, rather than hand-built curl/tarball commands —
# that way this Dockerfile tracks each project's own released artifact
# instead of us guessing a download URL + binary path per OS/arch that goes
# stale the moment a project changes its release layout.
#
# Pin the tags below to whatever you've validated; ":latest" here is a
# starting point, not a promise — see README.md "Docker image" for how to
# check a tag resolved correctly (`docker run --rm <image> <tool> --version`).

FROM aquasec/trivy:latest AS trivy
FROM zricethezav/gitleaks:latest AS gitleaks
FROM projectdiscovery/nuclei:latest AS nuclei
FROM projectdiscovery/subfinder:latest AS subfinder

FROM python:3.12-slim

LABEL org.opencontainers.image.title="janus" \
      org.opencontainers.image.description="Two-faced security pipeline: source-code engine + authorization-gated external recon engine, with a local findings dashboard." \
      org.opencontainers.image.licenses="MIT"

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

# Verified by actually building this image: these four paths are correct as
# of the base images' current "latest" (checked Nov 2026). If one of them
# ever fails with "no such file", that project moved its binary — run
# `docker run --rm --entrypoint sh <image> -c "which <tool> || find / -maxdepth 3 -iname '*<tool>*'"`
# against the base image named on the failing line and fix the path here.
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=gitleaks /usr/bin/gitleaks /usr/local/bin/gitleaks
COPY --from=nuclei /usr/local/bin/nuclei /usr/local/bin/nuclei
COPY --from=subfinder /usr/local/bin/subfinder /usr/local/bin/subfinder

# Best-effort, matching this whole project's "no mandatory dependency" rule
# (see ARCHITECTURE.md principle #1): if PyPI is unreachable from your
# Docker build context (seen in at least one sandboxed CI-like environment
# during development — see ARCHITECTURE.md's "Honest gaps" section), the
# image still builds and `janus` still runs; `janus doctor` will just show
# semgrep as missing until you install it some other way.
RUN pip install --no-cache-dir --retries 5 --timeout 30 semgrep \
    || echo "WARNING: semgrep install failed (likely a network restriction in this build context) — continuing without it, see ARCHITECTURE.md"

WORKDIR /opt/janus
COPY pyproject.toml README.md ./
COPY janus ./janus
COPY examples ./examples
# Unlike the semgrep line above, this one is NOT wrapped in `|| true` — a
# build that can't install janus itself hasn't produced a usable image, so
# it should fail loudly. If this fails in your environment with the same
# "can't reach PyPI from inside the build container" symptom the semgrep
# line is guarding against (see ARCHITECTURE.md "Honest gaps"), that's a
# network-egress problem to fix at the Docker/CI level, not something this
# Dockerfile can paper over.
RUN pip install --no-cache-dir .

# Bake nuclei's template set in at build time so a first run isn't blocked
# on a template download; harmless if nuclei isn't used (`janus scan recon`
# only invokes it under --mode active, which itself needs an explicit
# scope.toml opt-in — see janus/core/scope.py).
RUN nuclei -ut -silent || true

# The dashboard binds 127.0.0.1 by default; expose + rebind to 0.0.0.0 only
# if you're intentionally running the container with published ports and
# understand that widens who can reach it:
#   docker run -p 8787:8787 janus dashboard --host 0.0.0.0
EXPOSE 8787

WORKDIR /work
ENTRYPOINT ["janus"]
CMD ["--help"]
