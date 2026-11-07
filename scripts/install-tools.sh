#!/usr/bin/env bash
# Best-effort installer for Janus's optional external tools, for native
# (non-Docker) use on Linux/macOS/Git-Bash-on-Windows. Every tool here is
# optional — `janus doctor` tells you what's missing, and every adapter
# degrades to "skipped" gracefully — so feel free to comment out whatever
# you don't want. Installs into ./.tools/bin by default; add that to PATH.
set -euo pipefail

BIN_DIR="${1:-$(pwd)/.tools/bin}"
mkdir -p "$BIN_DIR"
echo "Installing into $BIN_DIR — add it to PATH, e.g.: export PATH=\"$BIN_DIR:\$PATH\""

echo "== semgrep (pip) =="
pip install --quiet --upgrade semgrep || echo "  semgrep install failed — skip, janus will report it as skipped"

echo "== gitleaks =="
curl -sSfL https://raw.githubusercontent.com/gitleaks/gitleaks/master/scripts/install.sh \
  | sh -s -- -b "$BIN_DIR" || echo "  gitleaks install failed — skip"

echo "== trivy =="
curl -sSfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
  | sh -s -- -b "$BIN_DIR" || echo "  trivy install failed — skip"

echo "== nuclei, subfinder (requires Go) =="
if command -v go >/dev/null 2>&1; then
  GOBIN="$BIN_DIR" go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest || echo "  nuclei install failed — skip"
  GOBIN="$BIN_DIR" go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest || echo "  subfinder install failed — skip"
else
  echo "  go not found — skipping nuclei/subfinder. Either install Go, grab a release"
  echo "  binary from projectdiscovery's GitHub releases, or use docker/Dockerfile instead."
fi

echo "== strix (optional AI-agent backend; needs Docker + an LLM API key — see"
echo "   https://github.com/usestrix/strix) =="
if command -v uv >/dev/null 2>&1; then
  uv tool install strix-agent || echo "  strix install failed — skip"
else
  echo "  uv not found — skipping. pipx/uv install strix-agent, or skip the agent layer entirely."
fi

echo
echo "Done (failures above are non-fatal — this script is best-effort by design)."
echo "Run: janus doctor"
