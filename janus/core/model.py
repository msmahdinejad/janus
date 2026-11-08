"""The shared Finding model.

Every engine (code, recon) and every adapter (semgrep, gitleaks, trivy,
nuclei, the builtin regex engine, the optional AI agent, ...) ultimately
produces a list of `Finding` objects. That is the single most important
design decision in this project: one normalized shape in, three report
formats out (Markdown for humans, JSON for machines/dashboards, SARIF for
GitHub/GitLab). Without it, every tool's quirky native output format has to
be special-cased everywhere a finding is displayed, filtered or counted.
"""

from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any

SEVERITIES = ("critical", "high", "medium", "low", "info")
_SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}  # lower = more severe
_CONFIDENCE_RANK = {"confirmed": 0, "likely": 1, "needs-review": 2}

# Categories shared by both engines, so the dashboard can filter across both
# at once instead of having a "code categories" list and a "recon categories"
# list that almost-but-not-quite line up.
CATEGORIES = (
    "injection", "xss", "deserialization", "auth", "access-control",
    "secrets", "crypto", "configuration", "container", "ci-cd",
    "supply-chain", "exposure", "network", "client", "other",
)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)


def mask_secret(value: str) -> str:
    """Keep enough of a secret to recognize it later; never enough to use it."""
    if not value:
        return value
    if len(value) <= 4:
        return "*" * len(value)
    if len(value) <= 8:
        return value[:2] + "*" * (len(value) - 2)
    return f"{value[:4]}{'*' * 12}{value[-2:]}"


# Patterns scrubbed out of any free-text field (message/snippet/detail/poc)
# before a Finding is ever stored or rendered. Order matters: credentialed
# URLs first, so "scheme://user:pass@host" doesn't also get half-masked by
# the generic "key=value" pass below.
_CREDENTIAL_URL_RE = re.compile(r"([a-zA-Z][a-zA-Z0-9+.\-]*://[^/\s:@\"']+):([^/\s@\"']+)@")
_SENSITIVE_KV_RE = re.compile(
    r"""(?i)\b(password|passwd|secret|token|api[_-]?key|access[_-]?key|
        private[_-]?key|auth|bearer|credential)\b\s*[:=]\s*["']?([^\s"',;]{4,})""",
    re.VERBOSE,
)

# Bare credential shapes, for free text that carries a key with no
# `name=value` context: an agent quoting a snippet, a scanner message that
# pastes the match, a title built from a filename. Matches the same families
# the code engine detects, so "we found a key" and "we print the key" can't
# disagree.
_TOKEN_SHAPE_RES = (
    re.compile(r"\bsk-(?:ant-)?[A-Za-z0-9_\-]{16,}"),
    re.compile(r"\b(?:ghp|gho|ghu|ghs|github_pat)_[A-Za-z0-9_]{20,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    re.compile(r"\b(?:glpat|npm)_[A-Za-z0-9_\-]{20,}"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
)


def redact_text(text: str) -> str:
    """Best-effort scrub of secret-shaped substrings from a free-text field.

    This is deliberately conservative (it over-redacts rather than under-
    redacts): the whole point of this tool is to never become the second
    place a credential leaks.
    """
    if not text:
        return text

    def _url_sub(m: re.Match) -> str:
        return f"{m.group(1)}:{mask_secret(m.group(2))}@"

    text = _CREDENTIAL_URL_RE.sub(_url_sub, text)

    def _kv_sub(m: re.Match) -> str:
        return f"{m.group(1)}={mask_secret(m.group(2))}"

    text = _SENSITIVE_KV_RE.sub(_kv_sub, text)

    for shape in _TOKEN_SHAPE_RES:
        text = shape.sub(lambda m: mask_secret(m.group(0)), text)
    return text


def redact_value(value: Any) -> Any:
    """Recursively scrub every string in a nested structure.

    The delivered version only redacted `message`, `snippet`, `notes` and
    `extra["poc"]`. Everything else — `title`, `remediation`, arbitrary keys
    under `extra` (tool stderr, provider payloads, snippets from adapters) —
    went into the register, the JSON, the SARIF and the dashboard verbatim.
    One recursive pass closes that whole class instead of enumerating fields
    and hoping the next field added is remembered.
    """
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {k: redact_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return type(value)(redact_value(v) for v in value)
    return value


@dataclass
class Finding:
    title: str
    severity: str  # one of SEVERITIES
    category: str  # one of CATEGORIES
    engine: str  # "code" | "recon"
    tool: str  # builtin | semgrep | gitleaks | trivy | nuclei | passive-recon | agent:<name> | manual
    rule_id: str = ""
    # Code-engine location:
    path: str = ""
    line: int = 0
    end_line: int = 0
    # Recon-engine location:
    target: str = ""
    host: str = ""
    endpoint: str = ""
    method: str = ""
    message: str = ""
    snippet: str = ""
    remediation: str = ""
    confidence: str = "needs-review"  # confirmed | likely | needs-review
    cwe: tuple[str, ...] = field(default_factory=tuple)
    owasp: tuple[str, ...] = field(default_factory=tuple)
    status: str = "open"  # open | needs-review | ruled-out | fixed | accepted-risk
    first_seen: str = field(default_factory=utc_now_iso)
    last_seen: str = field(default_factory=utc_now_iso)
    sources: tuple[str, ...] = field(default_factory=tuple)
    notes: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            self.severity = "info"
        if self.category not in CATEGORIES:
            self.category = "other"
        # Redact on the way in — every field that could carry a copy-pasted
        # secret is scrubbed once, here, rather than trusted to be clean by
        # whoever constructed the Finding. `extra` is included because it is
        # where adapters put raw tool output, and that is exactly the sort of
        # place a credential shows up.
        self.title = redact_text(self.title)
        self.message = redact_text(self.message)
        self.snippet = redact_text(self.snippet)
        self.notes = redact_text(self.notes)
        self.remediation = redact_text(self.remediation)
        self.extra = redact_value(self.extra)

    @property
    def location_key(self) -> str:
        """The part of identity that should stay stable across re-scans."""
        if self.engine == "code":
            return f"{self.path}:{self.line}"
        return f"{self.host or self.target}:{self.endpoint}:{self.method}"

    @property
    def fingerprint(self) -> str:
        raw = f"{self.location_key}:{self.category}:{self.title.strip().lower()}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:20]

    @property
    def rule_identity(self) -> str:
        # Native agents reuse a generic rule ID for unrelated vulnerabilities.
        # The URL alone cannot distinguish transport, CSP, and disclosure bugs.
        if self.engine == "recon" and self.rule_id == "AGENT-FINDING":
            return f"{self.rule_id}:{self.title.strip().lower()}"
        return self.rule_id

    @property
    def dedupe_key(self) -> str:
        """Used to merge near-duplicates.

        For source findings, two tools reporting the same line+category are
        almost always the same issue, so the tool is deliberately not part of
        the key (gitleaks and the builtin secret scanner should collapse).

        For recon findings that is wrong: "missing CSP", "cookie without
        HttpOnly" and "CORS reflects Origin" all live at `host:/:GET` in
        category `configuration` and would collapse into a single row,
        silently dropping the others. There, the rule id is part of identity.
        """
        if self.engine == "code":
            # Rule id matters: a dependency file can hold 50 different CVEs on
            # one line-less location, and collapsing them by file alone threw
            # 57 of 58 Trivy findings away. Cross-tool duplicates are handled
            # by the second pass in dedupe().
            return f"code:{self.location_key}:{self.category}:{self.rule_id or self.title}"
        return f"recon:{self.location_key}:{self.category}:{self.rule_identity}"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["fingerprint"] = self.fingerprint
        return d


def _rank(f: Finding) -> tuple[int, int]:
    return (_SEVERITY_RANK.get(f.severity, 9), _CONFIDENCE_RANK.get(f.confidence, 9))


def dedupe(findings: list[Finding]) -> list[Finding]:
    """Two passes.

    1. Exact duplicates (same rule, same spot) collapse to the most severe.
    2. Then findings from *different tools* at the same spot/category merge,
       because gitleaks and the builtin scanner flagging the same secret is
       one issue. Same-tool findings are never merged in this pass, so two
       CVEs in one lockfile stay two findings.
    """
    best: dict[str, Finding] = {}
    for f in findings:
        key = f.dedupe_key
        existing = best.get(key)
        if existing is None:
            best[key] = f
            continue
        f_rank = (_SEVERITY_RANK.get(f.severity, 9), _CONFIDENCE_RANK.get(f.confidence, 9))
        e_rank = (_SEVERITY_RANK.get(existing.severity, 9), _CONFIDENCE_RANK.get(existing.confidence, 9))
        winner, loser = (f, existing) if f_rank < e_rank else (existing, f)
        also = set(winner.extra.get("also_reported_by", []))
        also.add(loser.tool)
        winner.extra["also_reported_by"] = sorted(also)
        best[key] = winner
    return _merge_cross_tool(list(best.values()))


def _merge_cross_tool(items: list[Finding]) -> list[Finding]:
    buckets: dict[tuple[str, str, str], list[Finding]] = {}
    out: list[Finding] = []
    for f in items:
        # Recon findings keep their rule identity: several distinct checks
        # legitimately report the same host/path/category.
        if f.engine != "code":
            out.append(f)
            continue
        buckets.setdefault((f.engine, f.location_key, f.category), []).append(f)
    for group in buckets.values():
        if len(group) == 1:
            out.extend(group)
            continue
        if len({f.tool for f in group}) == 1:
            # One tool, several rules at the same spot: distinct findings.
            out.extend(group)
            continue
        by_tool: dict[str, Finding] = {}
        for f in group:
            current = by_tool.get(f.tool)
            if current is None or _rank(f) < _rank(current):
                by_tool[f.tool] = f
        kept = sorted(by_tool.values(), key=_rank)
        if len(kept) == 1:
            out.extend(kept)
            continue
        winner, losers = kept[0], kept[1:]
        also = set(winner.extra.get("also_reported_by", []))
        also.update(l.tool for l in losers)
        winner.extra["also_reported_by"] = sorted(also)
        out.append(winner)
    return out


def aggregate_repetitive(
    findings: list[Finding], threshold: int = 10,
    never_aggregate: tuple[str, ...] = ("secrets", "injection", "auth", "xss", "access-control", "deserialization"),
) -> list[Finding]:
    """Collapse "the same rule fired 2,000 times across a monorepo" into one
    row with an occurrence count, so the report stays readable. Categories
    where every single occurrence is independently worth a human's eyes are
    exempted."""
    groups: dict[str, list[Finding]] = {}
    for f in findings:
        groups.setdefault(f"{f.tool}:{f.rule_identity}:{f.category}", []).append(f)

    out: list[Finding] = []
    for key, group in groups.items():
        if len(group) < threshold or group[0].category in never_aggregate:
            out.extend(group)
            continue
        rep = group[0]
        locations = sorted({g.location_key for g in group})
        rep.extra["occurrences"] = len(group)
        rep.extra["locations_sample"] = locations[:10]
        rep.title = f"{rep.title} (x{len(group)} occurrences)"
        out.append(rep)
    return out


def summarize(findings: list[Finding]) -> dict[str, Any]:
    by_sev: dict[str, int] = {s: 0 for s in SEVERITIES}
    by_tool: dict[str, int] = {}
    by_category: dict[str, int] = {}
    by_engine: dict[str, int] = {"code": 0, "recon": 0}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        by_tool[f.tool] = by_tool.get(f.tool, 0) + 1
        by_category[f.category] = by_category.get(f.category, 0) + 1
        by_engine[f.engine] = by_engine.get(f.engine, 0) + 1
    return {
        "total": len(findings),
        "by_severity": by_sev,
        "by_tool": by_tool,
        "by_category": by_category,
        "by_engine": by_engine,
    }
