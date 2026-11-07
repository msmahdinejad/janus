"""The mandatory authorization gate.

This is the one file in the whole project that is allowed to be annoying.
Nothing in the `recon` engine is permitted to open a socket, shell out to an
external scanner, or hand a target list to an AI agent without going through
`Scope.authorize()` first — and `Scope.authorize()` fails CLOSED: missing
fields, an expired window, an out-of-scope host, a forbidden path, or a
disallowed HTTP method all produce a hard refusal, not a warning.

Design intent (see ARCHITECTURE.md for the full rationale): a generic,
publicly distributable "acts like an attacker" tool is dual-use. The
difference between a professional security tool and an attack script is
almost entirely this file. So:

  * There is no code path, flag, or config key that disables the gate.
    `--yes-i-know-what-im-doing` does not exist here on purpose.
  * The list of allowed HTTP methods is a Python constant, not a config
    value — because a config value can be edited by the same person who
    shouldn't edit it.
  * Every decision (allow or deny) is appended to a local, append-only audit
    log with the scope file's hash, so "who ran what, against what, under
    what authorization, when" is always reconstructable later.
  * Active testing (recon beyond passive observation) and the optional AI
    agent each need their OWN explicit opt-in in the scope file, on top of
    the base authorization — enabling one does not enable the other.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import tomllib
from dataclasses import dataclass, field
from datetime import datetime, time, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

# Hard constant. Not read from any config file. See module docstring.
SAFE_HTTP_METHODS: frozenset[str] = frozenset({"GET", "HEAD", "OPTIONS"})

# Directories that are never "the code under review": dependency trees,
# build output and caches. Applied in addition to the scope's own
# `[code].exclude`, so a report cannot be flooded by a vendored `node_modules`.
NOISE_DIRS: frozenset[str] = frozenset({
    "node_modules", ".git", "dist", "build", "target", "vendor", "__pycache__",
    ".venv", "venv", ".next", "coverage", ".tmp", ".mypy_cache", ".pytest_cache",
    ".ruff_cache", ".tox", "site-packages",
})


class ScopeError(Exception):
    """Raised for a malformed/invalid scope file. This stops the run (exit
    code 2 at the CLI), it does not produce a 'denied' Decision — a broken
    scope file is a setup bug, not a target that was checked and refused."""


@dataclass
class Decision:
    allowed: bool
    target: str
    reasons: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "target": self.target,
            "reasons": self.reasons,
            "warnings": self.warnings,
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }


@dataclass
class Engagement:
    name: str
    authorized_by: str
    reference: str
    valid_from: datetime
    valid_until: datetime


@dataclass(frozen=True)
class WriteTarget:
    """One endpoint the operator explicitly authorized for mutation testing.

    Deterministic write checks only ever touch these; the agent's free-form
    POST capability is separate. Keeping the list explicit is what makes
    "create a record" reproducible and reviewable.
    """

    url: str
    method: str = "POST"
    body: dict = field(default_factory=dict)
    expect_auth: bool = True


@dataclass
class Scope:
    engagement: Engagement
    allow: list[str]
    deny: list[str]
    seeds: list[str]
    allow_ports: list[int]
    forbidden_paths: list[re.Pattern]
    allow_active_recon: bool
    allow_agent: bool
    allow_state_changing: bool
    mutating_methods: tuple[str, ...]
    write_targets: list[WriteTarget]
    mass_assignment_fields: tuple[str, ...]
    allow_private_targets: bool
    require_nonprod_marker: bool
    nonprod_markers: list[str]
    max_rps: float
    max_requests: int
    code_roots: list[Path]
    code_exclude: list[str]
    source_path: Path
    source_sha256_16: str

    @property
    def allowed_methods(self) -> frozenset[str]:
        """Safe methods always; mutating ones only when the scope opted in.

        The default stays a hard-coded constant (see SAFE_HTTP_METHODS). A
        scope file can widen it to POST/PUT/PATCH, but only deliberately, and
        only with a non-production marker enforced — `load_scope` refuses the
        combination otherwise.
        """
        if not self.allow_state_changing:
            return SAFE_HTTP_METHODS
        return SAFE_HTTP_METHODS | frozenset(self.mutating_methods)

    # ---- target (recon engine) ---------------------------------------
    def authorize(self, target: str, method: str = "GET") -> Decision:
        reasons: list[str] = []
        warnings: list[str] = []

        if method.upper() not in self.allowed_methods:
            reasons.append(
                f"method {method!r} is not allowed by this engagement "
                f"(allowed: {sorted(self.allowed_methods)}). State-changing requests need "
                f"[limits].allow_state_changing = true, a non-production marker, and the "
                f"method listed in [limits].mutating_methods."
            )

        now = datetime.now(timezone.utc)
        if not (self.engagement.valid_from <= now <= self.engagement.valid_until):
            reasons.append(
                f"current time {now.isoformat()} is outside the authorized "
                f"window {self.engagement.valid_from.isoformat()}.."
                f"{self.engagement.valid_until.isoformat()}"
            )

        parts = urlsplit(target if "://" in target else f"https://{target}")
        if parts.scheme not in ("http", "https"):
            reasons.append(f"scheme {parts.scheme!r} is not http/https")
        host = _normalize_host(parts.hostname or "")
        try:
            explicit_port = parts.port
        except ValueError:
            reasons.append(f"target {target!r} has an invalid port")
            explicit_port = None
        port = explicit_port or (443 if parts.scheme == "https" else 80)
        path = parts.path or "/"

        if not host:
            reasons.append("could not parse a hostname out of the target")
        else:
            ip = _as_ip(host)
            if ip is not None:
                # Metadata endpoints are never in scope, even if someone
                # lists them: an SSRF-to-cloud-credentials check is not a
                # service this tool performs.
                if ip.is_link_local or ip.is_multicast or ip.is_unspecified:
                    reasons.append(f"target {host!r} is a link-local/metadata address - always refused")
                elif (ip.is_private or ip.is_loopback) and not self.allow_private_targets:
                    reasons.append(
                        f"target {host!r} resolves to a private/loopback address; set "
                        f"[limits].allow_private_targets = true only for a lab target you own"
                    )
            if not any(_host_matches(host, pat) for pat in self.allow):
                reasons.append(f"host {host!r} does not match any allow pattern")
            deny_hit = next((pat for pat in self.deny if _host_matches(host, pat)), None)
            if deny_hit:
                reasons.append(f"host {host!r} matches deny pattern {deny_hit!r} (deny always wins)")
            if self.require_nonprod_marker and not any(m in host for m in self.nonprod_markers):
                reasons.append(
                    f"require_nonprod_marker is set and host {host!r} contains none of "
                    f"{self.nonprod_markers}"
                )

        if port not in self.allow_ports:
            reasons.append(f"port {port} is not in allow_ports {self.allow_ports}")

        for pat in self.forbidden_paths:
            if pat.search(path):
                reasons.append(f"path {path!r} matches forbidden_paths {pat.pattern!r}")

        if parts.scheme == "http" and host not in ("localhost", "127.0.0.1"):
            warnings.append("plain http (not https) target - fine to observe, nothing to send")

        return Decision(allowed=not reasons, target=target, reasons=reasons, warnings=warnings)

    def require_active_recon(self) -> None:
        if not self.allow_active_recon:
            raise ScopeError(
                "this scope file has allow_active_recon = false. Active probing "
                "(nuclei templates, header/CORS probes beyond a single GET, etc.) "
                "is refused until the scope file is explicitly edited to enable "
                "it - which is a deliberate, auditable, out-of-band action, not "
                "a CLI flag."
            )

    def require_agent(self) -> None:
        if not self.allow_agent:
            raise ScopeError(
                "this scope file has allow_agent = false. The optional AI-agent "
                "testing layer (see janus/engines/recon/agent.py) needs its own "
                "explicit opt-in on top of allow_active_recon, because an agent "
                "can take actions its operator did not individually review."
            )

    # ---- path (code engine) ------------------------------------------
    def authorize_path(self, path: Path) -> bool:
        resolved = path.resolve()
        root = next((r for r in self.code_roots if _is_within(resolved, r)), None)
        if root is None:
            return False
        rel = resolved.relative_to(root)
        if any(part in NOISE_DIRS for part in rel.parts):
            return False
        rel_posix = rel.as_posix()
        return not any(
            _glob_match(pattern, rel_posix) or _glob_match(pattern, resolved.as_posix())
            for pattern in self.code_exclude
        )

    # ---- audit ---------------------------------------------------------
    def manifest(self, run_id: str, extra: dict[str, Any] | None = None) -> dict[str, Any]:
        return {
            "run_id": run_id,
            "scope_file": str(self.source_path),
            "scope_sha256_16": self.source_sha256_16,
            "engagement": self.engagement.name,
            "authorized_by": self.engagement.authorized_by,
            "authorization_reference": self.engagement.reference,
            "valid_from": self.engagement.valid_from.isoformat(),
            "valid_until": self.engagement.valid_until.isoformat(),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            **(extra or {}),
        }


def _normalize_host(host: str) -> str:
    """Lowercase, strip the root-label dot, and IDNA-encode. Without this,
    `EXAMPLE.com.` and `example.com` are different strings to the allow
    list, and an internationalised name never matches at all."""
    h = (host or "").strip().rstrip(".").lower()
    if not h:
        return ""
    try:
        return h.encode("idna").decode("ascii")
    except UnicodeError:
        return h


def _as_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def _host_matches(host: str, pattern: str) -> bool:
    host = _normalize_host(host)
    pattern = _normalize_host(pattern)
    if not pattern:
        return False
    if pattern.startswith("*."):
        suffix = pattern[1:]  # ".example.com"
        # Subdomains only; the apex must be listed explicitly. A wildcard
        # that also matched the apex would silently widen every engagement.
        return host.endswith(suffix) and host != suffix.lstrip(".")
    return host == pattern


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _glob_to_regex(pattern: str) -> re.Pattern:
    # Same bug class the codesec prototype hit with fnmatch: "**/x/**" has to
    # mean "zero or more directories", not be left to the stdlib's single-*
    # semantics. Translate explicitly instead of trusting fnmatch/pathlib.
    out = []
    i = 0
    while i < len(pattern):
        if pattern[i : i + 3] == "**/":
            out.append("(?:.*/)?")
            i += 3
        elif pattern[i : i + 2] == "**":
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("^" + "".join(out) + "$")


_GLOB_CACHE: dict[str, re.Pattern] = {}


def _glob_match(pattern: str, rel_posix_path: str) -> bool:
    rx = _GLOB_CACHE.setdefault(pattern, _glob_to_regex(pattern))
    return bool(rx.search(rel_posix_path)) or bool(rx.match(rel_posix_path))


def _parse_dt(value: Any, end_of_day: bool = False, field_name: str = "date") -> datetime:
    """Parse a scope date. Invalid values are setup errors, so they raise
    ScopeError (clean exit code 2) rather than leaking a ValueError
    traceback from deep inside the loader."""
    try:
        if isinstance(value, datetime):
            return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        if isinstance(value, str):
            dt = datetime.fromisoformat(value)
            if "T" not in value:
                dt = datetime.combine(dt.date(), time(23, 59, 59) if end_of_day else time(0, 0, 0))
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise ScopeError(f"[engagement].{field_name}: {value!r} is not a valid date/time ({exc})") from exc
    raise ScopeError(f"[engagement].{field_name}: unparseable date/time: {value!r}")


def load_scope(path: str | Path) -> Scope:
    path = Path(path)
    if not path.is_file():
        raise ScopeError(f"scope file not found: {path}")

    raw_bytes = path.read_bytes()
    sha16 = hashlib.sha256(raw_bytes).hexdigest()[:16]
    try:
        data = tomllib.loads(raw_bytes.decode("utf-8"))
    except Exception as e:  # noqa: BLE001 - surface as ScopeError
        raise ScopeError(f"invalid TOML in {path}: {e}") from e

    eng = data.get("engagement", {})
    for required in ("name", "authorized_by", "reference", "valid_from", "valid_until"):
        if not str(eng.get(required, "")).strip():
            raise ScopeError(f"[engagement].{required} is required and must be non-empty")
    if not eng.get("enabled", True):
        raise ScopeError("[engagement].enabled = false - this scope file has been switched off")

    engagement = Engagement(
        name=str(eng["name"]).strip(),
        authorized_by=str(eng["authorized_by"]).strip(),
        reference=str(eng["reference"]).strip(),
        valid_from=_parse_dt(eng["valid_from"], field_name="valid_from"),
        valid_until=_parse_dt(eng["valid_until"], end_of_day=True, field_name="valid_until"),
    )
    if engagement.valid_until < engagement.valid_from:
        raise ScopeError(
            f"[engagement].valid_until ({engagement.valid_until.date()}) is before "
            f"valid_from ({engagement.valid_from.date()})"
        )

    targets = data.get("targets", {})
    limits = data.get("limits", {})
    code = data.get("code", {})

    def _str_list(value: Any, field_name: str) -> list[str]:
        if not isinstance(value, list) or not all(isinstance(v, str) and v.strip() for v in value):
            raise ScopeError(f"{field_name} must be a list of non-empty strings")
        return [v.strip() for v in value]

    allow = _str_list(targets.get("allow", []), "[targets].allow")
    seeds = _str_list(targets.get("seeds", []), "[targets].seeds")
    for seed in seeds:
        if "://" not in seed:
            raise ScopeError(
                f"[targets].seeds entry {seed!r} must be an absolute URL "
                f"(scheme://host[:port]) - a bare host cannot express a non-443 port"
            )
    for pattern in allow + _str_list(targets.get("deny", []), "[targets].deny"):
        if "://" in pattern or "/" in pattern:
            raise ScopeError(
                f"target pattern {pattern!r} must be a hostname or '*.hostname', not a URL or path"
            )

    try:
        allow_ports = [int(p) for p in targets.get("allow_ports", [80, 443])]
    except (TypeError, ValueError) as exc:
        raise ScopeError("[targets].allow_ports must be a list of integers") from exc
    if not allow_ports or any(not (1 <= p <= 65535) for p in allow_ports):
        raise ScopeError(f"[targets].allow_ports contains an invalid port: {allow_ports}")

    forbidden: list[re.Pattern] = []
    for expr in _str_list(targets.get("forbidden_paths", []), "[targets].forbidden_paths"):
        try:
            forbidden.append(re.compile(expr))
        except re.error as exc:
            raise ScopeError(f"[targets].forbidden_paths entry {expr!r} is not a valid regex: {exc}") from exc

    try:
        max_rps = float(limits.get("max_rps", 3))
        max_requests = int(limits.get("max_requests", 20000))
    except (TypeError, ValueError) as exc:
        raise ScopeError("[limits].max_rps/max_requests must be numbers") from exc
    if max_rps <= 0:
        raise ScopeError(f"[limits].max_rps must be > 0 (got {max_rps})")
    if max_requests < 1:
        raise ScopeError(f"[limits].max_requests must be >= 1 (got {max_requests})")

    scope_dir = path.parent
    code_roots = [
        (scope_dir / r).resolve() if not Path(r).is_absolute() else Path(r).resolve()
        for r in _str_list(code.get("roots", []), "[code].roots")
    ]
    for r in code_roots:
        if not r.exists():
            raise ScopeError(f"[code].roots entry does not exist: {r}")

    allow_state_changing = bool(limits.get("allow_state_changing", False))
    mutating_raw = _str_list(limits.get("mutating_methods", ["POST"]), "[limits].mutating_methods")
    mutating: list[str] = []
    for m in mutating_raw:
        upper = m.upper()
        if upper in ("DELETE", "TRACE", "CONNECT"):
            raise ScopeError(
                f"[limits].mutating_methods: {upper} is never allowed - destructive or "
                f"tunnel-establishing methods stay out of this tool by construction"
            )
        if upper not in ("POST", "PUT", "PATCH"):
            raise ScopeError(
                f"[limits].mutating_methods: {m!r} is not a recognized mutating method "
                f"(choose from POST, PUT, PATCH)"
            )
        mutating.append(upper)
    if allow_state_changing:
        if not mutating:
            raise ScopeError("[limits].allow_state_changing is true but mutating_methods is empty")
        if not bool(limits.get("require_nonprod_marker", False)):
            raise ScopeError(
                "[limits].allow_state_changing = true also requires require_nonprod_marker = true. "
                "Write-path testing is staging-only by policy; a production host must never pass "
                "this gate."
            )

    write_cfg = data.get("write", {})
    write_targets: list[WriteTarget] = []
    for i, raw_target in enumerate(write_cfg.get("targets", []) or []):
        if not isinstance(raw_target, dict) or "url" not in raw_target:
            raise ScopeError(f"[[write.targets]] entry #{i + 1} needs at least a url")
        method = str(raw_target.get("method", "POST")).upper()
        body = raw_target.get("body", {})
        if not isinstance(body, dict):
            raise ScopeError(f"[[write.targets]] #{i + 1}: body must be a table/object")
        write_targets.append(WriteTarget(
            url=str(raw_target["url"]), method=method, body=body,
            expect_auth=bool(raw_target.get("expect_auth", True)),
        ))
    if write_targets and not allow_state_changing:
        raise ScopeError(
            "[[write.targets]] requires [limits].allow_state_changing = true (which in turn "
            "requires require_nonprod_marker). Write checks are opt-in, never implicit."
        )
    for target in write_targets:
        if target.method not in mutating:
            raise ScopeError(
                f"write target {target.url}: method {target.method} is not in "
                f"[limits].mutating_methods {mutating}"
            )
    fields = write_cfg.get("mass_assignment_fields", ["role", "is_staff", "is_admin", "owner_id",
                                                      "user_id", "price", "total", "balance",
                                                      "approved", "status", "credit"])
    if not isinstance(fields, list) or not all(isinstance(f, str) and f for f in fields):
        raise ScopeError("[write].mass_assignment_fields must be a list of field names")

    return Scope(
        engagement=engagement,
        allow=allow,
        deny=_str_list(targets.get("deny", []), "[targets].deny"),
        seeds=seeds,
        allow_ports=allow_ports,
        forbidden_paths=forbidden,
        allow_active_recon=bool(limits.get("allow_active_recon", False)),
        allow_agent=bool(limits.get("allow_agent", False)),
        allow_state_changing=allow_state_changing,
        mutating_methods=tuple(mutating),
        write_targets=write_targets,
        mass_assignment_fields=tuple(fields),
        allow_private_targets=bool(limits.get("allow_private_targets", False)),
        require_nonprod_marker=bool(limits.get("require_nonprod_marker", False)),
        nonprod_markers=list(limits.get(
            "nonprod_markers", ["staging", "stage", "test", "dev", "sandbox", "qa", "demo"]
        )),
        max_rps=max_rps,
        max_requests=max_requests,
        code_roots=code_roots,
        code_exclude=_str_list(code.get("exclude", []), "[code].exclude"),
        source_path=path,
        source_sha256_16=sha16,
    )


def write_manifest(scope: Scope, run_id: str, out_dir: str | Path, extra: dict[str, Any] | None = None) -> Path:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = out_dir / f"{run_id}.manifest.json"
    manifest_path.write_text(json.dumps(scope.manifest(run_id, extra), indent=2), encoding="utf-8")
    # Also append to a single running audit log that is never truncated.
    audit_path = out_dir / "audit.ndjson"
    with audit_path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(scope.manifest(run_id, extra)) + "\n")
    return manifest_path
