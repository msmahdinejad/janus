"""Built-in review lenses.

The premise of the pipeline is that an operator should not have to remember
to run five different prompts ("look for IDOR", "look for payment bugs",
"look at the upload path", ...) with three different models and then merge
the results by hand. Those prompts are product surface: they are versioned
here, selected with `--lens`, and merged into one run whose output lands in
one register.

A lens is not a scanner rule. It is a focus area handed to the agent, plus
the OWASP categories it is expected to exercise. `coverage.py` uses that
mapping to show which areas were actually attempted and which were skipped,
so "no findings here" can be distinguished from "nobody looked here".
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Lens:
    id: str
    title: str
    focus: str
    owasp: tuple[str, ...]


LENSES: tuple[Lens, ...] = (
    Lens(
        "authz", "Broken access control",
        "Object- and function-level authorization: swap identifiers between two accounts (IDOR/BOLA), "
        "call staff/seller-only endpoints as a normal user, check whether list endpoints leak rows "
        "belonging to other users, and test tenant boundaries. Compare status codes and body shapes, "
        "not just presence of a login page.",
        ("A01:2021",),
    ),
    Lens(
        "authn", "Authentication and session",
        "Login, OTP, password reset, session and token lifecycle: JWT algorithm/claim handling, "
        "refresh-token reuse, logout invalidation, account enumeration, rate limiting on OTP, "
        "and whether a disabled/deleted account still authenticates.",
        ("A07:2021",),
    ),
    Lens(
        "injection", "Injection and server-side execution",
        "SQL/NoSQL injection, template injection, command injection, SSRF (including cloud metadata), "
        "XXE and unsafe deserialization. Prefer boolean/time evidence over destructive payloads; "
        "prove reachability, then stop.",
        ("A03:2021",),
    ),
    Lens(
        "secrets", "Secrets and data exposure",
        "Credentials in shipped JS, sourcemaps, public config endpoints, verbose errors, stack traces, "
        "debug endpoints, directory listings, and internal identifiers exposed in public APIs.",
        ("A02:2021", "A05:2021"),
    ),
    Lens(
        "business", "Business logic and payments",
        "Price/quantity tampering, coupon and credit reuse, race conditions around balance or stock, "
        "order-state transitions that skip a step, refund/callback trust, and replay of signed "
        "notifications. Evidence must show the state change, not just the request.",
        ("A04:2021",),
    ),
    Lens(
        "files", "File handling and uploads",
        "Upload type/content validation, path traversal, stored XSS via SVG/HTML, image-processing "
        "resource exhaustion, private-file access by guessing keys, and signed-URL scope.",
        ("A03:2021", "A01:2021"),
    ),
    Lens(
        "client", "Client-side and browser trust",
        "Stored/reflected/DOM XSS, CSRF on state-changing endpoints, clickjacking, postMessage origin "
        "checks, CORS with credentials, cookie flags, and third-party script trust.",
        ("A03:2021", "A05:2021"),
    ),
    Lens(
        "write", "Write-path authorization and integrity",
        "For each write endpoint the scope allows: create one synthetic record with a unique "
        "marker, then check whether another identity (or no identity) can read or modify it; "
        "replay the create call with privileged fields added one at a time (role, owner_id, "
        "price, is_staff, approved) and see whether the response echoes them; try the same path "
        "with a safe verb; check whether the created object's identifier is guessable. Use only "
        "synthetic values, one record at a time, and list every record you created in your final "
        "summary so a human can remove it.",
        ("A01:2021", "A04:2021"),
    ),
    Lens(
        "infra", "Edge, platform and configuration",
        "Exposed admin/dev services, missing HSTS/CSP, TLS and header configuration, SPF/DMARC, "
        "public object storage, and reachable internal tooling. Observation only; no login attempts.",
        ("A05:2021", "A06:2021"),
    ),
)

LENS_BY_ID = {lens.id: lens for lens in LENSES}
ALL_LENS_IDS = tuple(lens.id for lens in LENSES)


def select(names: str | list[str] | None) -> list[Lens]:
    """Resolve `--lens` into Lens objects. Unknown names are an error the
    caller should surface; `all` expands to every lens."""
    if not names:
        return list(LENSES)
    if isinstance(names, str):
        wanted = [n.strip() for n in names.split(",") if n.strip()]
    else:
        wanted = list(names)
    if "all" in wanted:
        return list(LENSES)
    unknown = [n for n in wanted if n not in LENS_BY_ID]
    if unknown:
        raise ValueError(f"unknown lens {unknown}; available: {', '.join(ALL_LENS_IDS)}")
    return [LENS_BY_ID[n] for n in wanted]


def instruction(lenses: list[Lens]) -> str:
    """One instruction that carries every selected lens, so the operator runs
    one agent pass instead of five prompts."""
    lines = [
        "Work through these focus areas explicitly and say which ones you covered:",
    ]
    for lens in lenses:
        lines.append(f"- [{lens.id}] {lens.title}: {lens.focus}")
    lines.append(
        "If an area cannot be assessed from the outside (for example payment callbacks), "
        "record it as not-assessed in your final summary instead of guessing."
    )
    return "\n".join(lines)
