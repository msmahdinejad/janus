"""Janus — a two-faced security pipeline.

One face reads source code (the `code` engine: SAST, secrets, dependency
vulnerabilities). The other face looks outward like an attacker would (the
`recon` engine: passive asset discovery, header/config checks, optional
template-based scanning, optional pluggable AI-agent testing).

Both faces write into one shared, deduplicated findings register, and both
are gated by the same mandatory authorization check in `janus.core.scope`.

See README.md for usage and ARCHITECTURE.md for the design rationale and the
tool research behind each choice.
"""

__version__ = "0.2.0"
