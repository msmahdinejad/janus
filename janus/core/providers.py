"""Named LLM provider profiles for the optional agent-testing layer.

Why this file exists: the agent layer (janus/engines/recon/agent.py) needs
*an* OpenAI-compatible endpoint to drive Strix (or another agent backend),
but which one is a deployment choice, not a code choice — and per the
project's brief, it should be easy to run the SAME agent step across
several models at once for better coverage (different models catch
different bugs; this is a well-documented ensemble effect, not a hunch).

This module just maps a short name ("deepseek", "glm", ...) to
{base_url, model, api_key_env, api_format}. Nothing here ever reads, logs, or stores an
actual key value — `resolve()` only reports whether the named environment
variable is *set*, and the caller reads `os.environ[profile.api_key_env]`
itself at the point of use (see agent.py), the same discipline
`core/scope.py` and the Docker image apply to every other secret.

Defaults below were refreshed against the providers' current public model
catalogues on 2026-11-06. Model IDs can still change, so every value remains
an overrideable default rather than a hard-coded guarantee. Use
`providers.toml` (see `load_providers`) for an account-specific model or
gateway without changing this file.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, replace
from pathlib import Path


@dataclass(frozen=True)
class ProviderProfile:
    name: str
    base_url: str
    model: str
    api_key_env: str
    notes: str = ""
    # NativeAgent uses this to select the wire format required by the model.
    # External OpenAI-compatible backends continue to use chat completions.
    api_format: str = "chat_completions"
    # "httpx" or "urllib". Some gateways terminate TLS in a way httpx rejects
    # while urllib/.NET/curl succeed; making the transport a profile field is
    # cheaper than debugging someone else's TLS stack.
    transport: str = "httpx"

    @property
    def available(self) -> bool:
        """True if the API key this profile needs is actually set — does
        NOT read or return the value itself."""
        return bool(os.environ.get(self.api_key_env, "").strip())


# One entry per named provider the CLI/scope.toml can refer to. See the
# module docstring: these are starting points, not guarantees.
DEFAULT_PROVIDERS: dict[str, ProviderProfile] = {
    "deepseek": ProviderProfile(
        name="deepseek",
        base_url="https://api.deepseek.com",
        model="deepseek-flash",
        api_key_env="DEEPSEEK_API_KEY",
        notes=(
            "Direct DeepSeek OpenAI-compatible API. `deepseek-flash` is the stable alias for "
            "the current DeepSeek V4.1 Flash release; the documented base URL is the host root, "
            "not `/v1`. Override with `deepseek-v4-pro` when your account needs the Pro model."
        ),
    ),
    "glm": ProviderProfile(
        name="glm",
        base_url="https://api.z.ai/api/paas/v4",
        model="glm-5.3",
        api_key_env="GLM_API_KEY",
        notes=(
            "Z.AI international OpenAI-compatible API. `glm-5.3` is the current general GLM "
            "model in Z.AI's catalogue. Mainland accounts may need the equivalent "
            "`https://open.bigmodel.cn/api/paas/v4` endpoint; override `base_url` in providers.toml. "
            "Use `glm-5.3-flash` for a lower-cost/faster run."
        ),
    ),
    "openai": ProviderProfile(
        name="openai",
        base_url="https://api.openai.com/v1",
        model="gpt-6-astra",
        api_key_env="OPENAI_API_KEY",
        api_format="responses",
        notes=(
            "Direct OpenAI API. GPT-6 Astra is the current flagship for complex reasoning "
            "and coding. Its tool calling uses the Responses API; override `model` in "
            "providers.toml if your organization exposes a different model."
        ),
    ),
    "openrouter": ProviderProfile(
        name="openrouter",
        base_url="https://openrouter.ai/api/v1",
        model="deepseek/deepseek-v4.1-flash-1017",
        api_key_env="OPENROUTER_API_KEY",
        notes=(
            "One gateway, one API key, many providers (DeepSeek/GLM/OpenAI/others) — the pattern "
            "this project's predecessor pipeline used successfully in production. The default is "
            "DeepSeek V4.1 Flash 1017, a current OpenRouter model slug. Override `model` to any "
            "OpenRouter slug, e.g. 'z-ai/glm-5.3' or 'openai/gpt-6-astra'; you can register "
            "the SAME provider name multiple times under different names in providers.toml (e.g. "
            "'openrouter-glm', 'openrouter-deepseek') to run more than one OpenRouter-routed model "
            "in the same ensemble."
        ),
    ),
}


def load_providers(path: str | Path | None) -> dict[str, ProviderProfile]:
    """Start from DEFAULT_PROVIDERS, then merge in a providers.toml if
    given — new entries, or `[providers.<name>]` tables that override one
    or more fields of an existing default (handy for just changing a
    `model` without retyping base_url/api_key_env)."""
    providers = dict(DEFAULT_PROVIDERS)
    if not path:
        return providers
    path = Path(path)
    if not path.is_file():
        return providers
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    for name, fields in data.get("providers", {}).items():
        base = providers.get(name, ProviderProfile(name=name, base_url="", model="", api_key_env=""))
        providers[name] = replace(base, name=name, **{k: v for k, v in fields.items() if k != "name"})
    return providers


def resolve(names: list[str], providers: dict[str, ProviderProfile]) -> tuple[list[ProviderProfile], list[str]]:
    """Split requested provider names into (available, unavailable-with-reason)."""
    ready: list[ProviderProfile] = []
    problems: list[str] = []
    for name in names:
        profile = providers.get(name)
        if profile is None:
            problems.append(f"{name}: not a known provider (known: {sorted(providers)}; add it to providers.toml)")
        elif not profile.available:
            problems.append(f"{name}: {profile.api_key_env} is not set in the environment")
        else:
            ready.append(profile)
    return ready, problems


def probe_models(profile: ProviderProfile, timeout: float = 15.0) -> tuple[list[str] | None, str]:
    """Ask the provider what models this key can see.

    Model ids in this space move faster than any hard-coded default, so the
    reliable answer is a live `/models` call. Returns (ids, error).
    """
    import httpx

    key = os.environ.get(profile.api_key_env, "")
    if not key:
        return None, f"{profile.api_key_env} not set"
    try:
        with httpx.Client(timeout=timeout, trust_env=False) as client:
            resp = client.get(
                f"{profile.base_url.rstrip('/')}/models",
                headers={"Authorization": f"Bearer {key}"},
            )
        if resp.status_code >= 400:
            return None, f"HTTP {resp.status_code}"
        data = resp.json()
        ids = [m.get("id", "") for m in data.get("data", []) if isinstance(m, dict)]
        return [i for i in ids if i], ""
    except Exception as exc:  # noqa: BLE001
        return None, str(exc)[:160]
