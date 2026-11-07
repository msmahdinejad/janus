import os
import textwrap
from pathlib import Path

from janus.core.providers import DEFAULT_PROVIDERS, load_providers, resolve


def test_default_providers_cover_deepseek_glm_openai():
    assert {"deepseek", "glm", "openai"}.issubset(DEFAULT_PROVIDERS)


def test_defaults_are_overrideable_and_structurally_valid():
    # Model ids move faster than releases; the invariant is that every
    # profile is complete and overrideable, not that a specific id is pinned.
    for name in ("deepseek", "glm", "openai", "openrouter"):
        p = DEFAULT_PROVIDERS[name]
        assert p.base_url.startswith("https://")
        assert p.model and p.api_key_env
    assert DEFAULT_PROVIDERS["deepseek"].base_url == "https://api.deepseek.com"
    assert DEFAULT_PROVIDERS["deepseek"].model == "deepseek-flash"
    assert DEFAULT_PROVIDERS["glm"].base_url == "https://api.z.ai/api/paas/v4"
    assert DEFAULT_PROVIDERS["glm"].model == "glm-5.3"
    assert DEFAULT_PROVIDERS["openai"].model == "gpt-6-astra"
    assert DEFAULT_PROVIDERS["openai"].api_format == "responses"
    assert DEFAULT_PROVIDERS["openrouter"].model == "deepseek/deepseek-v4.1-flash-1017"


def test_available_is_false_without_env_key(monkeypatch):
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    assert DEFAULT_PROVIDERS["deepseek"].available is False


def test_available_is_true_with_env_key(monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "test-not-a-real-key")
    assert DEFAULT_PROVIDERS["deepseek"].available is True


def test_resolve_splits_ready_and_problems(monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "test-not-a-real-key")
    monkeypatch.delenv("GLM_API_KEY", raising=False)
    ready, problems = resolve(["deepseek", "glm", "not-a-real-provider"], DEFAULT_PROVIDERS)
    assert [p.name for p in ready] == ["deepseek"]
    assert any("GLM_API_KEY" in p for p in problems)
    assert any("not-a-real-provider" in p for p in problems)


def test_load_providers_overrides_model_only(tmp_path: Path):
    toml_path = tmp_path / "providers.toml"
    toml_path.write_text(textwrap.dedent("""\
        [providers.deepseek]
        model = "custom-model-name"
    """), encoding="utf-8")
    providers = load_providers(toml_path)
    assert providers["deepseek"].model == "custom-model-name"
    # Unspecified fields keep their default rather than being blanked out.
    assert providers["deepseek"].base_url == DEFAULT_PROVIDERS["deepseek"].base_url
    assert providers["deepseek"].api_key_env == DEFAULT_PROVIDERS["deepseek"].api_key_env


def test_load_providers_adds_brand_new_entry(tmp_path: Path):
    toml_path = tmp_path / "providers.toml"
    toml_path.write_text(textwrap.dedent("""\
        [providers.my-custom-gateway]
        base_url = "https://example.internal/v1"
        model = "whatever"
        api_key_env = "MY_GATEWAY_KEY"
    """), encoding="utf-8")
    providers = load_providers(toml_path)
    assert providers["my-custom-gateway"].base_url == "https://example.internal/v1"
    # Built-ins are still present alongside the new one.
    assert "deepseek" in providers


def test_load_providers_missing_file_returns_defaults():
    providers = load_providers(Path("does-not-exist.toml"))
    assert providers == DEFAULT_PROVIDERS


def test_load_providers_none_path_returns_defaults():
    assert load_providers(None) == DEFAULT_PROVIDERS
