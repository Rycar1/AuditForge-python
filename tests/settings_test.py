from __future__ import annotations

import json
from argparse import Namespace
from pathlib import Path

from auditforge.cli import build_llm_config, llm_profile_requested
from auditforge.deep_verification import DEFAULT_DEEP_SYSTEM_PROMPT, DEFAULT_DEEP_USER_PROMPT
from auditforge.llm_candidates import DEFAULT_CANDIDATE_SYSTEM_PROMPT, DEFAULT_CANDIDATE_USER_PROMPT, DEFAULT_MODEL
from auditforge.settings import (
    LEGACY_DEFAULT_PROMPTS,
    LEGACY_DEFAULT_PROMPTS_V2,
    LEGACY_DEFAULT_PROMPTS_V3,
    PROMPT_VERSION,
    llm_config_from_settings,
    load_workspace_settings,
    public_settings,
    sandbox_concurrency_from_settings,
    save_workspace_settings,
    settings_path,
)


def test_sandbox_concurrency_is_independent_and_legacy_compatible() -> None:
    assert sandbox_concurrency_from_settings({"llm": {"connection": {"concurrency": 5}}}) == 5
    assert sandbox_concurrency_from_settings({"llm": {"connection": {"concurrency": 5, "sandbox_concurrency": 2}}}) == 2


def test_workspace_settings_save_mask_and_cli_config(tmp_path: Path) -> None:
    settings = save_workspace_settings(
        tmp_path,
        {
            "llm": {
                "enabled": True,
                "provider": "openai-compatible",
                "model": "gpt-5.4-mini",
                "base_url": "https://lingzhi.agibot.com/v1",
                "api_key": "unit-test-api-key-value",
                "api_key_env": "AUDITFORGE_TEST_KEY",
                "response_file": "fixture-response.json",
                "max_candidates": 5,
                "timeout_seconds": 240,
                "concurrency": 4,
            }
        },
    )

    assert settings_path(tmp_path).exists()
    assert settings["llm"]["api_key"] == "unit-test-api-key-value"

    public = public_settings(settings)
    assert public["llm"]["has_api_key"] is True
    assert public["llm"]["api_key"].startswith("uni")
    assert "api-key-value" not in json.dumps(public, ensure_ascii=False)

    args = Namespace(use_workspace_settings=True, llm_response_file=None)
    config = build_llm_config(args, tmp_path)
    assert config.enabled is True
    assert config.model == "gpt-5.4-mini"
    assert config.base_url == "https://lingzhi.agibot.com/v1"
    assert config.api_key == "unit-test-api-key-value"
    assert config.api_key_env == "AUDITFORGE_TEST_KEY"
    assert config.response_file == "fixture-response.json"
    assert config.max_candidates == 5
    assert config.timeout_seconds == 240
    assert config.concurrency == 4


def test_workspace_settings_language_defaults_and_validation(tmp_path: Path) -> None:
    settings = load_workspace_settings(tmp_path)
    assert settings["language"] == "zh-CN"

    settings = save_workspace_settings(tmp_path, {"language": "en-US", "llm": {}})
    assert settings["language"] == "en-US"
    assert public_settings(settings)["language"] == "en-US"

    settings = save_workspace_settings(tmp_path, {"language": "fr-FR", "llm": {}})
    assert settings["language"] == "zh-CN"


def test_cli_llm_profiles_are_enabled_independently() -> None:
    deep_only = Namespace(llm_candidates=False, dependency_scan=False, verify="deep")
    dependency_only = Namespace(llm_candidates=False, dependency_scan=True, verify="none")

    assert llm_profile_requested(deep_only, "taint") is False
    assert llm_profile_requested(deep_only, "deep") is True
    assert llm_profile_requested(deep_only, "dependency") is False
    assert llm_profile_requested(dependency_only, "taint") is False
    assert llm_profile_requested(dependency_only, "deep") is False
    assert llm_profile_requested(dependency_only, "dependency") is True


def test_default_llm_model_is_gpt55(tmp_path: Path) -> None:
    settings = load_workspace_settings(tmp_path)

    assert DEFAULT_MODEL == "gpt-5.5"
    assert settings["llm"]["taint"]["model"] == "gpt-5.5"
    assert settings["llm"]["dependency"]["model"] == "gpt-5.5"
    assert settings["llm"]["deep"]["model"] == "gpt-5.5"


def test_workspace_settings_upgrades_legacy_default_prompts(tmp_path: Path) -> None:
    settings_path(tmp_path).write_text(
        json.dumps(
            {
                "llm": {
                    "taint": {
                        "model": "gpt-4o-mini",
                        "system_prompt": LEGACY_DEFAULT_PROMPTS["taint"]["system_prompt"],
                        "user_prompt": LEGACY_DEFAULT_PROMPTS["taint"]["user_prompt"],
                    },
                    "dependency": {
                        "system_prompt": "custom dependency system",
                        "user_prompt": "custom dependency user",
                    },
                }
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    settings = load_workspace_settings(tmp_path)

    assert settings["llm"]["taint"]["prompt_version"] == PROMPT_VERSION
    assert settings["llm"]["taint"]["system_prompt"] == DEFAULT_CANDIDATE_SYSTEM_PROMPT
    assert settings["llm"]["taint"]["model"] == "gpt-5.5"
    assert settings["llm"]["dependency"]["system_prompt"] == "custom dependency system"


def test_workspace_settings_upgrades_v2_default_prompts(tmp_path: Path) -> None:
    settings_path(tmp_path).write_text(
        json.dumps(
            {
                "llm": {
                    "taint": {
                        "prompt_version": 2,
                        "model": "gpt-5.4-mini",
                        "system_prompt": LEGACY_DEFAULT_PROMPTS_V2["taint"]["system_prompt"],
                        "user_prompt": LEGACY_DEFAULT_PROMPTS_V2["taint"]["user_prompt"],
                    }
                }
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    settings = load_workspace_settings(tmp_path)

    assert PROMPT_VERSION == 4
    assert settings["llm"]["taint"]["prompt_version"] == PROMPT_VERSION
    assert settings["llm"]["taint"]["system_prompt"] == DEFAULT_CANDIDATE_SYSTEM_PROMPT
    assert settings["llm"]["taint"]["user_prompt"] == DEFAULT_CANDIDATE_USER_PROMPT
    assert settings["llm"]["taint"]["model"] == "gpt-5.5"


def test_workspace_settings_upgrades_v3_deep_sandbox_prompt(tmp_path: Path) -> None:
    settings_path(tmp_path).write_text(
        json.dumps(
            {
                "llm": {
                    "deep": {
                        "prompt_version": 3,
                        "model": "gpt-5.4-mini",
                        "system_prompt": LEGACY_DEFAULT_PROMPTS_V3["deep"]["system_prompt"],
                        "user_prompt": LEGACY_DEFAULT_PROMPTS_V3["deep"]["user_prompt"],
                    }
                }
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    settings = load_workspace_settings(tmp_path)

    assert settings["llm"]["deep"]["prompt_version"] == PROMPT_VERSION
    assert settings["llm"]["deep"]["system_prompt"] == DEFAULT_DEEP_SYSTEM_PROMPT
    assert settings["llm"]["deep"]["user_prompt"] == DEFAULT_DEEP_USER_PROMPT
    assert settings["llm"]["deep"]["model"] == "gpt-5.5"


def test_workspace_settings_does_not_persist_masked_key(tmp_path: Path) -> None:
    save_workspace_settings(tmp_path, {"llm": {"api_key": "original-unit-test-key"}})
    masked = public_settings(load_workspace_settings(tmp_path))["llm"]["api_key"]

    save_workspace_settings(tmp_path, {"llm": {"api_key": masked, "model": "glm-5.2"}})
    settings = load_workspace_settings(tmp_path)

    assert settings["llm"]["api_key"] == "original-unit-test-key"
    assert settings["llm"]["model"] == "glm-5.2"


def test_workspace_settings_supports_separate_llm_profiles_and_prompts(tmp_path: Path) -> None:
    settings = save_workspace_settings(
        tmp_path,
        {
            "llm": {
                "connection": {
                    "enabled": True,
                    "provider": "openai-compatible",
                    "base_url": "https://shared.example/v1",
                    "api_key": "shared-key-value",
                    "api_key_env": "SHARED_KEY_ENV",
                    "response_file": "shared-response.json",
                    "max_candidates": 7,
                    "timeout_seconds": 300,
                    "concurrency": 6,
                },
                "taint": {
                    "model": "taint-model",
                    "system_prompt": "污点分析 system",
                    "user_prompt": "污点分析 user",
                },
                "dependency": {
                    "model": "dependency-model",
                    "system_prompt": "依赖审计 system",
                    "user_prompt": "依赖审计 user",
                },
                "deep": {
                    "model": "deep-model",
                    "system_prompt": "二次审计 system",
                    "user_prompt": "二次审计 user",
                },
            }
        },
    )

    taint = llm_config_from_settings(settings, profile="taint")
    dependency = llm_config_from_settings(settings, profile="dependency")
    deep = llm_config_from_settings(settings, profile="deep")

    assert taint.model == "taint-model"
    assert taint.base_url == "https://shared.example/v1"
    assert taint.api_key == "shared-key-value"
    assert taint.api_key_env == "SHARED_KEY_ENV"
    assert taint.response_file == "shared-response.json"
    assert taint.system_prompt == "污点分析 system"
    assert taint.user_prompt == "污点分析 user"
    assert taint.max_candidates == 7
    assert taint.timeout_seconds == 300
    assert taint.concurrency == 6
    assert dependency.model == "dependency-model"
    assert dependency.base_url == "https://shared.example/v1"
    assert dependency.api_key == "shared-key-value"
    assert dependency.api_key_env == "SHARED_KEY_ENV"
    assert dependency.response_file == "shared-response.json"
    assert dependency.system_prompt == "依赖审计 system"
    assert dependency.user_prompt == "依赖审计 user"
    assert dependency.max_candidates == 7
    assert dependency.timeout_seconds == 300
    assert dependency.concurrency == 6
    assert deep.model == "deep-model"
    assert deep.base_url == "https://shared.example/v1"
    assert deep.api_key == "shared-key-value"
    assert deep.response_file == "shared-response.json"
    assert deep.system_prompt == "二次审计 system"
    assert deep.user_prompt == "二次审计 user"
    assert deep.max_candidates == 7
    assert deep.timeout_seconds == 300
    assert deep.concurrency == 6

    public = public_settings(settings)
    assert public["llm"]["connection"]["has_api_key"] is True
    assert public["llm"]["has_api_key"] is True
    assert "api_key" not in public["llm"]["taint"]
    assert "api_key" not in public["llm"]["dependency"]
    assert "api_key" not in public["llm"]["deep"]
    serialized = json.dumps(public, ensure_ascii=False)
    assert "shared-key-value" not in serialized


def test_global_connection_clear_key_and_disable_do_not_fallback_to_legacy_flat_values(tmp_path: Path) -> None:
    save_workspace_settings(
        tmp_path,
        {
            "llm": {
                "connection": {"enabled": True, "api_key": "legacy-flat-key"},
            }
        },
    )
    save_workspace_settings(tmp_path, {"llm": {"connection": {"enabled": False, "clear_api_key": True}}})
    settings = load_workspace_settings(tmp_path)
    taint = llm_config_from_settings(settings, profile="taint")

    assert taint.enabled is False
    assert taint.api_key is None
