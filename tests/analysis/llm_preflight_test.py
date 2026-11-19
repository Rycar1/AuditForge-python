from __future__ import annotations

from auditforge.analysis.llm_candidates import LLMConfig, preflight_llm_config


def test_missing_remote_key_is_disabled_before_task_fan_out(monkeypatch) -> None:
    monkeypatch.delenv("AUDITFORGE_LLM_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    config, diagnostics = preflight_llm_config(LLMConfig(enabled=True, api_key_env="AUDITFORGE_LLM_API_KEY"))

    assert config.enabled is False
    assert diagnostics == {
        "requested": True,
        "enabled": False,
        "provider": "openai-compatible",
        "reason": "missing_api_key",
    }


def test_fixture_preflight_requires_an_existing_response_file(tmp_path) -> None:
    missing, missing_diagnostics = preflight_llm_config(
        LLMConfig(enabled=True, provider="fixture", response_file=str(tmp_path / "none.json"))
    )
    response = tmp_path / "response.json"
    response.write_text('{"candidates": []}', encoding="utf-8")
    fixture, fixture_diagnostics = preflight_llm_config(LLMConfig(enabled=True, provider="fixture", response_file=str(response)))

    assert missing.enabled is False
    assert missing_diagnostics["reason"] == "fixture_response_file_missing"
    assert fixture.enabled is True
    assert fixture_diagnostics["reason"] == "fixture"
