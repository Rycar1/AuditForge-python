from __future__ import annotations

from html.parser import HTMLParser
from pathlib import Path

from auditforge.core.settings import default_settings, public_settings
from auditforge.web import server
from auditforge.web.ui import server_ui, ui_settings


class SettingsDOM(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.elements: list[tuple[str, dict[str, str | None]]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.elements.append((tag, dict(attrs)))

    @property
    def ids(self) -> set[str]:
        return {str(attrs["id"]) for _, attrs in self.elements if attrs.get("id")}

    @property
    def classes(self) -> set[str]:
        return {name for _, attrs in self.elements for name in str(attrs.get("class") or "").split() if name}

    def data_values(self, name: str) -> set[str]:
        return {str(attrs[name]) for _, attrs in self.elements if attrs.get(name) is not None}


def parse_settings(markup: str) -> SettingsDOM:
    dom = SettingsDOM()
    dom.feed(markup)
    return dom


def test_settings_body_preserves_form_ids_and_data_hooks() -> None:
    body = ui_settings.render_settings_body()
    dom = parse_settings(body)

    expected_ids = {
        "settingsForm",
        "connectionEnabled",
        "connectionProvider",
        "connectionBaseUrl",
        "connectionApiKey",
        "connectionApiKeyEnv",
        "connectionResponseFile",
        "connectionMaxCandidates",
        "connectionTimeoutSeconds",
        "connectionConcurrency",
        "connectionClearApiKey",
        "connectionKeyHint",
        "connectionTestStatus",
        "taintModel",
        "taintSystemPrompt",
        "taintUserPrompt",
        "taintTestStatus",
        "dependencyModel",
        "dependencySystemPrompt",
        "dependencyUserPrompt",
        "dependencyTestStatus",
        "deepModel",
        "deepSystemPrompt",
        "deepUserPrompt",
        "deepTestStatus",
        "languageSelect",
        "resetButton",
        "statusText",
    }
    assert expected_ids <= dom.ids
    assert dom.data_values("data-settings-category-target") == {"llm", "system"}
    assert dom.data_values("data-settings-category") == {"llm", "system"}
    assert dom.data_values("data-settings-secondary") == {"llm", "system"}
    assert dom.data_values("data-settings-section-target") == {
        "llm-connection",
        "llm-taint",
        "llm-dependency",
        "llm-deep",
        "system-language",
        "system-cli",
    }
    assert dom.data_values("data-settings-section") == dom.data_values("data-settings-section-target")
    assert dom.data_values("data-reset-prompt") == {"taint", "dependency", "deep"}
    assert dom.data_values("data-test-llm") == {"taint", "dependency", "deep"}


def test_settings_body_uses_semantic_dense_workbench_structure() -> None:
    body = ui_settings.render_settings_body()
    dom = parse_settings(body)

    assert {"settings-layout", "settings-workbench", "settings-index", "settings-console"} <= dom.classes
    assert '<nav aria-label="设置页面导航">' in body
    assert 'role="tablist"' in body
    assert 'role="tab" aria-selected="true"' in body
    assert 'role="tabpanel"' in body
    assert 'role="status" aria-live="polite"' in body
    assert "<fieldset" not in body
    assert "<script" not in body


def test_profile_renderer_escapes_dynamic_copy_and_attributes() -> None:
    profile = ui_settings.render_llm_profile_settings(
        'taint" onfocus="bad',
        "<污点模型>",
        "source & sink",
    )

    assert 'onfocus="bad"' not in profile
    assert "taint&quot; onfocus=&quot;badModel" in profile
    assert "&lt;污点模型&gt;" in profile
    assert "source &amp; sink" in profile


def test_settings_script_preserves_endpoints_payload_and_safe_text_updates() -> None:
    initial = public_settings(default_settings())
    initial["llm"]["taint"]["system_prompt"] = "safe </script><script>bad()</script>"
    script = ui_settings.render_settings_script(initial, public_settings(default_settings()))

    assert "window.auditforgeRequestJson('/api/settings/test-llm'" in script
    assert "window.auditforgeRequestJson('/api/settings'" in script
    assert "buildConnectionPayload" in script
    assert "buildProfilePayload('taint')" in script
    assert "buildProfilePayload('dependency')" in script
    assert "buildProfilePayload('deep')" in script
    assert "api_key_env:" in script
    assert "clear_api_key:" in script
    assert "window.location.reload()" in script
    assert "window.auditforgeApplyLanguage" in script
    assert "setAttribute('aria-selected'" in script
    assert "window.auditforgeShowError" in script
    assert "window.auditforgeSetStatus" in script
    assert "window.auditforgeCreateError" in script
    assert "response.json()" not in script
    assert ".textContent" in script
    assert "innerHTML" not in script
    assert "</script><script>bad()" not in script
    assert "<\\/script><script>bad()<\\/script>" in script
    assert script.count("</script>") == 1


def test_server_settings_adapter_uses_new_shell_and_module(tmp_path: Path) -> None:
    document = server_ui.render_settings_page(tmp_path)
    dom = parse_settings(document)

    assert server.render_settings_page is server_ui.render_settings_page
    assert server_ui.render_settings_page.__module__ == "auditforge.web.ui.server_ui"
    assert {"app-shell", "command-bar", "side-rail", "workspace-main", "settings-workbench"} <= dom.classes
    assert '<a class="nav-link is-active" href="/settings" aria-current="page">设置</a>' in document
    assert "window.auditforgeRequestJson('/api/settings/test-llm'" in document
    assert "window.auditforgeRequestJson('/api/settings'" in document
    assert "X-AuditForge-Reference" in document
    assert "target.setAttribute('role', 'alert')" in document
    assert "—" not in document
    assert "–" not in document


def test_server_fragment_adapters_delegate_to_ui_settings() -> None:
    assert server_ui.render_llm_connection_settings() == ui_settings.render_llm_connection_settings()
    assert server_ui.render_llm_profile_settings("deep", "标题", "描述") == ui_settings.render_llm_profile_settings("deep", "标题", "描述")
    assert server_ui.render_language_settings() == ui_settings.render_language_settings()
    assert server_ui.render_cli_settings() == ui_settings.render_cli_settings()
