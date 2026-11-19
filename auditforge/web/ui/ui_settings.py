from __future__ import annotations

import html
import json
from collections.abc import Mapping

from .llm_candidates import DEFAULT_BASE_URL, DEFAULT_MODEL

__all__ = [
    "render_cli_settings",
    "render_language_settings",
    "render_llm_connection_settings",
    "render_llm_profile_settings",
    "render_settings_body",
    "render_settings_script",
]


def render_settings_body() -> str:
    """Render the settings workbench while preserving all integration hooks."""

    return f"""
      <section class="settings-layout settings-workbench" aria-label="设置工作台">
        <aside class="panel settings-nav settings-index" aria-label="设置分类">
          <nav aria-label="设置页面导航">
            <div class="settings-nav-group" role="tablist" aria-label="设置分类">
              <p class="settings-nav-title">设置分类</p>
              <button id="settings-category-tab-llm" type="button" class="settings-nav-button active" role="tab" aria-selected="true" aria-controls="settings-category-llm" data-settings-category-target="llm">LLM 配置</button>
              <button id="settings-category-tab-system" type="button" class="settings-nav-button" role="tab" aria-selected="false" aria-controls="settings-category-system" data-settings-category-target="system">系统配置</button>
            </div>
            <div class="settings-nav-group" role="tablist" aria-label="LLM 详细设置" data-settings-secondary="llm">
              <p class="settings-nav-title">LLM 详细设置</p>
              <button id="settings-section-tab-llm-connection" type="button" class="settings-subnav-button active" role="tab" aria-selected="true" aria-controls="settings-section-llm-connection" data-settings-section-target="llm-connection" data-settings-section-parent="llm">全局连接</button>
              <button id="settings-section-tab-llm-taint" type="button" class="settings-subnav-button" role="tab" aria-selected="false" aria-controls="settings-section-llm-taint" data-settings-section-target="llm-taint" data-settings-section-parent="llm">污点分析 LLM</button>
              <button id="settings-section-tab-llm-dependency" type="button" class="settings-subnav-button" role="tab" aria-selected="false" aria-controls="settings-section-llm-dependency" data-settings-section-target="llm-dependency" data-settings-section-parent="llm">依赖审计 LLM</button>
              <button id="settings-section-tab-llm-deep" type="button" class="settings-subnav-button" role="tab" aria-selected="false" aria-controls="settings-section-llm-deep" data-settings-section-target="llm-deep" data-settings-section-parent="llm">二次审计 LLM</button>
            </div>
            <div class="settings-nav-group" role="tablist" aria-label="系统详细设置" data-settings-secondary="system" hidden>
              <p class="settings-nav-title">系统详细设置</p>
              <button id="settings-section-tab-system-language" type="button" class="settings-subnav-button active" role="tab" aria-selected="true" aria-controls="settings-section-system-language" data-settings-section-target="system-language" data-settings-section-parent="system">界面语言</button>
              <button id="settings-section-tab-system-cli" type="button" class="settings-subnav-button" role="tab" aria-selected="false" aria-controls="settings-section-system-cli" data-settings-section-target="system-cli" data-settings-section-parent="system">CLI 使用</button>
            </div>
          </nav>
        </aside>
        <section class="panel settings-content settings-console" aria-label="设置详情">
          <form id="settingsForm">
            <div id="settings-category-llm" class="settings-category" role="tabpanel" aria-labelledby="settings-category-tab-llm" data-settings-category="llm">
              <header class="section settings-category-head">
                <h2>LLM 配置</h2>
                <p>API Base URL、API Key、Provider、环境变量和输出数量为全局连接配置；每个审计阶段只单独维护模型和提示词。</p>
              </header>
              <div class="notice" role="note">API key 会写入独立密钥仓库（Windows 使用当前用户 DPAPI 加密），普通设置、报告和 Dashboard 不保存明文。留空表示不修改已有 key。</div>
              <div class="settings-profiles">
                <div id="settings-section-llm-connection" class="settings-subpanel" role="tabpanel" tabindex="0" aria-labelledby="settings-section-tab-llm-connection" data-settings-section="llm-connection" data-settings-section-parent="llm">
                  {render_llm_connection_settings()}
                </div>
                <div id="settings-section-llm-taint" class="settings-subpanel" role="tabpanel" tabindex="0" aria-labelledby="settings-section-tab-llm-taint" data-settings-section="llm-taint" data-settings-section-parent="llm" hidden>
                  {render_llm_profile_settings("taint", "污点分析 LLM", "使用数据流与注入、认证授权、SSRF 与 XSS 专业 Agent 并行补充候选路径。")} 
                </div>
                <div id="settings-section-llm-dependency" class="settings-subpanel" role="tabpanel" tabindex="0" aria-labelledby="settings-section-tab-llm-dependency" data-settings-section="llm-dependency" data-settings-section-parent="llm" hidden>
                  {render_llm_profile_settings("dependency", "依赖审计 LLM", "用于 requirements.txt、pom.xml、package.json、go.mod 等依赖清单的 CVE/高危组件候选分析。")}
                </div>
                <div id="settings-section-llm-deep" class="settings-subpanel" role="tabpanel" tabindex="0" aria-labelledby="settings-section-tab-llm-deep" data-settings-section="llm-deep" data-settings-section-parent="llm" hidden>
                  {render_llm_profile_settings("deep", "二次审计 LLM", "用于 LLM 二次深入验证，在容器级隔离沙箱中生成安全测试并复核候选是否成立。")}
                </div>
              </div>
            </div>
            <div id="settings-category-system" class="settings-category" role="tabpanel" aria-labelledby="settings-category-tab-system" data-settings-category="system" hidden>
              <header class="section settings-category-head">
                <h2>系统配置</h2>
                <p>配置平台界面语言和本地 CLI 使用方式。</p>
              </header>
              <div class="settings-profiles">
                <div id="settings-section-system-language" class="settings-subpanel" role="tabpanel" tabindex="0" aria-labelledby="settings-section-tab-system-language" data-settings-section="system-language" data-settings-section-parent="system">
                  {render_language_settings()}
                </div>
                <div id="settings-section-system-cli" class="settings-subpanel" role="tabpanel" tabindex="0" aria-labelledby="settings-section-tab-system-cli" data-settings-section="system-cli" data-settings-section-parent="system" hidden>
                  {render_cli_settings()}
                </div>
              </div>
            </div>
            <footer class="actions settings-actions">
              <button class="primary" type="submit">保存设置</button>
              <button type="button" id="resetButton">恢复表单</button>
              <span class="status" id="statusText" role="status" aria-live="polite"></span>
            </footer>
          </form>
        </section>
      </section>"""


def render_llm_connection_settings() -> str:
    return f"""
              <section class="settings-profile" aria-labelledby="connection-settings-title">
                <header class="settings-profile-head">
                  <div>
                    <h3 id="connection-settings-title">全局连接</h3>
                    <p>所有 LLM 审计阶段共用 Provider、API Base URL、API Key、环境变量、Fixture 响应文件和输出数量限制。</p>
                  </div>
                  <label class="checkline" for="connectionEnabled"><input id="connectionEnabled" type="checkbox"> 启用</label>
                </header>
                <div class="settings-profile-body">
                  <div class="row">
                    <label for="connectionProvider">Provider
                      <select id="connectionProvider">
                        <option value="openai-compatible">openai-compatible</option>
                        <option value="fixture">fixture</option>
                      </select>
                    </label>
                    <label for="connectionBaseUrl">API Base URL
                      <span id="connectionBaseUrlHint">例如 <code>https://openai.com/v1</code></span>
                      <input id="connectionBaseUrl" aria-describedby="connectionBaseUrlHint" placeholder="{html.escape(DEFAULT_BASE_URL, quote=True)}">
                    </label>
                  </div>
                  <div class="row">
                    <label for="connectionApiKey">API Key
                      <span id="connectionKeyHint">留空表示不修改。</span>
                      <input id="connectionApiKey" type="password" autocomplete="off" aria-describedby="connectionKeyHint" placeholder="sk-...">
                    </label>
                    <label for="connectionApiKeyEnv">环境变量名
                      <input id="connectionApiKeyEnv" placeholder="AUDITFORGE_LLM_API_KEY">
                    </label>
                  </div>
                  <div class="row">
                    <label for="connectionMaxCandidates">最大候选 / 验证数量
                      <input id="connectionMaxCandidates" type="number" min="1" max="50">
                    </label>
                    <label for="connectionTimeoutSeconds">LLM 请求超时（秒）
                      <span id="connectionTimeoutHint">gpt-5.5 等慢模型建议 180-300 秒。</span>
                      <input id="connectionTimeoutSeconds" type="number" min="10" max="600" aria-describedby="connectionTimeoutHint">
                    </label>
                  </div>
                  <div class="row">
                    <label for="connectionConcurrency">LLM 并发线程数
                      <span id="connectionConcurrencyHint">用于多 Agent 审计、依赖拆分和二次复核；遇到模型限流时调低。</span>
                      <input id="connectionConcurrency" type="number" min="1" max="12" aria-describedby="connectionConcurrencyHint">
                    </label>
                    <label for="connectionSandboxConcurrency">验证并发数
                      <span id="connectionSandboxConcurrencyHint">独立控制同时提交并等待的声明式 runner 计划数量，不占用 LLM 队列槽位；runner 服务本身可单独限流。</span>
                      <input id="connectionSandboxConcurrency" type="number" min="1" max="12" aria-describedby="connectionSandboxConcurrencyHint">
                    </label>
                  </div>
                  <div class="row">
                    <label for="connectionResponseFile">Fixture 响应文件
                      <span id="connectionResponseFileHint">仅 provider 选择 fixture 时使用，用于离线回归测试。</span>
                      <input id="connectionResponseFile" aria-describedby="connectionResponseFileHint" placeholder="C:\\path\\to\\llm-response.json">
                    </label>
                  </div>
                  <label class="checkline" for="connectionClearApiKey"><input id="connectionClearApiKey" type="checkbox"> 清除已保存的 API Key</label>
                  <div class="prompt-tools">
                    <button type="button" data-test-llm="taint">发送测试消息</button>
                  </div>
                  <div class="status" id="connectionTestStatus" role="status" aria-live="polite"></div>
                </div>
              </section>"""


def render_llm_profile_settings(profile: str, title: str, description: str) -> str:
    prefix = html.escape(str(profile), quote=True)
    safe_title = html.escape(str(title))
    safe_description = html.escape(str(description))
    return f"""
              <section class="settings-profile" aria-labelledby="{prefix}ProfileTitle">
                <header class="settings-profile-head">
                  <div>
                    <h3 id="{prefix}ProfileTitle">{safe_title}</h3>
                    <p>{safe_description}</p>
                  </div>
                  <span class="profile-badge">复用全局连接</span>
                </header>
                <div class="settings-profile-body">
                  <label for="{prefix}Model">模型
                    <span id="{prefix}ModelHint">该阶段可以使用与其他阶段不同的模型；连接仍复用全局 API 配置。</span>
                    <input id="{prefix}Model" aria-describedby="{prefix}ModelHint" placeholder="{html.escape(DEFAULT_MODEL, quote=True)}">
                  </label>
                  <label for="{prefix}SystemPrompt">System Prompt
                    <span id="{prefix}SystemPromptHint">约束模型角色、输出格式和安全边界。</span>
                    <textarea id="{prefix}SystemPrompt" aria-describedby="{prefix}SystemPromptHint" spellcheck="false"></textarea>
                  </label>
                  <label for="{prefix}UserPrompt">任务 Prompt
                    <span id="{prefix}UserPromptHint">定义该阶段如何判断候选、污点传播或二次审计结论。</span>
                    <textarea id="{prefix}UserPrompt" aria-describedby="{prefix}UserPromptHint" spellcheck="false"></textarea>
                  </label>
                  <div class="prompt-tools">
                    <button type="button" data-reset-prompt="{prefix}">恢复默认模型和提示词</button>
                    <button type="button" data-test-llm="{prefix}">发送测试消息</button>
                  </div>
                  <div class="status" id="{prefix}TestStatus" role="status" aria-live="polite"></div>
                </div>
              </section>"""


def render_language_settings() -> str:
    return """
              <section class="settings-profile language-profile" aria-labelledby="language-settings-title">
                <header class="settings-profile-head">
                  <div>
                    <h3 id="language-settings-title">界面语言</h3>
                    <p>选择 Web UI 的显示语言。默认使用中文，保存后刷新页面生效。</p>
                  </div>
                </header>
                <div class="settings-profile-body">
                  <label for="languageSelect">界面语言
                    <select id="languageSelect">
                      <option value="zh-CN">中文</option>
                      <option value="en-US">English</option>
                    </select>
                  </label>
                </div>
              </section>"""


def render_cli_settings() -> str:
    return """
              <section class="settings-profile" aria-labelledby="cli-settings-title">
                <header class="settings-profile-head">
                  <div>
                    <h3 id="cli-settings-title">CLI 使用</h3>
                    <p>保存后可以在命令行复用当前工作区的 LLM 和系统设置。</p>
                  </div>
                </header>
                <div class="settings-profile-body">
                  <p>保存后可以运行：<code>python -m auditforge scan --repo &lt;repo&gt; --out &lt;workspace&gt; --use-workspace-settings</code></p>
                </div>
              </section>"""


def render_settings_script(initial_settings: Mapping[str, object], default_settings: Mapping[str, object]) -> str:
    initial = _json_for_script(initial_settings)
    defaults = _json_for_script(default_settings)
    return f"""
  <script>
    (() => {{
      const initialSettings = {initial};
      const defaultSettings = {defaults};
      const form = document.getElementById('settingsForm');
      const statusText = document.getElementById('statusText');
      const languageSelect = document.getElementById('languageSelect');
      const categoryButtons = Array.from(document.querySelectorAll('[data-settings-category-target]'));
      const categoryPanels = Array.from(document.querySelectorAll('[data-settings-category]'));
      const secondaryGroups = Array.from(document.querySelectorAll('[data-settings-secondary]'));
      const sectionButtons = Array.from(document.querySelectorAll('[data-settings-section-target]'));
      const sectionPanels = Array.from(document.querySelectorAll('[data-settings-section]'));
      const connectionFields = {{
        enabled: document.getElementById('connectionEnabled'),
        provider: document.getElementById('connectionProvider'),
        baseUrl: document.getElementById('connectionBaseUrl'),
        apiKey: document.getElementById('connectionApiKey'),
        apiKeyEnv: document.getElementById('connectionApiKeyEnv'),
        responseFile: document.getElementById('connectionResponseFile'),
        maxCandidates: document.getElementById('connectionMaxCandidates'),
        timeoutSeconds: document.getElementById('connectionTimeoutSeconds'),
        concurrency: document.getElementById('connectionConcurrency'),
        sandboxConcurrency: document.getElementById('connectionSandboxConcurrency'),
        clearApiKey: document.getElementById('connectionClearApiKey'),
        keyHint: document.getElementById('connectionKeyHint'),
        testStatus: document.getElementById('connectionTestStatus'),
      }};
      const profileIds = ['taint', 'dependency', 'deep'];
      const fields = Object.fromEntries(profileIds.map((profile) => [profile, {{
        model: document.getElementById(`${{profile}}Model`),
        systemPrompt: document.getElementById(`${{profile}}SystemPrompt`),
        userPrompt: document.getElementById(`${{profile}}UserPrompt`),
        testStatus: document.getElementById(`${{profile}}TestStatus`),
      }}]));

      function connectionFrom(settings) {{
        const llm = settings.llm || {{}};
        return llm.connection || llm || {{}};
      }}

      function profileFrom(settings, profile) {{
        const llm = settings.llm || {{}};
        return llm[profile] || {{}};
      }}

      function selectTab(button, selected) {{
        button.classList.toggle('active', selected);
        button.setAttribute('aria-selected', String(selected));
        button.tabIndex = selected ? 0 : -1;
      }}

      function activateSection(sectionId, updateHash = true) {{
        const targetButton = sectionButtons.find((button) => button.dataset.settingsSectionTarget === sectionId);
        const parent = targetButton?.dataset.settingsSectionParent || 'llm';
        categoryButtons.forEach((button) => selectTab(button, button.dataset.settingsCategoryTarget === parent));
        categoryPanels.forEach((panel) => {{
          panel.hidden = panel.dataset.settingsCategory !== parent;
        }});
        secondaryGroups.forEach((group) => {{
          group.hidden = group.dataset.settingsSecondary !== parent;
        }});
        sectionButtons.forEach((button) => selectTab(button, button.dataset.settingsSectionTarget === sectionId));
        sectionPanels.forEach((panel) => {{
          panel.hidden = panel.dataset.settingsSection !== sectionId;
        }});
        if (updateHash && window.history && window.history.replaceState) {{
          window.history.replaceState(null, '', `#${{sectionId}}`);
        }}
      }}

      function activateCategory(categoryId, updateHash = true) {{
        const activeSection = sectionButtons.find((button) => button.dataset.settingsSectionParent === categoryId && button.classList.contains('active'));
        const fallbackSection = sectionButtons.find((button) => button.dataset.settingsSectionParent === categoryId);
        const sectionId = (activeSection || fallbackSection)?.dataset.settingsSectionTarget || 'llm-connection';
        activateSection(sectionId, updateHash);
      }}

      function applyConnection(sourceSettings) {{
        const llm = connectionFrom(sourceSettings);
        connectionFields.enabled.checked = Boolean(llm.enabled);
        connectionFields.provider.value = llm.provider || 'openai-compatible';
        connectionFields.baseUrl.value = llm.base_url || '';
        connectionFields.apiKey.value = '';
        connectionFields.apiKeyEnv.value = llm.api_key_env || 'AUDITFORGE_LLM_API_KEY';
        connectionFields.responseFile.value = llm.response_file || '';
        connectionFields.maxCandidates.value = llm.max_candidates || 36;
        connectionFields.timeoutSeconds.value = llm.timeout_seconds || 180;
        connectionFields.concurrency.value = llm.concurrency || 3;
        connectionFields.sandboxConcurrency.value = llm.sandbox_concurrency || llm.concurrency || 3;
        connectionFields.clearApiKey.checked = false;
        connectionFields.keyHint.textContent = llm.has_api_key ? `已保存：${{llm.api_key}}；留空不修改。` : '未保存 key；也可以使用环境变量。';
        window.auditforgeSetStatus(connectionFields.testStatus, '');
      }}

      function applyProfile(profile, sourceSettings) {{
        const llm = profileFrom(sourceSettings, profile);
        const item = fields[profile];
        item.model.value = llm.model || '';
        item.systemPrompt.value = llm.system_prompt || '';
        item.userPrompt.value = llm.user_prompt || '';
        window.auditforgeSetStatus(item.testStatus, '');
      }}

      function applySettings(settings) {{
        if (languageSelect) languageSelect.value = settings.language || 'zh-CN';
        applyConnection(settings);
        profileIds.forEach((profile) => applyProfile(profile, settings));
      }}

      function buildConnectionPayload() {{
        return {{
          enabled: connectionFields.enabled.checked,
          provider: connectionFields.provider.value,
          base_url: connectionFields.baseUrl.value,
          api_key: connectionFields.apiKey.value,
          api_key_env: connectionFields.apiKeyEnv.value,
          response_file: connectionFields.responseFile.value,
          max_candidates: Number(connectionFields.maxCandidates.value || 36),
          timeout_seconds: Number(connectionFields.timeoutSeconds.value || 180),
          concurrency: Number(connectionFields.concurrency.value || 3),
          sandbox_concurrency: Number(connectionFields.sandboxConcurrency.value || connectionFields.concurrency.value || 3),
          clear_api_key: connectionFields.clearApiKey.checked,
        }};
      }}

      function buildProfilePayload(profile) {{
        const item = fields[profile];
        return {{
          model: item.model.value,
          system_prompt: item.systemPrompt.value,
          user_prompt: item.userPrompt.value,
        }};
      }}

      function buildSettingsPayload() {{
        return {{
          language: languageSelect ? languageSelect.value : 'zh-CN',
          llm: {{
            connection: buildConnectionPayload(),
            taint: buildProfilePayload('taint'),
            dependency: buildProfilePayload('dependency'),
            deep: buildProfilePayload('deep'),
          }},
        }};
      }}

      document.getElementById('resetButton').addEventListener('click', () => applySettings(initialSettings));
      categoryButtons.forEach((button) => {{
        button.addEventListener('click', () => activateCategory(button.dataset.settingsCategoryTarget || 'llm'));
      }});
      sectionButtons.forEach((button) => {{
        button.addEventListener('click', () => activateSection(button.dataset.settingsSectionTarget || 'llm-connection'));
      }});
      document.querySelectorAll('[data-reset-prompt]').forEach((button) => {{
        button.addEventListener('click', () => {{
          const profile = button.dataset.resetPrompt;
          const profileDefaults = profileFrom(defaultSettings, profile);
          fields[profile].model.value = profileDefaults.model || '';
          fields[profile].systemPrompt.value = profileDefaults.system_prompt || '';
          fields[profile].userPrompt.value = profileDefaults.user_prompt || '';
        }});
      }});

      document.querySelectorAll('[data-test-llm]').forEach((button) => {{
        button.addEventListener('click', async () => {{
          const profile = button.dataset.testLlm;
          const testStatus = fields[profile]?.testStatus || connectionFields.testStatus;
          window.auditforgeSetStatus(testStatus, '正在发送测试消息...');
          button.disabled = true;
          try {{
            const data = await window.auditforgeRequestJson('/api/settings/test-llm', {{
              method: 'POST',
              headers: {{'Content-Type': 'application/json', 'Accept': 'application/json'}},
              body: JSON.stringify({{profile, llm: buildSettingsPayload().llm}}),
            }}, '测试失败');
            if (data.ok !== true) {{
              throw window.auditforgeCreateError({{
                message: '服务返回了无法识别的响应。',
                code: 'RESPONSE_INVALID',
                action: '请刷新页面后重试；若问题持续，请查看运行日志。',
              }});
            }}
            const latency = data.latency_ms ? `，耗时 ${{data.latency_ms}}ms` : '';
            const reply = data.reply ? `，回复：${{data.reply}}` : '';
            window.auditforgeSetStatus(testStatus, `${{data.message || '测试成功'}}${{latency}}${{reply}}`, 'ok');
          }} catch (error) {{
            window.auditforgeShowError(testStatus, error, '测试失败');
          }} finally {{
            button.disabled = false;
          }}
        }});
      }});

      const initialHash = window.location.hash ? window.location.hash.slice(1) : 'llm-connection';
      if (sectionButtons.some((button) => button.dataset.settingsSectionTarget === initialHash)) {{
        activateSection(initialHash, false);
      }} else if (categoryButtons.some((button) => button.dataset.settingsCategoryTarget === initialHash)) {{
        activateCategory(initialHash, false);
      }} else {{
        activateSection('llm-connection', false);
      }}
      window.addEventListener('hashchange', () => {{
        const nextHash = window.location.hash ? window.location.hash.slice(1) : 'llm-connection';
        if (sectionButtons.some((button) => button.dataset.settingsSectionTarget === nextHash)) {{
          activateSection(nextHash, false);
        }}
      }});

      applySettings(initialSettings);
      form.addEventListener('submit', async (event) => {{
        event.preventDefault();
        window.auditforgeSetStatus(statusText, '保存中...');
        const payload = buildSettingsPayload();
        try {{
          const data = await window.auditforgeRequestJson('/api/settings', {{
            method: 'POST',
            headers: {{'Content-Type': 'application/json', 'Accept': 'application/json'}},
            body: JSON.stringify(payload),
          }}, '保存失败');
          if (!data.llm || typeof data.llm !== 'object') {{
            throw window.auditforgeCreateError({{
              message: '服务返回了无法识别的响应。',
              code: 'RESPONSE_INVALID',
              action: '请刷新页面后重试；若问题持续，请查看运行日志。',
            }});
          }}
          const nextLanguage = data.language || 'zh-CN';
          applySettings(data);
          window.auditforgeSetStatus(statusText, '已保存', 'ok');
          if (nextLanguage !== window.auditforgeLanguage) {{
            window.location.reload();
            return;
          }}
          if (window.auditforgeApplyLanguage) window.auditforgeApplyLanguage(nextLanguage);
        }} catch (error) {{
          window.auditforgeShowError(statusText, error, '保存失败');
        }}
      }});
    }})();
  </script>
"""


def _json_for_script(value: Mapping[str, object]) -> str:
    return (
        json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        .replace("</", "<\\/")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )
