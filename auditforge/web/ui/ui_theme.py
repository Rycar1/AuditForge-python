"""Self-contained visual theme for the AuditForge forensic console."""

from __future__ import annotations

__all__ = ["APP_CSS"]


APP_CSS = r"""
:root {
  color-scheme: dark;
  --bg: #090d10;
  --surface: #0f1519;
  --surface-raised: #151c21;
  --surface-inset: #0b1013;
  --border: #273137;
  --border-strong: #3a464d;
  --ink: #edf1f2;
  --muted: #96a2a8;
  --faint: #68757b;
  --accent: #d3a24f;
  --accent-hover: #e0b461;
  --accent-soft: #241d12;
  --accent-ink: #17130c;
  --danger: #d86c65;
  --danger-soft: #291615;
  --success: #76ad8f;
  --success-soft: #13231b;
  --radius: 4px;
  --radius-lg: 7px;
  --font-sans: "Segoe UI Variable", "Microsoft YaHei UI", Aptos, sans-serif;
  --font-mono: "Cascadia Mono", "SFMono-Regular", Consolas, monospace;
  --shadow: 0 18px 48px rgba(0, 0, 0, 0.28);
}

* { box-sizing: border-box; }
html { background: var(--bg); scroll-behavior: smooth; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--ink);
  font-family: var(--font-sans);
  font-size: 14px;
  line-height: 1.55;
}
::selection { background: var(--accent); color: var(--accent-ink); }
::-webkit-scrollbar { width: 10px; height: 10px; }
::-webkit-scrollbar-track { background: var(--surface-inset); }
::-webkit-scrollbar-thumb { border: 2px solid var(--surface-inset); border-radius: 8px; background: var(--border-strong); }
a, button, input, select, textarea, summary { -webkit-tap-highlight-color: transparent; }
a { color: var(--ink); text-underline-offset: 3px; }
a:hover { color: var(--accent-hover); }
button, input, select, textarea { font: inherit; }

button,
.primary-link,
.actions a,
.case-actions a,
.hero-actions a,
.empty-command a {
  display: inline-flex;
  min-height: 36px;
  align-items: center;
  justify-content: center;
  padding: 7px 13px;
  border: 1px solid var(--border-strong);
  border-radius: var(--radius);
  background: var(--surface-raised);
  color: var(--ink);
  font-size: 12px;
  font-weight: 680;
  line-height: 1.2;
  text-decoration: none;
  cursor: pointer;
  transition: border-color 160ms ease, background-color 160ms ease, color 160ms ease, transform 120ms ease;
}
button:hover,
.actions a:hover,
.case-actions a:hover,
.hero-actions a:hover,
.empty-command a:hover { border-color: var(--accent); background: #1b211f; color: var(--ink); }
button:active,
.actions a:active,
.case-actions a:active,
.hero-actions a:active,
.empty-command a:active { transform: translateY(1px); }
button.primary, .primary-link { border-color: var(--accent); background: var(--accent); color: var(--accent-ink); }
button.primary:hover, .primary-link:hover { border-color: var(--accent-hover); background: var(--accent-hover); color: var(--accent-ink); }
button.danger-button, .delete-run-button { border-color: #633532; background: var(--danger-soft); color: #efaaa5; }
button:disabled, input:disabled, select:disabled, textarea:disabled { cursor: not-allowed; opacity: 0.52; }
a:focus-visible,
button:focus-visible,
input:focus-visible,
select:focus-visible,
textarea:focus-visible,
summary:focus-visible,
[tabindex]:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }

input, select, textarea {
  width: 100%;
  min-height: 40px;
  padding: 9px 11px;
  border: 1px solid var(--border-strong);
  border-radius: var(--radius);
  background: var(--surface-inset);
  color: var(--ink);
  caret-color: var(--accent);
  transition: border-color 160ms ease, box-shadow 160ms ease, background-color 160ms ease;
}
textarea { min-height: 144px; resize: vertical; font-family: var(--font-mono); font-size: 12px; line-height: 1.55; tab-size: 2; }
input:hover, select:hover, textarea:hover { border-color: #526069; }
input:focus, select:focus, textarea:focus {
  border-color: var(--accent);
  background: #0d1316;
  box-shadow: 0 0 0 3px rgba(211, 162, 79, 0.11);
  outline: none;
}
input::placeholder, textarea::placeholder { color: var(--faint); }
input[type="checkbox"], input[type="radio"] { width: 16px; min-height: 16px; margin: 0; accent-color: var(--accent); }
input[type="file"] { padding: 6px; }
input[type="file"]::file-selector-button {
  margin-right: 10px;
  padding: 6px 10px;
  border: 1px solid var(--border-strong);
  border-radius: 3px;
  background: var(--surface-raised);
  color: var(--ink);
}
label { display: grid; gap: 7px; color: #cbd2d5; font-size: 12px; font-weight: 660; }
label > span, label > small, .field-stack small, .subtle, .form-note, .section-copy {
  color: var(--muted);
  font-size: 11px;
  font-weight: 450;
}
code, pre, .stat-value, .metric strong, .risk-value, .activity-meta, .case-reference, .telemetry-item strong {
  font-variant-numeric: tabular-nums;
}
code, pre { font-family: var(--font-mono); }
[hidden], .hidden { display: none !important; }
.panel { border: 1px solid var(--border); border-radius: var(--radius-lg); background: var(--surface); }
.page-kicker, .case-kicker {
  margin: 0 0 8px;
  color: var(--accent);
  font-family: var(--font-mono);
  font-size: 10px;
  font-weight: 760;
  letter-spacing: 0.11em;
}

.forensic-hero {
  position: relative;
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  align-items: end;
  gap: 36px;
  margin-bottom: 22px;
  padding: 30px 32px 34px;
  overflow: hidden;
  border: 1px solid var(--border-strong);
  border-radius: var(--radius-lg);
  background:
    linear-gradient(90deg, rgba(211, 162, 79, 0.055) 1px, transparent 1px) 0 0 / 48px 48px,
    linear-gradient(rgba(211, 162, 79, 0.035) 1px, transparent 1px) 0 0 / 48px 48px,
    var(--surface);
}
.forensic-hero::before { position: absolute; top: 0; left: 0; width: 128px; height: 2px; background: var(--accent); content: ""; }
.compact-hero { padding-top: 24px; padding-bottom: 26px; }
.hero-copy { max-width: 780px; }
.hero-copy h1 {
  margin: 0;
  color: var(--ink);
  font-size: clamp(30px, 4vw, 52px);
  font-weight: 720;
  letter-spacing: -0.045em;
  line-height: 1.02;
  text-wrap: balance;
}
.compact-hero .hero-copy h1 { font-size: clamp(27px, 3vw, 40px); }
.hero-copy > p:last-child { max-width: 62ch; margin: 14px 0 0; color: var(--muted); font-size: 14px; text-wrap: pretty; }
.hero-actions, .actions, .case-actions, .prompt-tools, .triage-actions, .page-header-actions {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
}
.system-signal { display: grid; min-width: 154px; gap: 5px; padding: 14px 16px; border-left: 2px solid var(--accent); background: rgba(11, 16, 19, 0.86); }
.system-signal span { color: var(--muted); font-family: var(--font-mono); font-size: 9px; letter-spacing: 0.1em; }
.system-signal strong { color: var(--ink); font-family: var(--font-mono); font-size: 12px; }

.signal-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  margin-bottom: 22px;
  overflow: hidden;
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  background: var(--surface);
}
.signal-item { display: grid; min-height: 126px; align-content: space-between; gap: 6px; padding: 18px 20px; border-right: 1px solid var(--border); }
.signal-item:last-child { border-right: 0; }
.stat-label, .stat-meta { color: var(--muted); font-size: 11px; }
.stat-label { font-weight: 650; }
.stat-value { color: var(--ink); font-family: var(--font-mono); font-size: clamp(22px, 3vw, 34px); font-weight: 630; letter-spacing: -0.04em; }
.overview-layout { display: grid; grid-template-columns: minmax(0, 1.45fr) minmax(300px, 0.85fr); gap: 16px; margin-bottom: 30px; }
.risk-board, .command-panel, .activity-section, .scan-guidance { padding: 20px; }
.section-heading { display: flex; align-items: flex-start; justify-content: space-between; gap: 18px; margin-bottom: 18px; }
.section-heading h2, .section-heading h3, .section h2, .section h3 { margin: 0; color: var(--ink); font-size: 17px; font-weight: 680; letter-spacing: -0.015em; }
.section-heading > a, .text-link { color: var(--muted); font-size: 12px; font-weight: 620; text-decoration: none; }
.section-heading > a:hover, .text-link:hover { color: var(--accent); }
.risk-list, .module-list { display: grid; gap: 2px; }
.risk-row { display: grid; grid-template-columns: 52px minmax(80px, 1fr) 36px; align-items: center; gap: 14px; min-height: 43px; padding: 0 10px; border-top: 1px solid var(--border); }
.risk-name { color: #cbd2d5; font-size: 11px; }
.risk-track, .language-track, .bar-track, .progress-track { display: block; height: 4px; overflow: hidden; background: #20292e; }
.risk-fill, .language-track span, .language-track i, .bar-track span, .progress-fill { display: block; height: 100%; background: var(--accent); }
.risk-critical .risk-fill, .risk-high .risk-fill { background: var(--danger); }
.risk-value { color: var(--ink); font-family: var(--font-mono); font-size: 12px; text-align: right; }
.module-item { display: grid; grid-template-columns: minmax(72px, auto) minmax(0, 1fr) auto; align-items: center; gap: 12px; min-height: 43px; padding: 8px 10px; border-top: 1px solid var(--border); }
.module-item code { color: var(--accent); font-size: 10px; font-weight: 750; }
.module-item span { color: var(--muted); font-size: 11px; }
.module-item strong { color: var(--ink); font-family: var(--font-mono); font-size: 12px; }
.policy-item { grid-template-columns: 80px 1fr; }
.activity-section { padding: 0; }
.activity-list, .history-list, .candidate-list, .dependency-list { display: grid; gap: 10px; }
.dependency-list { max-height: 760px; overflow: auto; padding-right: 4px; }
.activity-row { display: grid; grid-template-columns: minmax(0, 1fr) auto; align-items: center; gap: 22px; padding: 18px 20px; border: 1px solid var(--border); border-radius: var(--radius); background: var(--surface); transition: border-color 160ms ease, background-color 160ms ease; }
.activity-row:hover { border-color: var(--border-strong); background: var(--surface-raised); }
.run-heading { display: flex; min-width: 0; align-items: center; gap: 10px; }
.run-heading h3, .candidate-title { margin: 0; overflow-wrap: anywhere; color: var(--ink); font-size: 14px; font-weight: 680; }
.run-source { margin: 8px 0 0; overflow: hidden; color: var(--muted); font-family: var(--font-mono); font-size: 10px; text-overflow: ellipsis; white-space: nowrap; }
.activity-meta, .run-meta { display: flex; flex-wrap: wrap; gap: 7px 16px; margin-top: 9px; color: var(--faint); font-family: var(--font-mono); font-size: 9px; }
.status-chip, .tag, .profile-badge { display: inline-flex; min-height: 23px; align-items: center; padding: 3px 7px; border: 1px solid var(--border-strong); border-radius: 3px; background: var(--surface-inset); color: #bdc6ca; font-family: var(--font-mono); font-size: 9px; font-weight: 700; letter-spacing: 0.025em; }
.status-chip.ok, .tag.ok { border-color: #365c49; background: var(--success-soft); color: #9ed0b4; }
.status-chip.danger, .tag.danger { border-color: #633532; background: var(--danger-soft); color: #efaaa5; }
.status-chip.info, .status-chip.warn, .tag.info, .tag.warn { border-color: #5e4d2d; background: var(--accent-soft); color: #e2bc76; }
.empty-command, .diagnostic-empty, .empty { display: grid; justify-items: start; gap: 8px; padding: 28px; border: 1px dashed var(--border-strong); border-radius: var(--radius-lg); background: var(--surface-inset); color: var(--muted); }
.empty-command strong { color: var(--ink); font-size: 16px; }
.empty-command p { max-width: 58ch; margin: 0; }

.scan-workbench { display: grid; grid-template-columns: minmax(0, 1fr) 330px; align-items: start; gap: 16px; }
.scan-guidance { position: sticky; top: 78px; border: 1px solid var(--border); border-radius: var(--radius-lg); background: var(--surface); }
.scan-form-panel { overflow: hidden; }
.scan-form { display: grid; }
.form-section { display: grid; gap: 16px; padding: 24px 26px 28px; border-bottom: 1px solid var(--border); }
.form-section-head { display: grid; grid-template-columns: 32px minmax(0, 1fr); gap: 14px; align-items: start; }
.form-section-head > span { display: grid; width: 29px; height: 29px; place-items: center; border: 1px solid #5e4d2d; background: var(--accent-soft); color: var(--accent); font-family: var(--font-mono); font-size: 10px; }
.form-section-head h3 { margin: 0; color: var(--ink); font-size: 15px; }
.form-section-head p { margin: 4px 0 0; color: var(--muted); font-size: 11px; }
.field-stack { display: grid; gap: 7px; }
.row { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 14px; }
.scan-source-switch { display: inline-grid; width: fit-content; grid-template-columns: repeat(2, minmax(120px, 1fr)); padding: 3px; border: 1px solid var(--border); border-radius: var(--radius); background: var(--surface-inset); }
.scan-source-switch input, .mode-option input { position: absolute; opacity: 0; pointer-events: none; }
.scan-source-switch label { display: flex; min-height: 34px; align-items: center; justify-content: center; padding: 6px 12px; border: 1px solid transparent; border-radius: 3px; color: var(--muted); cursor: pointer; }
.scan-source-switch input:checked + label { border-color: #5e4d2d; background: var(--accent-soft); color: var(--accent-hover); }
.scan-source-switch input:focus-visible + label, .mode-option input:focus-visible + span { outline: 2px solid var(--accent); outline-offset: 2px; }
.mode-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 8px; }
.mode-option { display: block; cursor: pointer; }
.mode-option > span { display: grid; min-height: 88px; align-content: space-between; gap: 10px; padding: 13px; border: 1px solid var(--border); border-radius: var(--radius); background: var(--surface-inset); }
.mode-option strong { color: var(--ink); font-family: var(--font-mono); font-size: 11px; }
.mode-option small { color: var(--muted); font-size: 10px; }
.mode-option input:checked + span { border-color: var(--accent); background: var(--accent-soft); }
.checkline { display: flex; align-items: flex-start; gap: 10px; padding: 12px 13px; border: 1px solid var(--border); border-radius: var(--radius); background: var(--surface-inset); cursor: pointer; }
.checkline > span { display: grid; gap: 3px; }
.checkline strong { color: var(--ink); font-size: 12px; }
.form-submit-row { display: flex; align-items: center; justify-content: space-between; gap: 20px; padding: 20px 26px; background: var(--surface-raised); }
.form-submit-row p { margin: 3px 0 0; }
.status { color: var(--muted); font-size: 11px; }
.status.ok { color: #9ed0b4; }
.status.error, .error, .case-alert { color: #efaaa5; }
.scan-form > .status { padding: 0 26px 18px; background: var(--surface-raised); }

.logs-console { overflow: hidden; border: 1px solid var(--border-strong); border-radius: var(--radius-lg); background: var(--surface-inset); box-shadow: var(--shadow); }
.logs-toolbar { display: grid; grid-template-columns: minmax(220px, 1fr) 180px auto; align-items: end; gap: 12px; padding: 14px; border-bottom: 1px solid var(--border); background: var(--surface); }
.logs-actions { display: flex; gap: 7px; }
.logs-status-row { display: flex; align-items: center; justify-content: space-between; gap: 16px; padding: 8px 14px; border-bottom: 1px solid var(--border); color: var(--faint); font-family: var(--font-mono); font-size: 9px; }
.logs-stream { min-height: 440px; max-height: calc(100dvh - 300px); overflow: auto; background: linear-gradient(rgba(211, 162, 79, 0.025) 1px, transparent 1px) 0 0 / 100% 24px, #080c0e; }
.logs-empty { padding: 80px 20px; color: var(--faint); font-family: var(--font-mono); font-size: 11px; text-align: center; }
.log-entry { display: grid; gap: 7px; padding: 12px 14px; border-bottom: 1px solid #1d262b; }
.log-entry:hover { background: rgba(255, 255, 255, 0.018); }
.log-entry-head { display: grid; grid-template-columns: 174px 72px minmax(0, 1fr); gap: 10px; align-items: center; font-family: var(--font-mono); font-size: 9px; }
.log-time { color: var(--faint); }
.log-level { color: var(--accent); font-weight: 750; }
.log-entry[data-level="error"] .log-level, .log-entry[data-level="critical"] .log-level { color: var(--danger); }
.log-event { overflow: hidden; color: #c4cdd1; text-overflow: ellipsis; white-space: nowrap; }
.log-message { margin: 0; color: #d7dddf; font-family: var(--font-mono); font-size: 11px; }
.log-context { margin: 0; overflow-wrap: anywhere; color: var(--muted); font-family: var(--font-mono); font-size: 10px; white-space: pre-wrap; }

.settings-layout { display: grid; grid-template-columns: 230px minmax(0, 1fr); align-items: start; gap: 16px; }
.settings-nav { position: sticky; top: 78px; padding: 12px; }
.settings-nav-group + .settings-nav-group { margin-top: 14px; padding-top: 14px; border-top: 1px solid var(--border); }
.settings-nav-title { margin: 0 8px 7px; color: var(--faint); font-family: var(--font-mono); font-size: 9px; font-weight: 720; letter-spacing: 0.08em; }
.settings-nav-button, .settings-subnav-button { width: 100%; min-height: 34px; justify-content: flex-start; margin: 2px 0; border-color: transparent; background: transparent; color: var(--muted); text-align: left; }
.settings-subnav-button { padding-left: 20px; font-weight: 560; }
.settings-nav-button.active, .settings-subnav-button.active { border-color: #5e4d2d; background: var(--accent-soft); color: var(--accent-hover); }
.settings-content { min-width: 0; overflow: hidden; }
.settings-category-head, .settings-content > form > .settings-category > .section { padding: 23px 25px 18px; border-bottom: 1px solid var(--border); }
.settings-category-head p, .settings-content .section p { max-width: 72ch; margin: 7px 0 0; color: var(--muted); }
.notice { margin: 18px 25px 0; padding: 12px 14px; border-left: 2px solid var(--accent); background: var(--accent-soft); color: #d4bd91; font-size: 11px; }
.settings-profiles { padding: 18px 25px 26px; }
.settings-subpanel:focus { outline: none; }
.settings-profile { border: 1px solid var(--border); border-radius: var(--radius); background: var(--surface-inset); }
.settings-profile-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 18px; padding: 16px 18px; border-bottom: 1px solid var(--border); }
.settings-profile-head h3 { margin: 0; color: var(--ink); font-size: 14px; }
.settings-profile-head p { max-width: 68ch; margin: 5px 0 0; color: var(--muted); font-size: 11px; }
.settings-profile-head .checkline { flex: 0 0 auto; padding: 8px 10px; }
.settings-profile-body { display: grid; gap: 16px; padding: 18px; }
.settings-profile-body code { padding: 2px 5px; background: var(--surface-raised); color: var(--accent-hover); }
.settings-actions { position: sticky; bottom: 0; z-index: 4; padding: 13px 18px; border-top: 1px solid var(--border-strong); background: rgba(15, 21, 25, 0.96); backdrop-filter: blur(10px); }

.case-workspace { min-width: 0; }
.case-header { display: flex; align-items: flex-end; justify-content: space-between; gap: 28px; padding: 6px 0 20px; border-bottom: 1px solid var(--border-strong); }
.case-identity h1 { margin: 0; color: var(--ink); font-size: clamp(25px, 3.4vw, 42px); font-weight: 720; letter-spacing: -0.04em; line-height: 1.06; }
.case-reference { max-width: 76ch; margin: 9px 0 0; overflow: hidden; color: var(--muted); font-family: var(--font-mono); font-size: 10px; text-overflow: ellipsis; white-space: nowrap; }
.telemetry-strip { display: grid; grid-template-columns: 160px 180px minmax(0, 1fr); margin: 14px 0; overflow: hidden; border: 1px solid var(--border); border-radius: var(--radius); background: var(--surface); }
.telemetry-item { display: grid; gap: 4px; padding: 11px 14px; border-right: 1px solid var(--border); }
.telemetry-item:last-child { border-right: 0; }
.telemetry-item span { color: var(--faint); font-size: 9px; }
.telemetry-item strong { overflow: hidden; color: var(--ink); font-family: var(--font-mono); font-size: 10px; text-overflow: ellipsis; white-space: nowrap; }
.telemetry-item strong[data-run-state="completed"] { color: var(--success); }
.telemetry-item strong[data-run-state="failed"] { color: var(--danger); }
.telemetry-item strong[data-run-state="running"] { color: var(--accent); }
.case-alert { padding: 12px 14px; border: 1px solid #633532; background: var(--danger-soft); }
.evidence-layout { display: grid; grid-template-columns: 286px minmax(0, 1fr); align-items: start; gap: 18px; }
.evidence-rail { display: grid; gap: 10px; }
.case-context { min-width: 0; padding: 15px; border: 1px solid var(--border); border-radius: var(--radius); background: var(--surface); }
.case-context h2 { margin: 0 0 12px; color: var(--muted); font-family: var(--font-mono); font-size: 10px; font-weight: 720; letter-spacing: 0.06em; }
.case-context > p { margin: 0; overflow-wrap: anywhere; color: #c8d0d3; font-family: var(--font-mono); font-size: 10px; }
.case-context dl { display: grid; gap: 8px; margin: 12px 0 0; }
.case-context dl div { display: grid; gap: 3px; padding-top: 8px; border-top: 1px solid var(--border); }
.case-context dt { color: var(--faint); font-size: 9px; }
.case-context dd { margin: 0; overflow-wrap: anywhere; color: #c8d0d3; font-family: var(--font-mono); font-size: 10px; }
.case-metrics, .metrics, .inventory-metrics, .detail-metrics { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 6px; }
.metric, .inventory-metric { display: grid; gap: 3px; padding: 8px; border: 1px solid var(--border); background: var(--surface-inset); }
.metric span, .inventory-metric span { color: var(--faint); font-size: 8px; }
.metric strong, .inventory-metric strong { color: var(--ink); font-family: var(--font-mono); font-size: 14px; }
.evidence-main { min-width: 0; }
.evidence-heading { margin-bottom: 13px; }
.evidence-heading h2 { margin: 0; color: var(--ink); font-size: 23px; letter-spacing: -0.025em; }
.evidence-panel { padding: 18px; border: 1px solid var(--border); border-radius: var(--radius-lg); background: var(--surface); }
.evidence-controls { display: grid; gap: 10px; margin-bottom: 10px; }
.result-tabs {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(145px, 1fr));
  gap: 4px;
  margin: 0;
  padding: 4px;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  background: var(--surface-inset);
}
.result-tabs button { border-color: transparent; background: transparent; color: var(--muted); }
.result-tabs button.active { border-color: #5e4d2d; background: var(--accent-soft); color: var(--accent-hover); }
.result-tab {
  display: grid;
  min-width: 0;
  grid-template-columns: minmax(0, 1fr) auto;
  gap: 3px 12px;
  text-align: left;
}
.result-tab span { color: inherit; font-size: 11px; font-weight: 720; }
.result-tab strong { color: var(--ink); font-family: var(--font-mono); font-size: 17px; }
.result-tab em { grid-column: 1 / -1; overflow: hidden; color: var(--faint); font-size: 9px; font-style: normal; text-overflow: ellipsis; white-space: nowrap; }
.result-tab-panel { display: grid; gap: 14px; }
.result-tab-panel[hidden] { display: none; }
.result-tab-panel,
.result-zone,
.candidate-list,
.candidate-row,
.flow-section,
.flow-diagram,
.flow-node { min-width: 0; }
.result-tab-panel,
.result-zone,
.candidate-list,
.flow-diagram { grid-template-columns: minmax(0, 1fr); }
.candidate-toolbar { display: grid; grid-template-columns: minmax(200px, 1fr) auto; gap: 10px; margin: 0; padding: 11px; border: 1px solid var(--border); border-radius: var(--radius); background: var(--surface); }
.candidate-toolbar .search { min-width: 0; }
.filters { display: flex; flex-wrap: wrap; align-items: center; gap: 4px; }
.filter-button { min-height: 38px; padding-inline: 10px; border-color: transparent; background: transparent; color: var(--muted); }
.filter-button.active { border-color: var(--border-strong); background: var(--surface-raised); color: var(--ink); }
.result-zone { display: grid; gap: 12px; padding: 16px; }
.result-zone-head, .dependency-head, .candidate-head, .inventory-head, .progress-head, .diagnostic-head, .diagnostic-card-head, .verification-head, .node-head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 16px;
}
.result-zone-head { margin: 18px 0 10px; }
.result-zone-head h3, .dependency-head h3 { margin: 0; color: var(--ink); font-size: 15px; }
.result-zone-count { color: var(--muted); font-family: var(--font-mono); font-size: 10px; }
.candidate-row { overflow: hidden; padding: 0; border-color: var(--border); background: var(--surface); }
.dependency-item { padding: 16px; border-color: var(--border); background: var(--surface); }
.candidate-row:hover, .dependency-item:hover { border-color: var(--border-strong); }
.finding-summary {
  display: grid;
  width: 100%;
  min-height: 94px;
  grid-template-columns: minmax(0, 1fr) auto;
  align-items: center;
  gap: 20px;
  padding: 14px 16px;
  border: 0;
  border-radius: 0;
  background: transparent;
  color: var(--ink);
  text-align: left;
}
.finding-summary:hover { border-color: transparent; background: var(--surface-raised); }
.finding-summary-main { display: grid; min-width: 0; gap: 6px; }
.finding-summary-heading { display: flex; min-width: 0; align-items: center; gap: 10px; }
.finding-summary-id {
  padding: 0;
  overflow: hidden;
  border: 0;
  background: transparent;
  color: var(--accent);
  font-size: 10px;
  font-weight: 750;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.finding-summary-title { color: var(--ink); font-size: 13px; font-weight: 700; }
.finding-summary-copy {
  overflow: hidden;
  color: #b8c2c6;
  font-size: 11px;
  font-weight: 460;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.finding-summary-location {
  overflow: hidden;
  color: var(--faint);
  font-family: var(--font-mono);
  font-size: 9px;
  font-weight: 500;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.finding-summary-side { display: grid; justify-items: end; gap: 10px; }
.finding-summary-tags { display: flex; flex-wrap: wrap; justify-content: flex-end; gap: 4px; }
.finding-summary-action { color: var(--accent); font-size: 10px; font-weight: 700; white-space: nowrap; }
.finding-detail-content { display: grid; min-width: 0; gap: 18px; }
.finding-detail-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 22px;
  padding-bottom: 18px;
  border-bottom: 1px solid var(--border);
}
.finding-detail-header h2 { margin: 0; color: var(--ink); font-size: clamp(22px, 3vw, 32px); letter-spacing: -0.03em; }
.finding-detail-header p:last-child { max-width: 74ch; margin: 10px 0 0; color: var(--muted); font-size: 12px; }
.finding-detail-section { display: grid; gap: 12px; }
.finding-detail-section > h3,
.finding-detail-section-head h3 { margin: 0; color: var(--ink); font-size: 14px; }
.finding-detail-section-head { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
.finding-detail-section-head span { color: var(--faint); font-family: var(--font-mono); font-size: 9px; }
.finding-drawer-open { overflow: hidden; }
.finding-drawer {
  position: fixed;
  inset: 0;
  z-index: 80;
  display: grid;
  grid-template-columns: minmax(0, 1fr) min(74vw, 1120px);
}
.finding-drawer[hidden] { display: none; }
.finding-drawer-backdrop {
  grid-column: 1 / -1;
  grid-row: 1;
  width: 100%;
  height: 100%;
  min-height: 0;
  padding: 0;
  border: 0;
  border-radius: 0;
  background: rgba(2, 5, 7, 0.72);
  backdrop-filter: blur(2px);
}
.finding-drawer-backdrop:hover { border: 0; background: rgba(2, 5, 7, 0.76); }
.finding-drawer-panel {
  position: relative;
  z-index: 1;
  grid-column: 2;
  grid-row: 1;
  display: grid;
  min-width: 0;
  height: 100dvh;
  grid-template-rows: auto minmax(0, 1fr);
  border-left: 1px solid var(--border-strong);
  background: #0c1114;
  box-shadow: -28px 0 70px rgba(0, 0, 0, 0.42);
}
.finding-drawer-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 20px;
  padding: 18px 22px;
  border-bottom: 1px solid var(--border-strong);
  background: var(--surface);
}
.finding-drawer-header h2 { margin: 0; color: var(--ink); font-size: 17px; }
.finding-drawer-close { flex: 0 0 auto; }
.finding-drawer-body { min-width: 0; overflow-y: auto; overscroll-behavior: contain; padding: 24px; }
.tags { display: flex; flex-wrap: wrap; gap: 5px; margin-top: 9px; }
.evidence { margin: 13px 0; color: #b6c0c4; font-size: 12px; text-wrap: pretty; }
.path { display: flex; align-items: center; gap: 9px; overflow-x: auto; padding: 10px; border: 1px solid var(--border); background: var(--surface-inset); }
.path code { color: #d3dadd; font-size: 10px; white-space: nowrap; }
.arrow { color: var(--accent); }
.flow-section, .verification-box { margin-top: 14px; padding: 13px; border: 1px solid var(--border); background: var(--surface-inset); }
.flow-title { display: flex; align-items: center; justify-content: space-between; gap: 14px; margin-bottom: 11px; color: var(--ink); font-size: 12px; font-weight: 680; }
.flow-title span { color: var(--faint); font-size: 9px; font-weight: 450; }
.flow-diagram { display: grid; }
.flow-node { overflow: hidden; border: 1px solid var(--border); border-radius: var(--radius); background: #0a0f12; }
.flow-node.source { border-left: 2px solid var(--success); }
.flow-node.sink { border-left: 2px solid var(--danger); }
.node-head { padding: 10px 12px; border-bottom: 1px solid var(--border); }
.node-role { color: var(--ink); font-size: 11px; font-weight: 660; }
.node-symbol { margin-top: 3px; color: var(--faint); font-family: var(--font-mono); font-size: 9px; }
.flow-edge { display: grid; grid-template-columns: 28px minmax(0, 1fr); gap: 8px; min-height: 48px; align-items: center; }
.edge-rail { color: var(--accent); font-family: var(--font-mono); text-align: center; }
.edge-copy { color: var(--muted); font-size: 10px; }
.edge-copy strong { margin-right: 7px; color: #cbd2d5; }
.code-window, .sandbox-code { max-height: 420px; margin: 0; overflow: auto; background: #080c0e; color: #c9d1d4; font-size: 10px; line-height: 1.65; tab-size: 2; }
.code-line { display: grid; grid-template-columns: 48px minmax(max-content, 1fr); min-width: max-content; }
.code-line.hit { background: rgba(211, 162, 79, 0.12); box-shadow: inset 2px 0 var(--accent); }
.line-no { padding: 0 10px; color: #58656b; text-align: right; user-select: none; }
.line-text { padding-right: 14px; white-space: pre; }
.verification-head { color: var(--ink); font-size: 11px; font-weight: 680; }
.verification-list { margin: 10px 0 0; padding-left: 18px; color: var(--muted); font-size: 11px; }
.sandbox-details, .triage-box { margin-top: 12px; border-top: 1px solid var(--border); }
.sandbox-details summary, .triage-box summary { padding: 11px 0; color: #cbd2d5; font-size: 11px; cursor: pointer; }
.sandbox-case { margin-bottom: 9px; padding: 11px; border: 1px solid var(--border); background: var(--surface-inset); }
.triage-box { padding-top: 3px; }
.triage-box summary { display: flex; align-items: center; justify-content: space-between; gap: 12px; list-style: none; }
.triage-box summary::-webkit-details-marker { display: none; }
.triage-body { display: grid; gap: 12px; padding: 12px; border: 1px solid var(--border); background: var(--surface-inset); }
.triage-updated { color: var(--faint); }
.inventory-panel, .scan-progress, .diagnostic-panel { min-width: 0; }
.inventory-head, .progress-head, .diagnostic-head { margin-bottom: 10px; }
.inventory-head h2, .inventory-head h3, .progress-head h3, .diagnostic-head h3 { margin: 0; color: var(--ink); font-size: 12px; }
.inventory-head p, .progress-head p, .diagnostic-head p, .result-zone-head p, .dependency-head p { margin: 5px 0 0; color: var(--muted); font-size: 10px; }
.inventory-metrics { margin: 10px 0; }
.dependency-panel { padding: 16px; }
.dependency-item h4 { margin: 0; color: var(--ink); font-size: 12px; }
.progress-summary { display: flex; align-items: flex-start; justify-content: space-between; gap: 10px; margin: 0 0 9px; }
.language-list, .progress-body, .diagnostic-grid, .diagnostic-notes, .diagnostic-prompts { display: grid; gap: 7px; }
.language-row { display: grid; gap: 5px; }
.language-row-head { display: flex; justify-content: space-between; gap: 10px; color: var(--muted); font-family: var(--font-mono); font-size: 9px; }
.progress-stage { display: grid; grid-template-columns: 28px minmax(0, 1fr) auto; gap: 9px; align-items: center; padding: 8px; border: 1px solid var(--border); background: var(--surface-inset); }
.progress-index { display: grid; width: 24px; height: 24px; place-items: center; border: 1px solid var(--border-strong); color: var(--muted); font-family: var(--font-mono); font-size: 9px; }
.progress-title { color: #cbd2d5; font-size: 10px; }
.progress-state { color: var(--faint); font-family: var(--font-mono); font-size: 8px; }
.progress-stage.status-running { border-color: #5e4d2d; background: var(--accent-soft); }
.progress-stage.status-completed .progress-index { border-color: #365c49; color: var(--success); }
.progress-stage.status-failed { border-color: #633532; background: var(--danger-soft); }
.progress-summary, .progress-detail { margin-top: 9px; color: var(--muted); font-size: 10px; }
.diagnostic-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
.diagnostic-card { padding: 10px; border: 1px solid var(--border); background: var(--surface-inset); }
.diagnostic-card h4 { margin: 0; color: #cbd2d5; font-size: 10px; }
.diagnostic-kv { display: grid; gap: 5px; margin: 8px 0 0; color: var(--muted); font-family: var(--font-mono); font-size: 8px; }
.dependency-item p, .dependency-item ul { color: var(--muted); font-size: 11px; }

.login-body { min-height: 100dvh; display: grid; place-items: center; padding: 24px; background: radial-gradient(circle at 14% 12%, rgba(211, 162, 79, 0.11), transparent 30%), linear-gradient(rgba(211, 162, 79, 0.025) 1px, transparent 1px) 0 0 / 46px 46px, var(--bg); }
.login-shell { display: grid; width: min(940px, 100%); grid-template-columns: minmax(0, 1.08fr) minmax(340px, 0.92fr); overflow: hidden; border: 1px solid var(--border-strong); border-radius: var(--radius-lg); background: var(--surface); box-shadow: var(--shadow); }
.login-brand { position: relative; display: flex; min-height: 500px; flex-direction: column; justify-content: flex-end; padding: 42px; border-right: 1px solid var(--border-strong); background: linear-gradient(90deg, rgba(211, 162, 79, 0.05) 1px, transparent 1px) 0 0 / 44px 44px, linear-gradient(rgba(211, 162, 79, 0.035) 1px, transparent 1px) 0 0 / 44px 44px, #0c1215; }
.brand-lockup { position: absolute; top: 42px; left: 42px; display: flex; align-items: center; gap: 10px; color: var(--ink); font-size: 14px; font-weight: 700; }
.brand-mark { display: grid; width: 30px; height: 30px; place-items: center; border: 1px solid var(--accent); color: var(--accent); font-family: var(--font-mono); font-size: 10px; }
.login-brand h1 { max-width: 12ch; margin: 0; color: var(--ink); font-size: clamp(36px, 5vw, 56px); font-weight: 720; letter-spacing: -0.055em; line-height: 0.98; }
.login-brand > p:not(.page-kicker) { max-width: 46ch; margin: 18px 0 0; color: var(--muted); }
.login-signal { display: flex; flex-wrap: wrap; gap: 7px; margin-top: 28px; }
.login-signal span { padding: 5px 7px; border: 1px solid var(--border); color: var(--faint); font-family: var(--font-mono); font-size: 8px; }
.login-panel { display: grid; align-content: center; gap: 28px; padding: 42px; }
.login-panel h2 { margin: 0; color: var(--ink); font-size: 23px; letter-spacing: -0.025em; }
.login-panel .section-copy { margin: 8px 0 0; }
.login-form { display: grid; gap: 13px; }
.login-form small { overflow-wrap: anywhere; color: var(--faint); font-family: var(--font-mono); font-size: 9px; }
.login-form .status { min-height: 18px; margin: 0; }

@media (max-width: 1100px) {
  .signal-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .signal-item:nth-child(2) { border-right: 0; }
  .signal-item:nth-child(-n + 2) { border-bottom: 1px solid var(--border); }
  .scan-workbench { grid-template-columns: minmax(0, 1fr); }
  .scan-guidance, .settings-nav { position: static; }
  .candidate-toolbar { grid-template-columns: minmax(0, 1fr); }
  .finding-summary { grid-template-columns: minmax(0, 1fr); gap: 11px; }
  .finding-summary-side { display: flex; align-items: center; justify-content: space-between; justify-items: stretch; }
  .finding-summary-tags { justify-content: flex-start; }
}

@media (max-width: 760px) {
  body { font-size: 13px; }
  .forensic-hero, .case-header, .activity-row, .form-submit-row, .settings-profile-head {
    grid-template-columns: minmax(0, 1fr);
    align-items: stretch;
    flex-direction: column;
  }
  .forensic-hero { gap: 22px; padding: 24px 20px 26px; }
  .hero-actions, .case-actions { overflow-x: auto; flex-wrap: nowrap; padding-bottom: 2px; }
  .hero-actions a, .case-actions a, .case-actions button { flex: 0 0 auto; }
  .signal-grid, .overview-layout, .settings-layout, .login-shell, .row, .logs-toolbar, .diagnostic-grid, .evidence-rail { grid-template-columns: minmax(0, 1fr); }
  .evidence-layout { grid-template-columns: minmax(0, 1fr); }
  .signal-item { min-height: 104px; border-right: 0; border-bottom: 1px solid var(--border); }
  .signal-item:last-child { border-bottom: 0; }
  .activity-row { display: flex; gap: 16px; }
  .activity-row .actions { justify-content: flex-start; }
  .form-section, .settings-profiles, .settings-category-head { padding-right: 17px; padding-left: 17px; }
  .mode-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .settings-nav nav { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; }
  .settings-nav-group + .settings-nav-group { margin-top: 0; padding-top: 0; border-top: 0; }
  .settings-nav-group[data-settings-secondary] { grid-column: 1 / -1; }
  .settings-actions { position: static; }
  .telemetry-strip { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .telemetry-item:nth-child(2) { border-right: 0; }
  .telemetry-wide { grid-column: 1 / -1; border-top: 1px solid var(--border); }
  .log-entry-head { grid-template-columns: minmax(124px, 1fr) 64px; }
  .log-event { grid-column: 1 / -1; }
  .login-body { padding: 14px; }
  .login-brand { min-height: 340px; padding: 28px; border-right: 0; border-bottom: 1px solid var(--border-strong); }
  .brand-lockup { top: 28px; left: 28px; }
  .login-panel { padding: 28px; }
  .finding-drawer { grid-template-columns: 0 minmax(0, 1fr); }
  .finding-drawer-panel { width: 100%; }
  .finding-drawer-header { padding: 14px 16px; }
  .finding-drawer-body { padding: 18px 16px 28px; }
  .finding-detail-header { align-items: stretch; flex-direction: column; }
}

@media (max-width: 460px) {
  .result-tabs { grid-template-columns: minmax(0, 1fr); }
  .mode-grid, .case-metrics, .metrics, .inventory-metrics, .detail-metrics, .telemetry-strip { grid-template-columns: minmax(0, 1fr); }
  .telemetry-item { grid-column: 1; border-right: 0; border-bottom: 1px solid var(--border); }
  .telemetry-item:last-child { border-bottom: 0; }
  .scan-source-switch { width: 100%; }
  .path { align-items: flex-start; flex-direction: column; }
  .finding-summary-side { align-items: flex-start; flex-direction: column; }
}

@media (prefers-reduced-motion: reduce) {
  html { scroll-behavior: auto; }
  *, *::before, *::after {
    animation-duration: 0.01ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: 0.01ms !important;
  }
}
"""
