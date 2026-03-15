package ui

import (
	"html/template"
	"strings"
)

var LoginTemplate = template.Must(template.New("login").Parse(loginPageHTML))

func LoginPageCSP(scriptNonce string) string {
	builder := strings.Builder{}
	builder.WriteString("default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'; worker-src 'self' blob:")
	if scriptNonce == "" {
		builder.WriteString("; script-src 'self' 'unsafe-inline'")
		return builder.String()
	}
	builder.WriteString("; script-src 'nonce-")
	builder.WriteString(scriptNonce)
	builder.WriteString("'")
	return builder.String()
}

const loginPageHTML = `<!doctype html>
<html lang="{{.Lang}}">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{.Title}}</title>
  <style>
    :root {
      color-scheme: light dark;
      --font-body: "Verdana", "Geneva", "PingFang SC", "Hiragino Sans GB", "Microsoft YaHei", sans-serif;
      --font-title: "Georgia", "Times New Roman", "Noto Serif CJK SC", "Songti SC", serif;
      --font-mono: "Courier New", "Cascadia Mono", "Consolas", monospace;
      --bg: #d8cdbb;
      --bg-2: #d0c3ae;
      --paper: rgba(255, 252, 246, 0.04);
      --grid: rgba(33, 28, 22, 0.075);
      --ink: #15110d;
      --muted: #51483d;
      --rule: rgba(21, 17, 13, 0.22);
      --rule-strong: rgba(21, 17, 13, 0.36);
      --accent: #315f6d;
      --accent-2: #8b4f33;
      --danger-bg: rgba(139, 79, 51, 0.08);
      --danger-line: rgba(139, 79, 51, 0.5);
      --success-bg: rgba(49, 95, 109, 0.08);
      --success-line: rgba(49, 95, 109, 0.46);
      --button-bg: rgba(21, 17, 13, 0.08);
      --button-bg-hover: rgba(21, 17, 13, 0.15);
    }

    @media (prefers-color-scheme: dark) {
      :root {
        --bg: #15110d;
        --bg-2: #1b1611;
        --paper: rgba(255, 255, 255, 0.012);
        --grid: rgba(229, 221, 209, 0.06);
        --ink: #eee4d7;
        --muted: #b8ad9d;
        --rule: rgba(238, 228, 215, 0.18);
        --rule-strong: rgba(238, 228, 215, 0.32);
        --danger-bg: rgba(139, 79, 51, 0.14);
        --danger-line: rgba(221, 134, 96, 0.44);
        --success-bg: rgba(49, 95, 109, 0.16);
        --success-line: rgba(125, 180, 197, 0.42);
        --button-bg: rgba(255, 255, 255, 0.035);
        --button-bg-hover: rgba(255, 255, 255, 0.08);
      }
    }

    * {
      box-sizing: border-box;
    }

    html {
      min-height: 100%;
      -webkit-font-smoothing: antialiased;
      text-rendering: optimizeLegibility;
    }

    body {
      margin: 0;
      min-height: 100vh;
      font-family: var(--font-body);
      color: var(--ink);
      background:
        linear-gradient(180deg, var(--paper), transparent 22%),
        linear-gradient(var(--grid) 1px, transparent 1px),
        linear-gradient(90deg, var(--grid) 1px, transparent 1px),
        linear-gradient(180deg, var(--bg), var(--bg-2));
      background-size:
        100% 100%,
        13px 13px,
        13px 13px,
        100% 100%;
      display: grid;
      place-items: center;
      padding: 2rem 1.25rem;
    }

    .shell {
      width: min(35rem, 100%);
      padding: 0.25rem 0 0;
      background: none;
      border: 0;
      box-shadow: none;
    }

    .masthead {
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      gap: 0.75rem 1.25rem;
      align-items: end;
      padding-bottom: 0.9rem;
      border-bottom: 1px solid var(--rule);
    }

    .title-wrap {
      display: grid;
      gap: 0.55rem;
      min-width: 0;
    }

    .title-wrap::before {
      content: "";
      width: 2.4rem;
      height: 1px;
      background: linear-gradient(90deg, var(--accent), transparent);
    }

    h1 {
      margin: 0;
      font-family: var(--font-title);
      font-size: clamp(2.05rem, 4vw, 2.5rem);
      line-height: 1.04;
      font-weight: 600;
      letter-spacing: -0.035em;
    }

    html[lang="zh"] h1 {
      font-size: clamp(2.15rem, 4.4vw, 2.65rem);
      letter-spacing: -0.06em;
      font-weight: 650;
    }

    .subtitle {
      margin: 0;
      max-width: 28rem;
      font-size: 0.875rem;
      line-height: 1.6;
      color: var(--muted);
    }

    .lang-switch {
      display: flex;
      align-items: center;
      justify-content: flex-end;
      gap: 0.7rem;
      flex-wrap: wrap;
      padding-bottom: 0.1rem;
    }

    .lang-label {
      font-family: var(--font-mono);
      font-size: 12px;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      color: var(--muted);
      white-space: nowrap;
    }

    .lang-links {
      display: inline-flex;
      gap: 0.75rem;
      align-items: center;
    }

    .lang-form {
      display: block;
      margin: 0;
    }

    .lang-button {
      appearance: none;
      min-width: 0;
      padding: 0;
      border: 0;
      background: transparent;
      color: var(--muted);
      text-decoration: none;
      border-bottom: 1px solid transparent;
      font-family: var(--font-body);
      font-size: 0.92rem;
      line-height: 1.2;
      font-weight: 400;
      letter-spacing: 0;
      cursor: pointer;
    }

    .lang-button:hover,
    .lang-button.active {
      color: var(--ink);
      border-bottom-color: currentColor;
      background: transparent;
    }

    .stack {
      display: grid;
      gap: 0.55rem;
      margin-top: 0.55rem;
    }

    .notice {
      padding: 0.65rem 0.8rem;
      border-left: 2px solid;
      font-size: 0.82rem;
      line-height: 1.55;
    }

    .notice.error {
      border-color: var(--danger-line);
      background: var(--danger-bg);
    }

    .notice.success {
      border-color: var(--success-line);
      background: var(--success-bg);
    }

    form {
      display: grid;
      gap: 0;
      margin-top: 0.55rem;
    }

    .field {
      display: grid;
      gap: 0.45rem;
      padding: 0.95rem 0 0.9rem;
      border-top: 1px solid var(--rule);
    }

    .field > span {
      font-family: var(--font-mono);
      font-size: 12px;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      color: var(--muted);
    }

    input[type="password"] {
      width: 100%;
      padding: 0 0 0.55rem;
      border: 0;
      border-bottom: 1px solid var(--rule-strong);
      background: transparent;
      color: var(--ink);
      font-family: var(--font-body);
      font-size: 1.08rem;
      outline: none;
      border-radius: 0;
    }

    input[type="password"]::placeholder {
      color: var(--muted);
    }

    input[type="password"]:focus {
      border-bottom-color: var(--accent);
    }

    .pow-box {
      display: grid;
      gap: 0.55rem;
      padding: 0.95rem 0 0.9rem;
      border-top: 1px solid var(--rule);
    }

    .pow-status {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      min-height: 1rem;
      font-size: 0.85rem;
      line-height: 1.5;
      color: var(--muted);
    }

    .pow-status::before {
      content: "";
      width: 0.38rem;
      height: 0.38rem;
      border-radius: 0;
      background: var(--accent-2);
      flex: none;
    }

    .pow-status[data-state="running"],
    .pow-status[data-state="ready"] {
      color: var(--ink);
    }

    .pow-status[data-state="ready"]::before {
      background: var(--accent);
    }

    .pow-status[data-state="failed"],
    .pow-status[data-state="unsupported"] {
      color: var(--accent-2);
    }

    .pow-status[data-state="failed"]::before,
    .pow-status[data-state="unsupported"]::before {
      background: var(--accent-2);
    }

    .pow-progress {
      display: grid;
      gap: 0.35rem;
    }

    .pow-progress-track {
      width: 100%;
      height: 2px;
      overflow: hidden;
      background: rgba(49, 95, 109, 0.16);
    }

    .pow-progress-fill {
      width: 0%;
      height: 100%;
      background: linear-gradient(90deg, var(--accent), var(--accent-2));
      transition: width 0.18s ease;
    }

    .actions {
      display: flex;
      justify-content: flex-start;
      padding-top: 0.95rem;
      border-top: 1px solid var(--rule);
    }

    button:not(.lang-button) {
      appearance: none;
      min-width: 8.8rem;
      padding: 0.7rem 1rem;
      border: 1px solid var(--rule-strong);
      border-radius: 0;
      background: var(--button-bg);
      color: var(--ink);
      font-family: var(--font-body);
      font-size: 0.88rem;
      font-weight: 700;
      letter-spacing: 0.02em;
      cursor: pointer;
      transition: background 0.14s ease, border-color 0.14s ease;
    }

    button:not(.lang-button):disabled {
      cursor: wait;
      opacity: 0.72;
    }

    button:not(.lang-button):hover {
      background: var(--button-bg-hover);
      border-color: var(--rule-strong);
    }

    @media (max-width: 720px) {
      .masthead {
        grid-template-columns: 1fr;
        align-items: start;
      }

      .lang-switch {
        justify-content: flex-start;
      }
    }

    @media (max-width: 520px) {
      body {
        padding: 1rem 0.9rem;
      }

      .actions {
        display: block;
      }

      button:not(.lang-button) {
        width: 100%;
      }
    }
  </style>
</head>
<body>
  <main class="shell">
    <header class="masthead">
      <div class="title-wrap">
        <h1>{{.Title}}</h1>
        {{if .Tagline}}
        <p class="subtitle">{{.Tagline}}</p>
        {{end}}
      </div>
      <div class="lang-switch">
        <span class="lang-label">{{.LanguageLabel}}</span>
        <div class="lang-links">
          {{range .LanguageOptions}}
          <form class="lang-form" method="post" action="{{$.FormAction}}">
            <input type="hidden" name="intent" value="switch_lang">
            <input type="hidden" name="lang" value="{{.Code}}">
            <input type="hidden" name="next" value="{{$.Next}}">
            <button class="lang-button{{if .Active}} active{{end}}" type="submit"{{if .Active}} aria-current="true"{{end}}>{{.Label}}</button>
          </form>
          {{end}}
        </div>
      </div>
    </header>

    <div class="stack">
      {{if .Error}}
      <div class="notice error">{{.Error}}</div>
      {{end}}

      {{if .Message}}
      <div class="notice success">{{.Message}}</div>
      {{end}}
    </div>

    <form method="post" action="{{.FormAction}}">
      <input type="hidden" name="next" value="{{.Next}}">
      <input type="hidden" name="lang" value="{{.Lang}}">
      <label class="field">
        <span>{{.PasswordLabel}}</span>
        <input type="password" name="password" autocomplete="current-password" placeholder="{{.PasswordHint}}" required>
      </label>
      {{range .ChallengeHTML}}
      {{.}}
      {{end}}
      <div class="actions">
        <button type="submit">{{.SubmitLabel}}</button>
      </div>
    </form>
  </main>
</body>
</html>`
