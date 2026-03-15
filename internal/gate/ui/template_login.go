package ui

import (
	"html/template"
	"strings"
)

var LoginTemplate = template.Must(template.New("login").Parse(loginPageHTML))

func LoginPageCSP(scriptNonce string) string {
	builder := strings.Builder{}
	builder.WriteString("default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
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
      color-scheme: light;
      --bg1: #f4f7fb;
      --bg2: #e3ecff;
      --card: rgba(255, 255, 255, 0.88);
      --text: #14213d;
      --muted: #5c6784;
      --accent: #1565c0;
      --accent-2: #1f8a70;
      --border: rgba(20, 33, 61, 0.12);
      --danger: #b42318;
      --success: #067647;
      --shadow: 0 24px 60px rgba(21, 37, 66, 0.18);
    }

    * { box-sizing: border-box; }

    body {
      margin: 0;
      min-height: 100vh;
      font-family: "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif;
      color: var(--text);
      background:
        radial-gradient(circle at top left, rgba(21, 101, 192, 0.16), transparent 32%),
        radial-gradient(circle at bottom right, rgba(31, 138, 112, 0.18), transparent 28%),
        linear-gradient(135deg, var(--bg1), var(--bg2));
      display: grid;
      place-items: center;
      padding: 24px;
    }

    .card {
      width: min(460px, 100%);
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 24px;
      box-shadow: var(--shadow);
      backdrop-filter: blur(12px);
      overflow: hidden;
    }

    .hero {
      padding: 28px 28px 18px;
      background:
        linear-gradient(135deg, rgba(21, 101, 192, 0.96), rgba(31, 138, 112, 0.88));
      color: #fff;
    }

    .badge {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 6px 12px;
      border-radius: 999px;
      background: rgba(255, 255, 255, 0.18);
      font-size: 13px;
      letter-spacing: 0.02em;
    }

    h1 {
      margin: 18px 0 10px;
      font-size: 30px;
      line-height: 1.15;
    }

    .subtitle {
      margin: 0;
      color: rgba(255, 255, 255, 0.9);
      line-height: 1.6;
      font-size: 15px;
    }

    .content {
      padding: 24px 28px 28px;
    }

    .lang-switch {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      margin-bottom: 22px;
      flex-wrap: wrap;
    }

    .lang-switch span {
      font-size: 14px;
      color: var(--muted);
    }

    .lang-links {
      display: flex;
      gap: 10px;
    }

    .lang-links a {
      text-decoration: none;
      color: var(--accent);
      border: 1px solid rgba(21, 101, 192, 0.18);
      background: rgba(21, 101, 192, 0.06);
      padding: 8px 12px;
      border-radius: 999px;
      font-size: 14px;
      transition: transform 0.15s ease, background 0.15s ease;
    }

    .lang-links a:hover {
      transform: translateY(-1px);
      background: rgba(21, 101, 192, 0.12);
    }

    form {
      display: grid;
      gap: 16px;
    }

    label {
      display: grid;
      gap: 8px;
      font-size: 14px;
      color: var(--muted);
      font-weight: 600;
    }

    input[type="password"] {
      width: 100%;
      padding: 14px 16px;
      border-radius: 14px;
      border: 1px solid rgba(20, 33, 61, 0.14);
      background: rgba(255, 255, 255, 0.92);
      font-size: 16px;
      color: var(--text);
      outline: none;
    }

    input[type="password"]:focus {
      border-color: rgba(21, 101, 192, 0.5);
      box-shadow: 0 0 0 4px rgba(21, 101, 192, 0.12);
    }

    .pow-box {
      display: grid;
      gap: 8px;
      padding: 14px 16px;
      border-radius: 16px;
      border: 1px solid rgba(21, 101, 192, 0.14);
      background: rgba(21, 101, 192, 0.05);
    }

    .pow-title {
      font-size: 14px;
      font-weight: 700;
      color: var(--text);
    }

    .pow-description {
      font-size: 13px;
      line-height: 1.5;
      color: var(--muted);
    }

    .pow-status {
      font-size: 13px;
      line-height: 1.5;
      color: var(--accent);
    }

    .pow-progress {
      display: grid;
      gap: 10px;
      margin-top: 2px;
    }

    .pow-progress-track {
      width: 100%;
      height: 10px;
      overflow: hidden;
      border-radius: 999px;
      background: rgba(21, 101, 192, 0.12);
      box-shadow: inset 0 0 0 1px rgba(21, 101, 192, 0.08);
    }

    .pow-progress-fill {
      width: 0%;
      height: 100%;
      border-radius: inherit;
      background: linear-gradient(90deg, rgba(21, 101, 192, 0.95), rgba(31, 138, 112, 0.92));
      transition: width 0.18s ease;
    }

    .pow-progress-meta {
      display: grid;
      gap: 6px;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      font-size: 12px;
      color: var(--muted);
    }

    .pow-progress-percent {
      color: var(--accent);
      font-weight: 700;
    }

    .pow-progress-stat {
      white-space: nowrap;
    }

    button {
      appearance: none;
      border: 0;
      border-radius: 16px;
      background: linear-gradient(135deg, var(--accent), var(--accent-2));
      color: #fff;
      padding: 14px 18px;
      font-size: 16px;
      font-weight: 700;
      cursor: pointer;
      transition: transform 0.15s ease, box-shadow 0.15s ease;
      box-shadow: 0 14px 32px rgba(21, 101, 192, 0.22);
    }

    button:disabled {
      cursor: wait;
      opacity: 0.72;
      transform: none;
      box-shadow: none;
    }

    button:hover {
      transform: translateY(-1px);
      box-shadow: 0 18px 36px rgba(21, 101, 192, 0.24);
    }

    .notice {
      padding: 12px 14px;
      border-radius: 14px;
      font-size: 14px;
      line-height: 1.5;
    }

    .notice.error {
      background: rgba(180, 35, 24, 0.08);
      color: var(--danger);
      border: 1px solid rgba(180, 35, 24, 0.15);
    }

    .notice.success {
      background: rgba(6, 118, 71, 0.08);
      color: var(--success);
      border: 1px solid rgba(6, 118, 71, 0.14);
    }

    .meta {
      display: grid;
      gap: 10px;
      margin-top: 18px;
      color: var(--muted);
      font-size: 13px;
      line-height: 1.6;
    }

    @media (max-width: 540px) {
      body { padding: 16px; }
      .hero, .content { padding-left: 20px; padding-right: 20px; }
      h1 { font-size: 26px; }
      .lang-switch { align-items: flex-start; }
      .pow-progress-meta { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <main class="card">
    <section class="hero">
      <div class="badge">Reverse Proxy Auth</div>
      <h1>{{.Title}}</h1>
      <p class="subtitle">{{.Tagline}}</p>
    </section>
    <section class="content">
      <div class="lang-switch">
        <span>{{.LanguageLabel}}</span>
        <div class="lang-links">
          <a href="{{.ZHToggleURL}}">{{.ZHToggleLabel}}</a>
          <a href="{{.ENToggleURL}}">{{.ENToggleLabel}}</a>
        </div>
      </div>

      {{if .Error}}
      <div class="notice error">{{.Error}}</div>
      {{end}}

      {{if .Message}}
      <div class="notice success">{{.Message}}</div>
      {{end}}

      <form method="post" action="{{.FormAction}}">
        <input type="hidden" name="next" value="{{.Next}}">
        <input type="hidden" name="lang" value="{{.Lang}}">
        <label>
          <span>{{.PasswordLabel}}</span>
          <input type="password" name="password" autocomplete="current-password" placeholder="{{.PasswordHint}}" required>
        </label>
        {{range .ChallengeHTML}}
        {{.}}
        {{end}}
        <button type="submit">{{.SubmitLabel}}</button>
      </form>

      <div class="meta">
        <div>{{.Footer}}</div>
        <div>{{.Tip}}</div>
      </div>
    </section>
  </main>
</body>
</html>`
