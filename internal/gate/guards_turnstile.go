package gate

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"
)

const (
	turnstileGuardID        = "turnstile-login-guard"
	turnstileResponseField  = "turnstile_token"
	turnstileWatchdogMillis = 12000
)

type turnstileVerifyResponse struct {
	Success    bool     `json:"success"`
	Hostname   string   `json:"hostname"`
	Action     string   `json:"action"`
	CData      string   `json:"cdata"`
	ErrorCodes []string `json:"error-codes"`
}

func (g *turnstileLoginGuard) ID() string {
	return turnstileGuardID
}

func (g *turnstileLoginGuard) Render(w http.ResponseWriter, r *http.Request, lang string, scriptNonce string) template.HTML {
	browserSessionKey, err := g.ensureBrowserSession(w, r)
	if err != nil {
		return template.HTML(fmt.Sprintf(
			`<div class="notice error">%s</div>`,
			template.HTMLEscapeString(g.translator.Text(lang, "turnstile_unavailable")),
		))
	}

	callbackSuffix := turnstileCallbackSuffix(browserSessionKey)
	readyCallback := "__authTurnstileReady_" + callbackSuffix
	expiredCallback := "__authTurnstileExpired_" + callbackSuffix
	errorCallback := "__authTurnstileError_" + callbackSuffix
	unsupportedCallback := "__authTurnstileUnsupported_" + callbackSuffix

	statusWaiting := template.JSEscapeString(g.translator.Text(lang, "turnstile_status_waiting"))
	statusReady := template.JSEscapeString(g.translator.Text(lang, "turnstile_status_ready"))
	statusExpired := template.JSEscapeString(g.translator.Text(lang, "turnstile_status_expired"))
	statusFailed := template.JSEscapeString(g.translator.Text(lang, "turnstile_status_failed"))
	statusUnsupported := template.JSEscapeString(g.translator.Text(lang, "turnstile_status_unsupported"))
	noscript := template.HTMLEscapeString(g.translator.Text(lang, "turnstile_noscript"))

	return template.HTML(fmt.Sprintf(`
<div class="turnstile-box" data-turnstile-box>
  <div class="turnstile-status" data-turnstile-status>%s</div>
  <div class="turnstile-widget">
    <div
      class="cf-turnstile"
      data-sitekey="%s"
      data-action="%s"
      data-cdata="%s"
      data-theme="%s"
      data-language="%s"
      data-size="flexible"
      data-appearance="%s"
      data-retry="auto"
      data-refresh-expired="auto"
      data-refresh-timeout="auto"
      data-response-field-name="%s"
      data-callback="%s"
      data-expired-callback="%s"
      data-timeout-callback="%s"
      data-error-callback="%s"
      data-unsupported-callback="%s"></div>
  </div>
  <noscript><div class="notice error">%s</div></noscript>
</div>
<script nonce="%s">
(() => {
  const script = document.currentScript;
  if (!script) return;
  const tokenSelector = 'input[name="%s"]';
  const watchdogMs = %d;
  let form = null;
  let statusNode = null;
  let submitButton = null;
  let watchdog = 0;
  let settled = false;
  let initialized = false;
  const snapshot = {
    message: "%s",
    state: "waiting",
    ready: false,
  };

  function resolveNodes() {
    if (form && statusNode && submitButton) {
      return true;
    }
    form = script.closest("form");
    if (!form) return false;
    statusNode = form.querySelector("[data-turnstile-status]");
    submitButton = form.querySelector('button[type="submit"]');
    return Boolean(statusNode && submitButton);
  }

  function guardAPI() {
    return window.__authLoginGuards;
  }

  function applySnapshot() {
    if (!resolveNodes()) {
      return;
    }
    statusNode.textContent = snapshot.message;
    statusNode.dataset.state = snapshot.state;
    const guard = guardAPI();
    if (guard && typeof guard.setReady === "function") {
      guard.setReady(form, "%s", snapshot.ready);
      return;
    }
    submitButton.disabled = !snapshot.ready;
  }

  function updateSnapshot(message, state, ready) {
    snapshot.message = message;
    snapshot.state = state;
    snapshot.ready = ready;
    applySnapshot();
  }

  function startWatchdog() {
    window.clearTimeout(watchdog);
    if (snapshot.ready || !resolveNodes()) {
      return;
    }
    watchdog = window.setTimeout(() => {
      const tokenInput = form.querySelector(tokenSelector);
      if (settled || (tokenInput && tokenInput.value)) {
        return;
      }
      updateSnapshot("%s", "failed", false);
    }, watchdogMs);
  }

  function init() {
    if (!resolveNodes()) {
      return;
    }
    if (!initialized) {
      initialized = true;
      const guard = guardAPI();
      if (guard && typeof guard.register === "function") {
        guard.register(form, "%s", snapshot.ready);
      } else {
        submitButton.disabled = !snapshot.ready;
      }
      form.addEventListener("submit", (event) => {
        const tokenInput = form.querySelector(tokenSelector);
        if (!tokenInput || !tokenInput.value) {
          event.preventDefault();
          updateSnapshot("%s", "waiting", false);
        }
      });
    }
    applySnapshot();
    startWatchdog();
  }

  window["%s"] = function() {
    settled = true;
    window.clearTimeout(watchdog);
    updateSnapshot("%s", "ready", true);
  };

  window["%s"] = function() {
    settled = false;
    window.clearTimeout(watchdog);
    updateSnapshot("%s", "failed", false);
  };

  window["%s"] = function() {
    settled = false;
    window.clearTimeout(watchdog);
    updateSnapshot("%s", "expired", false);
  };

  window["%s"] = function() {
    settled = false;
    window.clearTimeout(watchdog);
    updateSnapshot("%s", "unsupported", false);
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init, { once: true });
  } else {
    init();
  }
})();
</script>`,
		template.HTMLEscapeString(g.translator.Text(lang, "turnstile_status_waiting")),
		template.HTMLEscapeString(g.siteKey),
		template.HTMLEscapeString(g.action),
		template.HTMLEscapeString(browserSessionKey),
		template.HTMLEscapeString(g.theme),
		template.HTMLEscapeString(turnstileWidgetLanguage(lang)),
		template.HTMLEscapeString(g.appearance),
		template.HTMLEscapeString(turnstileResponseField),
		template.HTMLEscapeString(readyCallback),
		template.HTMLEscapeString(expiredCallback),
		template.HTMLEscapeString(expiredCallback),
		template.HTMLEscapeString(errorCallback),
		template.HTMLEscapeString(unsupportedCallback),
		noscript,
		template.HTMLEscapeString(scriptNonce),
		template.JSEscapeString(turnstileResponseField),
		turnstileWatchdogMillis,
		statusWaiting,
		turnstileGuardID,
		statusFailed,
		turnstileGuardID,
		statusWaiting,
		readyCallback,
		statusReady,
		errorCallback,
		statusFailed,
		expiredCallback,
		statusExpired,
		unsupportedCallback,
		statusUnsupported,
	))
}

func (g *turnstileLoginGuard) Validate(r *http.Request, lang string) error {
	token := strings.TrimSpace(r.FormValue(turnstileResponseField))
	if token == "" {
		token = strings.TrimSpace(r.FormValue("cf-turnstile-response"))
	}
	if token == "" {
		return localizedUserError{key: "turnstile_missing", status: http.StatusForbidden}
	}
	if len(token) > 2048 {
		return localizedUserError{key: "turnstile_invalid", status: http.StatusForbidden}
	}

	browserSessionKey, err := g.browserSessionKeyFromRequest(r)
	if err != nil {
		return err
	}

	result, err := g.verifyToken(r.Context(), token)
	if err != nil {
		return localizedUserError{key: "turnstile_unavailable", status: http.StatusBadGateway}
	}
	if !result.Success {
		return g.mapVerifyFailure(result.ErrorCodes)
	}
	if !constantTimeEqual(result.Action, g.action) {
		return localizedUserError{key: "turnstile_invalid", status: http.StatusForbidden}
	}
	if !constantTimeEqual(result.CData, browserSessionKey) {
		return localizedUserError{key: "turnstile_invalid", status: http.StatusForbidden}
	}
	if err := g.validateHostname(r, result.Hostname); err != nil {
		return err
	}
	return nil
}

func (g *turnstileLoginGuard) OnLoginSuccess(r *http.Request) {}

func (g *turnstileLoginGuard) OnLoginFailure(r *http.Request, lang string) error {
	return nil
}

func (g *turnstileLoginGuard) ensureBrowserSession(w http.ResponseWriter, r *http.Request) (string, error) {
	if cookie, err := r.Cookie(g.cookieName); err == nil && g.signer.Verify(cookie.Value) {
		return g.browserSessionKey(cookie.Value), nil
	}

	token, err := g.signer.Issue(g.sessionTTL)
	if err != nil {
		return "", fmt.Errorf("issue turnstile browser session: %w", err)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     g.cookieName,
		Value:    token,
		Path:     loginPath,
		HttpOnly: true,
		Secure:   g.secureDecider(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(g.sessionTTL.Seconds()),
		Expires:  g.now().Add(g.sessionTTL),
	})
	return g.browserSessionKey(token), nil
}

func (g *turnstileLoginGuard) browserSessionKeyFromRequest(r *http.Request) (string, error) {
	cookie, err := r.Cookie(g.cookieName)
	if err != nil {
		return "", localizedUserError{key: "turnstile_missing", status: http.StatusForbidden}
	}
	if !g.signer.Verify(cookie.Value) {
		return "", localizedUserError{key: "turnstile_invalid", status: http.StatusForbidden}
	}
	return g.browserSessionKey(cookie.Value), nil
}

func (g *turnstileLoginGuard) browserSessionKey(token string) string {
	sum := sha256.Sum256([]byte("turnstile-browser:" + token))
	return base64.RawURLEncoding.EncodeToString(sum[:18])
}

func (g *turnstileLoginGuard) verifyToken(parent context.Context, token string) (turnstileVerifyResponse, error) {
	ctx, cancel := context.WithTimeout(parent, g.verifyTimeout)
	defer cancel()

	form := url.Values{}
	form.Set("secret", g.secretKey)
	form.Set("response", token)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.verifyURL, strings.NewReader(form.Encode()))
	if err != nil {
		return turnstileVerifyResponse{}, fmt.Errorf("build turnstile verify request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return turnstileVerifyResponse{}, fmt.Errorf("turnstile verify request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return turnstileVerifyResponse{}, fmt.Errorf("turnstile verify returned status %d", resp.StatusCode)
	}

	var result turnstileVerifyResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return turnstileVerifyResponse{}, fmt.Errorf("decode turnstile verify response: %w", err)
	}
	return result, nil
}

func (g *turnstileLoginGuard) mapVerifyFailure(errorCodes []string) error {
	if len(errorCodes) == 0 {
		return localizedUserError{key: "turnstile_invalid", status: http.StatusForbidden}
	}
	for _, code := range errorCodes {
		switch strings.TrimSpace(strings.ToLower(code)) {
		case "missing-input-response":
			return localizedUserError{key: "turnstile_missing", status: http.StatusForbidden}
		case "invalid-input-response":
			return localizedUserError{key: "turnstile_invalid", status: http.StatusForbidden}
		case "timeout-or-duplicate":
			return localizedUserError{key: "turnstile_expired", status: http.StatusForbidden}
		case "missing-input-secret", "invalid-input-secret", "bad-request", "internal-error":
			return localizedUserError{key: "turnstile_unavailable", status: http.StatusBadGateway}
		}
	}
	return localizedUserError{key: "turnstile_invalid", status: http.StatusForbidden}
}

func (g *turnstileLoginGuard) validateHostname(r *http.Request, actual string) error {
	actual = normalizeHostname(actual)
	if actual == "" {
		return localizedUserError{key: "turnstile_invalid", status: http.StatusForbidden}
	}

	expectedHosts := g.allowedHosts
	if len(expectedHosts) == 0 {
		if host := normalizeHostname(r.Host); host != "" {
			expectedHosts = []string{host}
		}
	}
	if len(expectedHosts) == 0 {
		return nil
	}

	for _, expected := range expectedHosts {
		if constantTimeEqual(actual, expected) {
			return nil
		}
	}
	return localizedUserError{key: "turnstile_invalid", status: http.StatusForbidden}
}

func turnstileWidgetLanguage(lang string) string {
	switch normalizeLang(lang) {
	case "zh":
		return "zh-CN"
	case "en":
		return "en"
	default:
		return "auto"
	}
}

func turnstileCallbackSuffix(browserSessionKey string) string {
	sum := sha256.Sum256([]byte("turnstile-callback:" + browserSessionKey))
	return hex.EncodeToString(sum[:6])
}
