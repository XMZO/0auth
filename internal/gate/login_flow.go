package gate

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func newLoginFlowManager(cfg Config, signer *SessionSigner) *loginFlowManager {
	return &loginFlowManager{
		cookieName: cfg.AuthCookieName + "_login_flow",
		cookiePath: loginPath,
		ttl:        resolveLoginFlowTTL(cfg.CookieTTL),
		signer:     signer,
		secureDecider: func(r *http.Request) bool {
			return shouldUseSecureCookie(cfg, r)
		},
	}
}

func resolveLoginFlowTTL(sessionTTL time.Duration) time.Duration {
	if sessionTTL > 0 && sessionTTL < defaultLoginFlowTTL {
		return sessionTTL
	}
	return defaultLoginFlowTTL
}

func normalizeLoginFlowState(state loginFlowState, fallbackLang string) loginFlowState {
	state.Next = sanitizeNext(state.Next)
	state.Lang = normalizeLang(state.Lang)
	if state.Lang == "" {
		state.Lang = normalizeLang(fallbackLang)
	}
	if state.Lang == "" {
		state.Lang = defaultLang
	}
	return state
}

func loginFlowStateFromQuery(r *http.Request, current loginFlowState, fallbackLang string) (loginFlowState, bool) {
	if r == nil || r.URL == nil {
		return loginFlowState{}, false
	}

	query := r.URL.Query()
	_, hasNext := query["next"]
	_, hasLang := query["lang"]
	_, hasLegacyFlow := query["flow"]
	if !hasNext && !hasLang && !hasLegacyFlow {
		return loginFlowState{}, false
	}

	state := current
	if hasNext {
		state.Next = query.Get("next")
	}
	if hasLang {
		state.Lang = query.Get("lang")
	}
	return normalizeLoginFlowState(state, fallbackLang), true
}

func loginFlowFallbackStateFromForm(r *http.Request, fallbackLang string) loginFlowState {
	if r == nil {
		return normalizeLoginFlowState(loginFlowState{}, fallbackLang)
	}
	return normalizeLoginFlowState(loginFlowState{
		Next: r.FormValue("next"),
		Lang: r.FormValue("lang"),
	}, fallbackLang)
}

func (m *loginFlowManager) Resolve(r *http.Request, fallbackLang string) (loginFlowState, bool) {
	if m == nil || m.signer == nil {
		return loginFlowState{}, false
	}

	cookie, err := r.Cookie(m.cookieName)
	if err != nil {
		return loginFlowState{}, false
	}

	next, lang, expiresAt, ok := m.signer.VerifyLoginFlowToken(cookie.Value)
	if !ok {
		return loginFlowState{}, false
	}

	state := normalizeLoginFlowState(loginFlowState{
		Next:      next,
		Lang:      lang,
		ExpiresAt: expiresAt,
	}, fallbackLang)
	return state, true
}

func (m *loginFlowManager) Issue(w http.ResponseWriter, r *http.Request, state loginFlowState, fallbackLang string) (loginFlowState, error) {
	if m == nil || m.signer == nil {
		return normalizeLoginFlowState(state, fallbackLang), nil
	}

	state = normalizeLoginFlowState(state, fallbackLang)
	now := m.signer.currentTime()
	state.ExpiresAt = now.Add(m.ttl)

	token, err := m.signer.IssueLoginFlowToken(state.Next, state.Lang, state.ExpiresAt)
	if err != nil {
		return state, err
	}

	maxAge := int(state.ExpiresAt.Sub(now).Seconds())
	if maxAge < 0 {
		maxAge = 0
	}

	http.SetCookie(w, &http.Cookie{
		Name:     m.cookieName,
		Value:    token,
		Path:     m.cookiePath,
		HttpOnly: true,
		Secure:   m.secureDecider(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
		Expires:  state.ExpiresAt,
	})

	return state, nil
}

func (m *loginFlowManager) Clear(w http.ResponseWriter, r *http.Request) {
	if m == nil {
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     m.cookieName,
		Value:    "",
		Path:     m.cookiePath,
		HttpOnly: true,
		Secure:   m.secureDecider(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})
}

func (s *SessionSigner) IssueLoginFlowToken(next string, lang string, expiresAt time.Time) (string, error) {
	if expiresAt.IsZero() {
		return "", fmt.Errorf("issue login flow token: empty expiry")
	}

	state := normalizeLoginFlowState(loginFlowState{Next: next, Lang: lang}, defaultLang)
	payload := fmt.Sprintf(
		"lflow|%d|%s|%s",
		expiresAt.Unix(),
		state.Lang,
		base64.RawURLEncoding.EncodeToString([]byte(state.Next)),
	)
	payloadEncoded := base64.RawURLEncoding.EncodeToString([]byte(payload))
	signature := s.sign(payloadEncoded)
	return payloadEncoded + "." + signature, nil
}

func (s *SessionSigner) VerifyLoginFlowToken(token string) (string, string, time.Time, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return "", "", time.Time{}, false
	}

	payloadEncoded := parts[0]
	signature := parts[1]
	expected := s.sign(payloadEncoded)
	if !constantTimeEqual(signature, expected) {
		return "", "", time.Time{}, false
	}

	payloadRaw, err := base64.RawURLEncoding.DecodeString(payloadEncoded)
	if err != nil {
		return "", "", time.Time{}, false
	}

	fields := strings.Split(string(payloadRaw), "|")
	if len(fields) != 4 || fields[0] != "lflow" {
		return "", "", time.Time{}, false
	}

	expiresUnix, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return "", "", time.Time{}, false
	}
	expiresAt := time.Unix(expiresUnix, 0)
	if s.currentTime().After(expiresAt) {
		return "", "", time.Time{}, false
	}

	nextRaw, err := base64.RawURLEncoding.DecodeString(fields[3])
	if err != nil {
		return "", "", time.Time{}, false
	}

	return sanitizeNext(string(nextRaw)), normalizeLang(fields[2]), expiresAt, true
}
