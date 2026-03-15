package gate

import (
	"crypto/sha256"
	"encoding/base64"
	"html/template"
	"net/http"
	"strings"
	"time"
)

func (g *passwordAttemptLimitGuard) ID() string {
	return "password-attempt-limit"
}

func (g *passwordAttemptLimitGuard) Render(w http.ResponseWriter, r *http.Request, lang string, scriptNonce string) template.HTML {
	return ""
}

func (g *passwordAttemptLimitGuard) Validate(r *http.Request, lang string) error {
	now := g.now()
	key := g.clientKey(r)

	g.mu.Lock()
	defer g.mu.Unlock()

	g.cleanupLocked(now)

	state := g.states[key]
	if state.bannedUntil.After(now) {
		return localizedUserError{key: "too_many_attempts", status: http.StatusTooManyRequests}
	}
	return nil
}

func (g *passwordAttemptLimitGuard) OnLoginSuccess(r *http.Request) {
	key := g.clientKey(r)
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.states, key)
}

func (g *passwordAttemptLimitGuard) OnLoginFailure(r *http.Request, lang string) error {
	now := g.now()
	key := g.clientKey(r)

	g.mu.Lock()
	defer g.mu.Unlock()

	g.cleanupLocked(now)

	state := g.states[key]
	state.lastSeen = now
	if state.bannedUntil.After(now) {
		g.states[key] = state
		return localizedUserError{key: "too_many_attempts", status: http.StatusTooManyRequests}
	}

	state.failures++
	if state.failures >= g.maxFailures {
		state.failures = 0
		state.bannedUntil = now.Add(g.banDuration)
		g.states[key] = state
		return localizedUserError{key: "too_many_attempts", status: http.StatusTooManyRequests}
	}

	g.states[key] = state
	return nil
}

func (g *passwordAttemptLimitGuard) clientKey(r *http.Request) string {
	agentHash := sha256.Sum256([]byte(strings.TrimSpace(r.UserAgent())))
	clientKey := "unknown"
	if ip, ok := clientIP(r, g.trustProxyHeaders); ok {
		clientKey = ip.String()
	}
	return clientKey + "|" + base64.RawURLEncoding.EncodeToString(agentHash[:8])
}

func (g *passwordAttemptLimitGuard) cleanupLocked(now time.Time) {
	for key, state := range g.states {
		if state.bannedUntil.IsZero() && now.Sub(state.lastSeen) > g.banDuration {
			delete(g.states, key)
			continue
		}
		if !state.bannedUntil.IsZero() && !state.bannedUntil.After(now) && now.Sub(state.bannedUntil) > g.banDuration {
			delete(g.states, key)
		}
	}
}
