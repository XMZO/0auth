package gate

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"

	gatei18n "auth-proxy/internal/gate/i18n"
)

func (e localizedUserError) Error() string {
	return e.key
}

func (e localizedUserError) HTTPStatus() int {
	if e.status == 0 {
		return http.StatusForbidden
	}
	return e.status
}

func (e localizedUserError) UserMessage(lang string, translator *gatei18n.Translator) string {
	return translator.Text(lang, e.key)
}

func issueNonce(size int) (string, error) {
	raw := make([]byte, size)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func powNonceMatches(token string, nonce string, difficulty int) bool {
	sum := sha256.Sum256([]byte(token + ":" + nonce))
	return hasLeadingZeroNibbles(sum, difficulty)
}

func hasLeadingZeroNibbles(sum [32]byte, difficulty int) bool {
	if difficulty <= 0 {
		return true
	}
	if difficulty > len(sum)*2 {
		return false
	}

	fullBytes := difficulty / 2
	for i := 0; i < fullBytes; i++ {
		if sum[i] != 0 {
			return false
		}
	}

	if difficulty%2 == 1 {
		return sum[fullBytes]>>4 == 0
	}
	return true
}

func constantTimeEqual(left string, right string) bool {
	leftHash := sha256.Sum256([]byte(left))
	rightHash := sha256.Sum256([]byte(right))
	return subtle.ConstantTimeCompare(leftHash[:], rightHash[:]) == 1 && len(left) == len(right)
}

func normalizeSecureMode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "always", "true":
		return "always"
	case "never", "false":
		return "never"
	default:
		return "auto"
	}
}

func normalizePoWProgressMode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "":
		return defaultPoWProgressMode
	case "estimated":
		return "estimated"
	case "fake":
		return "fake"
	case "hidden":
		return "hidden"
	default:
		return ""
	}
}

func normalizeLoginChallengeMode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "":
		return defaultLoginChallengeMode
	case "none", "off", "disabled":
		return "none"
	case "pow":
		return "pow"
	case "turnstile", "cf-turnstile":
		return "turnstile"
	case "pow+turnstile", "turnstile+pow", "both":
		return "pow+turnstile"
	default:
		return ""
	}
}

func normalizeProtectedCacheMode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "disabled", "none", "off":
		return "off"
	case "signed-url", "signed", "url":
		return "signed-url"
	default:
		return ""
	}
}

func challengeModeIncludesPoW(value string) bool {
	switch normalizeLoginChallengeMode(value) {
	case "pow", "pow+turnstile":
		return true
	default:
		return false
	}
}

func challengeModeIncludesTurnstile(value string) bool {
	switch normalizeLoginChallengeMode(value) {
	case "turnstile", "pow+turnstile":
		return true
	default:
		return false
	}
}

func normalizeTurnstileTheme(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", defaultTurnstileTheme:
		return defaultTurnstileTheme
	case "light":
		return "light"
	case "dark":
		return "dark"
	default:
		return ""
	}
}

func normalizeTurnstileAppearance(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "":
		return defaultTurnstileAppearance
	case "always":
		return "always"
	case "interaction-only":
		return "interaction-only"
	case "execute":
		return "execute"
	default:
		return ""
	}
}

func normalizeHostname(value string) string {
	raw := strings.TrimSpace(value)
	if raw == "" {
		return ""
	}
	if parsed, err := url.Parse("//" + raw); err == nil {
		if host := parsed.Hostname(); host != "" {
			return strings.ToLower(host)
		}
	}
	return strings.ToLower(strings.Trim(raw, "[]"))
}

func isTurnstileTokenLabel(value string, maxLen int) bool {
	if value == "" || len(value) > maxLen {
		return false
	}
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-', r == '_':
		default:
			return false
		}
	}
	return true
}

func normalizeAuthSessionStore(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", defaultAuthSessionStore:
		return defaultAuthSessionStore
	case "file":
		return "file"
	default:
		return ""
	}
}

func normalizeQueryParamName(value string, fallback string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return fallback
	}
	for _, r := range trimmed {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-', r == '_':
		default:
			return ""
		}
	}
	return trimmed
}

func parseProtectedCacheExtensions(raw string) []string {
	defaults := []string{
		".aac", ".avi", ".bmp", ".css", ".eot", ".gif", ".ico", ".jpeg", ".jpg", ".js", ".json", ".map",
		".m3u8", ".m4a", ".m4s", ".mp3", ".mp4", ".mpeg", ".mjs", ".ogg", ".ogv", ".otf", ".pdf", ".png",
		".svg", ".ts", ".ttf", ".txt", ".vtt", ".wasm", ".wav", ".webm", ".webmanifest", ".webp", ".woff",
		".woff2", ".xml", ".zip",
	}
	if strings.TrimSpace(raw) == "" {
		return defaults
	}

	seen := map[string]struct{}{}
	out := make([]string, 0)
	for _, token := range splitCSV(raw) {
		token = strings.ToLower(strings.TrimSpace(token))
		if token == "" {
			continue
		}
		if !strings.HasPrefix(token, ".") {
			token = "." + token
		}
		token = filepath.Clean(token)
		if token == "." || token == string(filepath.Separator) || strings.Contains(token, "/") || strings.Contains(token, "\\") {
			continue
		}
		if _, ok := seen[token]; ok {
			continue
		}
		seen[token] = struct{}{}
		out = append(out, token)
	}
	if len(out) == 0 {
		return defaults
	}
	return out
}

func NormalizePoWProgressMode(value string) string {
	return normalizePoWProgressMode(value)
}

func PoWNonceMatches(token string, nonce string, difficulty int) bool {
	return powNonceMatches(token, nonce, difficulty)
}
