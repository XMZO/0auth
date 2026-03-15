package gate

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"net/url"
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

func NormalizePoWProgressMode(value string) string {
	return normalizePoWProgressMode(value)
}

func PoWNonceMatches(token string, nonce string, difficulty int) bool {
	return powNonceMatches(token, nonce, difficulty)
}
