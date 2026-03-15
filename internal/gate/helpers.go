package gate

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
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
	case "", defaultPoWProgressMode:
		return defaultPoWProgressMode
	case "fake":
		return "fake"
	case "hidden":
		return "hidden"
	default:
		return ""
	}
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
