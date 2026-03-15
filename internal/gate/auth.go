package gate

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func (s *SinglePasswordAuth) ID() string {
	return "single-password-auth"
}

func (s *SinglePasswordAuth) Authenticate(w http.ResponseWriter, r *http.Request) bool {
	authCookie, err := r.Cookie(s.cookieName)
	if err != nil {
		return false
	}
	bindCookie, err := r.Cookie(s.bindCookieName)
	if err != nil {
		return false
	}
	authFamilyID, authGeneration, authExpiresAt, ok := s.signer.VerifyAuthSessionToken(authCookie.Value)
	if !ok {
		return false
	}
	bindFamilyID, bindGeneration, bindExpiresAt, ok := s.signer.VerifyBindSessionToken(bindCookie.Value)
	if !ok {
		return false
	}
	if !constantTimeEqual(authFamilyID, bindFamilyID) || authGeneration != bindGeneration {
		return false
	}
	if !authExpiresAt.Equal(bindExpiresAt) {
		return false
	}

	session, ok := s.store.Validate(authFamilyID, authGeneration, s.rotationEnabled, s.rotationInterval, s.rotationGrace)
	if !ok {
		return false
	}
	if session.reissue {
		s.writeSessionCookies(w, r, session.familyID, session.currentGeneration, session.expiresAt)
	}
	return true
}

func (s *SinglePasswordAuth) Login(w http.ResponseWriter, r *http.Request) error {
	password := r.FormValue("password")
	if !constantTimeEqual(password, s.expectedPassword) {
		return errInvalidCredentials
	}

	session, err := s.store.Issue(s.ttl, s.rotationEnabled, s.rotationInterval)
	if err != nil {
		return err
	}
	return s.writeSessionCookies(w, r, session.familyID, session.currentGeneration, session.expiresAt)
}

func (s *SinglePasswordAuth) Logout(w http.ResponseWriter, r *http.Request) {
	if authCookie, err := r.Cookie(s.cookieName); err == nil {
		if familyID, _, _, ok := s.signer.VerifyAuthSessionToken(authCookie.Value); ok {
			s.store.Delete(familyID)
		}
	}

	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   s.secureDecider(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})
	http.SetCookie(w, &http.Cookie{
		Name:     s.bindCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   s.secureDecider(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})
}

func (s *SinglePasswordAuth) writeSessionCookies(w http.ResponseWriter, r *http.Request, familyID string, generation uint64, expiresAt time.Time) error {
	authToken, err := s.signer.IssueAuthSessionToken(familyID, generation, expiresAt)
	if err != nil {
		return err
	}
	bindToken, err := s.signer.IssueBindSessionToken(familyID, generation, expiresAt)
	if err != nil {
		return err
	}

	remaining := int(expiresAt.Sub(s.signer.currentTime()).Seconds())
	if remaining < 0 {
		remaining = 0
	}

	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName,
		Value:    authToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.secureDecider(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   remaining,
		Expires:  expiresAt,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     s.bindCookieName,
		Value:    bindToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.secureDecider(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   remaining,
		Expires:  expiresAt,
	})
	return nil
}

func (s *SessionSigner) Issue(ttl time.Duration) (string, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generate session nonce: %w", err)
	}

	payload := fmt.Sprintf("v1|%d|%s", s.currentTime().Add(ttl).Unix(), base64.RawURLEncoding.EncodeToString(nonce))
	payloadEncoded := base64.RawURLEncoding.EncodeToString([]byte(payload))
	signature := s.sign(payloadEncoded)
	return payloadEncoded + "." + signature, nil
}

func (s *SessionSigner) Verify(token string) bool {
	_, ok := s.parse(token, "", false)
	return ok
}

func (s *SessionSigner) IssueBound(ttl time.Duration, binding string) (string, error) {
	if strings.TrimSpace(binding) == "" {
		return "", fmt.Errorf("issue bound session: empty binding")
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generate bound session nonce: %w", err)
	}

	payload := fmt.Sprintf("v2|%d|%s|%s", s.currentTime().Add(ttl).Unix(), base64.RawURLEncoding.EncodeToString(nonce), binding)
	payloadEncoded := base64.RawURLEncoding.EncodeToString([]byte(payload))
	signature := s.sign(payloadEncoded)
	return payloadEncoded + "." + signature, nil
}

func (s *SessionSigner) VerifyBound(token string, binding string) bool {
	_, ok := s.parse(token, binding, true)
	return ok
}

func (s *SessionSigner) IssueSessionID(sessionID string) (string, error) {
	if strings.TrimSpace(sessionID) == "" {
		return "", fmt.Errorf("issue session id token: empty session id")
	}
	payloadEncoded := base64.RawURLEncoding.EncodeToString([]byte("sid|" + sessionID))
	signature := s.sign(payloadEncoded)
	return payloadEncoded + "." + signature, nil
}

func (s *SessionSigner) VerifySessionID(token string) (string, bool) {
	fields, ok := s.parseSessionID(token)
	if !ok {
		return "", false
	}
	return fields[1], true
}

func (s *SessionSigner) IssueAuthSessionToken(familyID string, generation uint64, expiresAt time.Time) (string, error) {
	return s.issueSessionFamilyToken("authsid", familyID, generation, expiresAt)
}

func (s *SessionSigner) VerifyAuthSessionToken(token string) (string, uint64, time.Time, bool) {
	return s.verifySessionFamilyToken(token, "authsid")
}

func (s *SessionSigner) IssueBindSessionToken(familyID string, generation uint64, expiresAt time.Time) (string, error) {
	return s.issueSessionFamilyToken("bindsid", familyID, generation, expiresAt)
}

func (s *SessionSigner) VerifyBindSessionToken(token string) (string, uint64, time.Time, bool) {
	return s.verifySessionFamilyToken(token, "bindsid")
}

func (s *SessionSigner) parse(token string, binding string, requireBinding bool) ([]string, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return nil, false
	}

	payloadEncoded := parts[0]
	signature := parts[1]
	expected := s.sign(payloadEncoded)
	if subtle.ConstantTimeCompare([]byte(signature), []byte(expected)) != 1 {
		return nil, false
	}

	payloadRaw, err := base64.RawURLEncoding.DecodeString(payloadEncoded)
	if err != nil {
		return nil, false
	}
	fields := strings.Split(string(payloadRaw), "|")
	switch fields[0] {
	case "v1":
		if requireBinding || len(fields) != 3 {
			return nil, false
		}
	case "v2":
		if len(fields) != 4 || !requireBinding || !constantTimeEqual(fields[3], binding) {
			return nil, false
		}
	default:
		return nil, false
	}

	expiresAt, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return nil, false
	}
	if s.currentTime().Unix() > expiresAt {
		return nil, false
	}
	return fields, true
}

func (s *SessionSigner) parseSessionID(token string) ([]string, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return nil, false
	}

	payloadEncoded := parts[0]
	signature := parts[1]
	expected := s.sign(payloadEncoded)
	if subtle.ConstantTimeCompare([]byte(signature), []byte(expected)) != 1 {
		return nil, false
	}

	payloadRaw, err := base64.RawURLEncoding.DecodeString(payloadEncoded)
	if err != nil {
		return nil, false
	}
	fields := strings.Split(string(payloadRaw), "|")
	if len(fields) != 2 || fields[0] != "sid" || strings.TrimSpace(fields[1]) == "" {
		return nil, false
	}
	return fields, true
}

func (s *SessionSigner) issueSessionFamilyToken(kind string, familyID string, generation uint64, expiresAt time.Time) (string, error) {
	if strings.TrimSpace(familyID) == "" {
		return "", fmt.Errorf("issue %s token: empty family id", kind)
	}
	if expiresAt.IsZero() {
		return "", fmt.Errorf("issue %s token: empty expiry", kind)
	}

	payload := fmt.Sprintf("%s|%s|%d|%d", kind, familyID, generation, expiresAt.Unix())
	payloadEncoded := base64.RawURLEncoding.EncodeToString([]byte(payload))
	signature := s.sign(payloadEncoded)
	return payloadEncoded + "." + signature, nil
}

func (s *SessionSigner) verifySessionFamilyToken(token string, expectedKind string) (string, uint64, time.Time, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return "", 0, time.Time{}, false
	}

	payloadEncoded := parts[0]
	signature := parts[1]
	expected := s.sign(payloadEncoded)
	if subtle.ConstantTimeCompare([]byte(signature), []byte(expected)) != 1 {
		return "", 0, time.Time{}, false
	}

	payloadRaw, err := base64.RawURLEncoding.DecodeString(payloadEncoded)
	if err != nil {
		return "", 0, time.Time{}, false
	}
	fields := strings.Split(string(payloadRaw), "|")
	if len(fields) != 4 || fields[0] != expectedKind || strings.TrimSpace(fields[1]) == "" {
		return "", 0, time.Time{}, false
	}

	generation, err := strconv.ParseUint(fields[2], 10, 64)
	if err != nil {
		return "", 0, time.Time{}, false
	}
	expiresUnix, err := strconv.ParseInt(fields[3], 10, 64)
	if err != nil {
		return "", 0, time.Time{}, false
	}
	expiresAt := time.Unix(expiresUnix, 0)
	if s.currentTime().After(expiresAt) {
		return "", 0, time.Time{}, false
	}

	return fields[1], generation, expiresAt, true
}

func (s *SessionSigner) sign(payload string) string {
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (s *SessionSigner) currentTime() time.Time {
	if s != nil && s.now != nil {
		return s.now()
	}
	return time.Now()
}

func authCookieBinding(bindValue string) string {
	sum := sha256.Sum256([]byte("auth-bind:" + strings.TrimSpace(bindValue)))
	return base64.RawURLEncoding.EncodeToString(sum[:16])
}
