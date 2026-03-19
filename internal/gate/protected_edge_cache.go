package gate

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func newProtectedAssetCache(cfg Config, signer *SessionSigner) *protectedAssetCache {
	if normalizeProtectedCacheMode(cfg.ProtectedCacheMode) != "signed-url" {
		return nil
	}

	extensions := make(map[string]struct{}, len(cfg.ProtectedCacheExts))
	for _, ext := range cfg.ProtectedCacheExts {
		ext = strings.ToLower(strings.TrimSpace(ext))
		if ext == "" {
			continue
		}
		extensions[ext] = struct{}{}
	}
	if len(extensions) == 0 {
		for _, ext := range parseProtectedCacheExtensions("") {
			extensions[ext] = struct{}{}
		}
	}

	now := cfg.Now
	if now == nil {
		now = time.Now
	}

	return &protectedAssetCache{
		mode:       "signed-url",
		ttl:        cfg.ProtectedCacheTTL,
		paramName:  cfg.ProtectedCacheParam,
		extensions: extensions,
		signer:     signer,
		now:        now,
	}
}

func (c *protectedAssetCache) ProxiedRequest(r *http.Request) *http.Request {
	if !c.shouldHandle(r) {
		return nil
	}
	if !c.hasValidToken(r) {
		return nil
	}
	return c.cleanedRequestClone(r)
}

func (c *protectedAssetCache) RedirectLocation(r *http.Request) (string, bool) {
	if !c.shouldHandle(r) {
		return "", false
	}
	if c.hasValidToken(r) {
		return "", false
	}
	location, err := c.signedLocation(r)
	if err != nil {
		return "", false
	}
	return location, true
}

func (c *protectedAssetCache) CleanRequestURI(r *http.Request) string {
	if r == nil || r.URL == nil {
		return "/"
	}
	return sanitizeNext(c.cleanRequestURIFromURL(r.URL))
}

func (c *protectedAssetCache) shouldHandle(r *http.Request) bool {
	if c == nil || r == nil || r.URL == nil {
		return false
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
	default:
		return false
	}
	if strings.HasPrefix(r.URL.Path, authBasePath) {
		return false
	}
	if c.isEligiblePath(r.URL.Path) {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Dest"))) {
	case "audio", "font", "image", "manifest", "object", "script", "style", "track", "video":
		return true
	default:
		return false
	}
}

func (c *protectedAssetCache) isEligiblePath(rawPath string) bool {
	ext := strings.ToLower(filepath.Ext(rawPath))
	if ext == "" {
		return false
	}
	_, ok := c.extensions[ext]
	return ok
}

func (c *protectedAssetCache) hasValidToken(r *http.Request) bool {
	if c == nil || r == nil || r.URL == nil {
		return false
	}
	token := strings.TrimSpace(r.URL.Query().Get(c.paramName))
	if token == "" {
		return false
	}
	expectedURI := c.cleanRequestURIFromURL(r.URL)
	return c.verifyToken(token, expectedURI, r.Method)
}

func (c *protectedAssetCache) signedLocation(r *http.Request) (string, error) {
	if c == nil || r == nil || r.URL == nil {
		return "", fmt.Errorf("empty request")
	}
	cleanURI := c.cleanRequestURIFromURL(r.URL)
	token, err := c.issueToken(cleanURI, r.Method)
	if err != nil {
		return "", err
	}

	cloned := cloneURLWithoutParam(r.URL, c.paramName)
	query := cloned.Query()
	query.Set(c.paramName, token)
	cloned.RawQuery = query.Encode()
	return c.requestURIFromURL(cloned), nil
}

func (c *protectedAssetCache) cleanedRequestClone(r *http.Request) *http.Request {
	cloned := r.Clone(r.Context())
	cloned.URL = cloneURLWithoutParam(r.URL, c.paramName)
	cloned.RequestURI = ""
	return cloned
}

func (c *protectedAssetCache) issueToken(cleanURI string, method string) (string, error) {
	if c == nil || c.signer == nil {
		return "", fmt.Errorf("protected edge cache signer unavailable")
	}
	expiresAt := c.bucketExpiry(c.now())
	payload := fmt.Sprintf(
		"ec|%d|%s|%s",
		expiresAt.Unix(),
		c.canonicalMethod(method),
		base64.RawURLEncoding.EncodeToString([]byte(cleanURI)),
	)
	payloadEncoded := base64.RawURLEncoding.EncodeToString([]byte(payload))
	return payloadEncoded + "." + c.signer.sign(payloadEncoded), nil
}

func (c *protectedAssetCache) verifyToken(token string, expectedURI string, method string) bool {
	if c == nil || c.signer == nil {
		return false
	}

	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return false
	}
	payloadEncoded := parts[0]
	signature := parts[1]
	if !constantTimeEqual(signature, c.signer.sign(payloadEncoded)) {
		return false
	}

	payloadRaw, err := base64.RawURLEncoding.DecodeString(payloadEncoded)
	if err != nil {
		return false
	}
	fields := strings.Split(string(payloadRaw), "|")
	if len(fields) != 4 || fields[0] != "ec" {
		return false
	}
	if !constantTimeEqual(fields[2], c.canonicalMethod(method)) {
		return false
	}

	expiry, err := parseUnixTimestamp(fields[1])
	if err != nil {
		return false
	}
	if c.now().After(expiry) {
		return false
	}

	uriRaw, err := base64.RawURLEncoding.DecodeString(fields[3])
	if err != nil {
		return false
	}
	return constantTimeEqual(string(uriRaw), expectedURI)
}

func (c *protectedAssetCache) bucketExpiry(now time.Time) time.Time {
	step := int64(c.ttl / time.Second)
	if step <= 0 {
		step = 1
	}
	unix := now.Unix()
	expiryUnix := ((unix / step) + 1) * step
	return time.Unix(expiryUnix, 0)
}

func (c *protectedAssetCache) canonicalMethod(method string) string {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case http.MethodHead:
		return http.MethodGet
	default:
		return http.MethodGet
	}
}

func (c *protectedAssetCache) cleanRequestURIFromURL(u *url.URL) string {
	return c.requestURIFromURL(cloneURLWithoutParam(u, c.paramName))
}

func (c *protectedAssetCache) requestURIFromURL(u *url.URL) string {
	if u == nil {
		return "/"
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	if u.RawQuery != "" {
		return path + "?" + u.RawQuery
	}
	return path
}

func cloneURLWithoutParam(u *url.URL, paramName string) *url.URL {
	if u == nil {
		return &url.URL{Path: "/"}
	}
	cloned := *u
	query := cloned.Query()
	query.Del(paramName)
	cloned.RawQuery = query.Encode()
	return &cloned
}

func parseUnixTimestamp(raw string) (time.Time, error) {
	value, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(value, 0), nil
}
