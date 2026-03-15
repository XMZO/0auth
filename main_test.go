package main

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	. "auth-proxy/internal/gate"
)

const (
	defaultAuthCookie      = DefaultAuthCookie
	defaultLangCookie      = DefaultLangCookie
	defaultLoginFlowCookie = defaultAuthCookie + "_login_flow"
	loginPath              = LoginPath
	defaultPoWProgressMode = DefaultPoWProgressMode
)

var (
	parseDurationWithDays     = ParseDurationWithDays
	normalizePoWProgressMode  = NormalizePoWProgressMode
	defaultSuspiciousUATokens = DefaultSuspiciousUATokens
	parseUserAgentTokens      = ParseUserAgentTokens
	powNonceMatches           = PoWNonceMatches
)

func TestLoginAndProxyFlow(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("upstream ok"))
	}))
	defer upstream.Close()

	app, err := NewApp(Config{
		ListenAddr:       ":0",
		TargetURL:        upstream.URL,
		AuthPassword:     "secret-pass",
		SessionSecret:    "session-secret",
		CookieTTL:        24 * time.Hour,
		PoWDifficulty:    2,
		PoWChallengeTTL:  time.Minute,
		MaxLoginFailures: 5,
		LoginBanDuration: 10 * time.Minute,
		DefaultLang:      "en",
		AuthCookieName:   defaultAuthCookie,
		LangCookieName:   defaultLangCookie,
		CookieSecureMode: "never",
	})
	if err != nil {
		t.Fatalf("NewApp() error = %v", err)
	}

	proxy := httptest.NewServer(app)
	defer proxy.Close()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New() error = %v", err)
	}

	client := proxy.Client()
	client.Jar = jar

	unauthResp, err := client.Get(proxy.URL + "/")
	if err != nil {
		t.Fatalf("GET / without cookie error = %v", err)
	}
	defer unauthResp.Body.Close()

	unauthBody, err := io.ReadAll(unauthResp.Body)
	if err != nil {
		t.Fatalf("ReadAll(unauth) error = %v", err)
	}
	if unauthResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthorized status = %d, want %d", unauthResp.StatusCode, http.StatusUnauthorized)
	}
	if unauthResp.Request == nil || unauthResp.Request.URL == nil {
		t.Fatalf("unauthorized response missing final request URL")
	}
	if unauthResp.Request.URL.Path != loginPath {
		t.Fatalf("unauthorized final path = %q, want %q", unauthResp.Request.URL.Path, loginPath)
	}
	if unauthResp.Request.URL.RawQuery != "" {
		t.Fatalf("unauthorized final URL query = %q, want empty", unauthResp.Request.URL.RawQuery)
	}
	if cacheControl := unauthResp.Header.Get("Cache-Control"); !strings.Contains(cacheControl, "no-store") {
		t.Fatalf("challenge page Cache-Control = %q, want no-store", cacheControl)
	}
	if csp := unauthResp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "worker-src 'self' blob:") {
		t.Fatalf("challenge page CSP = %q, want worker-src blob support", csp)
	}
	if surrogate := unauthResp.Header.Get("Surrogate-Control"); !strings.Contains(strings.ToLower(surrogate), "no-store") {
		t.Fatalf("challenge page Surrogate-Control = %q, want no-store", surrogate)
	}
	if !strings.Contains(string(unauthBody), `input type="password" name="password"`) {
		t.Fatalf("unauthorized body did not render login form: %s", string(unauthBody))
	}
	hiddenPhrases := []string{
		"Before sign-in, the browser completes a small SHA-256 proof-of-work task.",
		"A persistent cookie is issued after login. Its lifetime is configurable, and only the cookie is checked. No IP binding is used.",
		"The module chain covers URL parameters, language cookie, IP rules, Accept-Language, PoW verification, and failure lockout.",
		"Browser PoW Verification",
		"Current difficulty:",
		"Hash rate:",
		"Attempts:",
	}
	for _, phrase := range hiddenPhrases {
		if strings.Contains(string(unauthBody), phrase) {
			t.Fatalf("unauthorized body leaked user-facing implementation detail %q: %s", phrase, string(unauthBody))
		}
	}
	if strings.Contains(string(unauthBody), "window.history.replaceState") {
		t.Fatalf("unauthorized body still contains obsolete clean URL script: %s", string(unauthBody))
	}
	if !strings.Contains(string(unauthBody), `form method="post" action="/_auth/login"`) {
		t.Fatalf("unauthorized body missing clean login form action: %s", string(unauthBody))
	}

	powID, powToken, powDifficulty := extractPoWFields(t, string(unauthBody))
	powNonce := solvePoWNonce(powToken, powDifficulty)

	loginResp, err := client.PostForm(proxy.URL+loginPath, url.Values{
		"password":       {"secret-pass"},
		"next":           {"/"},
		"lang":           {"en"},
		"pow_id":         {powID},
		"pow_token":      {powToken},
		"pow_nonce":      {powNonce},
		"pow_difficulty": {strconv.Itoa(powDifficulty)},
	})
	if err != nil {
		t.Fatalf("POST login error = %v", err)
	}
	defer loginResp.Body.Close()

	loginBody, err := io.ReadAll(loginResp.Body)
	if err != nil {
		t.Fatalf("ReadAll(login) error = %v", err)
	}
	if loginResp.StatusCode != http.StatusOK {
		t.Fatalf("login final status = %d, want %d", loginResp.StatusCode, http.StatusOK)
	}
	if strings.TrimSpace(string(loginBody)) != "upstream ok" {
		t.Fatalf("login final body = %q, want %q", strings.TrimSpace(string(loginBody)), "upstream ok")
	}

	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatalf("url.Parse(proxy.URL) error = %v", err)
	}

	var foundAuthCookie bool
	for _, cookie := range jar.Cookies(proxyURL) {
		if cookie.Name == defaultAuthCookie && cookie.Value != "" {
			foundAuthCookie = true
		}
	}
	if !foundAuthCookie {
		t.Fatalf("auth cookie %q was not set", defaultAuthCookie)
	}

	authedResp, err := client.Get(proxy.URL + "/")
	if err != nil {
		t.Fatalf("GET / with cookie error = %v", err)
	}
	defer authedResp.Body.Close()

	authedBody, err := io.ReadAll(authedResp.Body)
	if err != nil {
		t.Fatalf("ReadAll(authed) error = %v", err)
	}
	if authedResp.StatusCode != http.StatusOK {
		t.Fatalf("authed status = %d, want %d", authedResp.StatusCode, http.StatusOK)
	}
	if strings.TrimSpace(string(authedBody)) != "upstream ok" {
		t.Fatalf("authed body = %q, want %q", strings.TrimSpace(string(authedBody)), "upstream ok")
	}
}

func TestPoWAutoDifficulty(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("upstream ok"))
	}))
	defer upstream.Close()

	app, err := NewApp(Config{
		ListenAddr:            ":0",
		TargetURL:             upstream.URL,
		AuthPassword:          "secret-pass",
		SessionSecret:         "session-secret",
		CookieTTL:             24 * time.Hour,
		PoWDifficulty:         4,
		PoWAutoDifficulty:     true,
		PoWMinDifficulty:      2,
		PoWMaxDifficulty:      6,
		PoWSuspiciousUATokens: []string{"curl", "custom-bot"},
		PoWChallengeTTL:       time.Minute,
		MaxLoginFailures:      5,
		LoginBanDuration:      10 * time.Minute,
		DefaultLang:           "en",
		AuthCookieName:        defaultAuthCookie,
		LangCookieName:        defaultLangCookie,
		CookieSecureMode:      "never",
	})
	if err != nil {
		t.Fatalf("NewApp() error = %v", err)
	}

	proxy := httptest.NewServer(app)
	defer proxy.Close()

	assertDifficulty := func(userAgent string, want int) {
		req, err := http.NewRequest(http.MethodGet, proxy.URL+"/", nil)
		if err != nil {
			t.Fatalf("http.NewRequest() error = %v", err)
		}
		req.Header.Set("User-Agent", userAgent)

		resp, err := proxy.Client().Do(req)
		if err != nil {
			t.Fatalf("Do() error = %v", err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("ReadAll() error = %v", err)
		}

		_, _, got := extractPoWFields(t, string(body))
		if got != want {
			t.Fatalf("difficulty for %q = %d, want %d", userAgent, got, want)
		}
	}

	assertDifficulty("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/123.0 Safari/537.36", 4)
	assertDifficulty("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Version/17.0 Mobile/15E148 Safari/604.1", 3)
	assertDifficulty("curl/8.5.0", 6)
	assertDifficulty("custom-bot/1.0", 6)
	assertDifficulty("selenium-check/1.0", 4)
}

func TestPoWAutoDifficultyRespectsConfiguredRuleList(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("upstream ok"))
	}))
	defer upstream.Close()

	app, err := NewApp(Config{
		ListenAddr:            ":0",
		TargetURL:             upstream.URL,
		AuthPassword:          "secret-pass",
		SessionSecret:         "session-secret",
		CookieTTL:             24 * time.Hour,
		PoWDifficulty:         4,
		PoWAutoDifficulty:     true,
		PoWAutoRules:          []string{"mobile"},
		PoWMinDifficulty:      2,
		PoWMaxDifficulty:      6,
		PoWSuspiciousUATokens: []string{"curl", "custom-bot"},
		PoWChallengeTTL:       time.Minute,
		MaxLoginFailures:      5,
		LoginBanDuration:      10 * time.Minute,
		DefaultLang:           "en",
		AuthCookieName:        defaultAuthCookie,
		LangCookieName:        defaultLangCookie,
		CookieSecureMode:      "never",
	})
	if err != nil {
		t.Fatalf("NewApp() error = %v", err)
	}

	proxy := httptest.NewServer(app)
	defer proxy.Close()

	assertDifficulty := func(userAgent string, want int) {
		req, err := http.NewRequest(http.MethodGet, proxy.URL+"/", nil)
		if err != nil {
			t.Fatalf("http.NewRequest() error = %v", err)
		}
		req.Header.Set("User-Agent", userAgent)

		resp, err := proxy.Client().Do(req)
		if err != nil {
			t.Fatalf("Do() error = %v", err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("ReadAll() error = %v", err)
		}

		_, _, got := extractPoWFields(t, string(body))
		if got != want {
			t.Fatalf("difficulty for %q = %d, want %d", userAgent, got, want)
		}
	}

	assertDifficulty("curl/8.5.0", 4)
	assertDifficulty("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Version/17.0 Mobile/15E148 Safari/604.1", 3)
}

func TestAuthCookieRequiresBindCookie(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("upstream ok"))
	}))
	defer upstream.Close()

	app, err := NewApp(Config{
		ListenAddr:       ":0",
		TargetURL:        upstream.URL,
		AuthPassword:     "secret-pass",
		SessionSecret:    "session-secret",
		CookieTTL:        24 * time.Hour,
		PoWDifficulty:    2,
		PoWChallengeTTL:  time.Minute,
		MaxLoginFailures: 5,
		LoginBanDuration: 10 * time.Minute,
		DefaultLang:      "en",
		AuthCookieName:   defaultAuthCookie,
		LangCookieName:   defaultLangCookie,
		CookieSecureMode: "never",
	})
	if err != nil {
		t.Fatalf("NewApp() error = %v", err)
	}

	proxy := httptest.NewServer(app)
	defer proxy.Close()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New() error = %v", err)
	}

	client := proxy.Client()
	client.Jar = jar

	loginResp, err := client.Get(proxy.URL + "/")
	if err != nil {
		t.Fatalf("GET / error = %v", err)
	}
	loginBody, err := io.ReadAll(loginResp.Body)
	loginResp.Body.Close()
	if err != nil {
		t.Fatalf("ReadAll(login page) error = %v", err)
	}

	powID, powToken, powDifficulty := extractPoWFields(t, string(loginBody))
	powNonce := solvePoWNonce(powToken, powDifficulty)

	resp, err := client.PostForm(proxy.URL+loginPath, url.Values{
		"password":       {"secret-pass"},
		"next":           {"/"},
		"lang":           {"en"},
		"pow_id":         {powID},
		"pow_token":      {powToken},
		"pow_nonce":      {powNonce},
		"pow_difficulty": {strconv.Itoa(powDifficulty)},
	})
	if err != nil {
		t.Fatalf("POST login error = %v", err)
	}
	resp.Body.Close()

	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatalf("url.Parse(proxy.URL) error = %v", err)
	}

	var authCookie *http.Cookie
	for _, cookie := range jar.Cookies(proxyURL) {
		if cookie.Name == defaultAuthCookie {
			authCookie = cookie
			break
		}
	}
	if authCookie == nil {
		t.Fatalf("auth cookie %q not found", defaultAuthCookie)
	}

	clientB := &http.Client{
		Transport: proxy.Client().Transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequest(http.MethodGet, proxy.URL+"/", nil)
	if err != nil {
		t.Fatalf("http.NewRequest() error = %v", err)
	}
	req.AddCookie(authCookie)

	blockedResp, err := clientB.Do(req)
	if err != nil {
		t.Fatalf("clientB GET / error = %v", err)
	}
	defer blockedResp.Body.Close()

	if blockedResp.StatusCode != http.StatusSeeOther {
		t.Fatalf("auth-cookie-only status = %d, want %d", blockedResp.StatusCode, http.StatusSeeOther)
	}
	location := blockedResp.Header.Get("Location")
	target, err := url.Parse(location)
	if err != nil {
		t.Fatalf("url.Parse(Location) error = %v", err)
	}
	if target.Path != loginPath {
		t.Fatalf("auth-cookie-only redirect path = %q, want %q", target.Path, loginPath)
	}
}

func TestAuthSessionRotationGraceWindow(t *testing.T) {
	now := time.Date(2026, 3, 15, 17, 0, 0, 0, time.UTC)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("upstream ok"))
	}))
	defer upstream.Close()

	app, err := NewApp(Config{
		ListenAddr:           ":0",
		TargetURL:            upstream.URL,
		AuthPassword:         "secret-pass",
		SessionSecret:        "session-secret",
		CookieTTL:            24 * time.Hour,
		AuthSessionRotation:  true,
		AuthRotationInterval: time.Minute,
		AuthRotationGrace:    30 * time.Second,
		PoWDifficulty:        0,
		PoWChallengeTTL:      time.Minute,
		MaxLoginFailures:     5,
		LoginBanDuration:     10 * time.Minute,
		DefaultLang:          "en",
		AuthCookieName:       defaultAuthCookie,
		LangCookieName:       defaultLangCookie,
		CookieSecureMode:     "never",
		Now: func() time.Time {
			return now
		},
	})
	if err != nil {
		t.Fatalf("NewApp() error = %v", err)
	}

	proxy := httptest.NewServer(app)
	defer proxy.Close()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New() error = %v", err)
	}

	clientA := proxy.Client()
	clientA.Jar = jar

	loginResp, err := clientA.PostForm(proxy.URL+loginPath, url.Values{
		"password": {"secret-pass"},
		"next":     {"/"},
		"lang":     {"en"},
	})
	if err != nil {
		t.Fatalf("POST login error = %v", err)
	}
	loginResp.Body.Close()

	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatalf("url.Parse(proxy.URL) error = %v", err)
	}

	var oldAuthCookie, oldBindCookie *http.Cookie
	for _, cookie := range jar.Cookies(proxyURL) {
		switch cookie.Name {
		case defaultAuthCookie:
			value := *cookie
			oldAuthCookie = &value
		case defaultAuthCookie + "_bind":
			value := *cookie
			oldBindCookie = &value
		}
	}
	if oldAuthCookie == nil || oldBindCookie == nil {
		t.Fatalf("expected auth and bind cookies, got auth=%v bind=%v", oldAuthCookie != nil, oldBindCookie != nil)
	}

	now = now.Add(61 * time.Second)

	rotateResp, err := clientA.Get(proxy.URL + "/")
	if err != nil {
		t.Fatalf("rotate GET / error = %v", err)
	}
	rotateBody, err := io.ReadAll(rotateResp.Body)
	rotateResp.Body.Close()
	if err != nil {
		t.Fatalf("ReadAll(rotate) error = %v", err)
	}
	if rotateResp.StatusCode != http.StatusOK {
		t.Fatalf("rotate status = %d, want %d", rotateResp.StatusCode, http.StatusOK)
	}
	if strings.TrimSpace(string(rotateBody)) != "upstream ok" {
		t.Fatalf("rotate body = %q, want %q", strings.TrimSpace(string(rotateBody)), "upstream ok")
	}

	var newAuthCookie *http.Cookie
	for _, cookie := range jar.Cookies(proxyURL) {
		if cookie.Name == defaultAuthCookie {
			value := *cookie
			newAuthCookie = &value
			break
		}
	}
	if newAuthCookie == nil {
		t.Fatalf("new auth cookie missing after rotation")
	}
	if newAuthCookie.Value == oldAuthCookie.Value {
		t.Fatalf("auth cookie value did not rotate")
	}

	clientB := &http.Client{Transport: proxy.Client().Transport}
	graceReq, err := http.NewRequest(http.MethodGet, proxy.URL+"/", nil)
	if err != nil {
		t.Fatalf("http.NewRequest(grace) error = %v", err)
	}
	graceReq.AddCookie(oldAuthCookie)
	graceReq.AddCookie(oldBindCookie)

	graceResp, err := clientB.Do(graceReq)
	if err != nil {
		t.Fatalf("grace request error = %v", err)
	}
	graceBody, err := io.ReadAll(graceResp.Body)
	graceResp.Body.Close()
	if err != nil {
		t.Fatalf("ReadAll(grace) error = %v", err)
	}
	if graceResp.StatusCode != http.StatusOK {
		t.Fatalf("grace status = %d, want %d", graceResp.StatusCode, http.StatusOK)
	}
	if strings.TrimSpace(string(graceBody)) != "upstream ok" {
		t.Fatalf("grace body = %q, want %q", strings.TrimSpace(string(graceBody)), "upstream ok")
	}
	setCookies := graceResp.Header.Values("Set-Cookie")
	if len(setCookies) < 2 {
		t.Fatalf("grace response missing refreshed cookies: %v", setCookies)
	}

	now = now.Add(31 * time.Second)

	blockedClient := &http.Client{
		Transport: proxy.Client().Transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	blockedReq, err := http.NewRequest(http.MethodGet, proxy.URL+"/", nil)
	if err != nil {
		t.Fatalf("http.NewRequest(blocked) error = %v", err)
	}
	blockedReq.AddCookie(oldAuthCookie)
	blockedReq.AddCookie(oldBindCookie)

	blockedResp, err := blockedClient.Do(blockedReq)
	if err != nil {
		t.Fatalf("blocked request error = %v", err)
	}
	defer blockedResp.Body.Close()

	if blockedResp.StatusCode != http.StatusSeeOther {
		t.Fatalf("post-grace status = %d, want %d", blockedResp.StatusCode, http.StatusSeeOther)
	}
}

func TestFileAuthSessionStorePersistsAcrossRestartAndLogoutRevokes(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("upstream ok"))
	}))
	defer upstream.Close()

	sessionFile := filepath.Join(t.TempDir(), "auth-sessions.json")
	makeApp := func() *httptest.Server {
		t.Helper()

		app, err := NewApp(Config{
			ListenAddr:       ":0",
			TargetURL:        upstream.URL,
			AuthPassword:     "secret-pass",
			SessionSecret:    "session-secret",
			AuthSessionStore: "file",
			AuthSessionFile:  sessionFile,
			CookieTTL:        24 * time.Hour,
			PoWDifficulty:    0,
			PoWChallengeTTL:  time.Minute,
			MaxLoginFailures: 5,
			LoginBanDuration: 10 * time.Minute,
			DefaultLang:      "en",
			AuthCookieName:   defaultAuthCookie,
			LangCookieName:   defaultLangCookie,
			CookieSecureMode: "never",
		})
		if err != nil {
			t.Fatalf("NewApp() error = %v", err)
		}

		server := httptest.NewServer(app)
		t.Cleanup(server.Close)
		return server
	}

	serverA := makeApp()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New() error = %v", err)
	}

	clientA := serverA.Client()
	clientA.Jar = jar

	loginResp, err := clientA.PostForm(serverA.URL+loginPath, url.Values{
		"password": {"secret-pass"},
		"next":     {"/"},
		"lang":     {"en"},
	})
	if err != nil {
		t.Fatalf("POST login error = %v", err)
	}
	loginBody, err := io.ReadAll(loginResp.Body)
	loginResp.Body.Close()
	if err != nil {
		t.Fatalf("ReadAll(login) error = %v", err)
	}
	if loginResp.StatusCode != http.StatusOK {
		t.Fatalf("login status = %d, want %d", loginResp.StatusCode, http.StatusOK)
	}
	if strings.TrimSpace(string(loginBody)) != "upstream ok" {
		t.Fatalf("login body = %q, want %q", strings.TrimSpace(string(loginBody)), "upstream ok")
	}

	serverAURL, err := url.Parse(serverA.URL)
	if err != nil {
		t.Fatalf("url.Parse(serverA.URL) error = %v", err)
	}
	var authCookie, bindCookie *http.Cookie
	for _, cookie := range jar.Cookies(serverAURL) {
		switch cookie.Name {
		case defaultAuthCookie:
			value := *cookie
			authCookie = &value
		case defaultAuthCookie + "_bind":
			value := *cookie
			bindCookie = &value
		}
	}
	if authCookie == nil || bindCookie == nil {
		t.Fatalf("expected auth and bind cookies, got auth=%v bind=%v", authCookie != nil, bindCookie != nil)
	}

	serverA.Close()
	serverB := makeApp()
	clientB := &http.Client{Transport: serverB.Client().Transport}

	authedReq, err := http.NewRequest(http.MethodGet, serverB.URL+"/", nil)
	if err != nil {
		t.Fatalf("http.NewRequest(GET /) error = %v", err)
	}
	authedReq.AddCookie(authCookie)
	authedReq.AddCookie(bindCookie)

	authedResp, err := clientB.Do(authedReq)
	if err != nil {
		t.Fatalf("clientB GET / error = %v", err)
	}
	authedBody, err := io.ReadAll(authedResp.Body)
	authedResp.Body.Close()
	if err != nil {
		t.Fatalf("ReadAll(authed) error = %v", err)
	}
	if authedResp.StatusCode != http.StatusOK {
		t.Fatalf("post-restart status = %d, want %d", authedResp.StatusCode, http.StatusOK)
	}
	if strings.TrimSpace(string(authedBody)) != "upstream ok" {
		t.Fatalf("post-restart body = %q, want %q", strings.TrimSpace(string(authedBody)), "upstream ok")
	}

	logoutReq, err := http.NewRequest(http.MethodGet, serverB.URL+LogoutPath, nil)
	if err != nil {
		t.Fatalf("http.NewRequest(logout) error = %v", err)
	}
	logoutReq.AddCookie(authCookie)
	logoutReq.AddCookie(bindCookie)

	logoutResp, err := clientB.Do(logoutReq)
	if err != nil {
		t.Fatalf("logout request error = %v", err)
	}
	_ = logoutResp.Body.Close()

	blockedClient := &http.Client{
		Transport: serverB.Client().Transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	blockedReq, err := http.NewRequest(http.MethodGet, serverB.URL+"/", nil)
	if err != nil {
		t.Fatalf("http.NewRequest(blocked) error = %v", err)
	}
	blockedReq.AddCookie(authCookie)
	blockedReq.AddCookie(bindCookie)

	blockedResp, err := blockedClient.Do(blockedReq)
	if err != nil {
		t.Fatalf("blocked request error = %v", err)
	}
	defer blockedResp.Body.Close()

	if blockedResp.StatusCode != http.StatusSeeOther {
		t.Fatalf("post-logout status = %d, want %d", blockedResp.StatusCode, http.StatusSeeOther)
	}
}

func TestFileAuthSessionStoreCompactsExpiredSessionsOnRestart(t *testing.T) {
	now := time.Date(2026, 3, 15, 18, 0, 0, 0, time.UTC)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("upstream ok"))
	}))
	defer upstream.Close()

	sessionFile := filepath.Join(t.TempDir(), "auth-sessions.json")
	makeApp := func() *httptest.Server {
		t.Helper()

		app, err := NewApp(Config{
			ListenAddr:       ":0",
			TargetURL:        upstream.URL,
			AuthPassword:     "secret-pass",
			SessionSecret:    "session-secret",
			AuthSessionStore: "file",
			AuthSessionFile:  sessionFile,
			CookieTTL:        time.Minute,
			PoWDifficulty:    0,
			PoWChallengeTTL:  time.Minute,
			MaxLoginFailures: 5,
			LoginBanDuration: 10 * time.Minute,
			DefaultLang:      "en",
			AuthCookieName:   defaultAuthCookie,
			LangCookieName:   defaultLangCookie,
			CookieSecureMode: "never",
			Now: func() time.Time {
				return now
			},
		})
		if err != nil {
			t.Fatalf("NewApp() error = %v", err)
		}

		server := httptest.NewServer(app)
		t.Cleanup(server.Close)
		return server
	}

	serverA := makeApp()
	clientA := newCookieClient(t, serverA)

	loginResp, err := clientA.PostForm(serverA.URL+loginPath, url.Values{
		"password": {"secret-pass"},
		"next":     {"/"},
		"lang":     {"en"},
	})
	if err != nil {
		t.Fatalf("POST login error = %v", err)
	}
	_, _ = io.ReadAll(loginResp.Body)
	loginResp.Body.Close()

	initialRaw, err := os.ReadFile(sessionFile)
	if err != nil {
		t.Fatalf("os.ReadFile(initial session file) error = %v", err)
	}
	if !strings.Contains(string(initialRaw), `"family_id"`) {
		t.Fatalf("initial session file missing stored family: %s", string(initialRaw))
	}

	now = now.Add(2 * time.Minute)
	serverA.Close()
	_ = makeApp()

	compactedRaw, err := os.ReadFile(sessionFile)
	if err != nil {
		t.Fatalf("os.ReadFile(compacted session file) error = %v", err)
	}
	if !strings.Contains(string(compactedRaw), `"families":[]`) {
		t.Fatalf("compacted session file should have no active families: %s", string(compactedRaw))
	}
}

func TestFileAuthSessionStoreUsesWALForSubsequentUpdates(t *testing.T) {
	now := time.Date(2026, 3, 15, 18, 30, 0, 0, time.UTC)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("upstream ok"))
	}))
	defer upstream.Close()

	sessionFile := filepath.Join(t.TempDir(), "auth-sessions.json")
	app, err := NewApp(Config{
		ListenAddr:           ":0",
		TargetURL:            upstream.URL,
		AuthPassword:         "secret-pass",
		SessionSecret:        "session-secret",
		AuthSessionStore:     "file",
		AuthSessionFile:      sessionFile,
		AuthSessionRotation:  true,
		AuthRotationInterval: time.Minute,
		AuthRotationGrace:    30 * time.Second,
		CookieTTL:            24 * time.Hour,
		PoWDifficulty:        0,
		PoWChallengeTTL:      time.Minute,
		MaxLoginFailures:     5,
		LoginBanDuration:     10 * time.Minute,
		DefaultLang:          "en",
		AuthCookieName:       defaultAuthCookie,
		LangCookieName:       defaultLangCookie,
		CookieSecureMode:     "never",
		Now: func() time.Time {
			return now
		},
	})
	if err != nil {
		t.Fatalf("NewApp() error = %v", err)
	}

	server := httptest.NewServer(app)
	defer server.Close()

	client := newCookieClient(t, server)

	loginResp, err := client.PostForm(server.URL+loginPath, url.Values{
		"password": {"secret-pass"},
		"next":     {"/"},
		"lang":     {"en"},
	})
	if err != nil {
		t.Fatalf("POST login error = %v", err)
	}
	_, _ = io.ReadAll(loginResp.Body)
	loginResp.Body.Close()

	initialSnapshot, err := os.ReadFile(sessionFile)
	if err != nil {
		t.Fatalf("os.ReadFile(initial snapshot) error = %v", err)
	}
	if !strings.Contains(string(initialSnapshot), `"current_generation":1`) {
		t.Fatalf("initial snapshot missing generation 1 session: %s", string(initialSnapshot))
	}

	now = now.Add(61 * time.Second)

	rotateResp, err := client.Get(server.URL + "/")
	if err != nil {
		t.Fatalf("GET / after rotation interval error = %v", err)
	}
	_, _ = io.ReadAll(rotateResp.Body)
	rotateResp.Body.Close()
	if rotateResp.StatusCode != http.StatusOK {
		t.Fatalf("rotated GET status = %d, want %d", rotateResp.StatusCode, http.StatusOK)
	}

	postRotateSnapshot, err := os.ReadFile(sessionFile)
	if err != nil {
		t.Fatalf("os.ReadFile(post-rotate snapshot) error = %v", err)
	}
	if string(postRotateSnapshot) != string(initialSnapshot) {
		t.Fatalf("snapshot file was unexpectedly rewritten on rotation:\ninitial=%s\npost=%s", string(initialSnapshot), string(postRotateSnapshot))
	}

	walRaw, err := os.ReadFile(sessionFile + ".wal")
	if err != nil {
		t.Fatalf("os.ReadFile(session wal) error = %v", err)
	}
	if !strings.Contains(string(walRaw), `"op":"upsert"`) {
		t.Fatalf("session wal missing upsert mutation: %s", string(walRaw))
	}
	if !strings.Contains(string(walRaw), `"current_generation":2`) {
		t.Fatalf("session wal missing rotated generation: %s", string(walRaw))
	}
}

func TestPoWProgressModeRender(t *testing.T) {
	makeApp := func(mode string) *httptest.Server {
		t.Helper()

		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("upstream ok"))
		}))
		t.Cleanup(upstream.Close)

		app, err := NewApp(Config{
			ListenAddr:            ":0",
			TargetURL:             upstream.URL,
			AuthPassword:          "secret-pass",
			SessionSecret:         "session-secret",
			CookieTTL:             24 * time.Hour,
			PoWDifficulty:         4,
			PoWProgressMode:       mode,
			PoWChallengeTTL:       time.Minute,
			MaxLoginFailures:      5,
			LoginBanDuration:      10 * time.Minute,
			DefaultLang:           "en",
			AuthCookieName:        defaultAuthCookie,
			LangCookieName:        defaultLangCookie,
			CookieSecureMode:      "never",
			PoWSuspiciousUATokens: defaultSuspiciousUATokens(),
		})
		if err != nil {
			t.Fatalf("NewApp() error = %v", err)
		}

		server := httptest.NewServer(app)
		t.Cleanup(server.Close)
		return server
	}

	assertMode := func(mode string) {
		t.Helper()
		server := makeApp(mode)
		resp, err := server.Client().Get(server.URL + "/")
		if err != nil {
			t.Fatalf("GET / error = %v", err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("ReadAll() error = %v", err)
		}

		want := `const progressMode = "` + mode + `";`
		if !strings.Contains(string(body), want) {
			t.Fatalf("body missing progress mode marker %q", want)
		}
		if !strings.Contains(string(body), `const threadCount = Math.max(1, Math.min(8, Math.trunc(Math.max((navigator.hardwareConcurrency || 1) / 2, 1))));`) {
			t.Fatalf("body missing multi-worker thread count marker")
		}
		if !strings.Contains(string(body), `const workerSource = [`) {
			t.Fatalf("body missing worker PoW source marker")
		}
		if mode == "estimated" {
			if !strings.Contains(string(body), "const minProgressUpdateMs = 100;") {
				t.Fatalf("body missing minProgressUpdateMs throttle marker")
			}
			if !strings.Contains(string(body), "const minProgressAttemptDelta = 1024;") {
				t.Fatalf("body missing minProgressAttemptDelta throttle marker")
			}
		}
		if mode == "hidden" {
			if !strings.Contains(string(body), `<div class="pow-progress" data-pow-progress hidden aria-hidden="true">`) {
				t.Fatalf("hidden mode should render progress container hidden from first paint")
			}
			if !strings.Contains(string(body), `function revealSolvedProgress()`) {
				t.Fatalf("hidden mode body missing solved progress reveal helper")
			}
			if !strings.Contains(string(body), `requestAnimationFrame(() => {`) {
				t.Fatalf("hidden mode body missing smooth completion animation marker")
			}
		}
		if !strings.Contains(string(body), `document.addEventListener("DOMContentLoaded", init, { once: true });`) {
			t.Fatalf("body missing deferred PoW init marker")
		}
	}

	assertMode("estimated")
	assertMode("fake")
	assertMode("hidden")
}

func TestUnauthenticatedRedirectUsesChallengeURL(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("upstream ok"))
	}))
	defer upstream.Close()

	app, err := NewApp(Config{
		ListenAddr:       ":0",
		TargetURL:        upstream.URL,
		AuthPassword:     "secret-pass",
		SessionSecret:    "session-secret",
		CookieTTL:        24 * time.Hour,
		PoWDifficulty:    2,
		PoWChallengeTTL:  time.Minute,
		MaxLoginFailures: 5,
		LoginBanDuration: 10 * time.Minute,
		DefaultLang:      "en",
		AuthCookieName:   defaultAuthCookie,
		LangCookieName:   defaultLangCookie,
		CookieSecureMode: "never",
	})
	if err != nil {
		t.Fatalf("NewApp() error = %v", err)
	}

	proxy := httptest.NewServer(app)
	defer proxy.Close()

	client := proxy.Client()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	resp, err := client.Get(proxy.URL + "/admin?tab=metrics")
	if err != nil {
		t.Fatalf("GET /admin error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("redirect status = %d, want %d", resp.StatusCode, http.StatusSeeOther)
	}

	location := resp.Header.Get("Location")
	if location == "" {
		t.Fatalf("redirect missing Location header")
	}

	target, err := url.Parse(location)
	if err != nil {
		t.Fatalf("url.Parse(Location) error = %v", err)
	}
	if target.Path != loginPath {
		t.Fatalf("redirect path = %q, want %q", target.Path, loginPath)
	}
	if target.RawQuery != "" {
		t.Fatalf("redirect query = %q, want empty", target.RawQuery)
	}
	flowCookie := findCookie(resp.Cookies(), defaultLoginFlowCookie)
	if flowCookie == nil || flowCookie.Value == "" {
		t.Fatalf("redirect missing login flow cookie %q", defaultLoginFlowCookie)
	}
	if flowCookie.Path != loginPath {
		t.Fatalf("login flow cookie path = %q, want %q", flowCookie.Path, loginPath)
	}
}

func TestLoginPageMigratesLegacyQueryToCleanURL(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("upstream ok"))
	}))
	defer upstream.Close()

	app, err := NewApp(Config{
		ListenAddr:       ":0",
		TargetURL:        upstream.URL,
		AuthPassword:     "secret-pass",
		SessionSecret:    "session-secret",
		CookieTTL:        24 * time.Hour,
		PoWDifficulty:    2,
		PoWChallengeTTL:  time.Minute,
		MaxLoginFailures: 5,
		LoginBanDuration: 10 * time.Minute,
		DefaultLang:      "en",
		AuthCookieName:   defaultAuthCookie,
		LangCookieName:   defaultLangCookie,
		CookieSecureMode: "never",
	})
	if err != nil {
		t.Fatalf("NewApp() error = %v", err)
	}

	proxy := httptest.NewServer(app)
	defer proxy.Close()

	client := newCookieClient(t, proxy)

	resp, err := client.Get(proxy.URL + loginPath + "?next=%2Fadmin%3Ftab%3Dusers&lang=en")
	if err != nil {
		t.Fatalf("GET legacy login URL error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("legacy login final status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
	if resp.Request == nil || resp.Request.URL == nil {
		t.Fatalf("legacy login response missing final request URL")
	}
	if resp.Request.URL.Path != loginPath {
		t.Fatalf("legacy login final path = %q, want %q", resp.Request.URL.Path, loginPath)
	}
	if resp.Request.URL.RawQuery != "" {
		t.Fatalf("legacy login final query = %q, want empty", resp.Request.URL.RawQuery)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll(legacy login) error = %v", err)
	}
	if !strings.Contains(string(body), `<html lang="en">`) {
		t.Fatalf("legacy login page did not preserve language: %s", string(body))
	}
	if !strings.Contains(string(body), `name="next" value="/admin?tab=users"`) {
		t.Fatalf("legacy login page did not preserve next target: %s", string(body))
	}
	if !strings.Contains(string(body), `form method="post" action="/_auth/login"`) {
		t.Fatalf("legacy login page did not render clean form action: %s", string(body))
	}
}

func TestLoginSuccessUsesStoredNextFromFlow(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(r.URL.RequestURI()))
	}))
	defer upstream.Close()

	app, err := NewApp(Config{
		ListenAddr:       ":0",
		TargetURL:        upstream.URL,
		AuthPassword:     "secret-pass",
		SessionSecret:    "session-secret",
		CookieTTL:        24 * time.Hour,
		PoWDifficulty:    0,
		PoWChallengeTTL:  time.Minute,
		MaxLoginFailures: 5,
		LoginBanDuration: 10 * time.Minute,
		DefaultLang:      "en",
		AuthCookieName:   defaultAuthCookie,
		LangCookieName:   defaultLangCookie,
		CookieSecureMode: "never",
	})
	if err != nil {
		t.Fatalf("NewApp() error = %v", err)
	}

	proxy := httptest.NewServer(app)
	defer proxy.Close()

	client := newCookieClient(t, proxy)

	getResp, err := client.Get(proxy.URL + "/admin?tab=metrics")
	if err != nil {
		t.Fatalf("GET protected path error = %v", err)
	}
	getBody, err := io.ReadAll(getResp.Body)
	getResp.Body.Close()
	if err != nil {
		t.Fatalf("ReadAll(protected login page) error = %v", err)
	}
	if getResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("protected login page status = %d, want %d", getResp.StatusCode, http.StatusUnauthorized)
	}
	if !strings.Contains(string(getBody), `name="next" value="/admin?tab=metrics"`) {
		t.Fatalf("protected login page did not preserve next target: %s", string(getBody))
	}

	loginResp, err := client.PostForm(proxy.URL+loginPath, url.Values{
		"password": {"secret-pass"},
		"next":     {"/"},
		"lang":     {"en"},
	})
	if err != nil {
		t.Fatalf("POST login error = %v", err)
	}
	defer loginResp.Body.Close()

	loginBody, err := io.ReadAll(loginResp.Body)
	if err != nil {
		t.Fatalf("ReadAll(login) error = %v", err)
	}
	if loginResp.StatusCode != http.StatusOK {
		t.Fatalf("login final status = %d, want %d", loginResp.StatusCode, http.StatusOK)
	}
	if strings.TrimSpace(string(loginBody)) != "/admin?tab=metrics" {
		t.Fatalf("login redirected to %q, want %q", strings.TrimSpace(string(loginBody)), "/admin?tab=metrics")
	}
}

func TestLanguageSwitchKeepsCleanURLAndNext(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("upstream ok"))
	}))
	defer upstream.Close()

	app, err := NewApp(Config{
		ListenAddr:       ":0",
		TargetURL:        upstream.URL,
		AuthPassword:     "secret-pass",
		SessionSecret:    "session-secret",
		CookieTTL:        24 * time.Hour,
		PoWDifficulty:    0,
		PoWChallengeTTL:  time.Minute,
		MaxLoginFailures: 5,
		LoginBanDuration: 10 * time.Minute,
		DefaultLang:      "zh",
		AuthCookieName:   defaultAuthCookie,
		LangCookieName:   defaultLangCookie,
		CookieSecureMode: "never",
	})
	if err != nil {
		t.Fatalf("NewApp() error = %v", err)
	}

	proxy := httptest.NewServer(app)
	defer proxy.Close()

	client := newCookieClient(t, proxy)

	firstResp, err := client.Get(proxy.URL + "/admin?tab=metrics")
	if err != nil {
		t.Fatalf("GET protected path error = %v", err)
	}
	_, _ = io.ReadAll(firstResp.Body)
	firstResp.Body.Close()

	switchResp, err := client.PostForm(proxy.URL+loginPath, url.Values{
		"intent": {"switch_lang"},
		"lang":   {"en"},
		"next":   {"/admin?tab=metrics"},
	})
	if err != nil {
		t.Fatalf("POST switch_lang error = %v", err)
	}
	defer switchResp.Body.Close()

	if switchResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("switch_lang final status = %d, want %d", switchResp.StatusCode, http.StatusUnauthorized)
	}
	if switchResp.Request == nil || switchResp.Request.URL == nil {
		t.Fatalf("switch_lang response missing final request URL")
	}
	if switchResp.Request.URL.Path != loginPath {
		t.Fatalf("switch_lang final path = %q, want %q", switchResp.Request.URL.Path, loginPath)
	}
	if switchResp.Request.URL.RawQuery != "" {
		t.Fatalf("switch_lang final query = %q, want empty", switchResp.Request.URL.RawQuery)
	}

	body, err := io.ReadAll(switchResp.Body)
	if err != nil {
		t.Fatalf("ReadAll(switch_lang) error = %v", err)
	}
	if !strings.Contains(string(body), `<html lang="en">`) {
		t.Fatalf("switch_lang page did not switch language: %s", string(body))
	}
	if !strings.Contains(string(body), `name="next" value="/admin?tab=metrics"`) {
		t.Fatalf("switch_lang page did not preserve next target: %s", string(body))
	}

	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatalf("url.Parse(proxy.URL) error = %v", err)
	}
	langCookie := findCookie(client.Jar.Cookies(proxyURL), defaultLangCookie)
	if langCookie == nil || langCookie.Value != "en" {
		t.Fatalf("language cookie = %v, want en", langCookie)
	}
}

func TestDirectLoginPostStillWorksWithoutFlowCookie(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(r.URL.RequestURI()))
	}))
	defer upstream.Close()

	app, err := NewApp(Config{
		ListenAddr:       ":0",
		TargetURL:        upstream.URL,
		AuthPassword:     "secret-pass",
		SessionSecret:    "session-secret",
		CookieTTL:        24 * time.Hour,
		PoWDifficulty:    0,
		PoWChallengeTTL:  time.Minute,
		MaxLoginFailures: 5,
		LoginBanDuration: 10 * time.Minute,
		DefaultLang:      "en",
		AuthCookieName:   defaultAuthCookie,
		LangCookieName:   defaultLangCookie,
		CookieSecureMode: "never",
	})
	if err != nil {
		t.Fatalf("NewApp() error = %v", err)
	}

	proxy := httptest.NewServer(app)
	defer proxy.Close()

	client := newCookieClient(t, proxy)

	resp, err := client.PostForm(proxy.URL+loginPath, url.Values{
		"password": {"secret-pass"},
		"next":     {"/admin?tab=metrics"},
		"lang":     {"en"},
	})
	if err != nil {
		t.Fatalf("direct POST login error = %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll(direct login) error = %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("direct login final status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if strings.TrimSpace(string(body)) != "/admin?tab=metrics" {
		t.Fatalf("direct login redirected to %q, want %q", strings.TrimSpace(string(body)), "/admin?tab=metrics")
	}
}

func TestPasswordAttemptLimitGuard(t *testing.T) {
	now := time.Date(2026, 3, 15, 16, 0, 0, 0, time.UTC)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("upstream ok"))
	}))
	defer upstream.Close()

	app, err := NewApp(Config{
		ListenAddr:       ":0",
		TargetURL:        upstream.URL,
		AuthPassword:     "secret-pass",
		SessionSecret:    "session-secret",
		CookieTTL:        24 * time.Hour,
		PoWDifficulty:    0,
		PoWChallengeTTL:  time.Minute,
		MaxLoginFailures: 2,
		LoginBanDuration: 10 * time.Minute,
		DefaultLang:      "en",
		AuthCookieName:   defaultAuthCookie,
		LangCookieName:   defaultLangCookie,
		CookieSecureMode: "never",
		Now: func() time.Time {
			return now
		},
	})
	if err != nil {
		t.Fatalf("NewApp() error = %v", err)
	}

	proxy := httptest.NewServer(app)
	defer proxy.Close()

	client := proxy.Client()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New() error = %v", err)
	}
	client.Jar = jar

	postPassword := func(password string) (int, string) {
		resp, err := client.PostForm(proxy.URL+loginPath, url.Values{
			"password": {password},
			"next":     {"/"},
			"lang":     {"en"},
		})
		if err != nil {
			t.Fatalf("POST login error = %v", err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("ReadAll(login) error = %v", err)
		}
		return resp.StatusCode, string(body)
	}

	status, body := postPassword("wrong-1")
	if status != http.StatusUnauthorized {
		t.Fatalf("first wrong password status = %d, want %d", status, http.StatusUnauthorized)
	}
	if !strings.Contains(body, "Incorrect password") {
		t.Fatalf("first wrong password body missing error: %s", body)
	}

	status, body = postPassword("wrong-2")
	if status != http.StatusTooManyRequests {
		t.Fatalf("second wrong password status = %d, want %d", status, http.StatusTooManyRequests)
	}
	if !strings.Contains(body, "Too many failed password attempts") {
		t.Fatalf("second wrong password body missing lockout: %s", body)
	}

	status, body = postPassword("secret-pass")
	if status != http.StatusTooManyRequests {
		t.Fatalf("locked login status = %d, want %d", status, http.StatusTooManyRequests)
	}
	if !strings.Contains(body, "Too many failed password attempts") {
		t.Fatalf("locked login body missing lockout: %s", body)
	}

	now = now.Add(11 * time.Minute)

	status, body = postPassword("secret-pass")
	if status != http.StatusOK {
		t.Fatalf("post-ban login status = %d, want %d", status, http.StatusOK)
	}
	if strings.TrimSpace(body) != "upstream ok" {
		t.Fatalf("post-ban login body = %q, want %q", strings.TrimSpace(body), "upstream ok")
	}
}

func TestPoWChallengeIsSingleUse(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("upstream ok"))
	}))
	defer upstream.Close()

	app, err := NewApp(Config{
		ListenAddr:       ":0",
		TargetURL:        upstream.URL,
		AuthPassword:     "secret-pass",
		SessionSecret:    "session-secret",
		CookieTTL:        24 * time.Hour,
		PoWDifficulty:    2,
		PoWChallengeTTL:  time.Minute,
		MaxLoginFailures: 5,
		LoginBanDuration: 10 * time.Minute,
		DefaultLang:      "en",
		AuthCookieName:   defaultAuthCookie,
		LangCookieName:   defaultLangCookie,
		CookieSecureMode: "never",
	})
	if err != nil {
		t.Fatalf("NewApp() error = %v", err)
	}

	proxy := httptest.NewServer(app)
	defer proxy.Close()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New() error = %v", err)
	}

	client := proxy.Client()
	client.Jar = jar

	resp, err := client.Get(proxy.URL + "/")
	if err != nil {
		t.Fatalf("GET / error = %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}

	powID, powToken, powDifficulty := extractPoWFields(t, string(body))
	powNonce := solvePoWNonce(powToken, powDifficulty)

	wrongResp, err := client.PostForm(proxy.URL+loginPath, url.Values{
		"password":       {"wrong-pass"},
		"next":           {"/"},
		"lang":           {"en"},
		"pow_id":         {powID},
		"pow_token":      {powToken},
		"pow_nonce":      {powNonce},
		"pow_difficulty": {strconv.Itoa(powDifficulty)},
	})
	if err != nil {
		t.Fatalf("first POST login error = %v", err)
	}
	wrongBody, err := io.ReadAll(wrongResp.Body)
	wrongResp.Body.Close()
	if err != nil {
		t.Fatalf("ReadAll(wrong login) error = %v", err)
	}
	if wrongResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong password status = %d, want %d", wrongResp.StatusCode, http.StatusUnauthorized)
	}
	if !strings.Contains(string(wrongBody), "Incorrect password") {
		t.Fatalf("wrong password body missing error: %s", wrongBody)
	}

	replayResp, err := client.PostForm(proxy.URL+loginPath, url.Values{
		"password":       {"secret-pass"},
		"next":           {"/"},
		"lang":           {"en"},
		"pow_id":         {powID},
		"pow_token":      {powToken},
		"pow_nonce":      {powNonce},
		"pow_difficulty": {strconv.Itoa(powDifficulty)},
	})
	if err != nil {
		t.Fatalf("replay POST login error = %v", err)
	}
	replayBody, err := io.ReadAll(replayResp.Body)
	replayResp.Body.Close()
	if err != nil {
		t.Fatalf("ReadAll(replay login) error = %v", err)
	}
	if replayResp.StatusCode != http.StatusForbidden {
		t.Fatalf("replayed challenge status = %d, want %d", replayResp.StatusCode, http.StatusForbidden)
	}
	if !strings.Contains(string(replayBody), "The security check expired. Please refresh the page and try again.") {
		t.Fatalf("replayed challenge body missing expiration: %s", replayBody)
	}
}

func TestPoWChallengeRequiresBrowserSession(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("upstream ok"))
	}))
	defer upstream.Close()

	app, err := NewApp(Config{
		ListenAddr:       ":0",
		TargetURL:        upstream.URL,
		AuthPassword:     "secret-pass",
		SessionSecret:    "session-secret",
		CookieTTL:        24 * time.Hour,
		PoWDifficulty:    2,
		PoWChallengeTTL:  time.Minute,
		MaxLoginFailures: 5,
		LoginBanDuration: 10 * time.Minute,
		DefaultLang:      "en",
		AuthCookieName:   defaultAuthCookie,
		LangCookieName:   defaultLangCookie,
		CookieSecureMode: "never",
	})
	if err != nil {
		t.Fatalf("NewApp() error = %v", err)
	}

	proxy := httptest.NewServer(app)
	defer proxy.Close()

	jarA, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New(jarA) error = %v", err)
	}
	clientA := proxy.Client()
	clientA.Jar = jarA

	getResp, err := clientA.Get(proxy.URL + "/")
	if err != nil {
		t.Fatalf("clientA GET / error = %v", err)
	}
	getBody, err := io.ReadAll(getResp.Body)
	getResp.Body.Close()
	if err != nil {
		t.Fatalf("ReadAll(clientA GET) error = %v", err)
	}

	powID, powToken, powDifficulty := extractPoWFields(t, string(getBody))
	powNonce := solvePoWNonce(powToken, powDifficulty)

	clientB := &http.Client{Transport: proxy.Client().Transport}
	forgedResp, err := clientB.PostForm(proxy.URL+loginPath, url.Values{
		"password":       {"secret-pass"},
		"next":           {"/"},
		"lang":           {"en"},
		"pow_id":         {powID},
		"pow_token":      {powToken},
		"pow_nonce":      {powNonce},
		"pow_difficulty": {strconv.Itoa(powDifficulty)},
	})
	if err != nil {
		t.Fatalf("clientB POST login error = %v", err)
	}
	forgedBody, err := io.ReadAll(forgedResp.Body)
	forgedResp.Body.Close()
	if err != nil {
		t.Fatalf("ReadAll(clientB POST) error = %v", err)
	}
	if forgedResp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-client replay status = %d, want %d", forgedResp.StatusCode, http.StatusForbidden)
	}
	if !strings.Contains(string(forgedBody), "The security check did not finish. Please refresh the page and try again.") {
		t.Fatalf("cross-client replay body missing guard error: %s", forgedBody)
	}

	okResp, err := clientA.PostForm(proxy.URL+loginPath, url.Values{
		"password":       {"secret-pass"},
		"next":           {"/"},
		"lang":           {"en"},
		"pow_id":         {powID},
		"pow_token":      {powToken},
		"pow_nonce":      {powNonce},
		"pow_difficulty": {strconv.Itoa(powDifficulty)},
	})
	if err != nil {
		t.Fatalf("clientA POST login error = %v", err)
	}
	okBody, err := io.ReadAll(okResp.Body)
	okResp.Body.Close()
	if err != nil {
		t.Fatalf("ReadAll(clientA POST) error = %v", err)
	}
	if okResp.StatusCode != http.StatusOK {
		t.Fatalf("clientA login status = %d, want %d", okResp.StatusCode, http.StatusOK)
	}
	if strings.TrimSpace(string(okBody)) != "upstream ok" {
		t.Fatalf("clientA login body = %q, want %q", strings.TrimSpace(string(okBody)), "upstream ok")
	}
}

func TestParseDurationWithDays(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    time.Duration
		wantErr bool
	}{
		{name: "days", input: "30d", want: 30 * 24 * time.Hour},
		{name: "hours", input: "720h", want: 720 * time.Hour},
		{name: "invalid", input: "0d", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseDurationWithDays(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseDurationWithDays(%q) error = nil, want non-nil", tt.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseDurationWithDays(%q) error = %v", tt.input, err)
			}
			if got != tt.want {
				t.Fatalf("parseDurationWithDays(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestNormalizePoWProgressMode(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{input: "", want: defaultPoWProgressMode},
		{input: "estimated", want: "estimated"},
		{input: "fake", want: "fake"},
		{input: "hidden", want: "hidden"},
		{input: "bad-mode", want: ""},
	}

	for _, tt := range tests {
		if got := normalizePoWProgressMode(tt.input); got != tt.want {
			t.Fatalf("normalizePoWProgressMode(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestParseUserAgentTokens(t *testing.T) {
	got := parseUserAgentTokens(" Curl , custom-bot, curl ,  ")
	want := []string{"curl", "custom-bot"}

	if len(got) != len(want) {
		t.Fatalf("len(parseUserAgentTokens()) = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("parseUserAgentTokens()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func extractPoWFields(t *testing.T, body string) (string, string, int) {
	t.Helper()

	idMatch := regexp.MustCompile(`name="pow_id" value="([^"]+)"`).FindStringSubmatch(body)
	if len(idMatch) != 2 {
		t.Fatalf("pow id not found in body: %s", body)
	}

	tokenMatch := regexp.MustCompile(`name="pow_token" value="([^"]+)"`).FindStringSubmatch(body)
	if len(tokenMatch) != 2 {
		t.Fatalf("pow token not found in body: %s", body)
	}

	difficultyMatch := regexp.MustCompile(`name="pow_difficulty" value="([^"]+)"`).FindStringSubmatch(body)
	if len(difficultyMatch) != 2 {
		t.Fatalf("pow difficulty not found in body: %s", body)
	}

	difficulty, err := strconv.Atoi(difficultyMatch[1])
	if err != nil {
		t.Fatalf("strconv.Atoi(%q) error = %v", difficultyMatch[1], err)
	}

	return idMatch[1], tokenMatch[1], difficulty
}

func solvePoWNonce(token string, difficulty int) string {
	for nonce := 0; ; nonce++ {
		candidate := strconv.Itoa(nonce)
		if powNonceMatches(token, candidate, difficulty) {
			return candidate
		}
	}
}

func newCookieClient(t *testing.T, server *httptest.Server) *http.Client {
	t.Helper()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New() error = %v", err)
	}

	client := server.Client()
	client.Jar = jar
	return client
}

func findCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}
