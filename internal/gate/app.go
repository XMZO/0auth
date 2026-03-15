package gate

import (
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	gatei18n "auth-proxy/internal/gate/i18n"
	gateui "auth-proxy/internal/gate/ui"
)

func NewApp(cfg Config) (*App, error) {
	if cfg.CookieTTL <= 0 {
		cfg.CookieTTL = defaultCookieTTL
	}
	if cfg.AuthSessionRotation {
		if cfg.AuthRotationInterval <= 0 {
			cfg.AuthRotationInterval = defaultAuthRotationInterval
		}
		if cfg.AuthRotationGrace <= 0 {
			cfg.AuthRotationGrace = defaultAuthRotationGrace
		}
	}
	if cfg.PoWChallengeTTL <= 0 {
		cfg.PoWChallengeTTL = defaultPoWTTL
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	cfg.PoWProgressMode = normalizePoWProgressMode(cfg.PoWProgressMode)
	if cfg.PoWDifficulty < 0 || cfg.PoWDifficulty > 64 {
		return nil, fmt.Errorf("POW_DIFFICULTY must be between 0 and 64")
	}
	if cfg.PoWMinDifficulty < 0 || cfg.PoWMinDifficulty > 64 {
		return nil, fmt.Errorf("POW_MIN_DIFFICULTY must be between 0 and 64")
	}
	if cfg.PoWMaxDifficulty < 0 || cfg.PoWMaxDifficulty > 64 {
		return nil, fmt.Errorf("POW_MAX_DIFFICULTY must be between 0 and 64")
	}
	if cfg.PoWAutoDifficulty && cfg.PoWMinDifficulty > cfg.PoWMaxDifficulty {
		return nil, fmt.Errorf("POW_MIN_DIFFICULTY must be less than or equal to POW_MAX_DIFFICULTY")
	}
	if cfg.PoWProgressMode == "" {
		return nil, fmt.Errorf("POW_PROGRESS_MODE must be one of estimated, fake, or hidden")
	}

	target, err := url.Parse(cfg.TargetURL)
	if err != nil {
		return nil, fmt.Errorf("parse TARGET_URL: %w", err)
	}
	if target.Scheme == "" || target.Host == "" {
		return nil, fmt.Errorf("TARGET_URL must include scheme and host")
	}

	signer := &SessionSigner{secret: []byte(cfg.SessionSecret), now: cfg.Now}
	translator := gatei18n.New()
	authStore, err := newAuthSessionStore(cfg.AuthSessionStore, cfg.AuthSessionFile, cfg.Now)
	if err != nil {
		return nil, fmt.Errorf("build auth session store: %w", err)
	}
	auth := &SinglePasswordAuth{
		expectedPassword: cfg.AuthPassword,
		cookieName:       cfg.AuthCookieName,
		bindCookieName:   cfg.AuthCookieName + "_bind",
		ttl:              cfg.CookieTTL,
		rotationEnabled:  cfg.AuthSessionRotation,
		rotationInterval: cfg.AuthRotationInterval,
		rotationGrace:    cfg.AuthRotationGrace,
		signer:           signer,
		store:            authStore,
		secureDecider: func(r *http.Request) bool {
			return shouldUseSecureCookie(cfg, r)
		},
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	app := &App{
		cfg:           cfg,
		proxy:         proxy,
		auth:          auth,
		translator:    translator,
		langDetectors: buildLanguageDetectors(cfg),
		loginGuards:   buildLoginGuards(cfg, signer, translator),
	}

	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		if errors.Is(err, http.ErrAbortHandler) {
			return
		}
		log.Printf("proxy error: %v", err)
		http.Error(w, app.translator.Text(app.detectLanguage(r), "proxy_error"), http.StatusBadGateway)
	}

	log.Printf("enabled language modules: %s", strings.Join(languageDetectorIDs(app.langDetectors), ", "))
	log.Printf("enabled login modules: %s", strings.Join(loginGuardIDs(app.loginGuards), ", "))
	log.Printf("auth session store: %s", describeAuthSessionStore(cfg))
	if cfg.AuthSessionRotation {
		log.Printf("auth session rotation: enabled interval=%s grace=%s", cfg.AuthRotationInterval, cfg.AuthRotationGrace)
	} else {
		log.Printf("auth session rotation: disabled")
	}
	if len(cfg.DisabledModules) > 0 {
		log.Printf("disabled modules: %s", strings.Join(sortedDisabledModules(cfg.DisabledModules), ", "))
	}

	return app, nil
}

func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.persistLanguageCookie(w, r, normalizeLang(r.URL.Query().Get("lang")))

	switch r.URL.Path {
	case healthPath:
		a.handleHealth(w)
		return
	case loginPath:
		a.handleLogin(w, r)
		return
	case logoutPath:
		a.handleLogout(w, r)
		return
	}

	if !a.auth.Authenticate(w, r) {
		a.redirectToLogin(w, r, requestedPath(r), a.detectLanguage(r), http.StatusSeeOther)
		return
	}

	a.proxy.ServeHTTP(w, r)
}

func (a *App) handleHealth(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ok"))
}

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	lang := a.detectLanguage(r)

	if a.auth.Authenticate(w, r) && r.Method == http.MethodGet {
		http.Redirect(w, r, sanitizeNext(r.URL.Query().Get("next")), http.StatusSeeOther)
		return
	}

	switch r.Method {
	case http.MethodGet:
		if !hasValidChallengeFlow(r) {
			a.redirectToLogin(w, r, sanitizeNext(r.URL.Query().Get("next")), lang, http.StatusSeeOther)
			return
		}
		a.renderLoginPage(w, r, lang, http.StatusUnauthorized, "", "")
		return
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			a.renderLoginPage(w, r, lang, http.StatusBadRequest, a.translator.Text(lang, "bad_request"), "")
			return
		}

		a.persistLanguageCookie(w, r, normalizeLang(r.FormValue("lang")))
		lang = a.detectLanguage(r)

		for _, guard := range a.loginGuards {
			if err := guard.Validate(r, lang); err != nil {
				log.Printf("login blocked by guard %s: %v", guard.ID(), err)
				status, message := a.userFacingError(lang, err)
				a.renderLoginPage(w, r, lang, status, message, "")
				return
			}
		}

		if err := a.auth.Login(w, r); err != nil {
			switch {
			case errors.Is(err, errInvalidCredentials):
				status, message := http.StatusUnauthorized, a.translator.Text(lang, "invalid_password")
				if hookErr := a.notifyLoginFailure(r, lang); hookErr != nil {
					status, message = a.userFacingError(lang, hookErr)
				}
				a.renderLoginPage(w, r, lang, status, message, "")
			case errors.Is(err, errLoginBlocked):
				a.renderLoginPage(w, r, lang, http.StatusForbidden, a.translator.Text(lang, "login_blocked"), "")
			default:
				log.Printf("login error: %v", err)
				a.renderLoginPage(w, r, lang, http.StatusInternalServerError, a.translator.Text(lang, "server_error"), "")
			}
			return
		}

		a.notifyLoginSuccess(r)
		http.Redirect(w, r, sanitizeNext(r.FormValue("next")), http.StatusSeeOther)
		return
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	lang := a.detectLanguage(r)
	a.auth.Logout(w, r)
	a.renderLoginPage(w, r, lang, http.StatusUnauthorized, "", a.translator.Text(lang, "logged_out"))
}

func (a *App) renderLoginPage(w http.ResponseWriter, r *http.Request, lang string, status int, errMessage string, message string) {
	scriptNonce, err := issueNonce(16)
	if err != nil {
		log.Printf("generate CSP nonce: %v", err)
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "private, no-store, no-cache, max-age=0, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	w.Header().Set("Surrogate-Control", "no-store")
	w.Header().Set("Vary", "Accept-Language, Cookie")
	w.Header().Set("Content-Security-Policy", gateui.LoginPageCSP(scriptNonce))
	next := requestedPath(r)
	if r.Method == http.MethodPost {
		if value := sanitizeNext(r.FormValue("next")); value != "/" {
			next = value
		}
	}
	if r.URL.Path == loginPath {
		if value := sanitizeNext(r.URL.Query().Get("next")); value != "/" {
			next = value
		}
	}

	challengeHTML := make([]template.HTML, 0, len(a.loginGuards))
	for _, guard := range a.loginGuards {
		challengeHTML = append(challengeHTML, guard.Render(w, r, lang, scriptNonce))
	}

	data := LoginPageData{
		Lang:          lang,
		Title:         a.translator.Text(lang, "login_title"),
		Tagline:       a.translator.Text(lang, "login_tagline"),
		PasswordLabel: a.translator.Text(lang, "password_label"),
		PasswordHint:  a.translator.Text(lang, "password_hint"),
		SubmitLabel:   a.translator.Text(lang, "submit_label"),
		Error:         errMessage,
		Message:       message,
		Next:          next,
		FormAction:    authFlowURL(next, lang),
		ZHToggleURL:   authFlowURL(next, "zh"),
		ENToggleURL:   authFlowURL(next, "en"),
		ZHToggleLabel: a.translator.Text(lang, "toggle_zh"),
		ENToggleLabel: a.translator.Text(lang, "toggle_en"),
		LanguageLabel: a.translator.Text(lang, "language_label"),
		ChallengeHTML: challengeHTML,
	}

	w.WriteHeader(status)
	if err := gateui.LoginTemplate.Execute(w, data); err != nil {
		log.Printf("render login page: %v", err)
	}
}

func (a *App) notifyLoginFailure(r *http.Request, lang string) error {
	for _, guard := range a.loginGuards {
		if err := guard.OnLoginFailure(r, lang); err != nil {
			log.Printf("login failure hook from %s: %v", guard.ID(), err)
			return err
		}
	}
	return nil
}

func (a *App) notifyLoginSuccess(r *http.Request) {
	for _, guard := range a.loginGuards {
		guard.OnLoginSuccess(r)
	}
}

func (a *App) userFacingError(lang string, err error) (int, string) {
	type visible interface {
		error
		HTTPStatus() int
		UserMessage(lang string, translator *gatei18n.Translator) string
	}

	var visibleErr visible
	if errors.As(err, &visibleErr) {
		return visibleErr.HTTPStatus(), visibleErr.UserMessage(lang, a.translator)
	}
	return http.StatusForbidden, a.translator.Text(lang, "login_blocked")
}

func (a *App) redirectToLogin(w http.ResponseWriter, r *http.Request, next string, lang string, status int) {
	http.Redirect(w, r, authFlowURL(next, lang), status)
}

func (a *App) detectLanguage(r *http.Request) string {
	for _, detector := range a.langDetectors {
		if lang, ok := detector.Detect(r); ok {
			return lang
		}
	}
	return a.cfg.DefaultLang
}

func (a *App) persistLanguageCookie(w http.ResponseWriter, r *http.Request, candidate string) {
	if candidate == "" {
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     a.cfg.LangCookieName,
		Value:    candidate,
		Path:     "/",
		HttpOnly: false,
		Secure:   shouldUseSecureCookie(a.cfg, r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(a.cfg.CookieTTL.Seconds()),
		Expires:  time.Now().Add(a.cfg.CookieTTL),
	})
}
