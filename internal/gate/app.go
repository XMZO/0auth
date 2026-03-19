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
	if cfg.TurnstileVerifyTimeout <= 0 {
		cfg.TurnstileVerifyTimeout = defaultTurnstileTimeout
	}
	if cfg.TurnstileSessionTTL <= 0 {
		cfg.TurnstileSessionTTL = defaultTurnstileVerifyTTL
	}
	if cfg.ProtectedCacheTTL <= 0 {
		cfg.ProtectedCacheTTL = defaultProtectedCacheTTL
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	cfg.LoginChallengeMode = normalizeLoginChallengeMode(cfg.LoginChallengeMode)
	cfg.ProtectedCacheMode = normalizeProtectedCacheMode(cfg.ProtectedCacheMode)
	cfg.PoWProgressMode = normalizePoWProgressMode(cfg.PoWProgressMode)
	cfg.TurnstileTheme = normalizeTurnstileTheme(cfg.TurnstileTheme)
	cfg.TurnstileAppearance = normalizeTurnstileAppearance(cfg.TurnstileAppearance)
	cfg.TurnstileAction = strings.TrimSpace(cfg.TurnstileAction)
	if cfg.LoginChallengeMode == "" {
		return nil, fmt.Errorf("LOGIN_CHALLENGE_MODE must be one of none, pow, turnstile, or pow+turnstile")
	}
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
	if cfg.ProtectedCacheMode == "" {
		return nil, fmt.Errorf("PROTECTED_EDGE_CACHE_MODE must be off or signed-url")
	}
	cfg.ProtectedCacheParam = normalizeQueryParamName(cfg.ProtectedCacheParam, defaultProtectedCacheParam)
	if cfg.ProtectedCacheParam == "" {
		return nil, fmt.Errorf("PROTECTED_EDGE_CACHE_PARAM must use only letters, numbers, hyphens, or underscores")
	}
	if cfg.TurnstileTheme == "" {
		return nil, fmt.Errorf("TURNSTILE_THEME must be one of auto, light, or dark")
	}
	if cfg.TurnstileAppearance == "" {
		return nil, fmt.Errorf("TURNSTILE_APPEARANCE must be one of always, interaction-only, or execute")
	}
	if cfg.TurnstileAction == "" {
		cfg.TurnstileAction = defaultTurnstileAction
	}
	if !isTurnstileTokenLabel(cfg.TurnstileAction, 32) {
		return nil, fmt.Errorf("TURNSTILE_ACTION must be 1-32 characters using only letters, numbers, hyphens, or underscores")
	}
	if challengeModeIncludesTurnstile(cfg.LoginChallengeMode) {
		if strings.TrimSpace(cfg.TurnstileSiteKey) == "" {
			return nil, fmt.Errorf("TURNSTILE_SITE_KEY is required when LOGIN_CHALLENGE_MODE enables turnstile")
		}
		if strings.TrimSpace(cfg.TurnstileSecretKey) == "" {
			return nil, fmt.Errorf("TURNSTILE_SECRET_KEY is required when LOGIN_CHALLENGE_MODE enables turnstile")
		}
		if _, err := url.Parse(cfg.TurnstileVerifyURL); err != nil {
			return nil, fmt.Errorf("parse TURNSTILE_VERIFY_URL: %w", err)
		}
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
		cfg:            cfg,
		proxy:          proxy,
		auth:           auth,
		loginFlow:      newLoginFlowManager(cfg, signer),
		protectedCache: newProtectedAssetCache(cfg, signer),
		translator:     translator,
		langDetectors:  buildLanguageDetectors(cfg),
		loginGuards:    buildLoginGuards(cfg, signer, translator),
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
	if app.protectedCache != nil {
		log.Printf("protected edge cache: %s ttl=%s param=%s", app.protectedCache.mode, app.protectedCache.ttl, app.protectedCache.paramName)
	} else {
		log.Printf("protected edge cache: off")
	}
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

	if a.protectedCache != nil {
		if proxied := a.protectedCache.ProxiedRequest(r); proxied != nil {
			a.proxy.ServeHTTP(w, proxied)
			return
		}
	}

	if !a.auth.Authenticate(w, r) {
		a.redirectToLogin(w, r, a.requestedPath(r), a.detectLanguage(r), http.StatusSeeOther)
		return
	}

	if a.protectedCache != nil {
		if location, ok := a.protectedCache.RedirectLocation(r); ok {
			redirectNoStore(w, r, location, http.StatusTemporaryRedirect)
			return
		}
	}

	a.proxy.ServeHTTP(w, r)
}

func (a *App) handleHealth(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ok"))
}

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	detectedLang := a.detectLanguage(r)

	switch r.Method {
	case http.MethodGet:
		flowState, hasFlow := a.loginFlow.Resolve(r, detectedLang)
		if queryState, hasQuery := loginFlowStateFromQuery(r, flowState, detectedLang); hasQuery {
			if a.auth.Authenticate(w, r) {
				a.loginFlow.Clear(w, r)
				redirectNoStore(w, r, queryState.Next, http.StatusSeeOther)
				return
			}
			if lang := normalizeLang(r.URL.Query().Get("lang")); lang != "" {
				a.persistLanguageCookie(w, r, lang)
			}
			if _, err := a.loginFlow.Issue(w, r, queryState, queryState.Lang); err != nil {
				log.Printf("issue login flow from query: %v", err)
				a.renderLoginPage(w, r, queryState, http.StatusUnauthorized, "", "")
				return
			}
			redirectNoStore(w, r, loginPath, http.StatusSeeOther)
			return
		}

		if a.auth.Authenticate(w, r) {
			a.loginFlow.Clear(w, r)
			if hasFlow {
				redirectNoStore(w, r, flowState.Next, http.StatusSeeOther)
				return
			}
			redirectNoStore(w, r, "/", http.StatusSeeOther)
			return
		}

		if hasFlow {
			a.renderLoginPageWithState(w, r, flowState, http.StatusUnauthorized, "", "")
			return
		}

		a.renderLoginPageWithState(w, r, loginFlowState{
			Next: "/",
			Lang: detectedLang,
		}, http.StatusUnauthorized, "", "")
		return
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			a.renderLoginPageWithState(w, r, loginFlowState{
				Next: "/",
				Lang: detectedLang,
			}, http.StatusBadRequest, a.translator.Text(detectedLang, "bad_request"), "")
			return
		}

		state, hasFlow := a.loginFlow.Resolve(r, detectedLang)
		if !hasFlow {
			state = loginFlowFallbackStateFromForm(r, detectedLang)
		}
		if _, ok := r.Form["next"]; ok {
			state.Next = sanitizeNext(r.FormValue("next"))
		}
		if lang := normalizeLang(r.FormValue("lang")); lang != "" {
			state.Lang = lang
		}
		state = normalizeLoginFlowState(state, detectedLang)
		a.persistLanguageCookie(w, r, state.Lang)

		if strings.EqualFold(strings.TrimSpace(r.FormValue("intent")), "switch_lang") {
			if _, err := a.loginFlow.Issue(w, r, state, state.Lang); err != nil {
				log.Printf("issue login flow for language switch: %v", err)
				a.renderLoginPage(w, r, state, http.StatusUnauthorized, "", "")
				return
			}
			redirectNoStore(w, r, loginPath, http.StatusSeeOther)
			return
		}

		for _, guard := range a.loginGuards {
			if err := guard.Validate(r, state.Lang); err != nil {
				log.Printf("login blocked by guard %s: %v", guard.ID(), err)
				status, message := a.userFacingError(state.Lang, err)
				a.renderLoginPageWithState(w, r, state, status, message, "")
				return
			}
		}

		if err := a.auth.Login(w, r); err != nil {
			switch {
			case errors.Is(err, errInvalidCredentials):
				status, message := http.StatusUnauthorized, a.translator.Text(state.Lang, "invalid_password")
				if hookErr := a.notifyLoginFailure(r, state.Lang); hookErr != nil {
					status, message = a.userFacingError(state.Lang, hookErr)
				}
				a.renderLoginPageWithState(w, r, state, status, message, "")
			case errors.Is(err, errLoginBlocked):
				a.renderLoginPageWithState(w, r, state, http.StatusForbidden, a.translator.Text(state.Lang, "login_blocked"), "")
			default:
				log.Printf("login error: %v", err)
				a.renderLoginPageWithState(w, r, state, http.StatusInternalServerError, a.translator.Text(state.Lang, "server_error"), "")
			}
			return
		}

		a.notifyLoginSuccess(r)
		a.loginFlow.Clear(w, r)
		redirectNoStore(w, r, state.Next, http.StatusSeeOther)
		return
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	lang := a.detectLanguage(r)
	a.auth.Logout(w, r)
	a.loginFlow.Clear(w, r)
	a.renderLoginPageWithState(w, r, loginFlowState{
		Next: "/",
		Lang: lang,
	}, http.StatusUnauthorized, "", a.translator.Text(lang, "logged_out"))
}

func (a *App) renderLoginPageWithState(w http.ResponseWriter, r *http.Request, state loginFlowState, status int, errMessage string, message string) {
	fallbackLang := state.Lang
	if fallbackLang == "" {
		fallbackLang = a.detectLanguage(r)
	}
	state = normalizeLoginFlowState(state, fallbackLang)
	if issuedState, err := a.loginFlow.Issue(w, r, state, fallbackLang); err != nil {
		log.Printf("issue login flow before render: %v", err)
	} else {
		state = issuedState
	}
	a.renderLoginPage(w, r, state, status, errMessage, message)
}

func (a *App) renderLoginPage(w http.ResponseWriter, r *http.Request, state loginFlowState, status int, errMessage string, message string) {
	state = normalizeLoginFlowState(state, a.detectLanguage(r))
	lang := state.Lang
	scriptNonce, err := issueNonce(16)
	if err != nil {
		log.Printf("generate CSP nonce: %v", err)
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	setNoStoreHeaders(w)
	w.Header().Set("Vary", "Accept-Language, Cookie")

	challengeHTML := make([]template.HTML, 0, len(a.loginGuards))
	usesTurnstile := false
	for _, guard := range a.loginGuards {
		if guard.ID() == "turnstile-login-guard" {
			usesTurnstile = true
		}
		challengeHTML = append(challengeHTML, guard.Render(w, r, lang, scriptNonce))
	}
	w.Header().Set("Content-Security-Policy", gateui.LoginPageCSP(scriptNonce, usesTurnstile))

	data := LoginPageData{
		Lang:          lang,
		Title:         a.translator.Text(lang, "login_title"),
		Tagline:       a.translator.Text(lang, "login_tagline"),
		PasswordLabel: a.translator.Text(lang, "password_label"),
		PasswordHint:  a.translator.Text(lang, "password_hint"),
		SubmitLabel:   a.translator.Text(lang, "submit_label"),
		Error:         errMessage,
		Message:       message,
		Next:          state.Next,
		FormAction:    loginPath,
		LanguageLabel: a.translator.Text(lang, "language_label"),
		LanguageOptions: []LoginLanguageOption{
			{Code: "zh", Label: a.translator.Text(lang, "toggle_zh"), Active: lang == "zh"},
			{Code: "en", Label: a.translator.Text(lang, "toggle_en"), Active: lang == "en"},
		},
		ChallengeHTML: challengeHTML,
		ScriptNonce:   scriptNonce,
		UsesTurnstile: usesTurnstile,
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
	state := loginFlowState{
		Next: next,
		Lang: lang,
	}
	if _, err := a.loginFlow.Issue(w, r, state, lang); err != nil {
		log.Printf("issue login flow during redirect: %v", err)
	}
	redirectNoStore(w, r, loginPath, status)
}

func (a *App) detectLanguage(r *http.Request) string {
	for _, detector := range a.langDetectors {
		if lang, ok := detector.Detect(r); ok {
			return lang
		}
	}
	return a.cfg.DefaultLang
}

func (a *App) requestedPath(r *http.Request) string {
	if a != nil && a.protectedCache != nil {
		return a.protectedCache.CleanRequestURI(r)
	}
	return requestedPath(r)
}

func (a *App) persistLanguageCookie(w http.ResponseWriter, r *http.Request, candidate string) {
	if candidate == "" {
		return
	}

	now := time.Now()
	if a.cfg.Now != nil {
		now = a.cfg.Now()
	}

	http.SetCookie(w, &http.Cookie{
		Name:     a.cfg.LangCookieName,
		Value:    candidate,
		Path:     "/",
		HttpOnly: false,
		Secure:   shouldUseSecureCookie(a.cfg, r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(a.cfg.CookieTTL.Seconds()),
		Expires:  now.Add(a.cfg.CookieTTL),
	})
}
