package gate

import (
	"errors"
	"time"
)

const (
	DefaultListenAddr           = ":8088"
	DefaultLang                 = "zh"
	DefaultAuthCookie           = "rp_auth"
	DefaultLangCookie           = "rp_lang"
	defaultAuthSessionStore     = "memory"
	defaultAuthSessionFile      = "/var/lib/0auth/auth-sessions.json"
	defaultAuthSessionCleanup   = 5 * time.Minute
	defaultAuthRotationInterval = 5 * time.Minute
	defaultAuthRotationGrace    = 30 * time.Second
	defaultCookieTTL            = 30 * 24 * time.Hour
	defaultLoginFlowTTL         = 24 * time.Hour
	defaultLoginChallengeMode   = "pow"
	defaultProtectedCacheMode   = "off"
	defaultProtectedCacheTTL    = 10 * time.Minute
	defaultProtectedCacheParam  = "__oa"
	defaultPoWDifficulty        = 4
	defaultPoWTTL               = 5 * time.Minute
	defaultTurnstileTheme       = "auto"
	defaultTurnstileAppearance  = "always"
	defaultTurnstileAction      = "login"
	defaultTurnstileVerifyURL   = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
	defaultTurnstileVerifyTTL   = 15 * time.Minute
	defaultTurnstileTimeout     = 5 * time.Second
	defaultMaxFailures          = 5
	defaultBanDuration          = 15 * time.Minute
	DefaultPoWProgressMode      = "hidden"
	maxNextPathLength           = 2048

	AuthBasePath = "/_auth"
	LoginPath    = AuthBasePath + "/login"
	LogoutPath   = AuthBasePath + "/logout"
	HealthPath   = AuthBasePath + "/healthz"
)

const (
	defaultListenAddr      = DefaultListenAddr
	defaultLang            = DefaultLang
	defaultAuthCookie      = DefaultAuthCookie
	defaultLangCookie      = DefaultLangCookie
	defaultPoWProgressMode = DefaultPoWProgressMode
	authBasePath           = AuthBasePath
	loginPath              = LoginPath
	logoutPath             = LogoutPath
	healthPath             = HealthPath
)

var (
	errInvalidCredentials = errors.New("invalid credentials")
	errLoginBlocked       = errors.New("login blocked by guard")
)
