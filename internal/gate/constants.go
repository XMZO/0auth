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
	defaultAuthRotationInterval = 5 * time.Minute
	defaultAuthRotationGrace    = 30 * time.Second
	defaultCookieTTL            = 30 * 24 * time.Hour
	defaultLoginFlowTTL         = 24 * time.Hour
	defaultPoWDifficulty        = 4
	defaultPoWTTL               = 5 * time.Minute
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
