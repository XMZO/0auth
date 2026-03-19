package gate

import (
	"context"
	"html/template"
	"net"
	"net/http"
	"net/http/httputil"
	"sync"
	"time"

	gatei18n "auth-proxy/internal/gate/i18n"
)

type Config struct {
	ListenAddr             string
	TargetURL              string
	AuthPassword           string
	SessionSecret          string
	AuthSessionStore       string
	AuthSessionFile        string
	AuthSessionRotation    bool
	AuthRotationInterval   time.Duration
	AuthRotationGrace      time.Duration
	CookieTTL              time.Duration
	LoginChallengeMode     string
	ProtectedCacheMode     string
	ProtectedCacheTTL      time.Duration
	ProtectedCacheParam    string
	ProtectedCacheExts     []string
	PoWDifficulty          int
	PoWAutoDifficulty      bool
	PoWAutoRules           []string
	PoWMinDifficulty       int
	PoWMaxDifficulty       int
	PoWSuspiciousUATokens  []string
	PoWProgressMode        string
	PoWChallengeTTL        time.Duration
	TurnstileSiteKey       string
	TurnstileSecretKey     string
	TurnstileTheme         string
	TurnstileAppearance    string
	TurnstileAction        string
	TurnstileVerifyURL     string
	TurnstileVerifyTimeout time.Duration
	TurnstileSessionTTL    time.Duration
	TurnstileAllowedHosts  []string
	MaxLoginFailures       int
	LoginBanDuration       time.Duration
	DefaultLang            string
	AuthCookieName         string
	LangCookieName         string
	TrustProxyHeaders      bool
	CookieSecureMode       string
	DisabledModules        map[string]struct{}
	IPLangRules            []ipLangRule
	Now                    func() time.Time
}

type App struct {
	cfg            Config
	proxy          *httputil.ReverseProxy
	auth           AuthStrategy
	loginFlow      *loginFlowManager
	protectedCache *protectedAssetCache
	translator     *gatei18n.Translator
	langDetectors  []LanguageDetector
	loginGuards    []LoginGuard
}

type Module interface {
	ID() string
}

type AuthStrategy interface {
	Module
	Authenticate(w http.ResponseWriter, r *http.Request) bool
	Login(w http.ResponseWriter, r *http.Request) error
	Logout(w http.ResponseWriter, r *http.Request)
}

type authSessionStore interface {
	Issue(ttl time.Duration, rotationEnabled bool, rotationInterval time.Duration) (authSession, error)
	Validate(familyID string, generation uint64, rotationEnabled bool, rotationInterval time.Duration, rotationGrace time.Duration) (authSessionValidation, bool)
	Delete(familyID string)
}

type LanguageDetector interface {
	Module
	Detect(r *http.Request) (string, bool)
}

type LoginGuard interface {
	Module
	Render(w http.ResponseWriter, r *http.Request, lang string, scriptNonce string) template.HTML
	Validate(r *http.Request, lang string) error
	OnLoginSuccess(r *http.Request)
	OnLoginFailure(r *http.Request, lang string) error
}

type SinglePasswordAuth struct {
	expectedPassword string
	cookieName       string
	bindCookieName   string
	ttl              time.Duration
	rotationEnabled  bool
	rotationInterval time.Duration
	rotationGrace    time.Duration
	signer           *SessionSigner
	store            authSessionStore
	secureDecider    func(*http.Request) bool
}

type SessionSigner struct {
	secret []byte
	now    func() time.Time
}

type loginFlowManager struct {
	cookieName    string
	cookiePath    string
	ttl           time.Duration
	signer        *SessionSigner
	secureDecider func(*http.Request) bool
}

type loginFlowState struct {
	Next      string
	Lang      string
	ExpiresAt time.Time
}

type queryLangDetector struct{}

type cookieLangDetector struct {
	cookieName string
}

type acceptLanguageDetector struct{}

type ipLangDetector struct {
	rules             []ipLangRule
	trustProxyHeaders bool
}

type ipLangRule struct {
	network *net.IPNet
	lang    string
}

type powLoginGuard struct {
	baseDifficulty     int
	autoDifficulty     bool
	autoRules          []string
	minDifficulty      int
	maxDifficulty      int
	suspiciousUATokens []string
	progressMode       string
	ttl                time.Duration
	cookieName         string
	signer             *SessionSigner
	secureDecider      func(*http.Request) bool
	store              *powChallengeStore
	translator         *gatei18n.Translator
	now                func() time.Time
}

type turnstileLoginGuard struct {
	siteKey       string
	secretKey     string
	theme         string
	appearance    string
	action        string
	verifyURL     string
	verifyTimeout time.Duration
	sessionTTL    time.Duration
	allowedHosts  []string
	cookieName    string
	signer        *SessionSigner
	secureDecider func(*http.Request) bool
	translator    *gatei18n.Translator
	now           func() time.Time
}

type powChallengeStore struct {
	mu         sync.Mutex
	challenges map[string]powChallenge
	now        func() time.Time
}

type authSession struct {
	familyID           string
	currentGeneration  uint64
	previousGeneration uint64
	previousValidUntil time.Time
	expiresAt          time.Time
	nextRotateAt       time.Time
}

type authSessionValidation struct {
	familyID          string
	currentGeneration uint64
	expiresAt         time.Time
	reissue           bool
}

type powChallenge struct {
	id                string
	token             string
	browserSessionKey string
	difficulty        int
	expiresAt         time.Time
}

type passwordAttemptLimitGuard struct {
	maxFailures       int
	banDuration       time.Duration
	trustProxyHeaders bool
	translator        *gatei18n.Translator
	now               func() time.Time

	mu     sync.Mutex
	states map[string]attemptState
}

type attemptState struct {
	failures    int
	bannedUntil time.Time
	lastSeen    time.Time
}

type localizedUserError struct {
	key    string
	status int
}

type protectedAssetCache struct {
	mode       string
	ttl        time.Duration
	paramName  string
	extensions map[string]struct{}
	signer     *SessionSigner
	now        func() time.Time
}

type proxyResponseCacheMode int

const (
	proxyResponseCacheModePrivateNoStore proxyResponseCacheMode = iota
	proxyResponseCacheModeSignedEdgeCache
)

type proxyResponsePolicy struct {
	cacheMode      proxyResponseCacheMode
	sharedCacheTTL time.Duration
}

type proxyResponsePolicyContextKey struct{}

func withProxyResponsePolicy(ctx context.Context, policy proxyResponsePolicy) context.Context {
	return context.WithValue(ctx, proxyResponsePolicyContextKey{}, policy)
}

func proxyResponsePolicyFromContext(ctx context.Context) (proxyResponsePolicy, bool) {
	if ctx == nil {
		return proxyResponsePolicy{}, false
	}
	policy, ok := ctx.Value(proxyResponsePolicyContextKey{}).(proxyResponsePolicy)
	return policy, ok
}

type LoginLanguageOption struct {
	Code   string
	Label  string
	Active bool
}

type LoginPageData struct {
	Lang            string
	Title           string
	Tagline         string
	PasswordLabel   string
	PasswordHint    string
	SubmitLabel     string
	Error           string
	Message         string
	Next            string
	FormAction      string
	LanguageLabel   string
	LanguageOptions []LoginLanguageOption
	ChallengeHTML   []template.HTML
	ScriptNonce     string
	UsesTurnstile   bool
}
