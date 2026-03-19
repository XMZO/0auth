package gate

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

func LoadConfigFromEnv() (Config, error) {
	cookieTTL, err := parseDurationWithDays(envOrDefault("COOKIE_TTL", "30d"))
	if err != nil {
		return Config{}, fmt.Errorf("parse COOKIE_TTL: %w", err)
	}
	authRotationInterval, err := parseDurationWithDays(envOrDefault("AUTH_ROTATION_INTERVAL", defaultAuthRotationInterval.String()))
	if err != nil {
		return Config{}, fmt.Errorf("parse AUTH_ROTATION_INTERVAL: %w", err)
	}
	authRotationGrace, err := parseDurationWithDays(envOrDefault("AUTH_ROTATION_GRACE", defaultAuthRotationGrace.String()))
	if err != nil {
		return Config{}, fmt.Errorf("parse AUTH_ROTATION_GRACE: %w", err)
	}
	loginChallengeMode := normalizeLoginChallengeMode(envOrDefault("LOGIN_CHALLENGE_MODE", defaultLoginChallengeMode))
	if loginChallengeMode == "" {
		return Config{}, fmt.Errorf("parse LOGIN_CHALLENGE_MODE: unsupported mode %q", os.Getenv("LOGIN_CHALLENGE_MODE"))
	}
	protectedCacheMode := normalizeProtectedCacheMode(envOrDefault("PROTECTED_EDGE_CACHE_MODE", defaultProtectedCacheMode))
	if protectedCacheMode == "" {
		return Config{}, fmt.Errorf("parse PROTECTED_EDGE_CACHE_MODE: unsupported mode %q", os.Getenv("PROTECTED_EDGE_CACHE_MODE"))
	}
	protectedCacheTTL, err := parseDurationWithDays(envOrDefault("PROTECTED_EDGE_CACHE_TTL", defaultProtectedCacheTTL.String()))
	if err != nil {
		return Config{}, fmt.Errorf("parse PROTECTED_EDGE_CACHE_TTL: %w", err)
	}
	powChallengeTTL, err := parseDurationWithDays(envOrDefault("POW_CHALLENGE_TTL", defaultPoWTTL.String()))
	if err != nil {
		return Config{}, fmt.Errorf("parse POW_CHALLENGE_TTL: %w", err)
	}
	turnstileVerifyTimeout, err := parseDurationWithDays(envOrDefault("TURNSTILE_VERIFY_TIMEOUT", defaultTurnstileTimeout.String()))
	if err != nil {
		return Config{}, fmt.Errorf("parse TURNSTILE_VERIFY_TIMEOUT: %w", err)
	}
	turnstileSessionTTL, err := parseDurationWithDays(envOrDefault("TURNSTILE_SESSION_TTL", defaultTurnstileVerifyTTL.String()))
	if err != nil {
		return Config{}, fmt.Errorf("parse TURNSTILE_SESSION_TTL: %w", err)
	}
	authSessionRotation := envBool("AUTH_SESSION_ROTATION", true)
	powAutoDifficulty := envBool("POW_AUTO_DIFFICULTY", false)
	powProgressMode := normalizePoWProgressMode(envOrDefault("POW_PROGRESS_MODE", defaultPoWProgressMode))
	if powProgressMode == "" {
		return Config{}, fmt.Errorf("parse POW_PROGRESS_MODE: unsupported mode %q", os.Getenv("POW_PROGRESS_MODE"))
	}
	turnstileTheme := normalizeTurnstileTheme(envOrDefault("TURNSTILE_THEME", defaultTurnstileTheme))
	if turnstileTheme == "" {
		return Config{}, fmt.Errorf("parse TURNSTILE_THEME: unsupported theme %q", os.Getenv("TURNSTILE_THEME"))
	}
	turnstileAppearance := normalizeTurnstileAppearance(envOrDefault("TURNSTILE_APPEARANCE", defaultTurnstileAppearance))
	if turnstileAppearance == "" {
		return Config{}, fmt.Errorf("parse TURNSTILE_APPEARANCE: unsupported appearance %q", os.Getenv("TURNSTILE_APPEARANCE"))
	}
	protectedCacheParam := normalizeQueryParamName(envOrDefault("PROTECTED_EDGE_CACHE_PARAM", defaultProtectedCacheParam), defaultProtectedCacheParam)
	if protectedCacheParam == "" {
		return Config{}, fmt.Errorf("parse PROTECTED_EDGE_CACHE_PARAM: unsupported parameter name %q", os.Getenv("PROTECTED_EDGE_CACHE_PARAM"))
	}
	authSessionStore := normalizeAuthSessionStore(envOrDefault("AUTH_SESSION_STORE", defaultAuthSessionStore))
	if authSessionStore == "" {
		return Config{}, fmt.Errorf("parse AUTH_SESSION_STORE: unsupported backend %q", os.Getenv("AUTH_SESSION_STORE"))
	}
	rawPowSuspiciousUATokens, ok := os.LookupEnv("POW_SUSPICIOUS_UA_TOKENS")
	if !ok {
		rawPowSuspiciousUATokens = defaultSuspiciousUATokensEnv()
	}
	rawPoWAutoRules, ok := os.LookupEnv("POW_AUTO_RULES")
	if !ok {
		rawPoWAutoRules = defaultPoWAutoRulesEnv()
	}
	powAutoRules, err := parsePoWAutoRules(rawPoWAutoRules)
	if err != nil {
		return Config{}, fmt.Errorf("parse POW_AUTO_RULES: %w", err)
	}
	powSuspiciousUATokens := parseUserAgentTokens(rawPowSuspiciousUATokens)
	loginBanDuration, err := parseDurationWithDays(envOrDefault("LOGIN_BAN_DURATION", defaultBanDuration.String()))
	if err != nil {
		return Config{}, fmt.Errorf("parse LOGIN_BAN_DURATION: %w", err)
	}
	powDifficulty, err := envInt("POW_DIFFICULTY", defaultPoWDifficulty)
	if err != nil {
		return Config{}, fmt.Errorf("parse POW_DIFFICULTY: %w", err)
	}
	powMinDifficulty, err := envInt("POW_MIN_DIFFICULTY", 2)
	if err != nil {
		return Config{}, fmt.Errorf("parse POW_MIN_DIFFICULTY: %w", err)
	}
	powMaxDifficulty, err := envInt("POW_MAX_DIFFICULTY", 6)
	if err != nil {
		return Config{}, fmt.Errorf("parse POW_MAX_DIFFICULTY: %w", err)
	}
	maxLoginFailures, err := envInt("MAX_LOGIN_FAILURES", defaultMaxFailures)
	if err != nil {
		return Config{}, fmt.Errorf("parse MAX_LOGIN_FAILURES: %w", err)
	}

	cfg := Config{
		ListenAddr:             envOrDefault("LISTEN_ADDR", defaultListenAddr),
		TargetURL:              strings.TrimSpace(os.Getenv("TARGET_URL")),
		AuthPassword:           os.Getenv("AUTH_PASSWORD"),
		SessionSecret:          os.Getenv("SESSION_SECRET"),
		AuthSessionStore:       authSessionStore,
		AuthSessionFile:        envOrDefault("AUTH_SESSION_FILE", defaultAuthSessionFile),
		AuthSessionRotation:    authSessionRotation,
		AuthRotationInterval:   authRotationInterval,
		AuthRotationGrace:      authRotationGrace,
		CookieTTL:              cookieTTL,
		LoginChallengeMode:     loginChallengeMode,
		ProtectedCacheMode:     protectedCacheMode,
		ProtectedCacheTTL:      protectedCacheTTL,
		ProtectedCacheParam:    protectedCacheParam,
		ProtectedCacheExts:     parseProtectedCacheExtensions(os.Getenv("PROTECTED_EDGE_CACHE_EXTENSIONS")),
		PoWDifficulty:          powDifficulty,
		PoWAutoDifficulty:      powAutoDifficulty,
		PoWAutoRules:           powAutoRules,
		PoWMinDifficulty:       powMinDifficulty,
		PoWMaxDifficulty:       powMaxDifficulty,
		PoWSuspiciousUATokens:  powSuspiciousUATokens,
		PoWProgressMode:        powProgressMode,
		PoWChallengeTTL:        powChallengeTTL,
		TurnstileSiteKey:       strings.TrimSpace(os.Getenv("TURNSTILE_SITE_KEY")),
		TurnstileSecretKey:     strings.TrimSpace(os.Getenv("TURNSTILE_SECRET_KEY")),
		TurnstileTheme:         turnstileTheme,
		TurnstileAppearance:    turnstileAppearance,
		TurnstileAction:        envOrDefault("TURNSTILE_ACTION", defaultTurnstileAction),
		TurnstileVerifyURL:     envOrDefault("TURNSTILE_VERIFY_URL", defaultTurnstileVerifyURL),
		TurnstileVerifyTimeout: turnstileVerifyTimeout,
		TurnstileSessionTTL:    turnstileSessionTTL,
		TurnstileAllowedHosts:  parseHostList(os.Getenv("TURNSTILE_ALLOWED_HOSTS")),
		MaxLoginFailures:       maxLoginFailures,
		LoginBanDuration:       loginBanDuration,
		DefaultLang:            normalizeLang(envOrDefault("DEFAULT_LANG", defaultLang)),
		AuthCookieName:         envOrDefault("AUTH_COOKIE_NAME", defaultAuthCookie),
		LangCookieName:         envOrDefault("LANG_COOKIE_NAME", defaultLangCookie),
		TrustProxyHeaders:      envBool("TRUST_PROXY_HEADERS", false),
		CookieSecureMode:       normalizeSecureMode(envOrDefault("COOKIE_SECURE_MODE", "auto")),
		DisabledModules:        parseDisabledModules(os.Getenv("DISABLED_MODULES")),
	}

	if cfg.TargetURL == "" {
		return Config{}, errors.New("TARGET_URL is required")
	}
	if cfg.AuthPassword == "" {
		return Config{}, errors.New("AUTH_PASSWORD is required")
	}
	if cfg.DefaultLang == "" {
		cfg.DefaultLang = defaultLang
	}
	if cfg.AuthSessionStore == "file" && strings.TrimSpace(cfg.AuthSessionFile) == "" {
		return Config{}, errors.New("AUTH_SESSION_FILE is required when AUTH_SESSION_STORE=file")
	}
	if cfg.AuthSessionRotation {
		if cfg.AuthRotationInterval <= 0 {
			return Config{}, errors.New("AUTH_ROTATION_INTERVAL must be positive when AUTH_SESSION_ROTATION=true")
		}
		if cfg.AuthRotationGrace <= 0 {
			return Config{}, errors.New("AUTH_ROTATION_GRACE must be positive when AUTH_SESSION_ROTATION=true")
		}
	}
	if cfg.SessionSecret == "" {
		cfg.SessionSecret = cfg.AuthPassword
		log.Printf("warning: SESSION_SECRET is empty; using AUTH_PASSWORD-derived secret. Set SESSION_SECRET for better separation.")
	}
	if challengeModeIncludesTurnstile(cfg.LoginChallengeMode) {
		if cfg.TurnstileSiteKey == "" {
			return Config{}, errors.New("TURNSTILE_SITE_KEY is required when LOGIN_CHALLENGE_MODE enables turnstile")
		}
		if cfg.TurnstileSecretKey == "" {
			return Config{}, errors.New("TURNSTILE_SECRET_KEY is required when LOGIN_CHALLENGE_MODE enables turnstile")
		}
	}

	rules, err := parseIPLangRules(envOrDefault("I18N_IP_LANG_RULES", defaultIPLangRules()))
	if err != nil {
		return Config{}, fmt.Errorf("parse I18N_IP_LANG_RULES: %w", err)
	}
	cfg.IPLangRules = rules
	return cfg, nil
}

func loadConfigFromEnv() (Config, error) {
	return LoadConfigFromEnv()
}

func ParseDurationWithDays(raw string) (time.Duration, error) {
	return parseDurationWithDays(raw)
}

func parseDurationWithDays(raw string) (time.Duration, error) {
	value := strings.ToLower(strings.TrimSpace(raw))
	if value == "" {
		return 0, errors.New("value is empty")
	}

	if strings.HasSuffix(value, "d") {
		daysRaw := strings.TrimSpace(strings.TrimSuffix(value, "d"))
		days, err := strconv.Atoi(daysRaw)
		if err != nil {
			return 0, fmt.Errorf("invalid day count %q", raw)
		}
		if days <= 0 {
			return 0, errors.New("duration must be positive")
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}

	duration, err := time.ParseDuration(value)
	if err != nil {
		return 0, err
	}
	if duration <= 0 {
		return 0, errors.New("duration must be positive")
	}
	return duration, nil
}

func envOrDefault(key string, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return strings.TrimSpace(value)
	}
	return fallback
}

func envBool(key string, fallback bool) bool {
	value, ok := os.LookupEnv(key)
	if !ok {
		return fallback
	}
	value = strings.TrimSpace(strings.ToLower(value))
	return value == "1" || value == "true" || value == "yes" || value == "on"
}

func envInt(key string, fallback int) (int, error) {
	value, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(value) == "" {
		return fallback, nil
	}
	number, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return 0, err
	}
	return number, nil
}

func shouldUseSecureCookie(cfg Config, r *http.Request) bool {
	switch cfg.CookieSecureMode {
	case "always":
		return true
	case "never":
		return false
	default:
		if r.TLS != nil {
			return true
		}
		if cfg.TrustProxyHeaders && strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
			return true
		}
		return false
	}
}

func parseDisabledModules(raw string) map[string]struct{} {
	disabled := map[string]struct{}{}
	for _, token := range splitCSV(raw) {
		if token == "" {
			continue
		}
		disabled[strings.ToLower(token)] = struct{}{}
	}
	return disabled
}

func parseIPLangRules(raw string) ([]ipLangRule, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}

	rules := make([]ipLangRule, 0)
	for _, token := range splitCSV(raw) {
		parts := strings.SplitN(token, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid rule %q", token)
		}

		_, network, err := net.ParseCIDR(strings.TrimSpace(parts[0]))
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", parts[0], err)
		}

		lang := normalizeLang(parts[1])
		if lang == "" {
			return nil, fmt.Errorf("unsupported language %q", parts[1])
		}

		rules = append(rules, ipLangRule{network: network, lang: lang})
	}
	return rules, nil
}

func splitCSV(raw string) []string {
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n'
	})
	out := make([]string, 0, len(fields))
	for _, field := range fields {
		out = append(out, strings.TrimSpace(field))
	}
	return out
}

func parseHostList(raw string) []string {
	hosts := make([]string, 0)
	for _, token := range splitCSV(raw) {
		host := normalizeHostname(token)
		if host == "" {
			continue
		}
		hosts = append(hosts, host)
	}
	return hosts
}

func isDisabled(cfg Config, moduleID string) bool {
	_, ok := cfg.DisabledModules[strings.ToLower(moduleID)]
	return ok
}

func normalizeLang(raw string) string {
	value := strings.ToLower(strings.TrimSpace(raw))
	switch {
	case value == "zh", strings.HasPrefix(value, "zh-"), strings.HasPrefix(value, "zh_"):
		return "zh"
	case value == "en", strings.HasPrefix(value, "en-"), strings.HasPrefix(value, "en_"):
		return "en"
	default:
		return ""
	}
}

func defaultIPLangRules() string {
	return strings.Join([]string{
		"127.0.0.0/8=zh",
		"::1/128=zh",
		"10.0.0.0/8=zh",
		"172.16.0.0/12=zh",
		"192.168.0.0/16=zh",
		"fc00::/7=zh",
	}, ",")
}
