package gate

import (
	"net/http"
	"sort"

	gatei18n "auth-proxy/internal/gate/i18n"
)

func buildLanguageDetectors(cfg Config) []LanguageDetector {
	modules := []LanguageDetector{
		&queryLangDetector{},
		&cookieLangDetector{cookieName: cfg.LangCookieName},
		&ipLangDetector{rules: cfg.IPLangRules, trustProxyHeaders: cfg.TrustProxyHeaders},
		&acceptLanguageDetector{},
	}

	filtered := make([]LanguageDetector, 0, len(modules))
	for _, module := range modules {
		if isDisabled(cfg, module.ID()) {
			continue
		}
		filtered = append(filtered, module)
	}
	return filtered
}

func buildLoginGuards(cfg Config, signer *SessionSigner, translator *gatei18n.Translator) []LoginGuard {
	guards := make([]LoginGuard, 0, 3)
	powStore := newPowChallengeStore(cfg.Now)

	if cfg.MaxLoginFailures > 0 && cfg.LoginBanDuration > 0 {
		guards = append(guards, &passwordAttemptLimitGuard{
			maxFailures:       cfg.MaxLoginFailures,
			banDuration:       cfg.LoginBanDuration,
			trustProxyHeaders: cfg.TrustProxyHeaders,
			translator:        translator,
			now:               cfg.Now,
			states:            map[string]attemptState{},
		})
	}
	if challengeModeIncludesPoW(cfg.LoginChallengeMode) && cfg.PoWDifficulty > 0 {
		guards = append(guards, &powLoginGuard{
			baseDifficulty:     cfg.PoWDifficulty,
			autoDifficulty:     cfg.PoWAutoDifficulty,
			autoRules:          cfg.PoWAutoRules,
			minDifficulty:      cfg.PoWMinDifficulty,
			maxDifficulty:      cfg.PoWMaxDifficulty,
			suspiciousUATokens: cfg.PoWSuspiciousUATokens,
			progressMode:       cfg.PoWProgressMode,
			ttl:                cfg.PoWChallengeTTL,
			cookieName:         cfg.AuthCookieName + "_pow",
			signer:             signer,
			secureDecider: func(r *http.Request) bool {
				return shouldUseSecureCookie(cfg, r)
			},
			store:      powStore,
			translator: translator,
			now:        cfg.Now,
		})
	}
	if challengeModeIncludesTurnstile(cfg.LoginChallengeMode) {
		guards = append(guards, &turnstileLoginGuard{
			siteKey:       cfg.TurnstileSiteKey,
			secretKey:     cfg.TurnstileSecretKey,
			theme:         cfg.TurnstileTheme,
			appearance:    cfg.TurnstileAppearance,
			action:        cfg.TurnstileAction,
			verifyURL:     cfg.TurnstileVerifyURL,
			verifyTimeout: cfg.TurnstileVerifyTimeout,
			sessionTTL:    cfg.TurnstileSessionTTL,
			allowedHosts:  cfg.TurnstileAllowedHosts,
			cookieName:    cfg.AuthCookieName + "_turnstile",
			signer:        signer,
			secureDecider: func(r *http.Request) bool {
				return shouldUseSecureCookie(cfg, r)
			},
			translator: translator,
			now:        cfg.Now,
		})
	}

	filtered := make([]LoginGuard, 0, len(guards))
	for _, guard := range guards {
		if isDisabled(cfg, guard.ID()) {
			continue
		}
		filtered = append(filtered, guard)
	}
	return filtered
}

func languageDetectorIDs(modules []LanguageDetector) []string {
	ids := make([]string, 0, len(modules))
	for _, module := range modules {
		ids = append(ids, module.ID())
	}
	if len(ids) == 0 {
		return []string{"none"}
	}
	return ids
}

func loginGuardIDs(modules []LoginGuard) []string {
	ids := make([]string, 0, len(modules))
	for _, module := range modules {
		ids = append(ids, module.ID())
	}
	if len(ids) == 0 {
		return []string{"none"}
	}
	return ids
}

func sortedDisabledModules(disabled map[string]struct{}) []string {
	if len(disabled) == 0 {
		return nil
	}

	ids := make([]string, 0, len(disabled))
	for id := range disabled {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
