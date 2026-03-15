package gate

import (
	"fmt"
	"net/http"
	"strings"
)

func powDifficultyDelta(r *http.Request, autoRules []string, suspiciousUATokens []string) int {
	if r == nil {
		return 0
	}
	if len(autoRules) == 0 {
		autoRules = defaultPoWAutoRules()
	}

	ua := strings.ToLower(strings.TrimSpace(r.UserAgent()))
	for _, rule := range autoRules {
		switch rule {
		case "empty-ua":
			if ua == "" {
				return 1
			}
		case "suspicious-ua":
			if isSuspiciousAutomationUA(ua, suspiciousUATokens) {
				return 2
			}
		case "mobile":
			if isMobileUA(ua) {
				return -1
			}
		}
	}
	return 0
}

func isSuspiciousAutomationUA(ua string, suspiciousTokens []string) bool {
	for _, token := range suspiciousTokens {
		if strings.Contains(ua, token) {
			return true
		}
	}
	return false
}

func isMobileUA(ua string) bool {
	mobileTokens := []string{
		"mobile",
		"android",
		"iphone",
		"ipad",
		"ipod",
		"harmonyos",
	}

	for _, token := range mobileTokens {
		if strings.Contains(ua, token) {
			return true
		}
	}
	return false
}

func clampInt(value int, min int, max int) int {
	if min > max {
		return value
	}
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

func defaultSuspiciousUATokens() []string {
	return []string{
		"bot",
		"spider",
		"crawler",
		"curl",
		"wget",
		"python-requests",
		"go-http-client",
		"headless",
		"playwright",
		"selenium",
		"phantomjs",
		"scrapy",
		"postmanruntime",
		"httpie",
		"libwww-perl",
		"aiohttp",
	}
}

func DefaultSuspiciousUATokens() []string {
	return defaultSuspiciousUATokens()
}

func defaultPoWAutoRules() []string {
	return []string{
		"empty-ua",
		"suspicious-ua",
		"mobile",
	}
}

func defaultPoWAutoRulesEnv() string {
	return strings.Join(defaultPoWAutoRules(), ",")
}

func parsePoWAutoRules(raw string) ([]string, error) {
	rules := splitCSV(raw)
	if len(rules) == 0 {
		return nil, nil
	}

	normalized := make([]string, 0, len(rules))
	seen := make(map[string]struct{}, len(rules))
	for _, rule := range rules {
		rule = strings.ToLower(strings.TrimSpace(rule))
		switch rule {
		case "empty-ua", "suspicious-ua", "mobile":
		default:
			return nil, fmt.Errorf("unsupported auto rule %q", rule)
		}
		if _, ok := seen[rule]; ok {
			continue
		}
		seen[rule] = struct{}{}
		normalized = append(normalized, rule)
	}
	return normalized, nil
}

func defaultSuspiciousUATokensEnv() string {
	return strings.Join(defaultSuspiciousUATokens(), ",")
}

func parseUserAgentTokens(raw string) []string {
	tokens := splitCSV(raw)
	if len(tokens) == 0 {
		return nil
	}

	normalized := make([]string, 0, len(tokens))
	seen := make(map[string]struct{}, len(tokens))
	for _, token := range tokens {
		token = strings.ToLower(strings.TrimSpace(token))
		if token == "" {
			continue
		}
		if _, ok := seen[token]; ok {
			continue
		}
		seen[token] = struct{}{}
		normalized = append(normalized, token)
	}
	return normalized
}

func ParseUserAgentTokens(raw string) []string {
	return parseUserAgentTokens(raw)
}
