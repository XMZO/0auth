package gate

import (
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
)

func clientIP(r *http.Request, trustProxyHeaders bool) (net.IP, bool) {
	if trustProxyHeaders {
		if raw := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); raw != "" {
			first := strings.TrimSpace(strings.Split(raw, ",")[0])
			if ip := net.ParseIP(first); ip != nil {
				return ip, true
			}
		}
		if raw := strings.TrimSpace(r.Header.Get("X-Real-IP")); raw != "" {
			if ip := net.ParseIP(raw); ip != nil {
				return ip, true
			}
		}
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(strings.TrimSpace(host))
	if ip == nil {
		return nil, false
	}
	return ip, true
}

func requestedPath(r *http.Request) string {
	if r == nil || r.URL == nil {
		return "/"
	}
	return sanitizeNext(r.URL.RequestURI())
}

func sanitizeNext(next string) string {
	next = strings.TrimSpace(next)
	if next == "" {
		return "/"
	}
	if strings.HasPrefix(next, "//") {
		return "/"
	}
	if !strings.HasPrefix(next, "/") {
		return "/"
	}
	if strings.HasPrefix(next, authBasePath) {
		return "/"
	}
	return next
}

func authFlowURL(next string, lang string) string {
	values := url.Values{}
	values.Set("next", sanitizeNext(next))
	if normalizedLang := normalizeLang(lang); normalizedLang != "" {
		values.Set("lang", normalizedLang)
	}
	flow, err := issueNonce(12)
	if err != nil {
		log.Printf("generate auth flow token: %v", err)
	} else {
		values.Set("flow", flow)
	}
	return loginPath + "?" + values.Encode()
}

func hasValidChallengeFlow(r *http.Request) bool {
	if r == nil || r.URL == nil {
		return false
	}
	flow := strings.TrimSpace(r.URL.Query().Get("flow"))
	return len(flow) >= 8 && len(flow) <= 128
}
