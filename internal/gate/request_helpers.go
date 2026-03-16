package gate

import (
	"net"
	"net/http"
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

func setNoStoreHeaders(w http.ResponseWriter) {
	if w == nil {
		return
	}
	w.Header().Set("Cache-Control", "private, no-store, no-cache, max-age=0, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	w.Header().Set("Surrogate-Control", "no-store")
}

func redirectNoStore(w http.ResponseWriter, r *http.Request, location string, status int) {
	setNoStoreHeaders(w)
	http.Redirect(w, r, location, status)
}

func sanitizeNext(next string) string {
	next = strings.TrimSpace(next)
	if next == "" {
		return "/"
	}
	if len(next) > maxNextPathLength {
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
