package gate

import (
	"net/http"
	"strings"
)

func (d *queryLangDetector) ID() string {
	return "query-lang"
}

func (d *queryLangDetector) Detect(r *http.Request) (string, bool) {
	lang := normalizeLang(r.URL.Query().Get("lang"))
	return lang, lang != ""
}

func (d *cookieLangDetector) ID() string {
	return "lang-cookie"
}

func (d *cookieLangDetector) Detect(r *http.Request) (string, bool) {
	cookie, err := r.Cookie(d.cookieName)
	if err != nil {
		return "", false
	}
	lang := normalizeLang(cookie.Value)
	return lang, lang != ""
}

func (d *acceptLanguageDetector) ID() string {
	return "accept-language"
}

func (d *acceptLanguageDetector) Detect(r *http.Request) (string, bool) {
	header := r.Header.Get("Accept-Language")
	if header == "" {
		return "", false
	}

	for _, part := range strings.Split(header, ",") {
		token := strings.TrimSpace(strings.Split(part, ";")[0])
		if lang := normalizeLang(token); lang != "" {
			return lang, true
		}
	}
	return "", false
}

func (d *ipLangDetector) ID() string {
	return "ip-lang"
}

func (d *ipLangDetector) Detect(r *http.Request) (string, bool) {
	ip, ok := clientIP(r, d.trustProxyHeaders)
	if !ok {
		return "", false
	}
	for _, rule := range d.rules {
		if rule.network.Contains(ip) {
			return rule.lang, true
		}
	}
	return "", false
}
