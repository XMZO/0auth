package gate

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func applyProxyResponsePolicy(resp *http.Response) error {
	if resp == nil || resp.Request == nil {
		return nil
	}

	policy, ok := proxyResponsePolicyFromContext(resp.Request.Context())
	if !ok {
		return nil
	}

	switch policy.cacheMode {
	case proxyResponseCacheModeSignedEdgeCache:
		applySignedEdgeCacheHeaders(resp, policy.sharedCacheTTL)
	default:
		applyPrivateNoStoreHeaders(resp)
	}
	return nil
}

func applyPrivateNoStoreHeaders(resp *http.Response) {
	resp.Header.Set("Cache-Control", "private, no-store, no-cache, max-age=0, must-revalidate")
	resp.Header.Set("Pragma", "no-cache")
	resp.Header.Set("Expires", "0")
	resp.Header.Set("Surrogate-Control", "no-store")
	resp.Header.Del("CDN-Cache-Control")
	resp.Header.Del("Cloudflare-CDN-Cache-Control")
}

func applySignedEdgeCacheHeaders(resp *http.Response, ttl time.Duration) {
	if ttl <= 0 {
		ttl = defaultProtectedCacheTTL
	}
	seconds := int(ttl / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	value := fmt.Sprintf("public, max-age=%d, s-maxage=%d", seconds, seconds)
	resp.Header.Set("CDN-Cache-Control", value)
	resp.Header.Set("Cloudflare-CDN-Cache-Control", value)
	if strings.TrimSpace(resp.Header.Get("Surrogate-Control")) == "" {
		resp.Header.Set("Surrogate-Control", "max-age="+strconv.Itoa(seconds))
	}
	resp.Header.Del("Pragma")
	if strings.TrimSpace(resp.Header.Get("Expires")) == "0" {
		resp.Header.Del("Expires")
	}
}
