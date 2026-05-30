package handlers

import (
	"net"
	"net/http"
	"strings"
)

// clientIP returns the real client IP suitable for Postgres INET.
// Order: X-Real-IP (set by trusted proxy) → first X-Forwarded-For hop → r.RemoteAddr (stripped of port).
func clientIP(r *http.Request) string {
	if h := r.Header.Get("X-Real-IP"); h != "" {
		return h
	}
	if h := r.Header.Get("X-Forwarded-For"); h != "" {
		// X-Forwarded-For may be "client, proxy1, proxy2" — first hop is the original client.
		if idx := strings.IndexByte(h, ','); idx > 0 {
			return strings.TrimSpace(h[:idx])
		}
		return strings.TrimSpace(h)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

const refreshCookieName = "refresh_token"

func setRefreshCookie(w http.ResponseWriter, value string, maxAgeSeconds int, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     refreshCookieName,
		Value:    value,
		Path:     "/auth",
		MaxAge:   maxAgeSeconds,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
	})
}

func clearRefreshCookie(w http.ResponseWriter, secure bool) {
	setRefreshCookie(w, "", -1, secure)
}
