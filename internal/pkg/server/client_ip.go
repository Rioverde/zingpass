package server

import (
	"net"
	"net/http"
	"strings"
)

// ClientIP returns the real client IP suitable for Postgres INET and rate limiting.
// Trust order: X-Real-IP (set by trusted proxy) → first X-Forwarded-For hop → r.RemoteAddr (stripped of port).
// Only safe behind a trusted proxy that overwrites these headers.
func ClientIP(r *http.Request) string {
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
