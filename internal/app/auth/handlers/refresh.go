package handlers

import (
	"context"
	"net/http"
	"time"

	apperr "github.com/Rioverde/zingpass/internal/pkg/errors"
	"github.com/Rioverde/zingpass/internal/pkg/server"
)

const invalidRefresh = "invalid refresh token"

type RefreshService interface {
	Refresh(ctx context.Context, refreshToken, userAgent, ip string) (accessToken, newRefreshToken string, err error)
	Logout(ctx context.Context, refreshToken string) error
}

type RefreshHandler struct {
	svc           RefreshService
	refreshTTL    time.Duration
	secureCookies bool
}

func NewRefreshHandler(svc RefreshService, refreshTTL time.Duration, secureCookies bool) *RefreshHandler {
	return &RefreshHandler{svc: svc, refreshTTL: refreshTTL, secureCookies: secureCookies}
}

func (h *RefreshHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	token := extractRefreshToken(r)
	if token == "" {
		server.RespondErr(w, r, apperr.Unauthorized(apperr.CodeTokenMissing, invalidRefresh))
		return
	}

	access, newRefresh, err := h.svc.Refresh(r.Context(), token, r.UserAgent(), r.RemoteAddr)
	if err != nil {
		server.RespondErr(w, r, err)
		return
	}

	setRefreshCookie(w, newRefresh, int(h.refreshTTL/time.Second), h.secureCookies)

	_ = server.WriteJSON(w, http.StatusOK, map[string]string{
		"token":   access,
		"refresh": newRefresh,
	})
}

func (h *RefreshHandler) Logout(w http.ResponseWriter, r *http.Request) {
	token := extractRefreshToken(r)

	// Always clear the cookie, regardless of whether we found a token.
	clearRefreshCookie(w, h.secureCookies)

	// If no token at all — idempotent success.
	if token == "" {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if err := h.svc.Logout(r.Context(), token); err != nil {
		server.RespondErr(w, r, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// extractRefreshToken reads refresh token from header (mobile) or cookie (browser).
func extractRefreshToken(r *http.Request) string {
	if header := r.Header.Get("X-Refresh-Token"); header != "" {
		return header
	}
	if cookie, err := r.Cookie(refreshCookieName); err == nil {
		return cookie.Value
	}
	return ""
}
