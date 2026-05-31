package handlers

import (
	"context"
	"net/http"
	"time"

	apperr "github.com/Rioverde/zingpass/internal/pkg/errors"
	"github.com/Rioverde/zingpass/internal/pkg/server"
)

const invalidRefresh = "invalid refresh token"

// RefreshService defines the business logic for token refresh and logout.
type RefreshService interface {
	Refresh(ctx context.Context, refreshToken, userAgent, ip string) (accessToken, newRefreshToken string, err error)
	Logout(ctx context.Context, refreshToken string) error
}

// RefreshHandler is the HTTP layer for token refresh and logout endpoints.
// It decouples the two token sources (browser cookies and mobile headers), handles secure refresh
// cookie management, and provides an idempotent logout mechanism.
type RefreshHandler struct {
	svc           RefreshService
	refreshTTL    time.Duration
	secureCookies bool
}

// NewRefreshHandler creates a new RefreshHandler with the given service and configuration.
func NewRefreshHandler(svc RefreshService, refreshTTL time.Duration, secureCookies bool) *RefreshHandler {
	return &RefreshHandler{svc: svc, refreshTTL: refreshTTL, secureCookies: secureCookies}
}

// Refresh rotates the refresh token and issues a new access token.
// The refresh token is read from either the httpOnly cookie (browser) or the X-Refresh-Token header
// (mobile/API clients), supporting both client types without forcing a single transport mechanism.
// On success, the old refresh token is revoked in the service and a new one is issued and set as a cookie.
//
// Refresh godoc
//
//	@Summary		Rotate refresh token and issue a new access token
//	@Description	Reads the refresh token from cookie (browser) or `X-Refresh-Token` header (mobile/API). On success rotates: the old refresh is revoked and replaced by a new one.
//	@Tags			auth
//	@Produce		json
//	@Param			X-Refresh-Token	header		string	false	"Refresh token (alternative to cookie)"
//	@Success		200				{object}	tokenResponse
//	@Header			200				{string}	Set-Cookie	"refresh_token=...; HttpOnly; Path=/auth"
//	@Failure		401				{object}	server.ErrorResponse	"Missing, invalid, expired, or revoked refresh token"
//	@Failure		500				{object}	server.ErrorResponse
//	@Router			/auth/refresh [post]
func (h *RefreshHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	token := extractRefreshToken(r)
	if token == "" {
		server.RespondErr(w, r, apperr.Unauthorized(apperr.CodeTokenMissing, invalidRefresh))
		return
	}

	access, newRefresh, err := h.svc.Refresh(r.Context(), token, r.UserAgent(), server.ClientIP(r))
	if err != nil {
		server.RespondErr(w, r, err)
		return
	}

	setRefreshCookie(w, newRefresh, int(h.refreshTTL/time.Second), h.secureCookies)

	_ = server.WriteJSON(w, http.StatusOK, tokenResponse{Token: access, Refresh: newRefresh})
}

// Logout revokes the refresh token and clears its cookie.
// Designed to be idempotent: the cookie is always cleared regardless of whether a token is present,
// and if a token exists, it is revoked in storage. This ensures clients can safely log out without
// worrying about missing or mismatched tokens.
//
// Logout godoc
//
//	@Summary		Revoke refresh token and clear cookie
//	@Description	Idempotent. Always clears the refresh cookie; if a valid token is present, revokes it in storage too.
//	@Tags			auth
//	@Param			X-Refresh-Token	header	string	false	"Refresh token (alternative to cookie)"
//	@Success		204		"No Content"
//	@Failure		500		{object}	server.ErrorResponse
//	@Router			/auth/logout [post]
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

// extractRefreshToken retrieves the refresh token from either the X-Refresh-Token header (mobile/API)
// or the httpOnly cookie (browser), preferring the header if both are present. This flexibility
// allows the same endpoint to serve multiple client types without requiring separate routes.
func extractRefreshToken(r *http.Request) string {
	if header := r.Header.Get("X-Refresh-Token"); header != "" {
		return header
	}
	if cookie, err := r.Cookie(refreshCookieName); err == nil {
		return cookie.Value
	}
	return ""
}
