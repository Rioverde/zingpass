package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/Rioverde/zingpass/internal/pkg/crypto"
	apperr "github.com/Rioverde/zingpass/internal/pkg/errors"
	"github.com/Rioverde/zingpass/internal/pkg/server"
)

const (
	oauthStateCookieName = "oauth_state"
	oauthStateMaxAge     = 10 * 60 // 10 minutes
	accessHandoffCookie  = "access_token"
	accessHandoffMaxAge  = 60 // 1 minute — frontend reads and clears it
)

// OAuthService defines the business logic for GitHub OAuth integration.
type OAuthService interface {
	GithubAuthURL(state string) string
	LoginViaGithub(ctx context.Context, code, userAgent, ip string) (access, refresh string, err error)
}

// OAuthHandler is the HTTP layer for GitHub OAuth endpoints.
// It manages the OAuth flow including CSRF state validation, token exchange, and secure token delivery
// to both browser (via cookies) and API clients.
type OAuthHandler struct {
	svc           OAuthService
	refreshTTL    time.Duration
	secureCookies bool
}

// NewOAuthHandler creates a new OAuthHandler with the given service and configuration.
func NewOAuthHandler(svc OAuthService, refreshTTL time.Duration, secureCookies bool) *OAuthHandler {
	return &OAuthHandler{svc: svc, refreshTTL: refreshTTL, secureCookies: secureCookies}
}

// LoginViaGithub initiates the GitHub OAuth flow.
// It generates a cryptographic CSRF state token, stores it in a short-lived, httpOnly, Lax SameSite
// cookie (Lax is required because the state must survive the cross-site redirect back from GitHub),
// and then redirects the browser to GitHub's authorization endpoint.
//
// LoginViaGithub godoc
//
//	@Summary		Start GitHub OAuth login
//	@Description	Generates a CSRF state, stores it in a short-lived cookie, and redirects the user to GitHub.
//	@Tags			auth
//	@Success		302	"Redirect to github.com"
//	@Failure		500	{object}	server.ErrorResponse
//	@Router			/auth/github [get]
func (h *OAuthHandler) LoginViaGithub(w http.ResponseWriter, r *http.Request) {
	state, err := crypto.RandomHex(32)
	if err != nil {
		server.RespondErr(w, r, apperr.Internal(err))
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     oauthStateCookieName,
		Value:    state,
		Path:     "/auth",
		MaxAge:   oauthStateMaxAge,
		HttpOnly: true,
		Secure:   h.secureCookies,
		// Lax — needed because the cookie must survive the cross-site redirect back from github.com.
		SameSite: http.SameSiteLaxMode,
	})

	http.Redirect(w, r, h.svc.GithubAuthURL(state), http.StatusFound)
}

// GithubCallback handles the OAuth callback from GitHub.
// It validates the CSRF state (comparing query param against the cookie), exchanges the authorization code
// for access and refresh tokens, and orchestrates token delivery: refresh token goes into a secure httpOnly
// Strict SameSite cookie (for subsequent authenticated requests), while access token goes into a non-httpOnly
// Lax SameSite cookie (for the frontend SPA to read, copy to sessionStorage, and clear within one minute).
// On success, redirects to /dashboard; on failure, redirects to /login with an error parameter.
//
// GithubCallback godoc
//
//	@Summary		Handle GitHub OAuth callback
//	@Description	Verifies state, exchanges code for tokens, sets refresh cookie, and redirects to the dashboard.
//	@Tags			auth
//	@Param			code	query	string	false	"Authorization code from GitHub"
//	@Param			state	query	string	false	"CSRF state echoed by GitHub"
//	@Param			error	query	string	false	"Error code if user denied access"
//	@Success		302	"Redirect to /dashboard on success, /login on failure"
//	@Router			/auth/github/callback [get]
func (h *OAuthHandler) GithubCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	// Always clear the state cookie afterwards — single-use.
	defer clearStateCookie(w, h.secureCookies)

	// GitHub may have signalled refusal.
	if errMsg := q.Get("error"); errMsg != "" {
		http.Redirect(w, r, "/login?error=oauth_denied", http.StatusFound)
		return
	}

	code := q.Get("code")
	state := q.Get("state")
	if code == "" || state == "" {
		http.Redirect(w, r, "/login?error=oauth_invalid_callback", http.StatusFound)
		return
	}

	// CSRF check — state from URL must match the cookie we set in LoginViaGithub.
	cookie, err := r.Cookie(oauthStateCookieName)
	if err != nil || cookie.Value != state {
		http.Redirect(w, r, "/login?error=oauth_state_mismatch", http.StatusFound)
		return
	}

	access, refresh, err := h.svc.LoginViaGithub(r.Context(), code, r.UserAgent(), server.ClientIP(r))
	if err != nil {
		http.Redirect(w, r, "/login?error=oauth_failed", http.StatusFound)
		return
	}

	// Refresh in httpOnly cookie just like normal Login does.
	setRefreshCookie(w, refresh, int(h.refreshTTL/time.Second), h.secureCookies)

	// Hand off the access token to the SPA via a 1-minute non-httpOnly cookie.
	// Dashboard JS reads it, copies to sessionStorage, and clears the cookie.
	http.SetCookie(w, &http.Cookie{
		Name:     accessHandoffCookie,
		Value:    access,
		Path:     "/",
		MaxAge:   accessHandoffMaxAge,
		HttpOnly: false,
		Secure:   h.secureCookies,
		SameSite: http.SameSiteLaxMode,
	})

	http.Redirect(w, r, "/dashboard", http.StatusFound)
}
