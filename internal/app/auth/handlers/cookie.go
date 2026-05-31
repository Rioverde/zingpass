package handlers

import (
	"net/http"
)

const refreshCookieName = "refresh_token"

// setRefreshCookie sets the refresh token in a secure httpOnly cookie with Strict SameSite.
// Strict is used because refresh tokens should only be sent to the same origin (not cross-site),
// ensuring maximum protection against CSRF. The cookie is scoped to /auth so it is only sent to
// refresh, logout, and other auth endpoints, not to the wider application.
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

// clearStateCookie clears the OAuth state cookie.
// The state cookie uses Lax SameSite (not Strict) because it must survive the cross-site redirect
// back from GitHub during the OAuth flow. A client-side redirect from github.com back to this origin
// would be blocked by Strict, so Lax is necessary for the OAuth callback to work.
func clearStateCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     oauthStateCookieName,
		Value:    "",
		Path:     "/auth",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// clearRefreshCookie deletes the refresh token cookie by setting an empty value with MaxAge -1.
func clearRefreshCookie(w http.ResponseWriter, secure bool) {
	setRefreshCookie(w, "", -1, secure)
}
