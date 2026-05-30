package handlers

import (
	"net/http"
)

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
