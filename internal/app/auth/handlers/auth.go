package handlers

import (
	"context"
	"net/http"
	"strings"
	"time"

	apperr "github.com/Rioverde/zingpass/internal/pkg/errors"
	"github.com/Rioverde/zingpass/internal/pkg/server"
)

const (
	invalidBody      = "invalid request body"
	emailRequired    = "email is required"
	passwordRequired = "password is required"
)

type AuthService interface {
	Register(ctx context.Context, email, nickname, password string) (userID string, err error)
	Login(ctx context.Context, email, password, userAgent, ip string) (access, refresh string, err error)
}

type AuthHandler struct {
	svc           AuthService
	refreshTTL    time.Duration
	secureCookies bool
}

func NewAuthHandler(svc AuthService, refreshTTL time.Duration, secureCookies bool) *AuthHandler {
	return &AuthHandler{svc: svc, refreshTTL: refreshTTL, secureCookies: secureCookies}
}

// Register godoc
//
//	@Summary		Create a new user account
//	@Description	Validates input, ensures email and nickname are unique, hashes password with bcrypt, and creates the user.
//	@Tags			auth
//	@Accept			json
//	@Produce		json
//	@Param			request	body		registerRequest	true	"Registration payload"
//	@Success		201		{object}	userIDResponse
//	@Failure		400		{object}	server.ErrorResponse	"Invalid input"
//	@Failure		409		{object}	server.ErrorResponse	"Email or nickname already taken"
//	@Failure		500		{object}	server.ErrorResponse
//	@Router			/auth/register [post]
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := server.DecodeJSON(w, r, &req); err != nil {
		server.RespondErr(w, r, apperr.BadRequest(apperr.CodeMalformedJSON, invalidBody))
		return
	}

	req.Email = strings.TrimSpace(strings.ToLower(req.Email))
	req.Nickname = strings.TrimSpace(req.Nickname)

	userID, err := h.svc.Register(r.Context(), req.Email, req.Nickname, req.Password)
	if err != nil {
		server.RespondErr(w, r, err)
		return
	}

	_ = server.WriteJSON(w, http.StatusCreated, userIDResponse{UserID: userID})
}

// Login godoc
//
//	@Summary		Authenticate and issue tokens
//	@Description	Verifies email/password and returns a short-lived access JWT plus a long-lived refresh token. Refresh is also set as an httpOnly cookie for browser clients.
//	@Tags			auth
//	@Accept			json
//	@Produce		json
//	@Param			request	body		credentials	true	"Login payload"
//	@Success		200		{object}	tokenResponse
//	@Header			200		{string}	Set-Cookie	"refresh_token=...; HttpOnly; Path=/auth"
//	@Failure		400		{object}	server.ErrorResponse	"Invalid input"
//	@Failure		401		{object}	server.ErrorResponse	"Invalid credentials"
//	@Failure		500		{object}	server.ErrorResponse
//	@Router			/auth/login [post]
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var creds credentials
	if err := server.DecodeJSON(w, r, &creds); err != nil {
		server.RespondErr(w, r, apperr.BadRequest(apperr.CodeMalformedJSON, invalidBody))
		return
	}

	creds.Email = strings.TrimSpace(strings.ToLower(creds.Email))

	if creds.Email == "" {
		server.RespondErr(w, r, apperr.BadRequest(apperr.CodeMissingField, emailRequired))
		return
	}
	if creds.Password == "" {
		server.RespondErr(w, r, apperr.BadRequest(apperr.CodeMissingField, passwordRequired))
		return
	}

	access, refresh, err := h.svc.Login(r.Context(), creds.Email, creds.Password, r.UserAgent(), clientIP(r))
	if err != nil {
		server.RespondErr(w, r, err)
		return
	}

	setRefreshCookie(w, refresh, int(h.refreshTTL/time.Second), h.secureCookies)

	_ = server.WriteJSON(w, http.StatusOK, tokenResponse{Token: access, Refresh: refresh})
}
