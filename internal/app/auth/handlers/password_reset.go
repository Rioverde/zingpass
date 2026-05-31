package handlers

import (
	"context"
	"net/http"
	"strings"

	apperr "github.com/Rioverde/zingpass/internal/pkg/errors"
	"github.com/Rioverde/zingpass/internal/pkg/server"
)

// PasswordResetService is the slice of AuthService used by PasswordResetHandler.
type PasswordResetService interface {
	RequestPasswordReset(ctx context.Context, email string) error
	ResetPassword(ctx context.Context, token, newPassword string) error
}

type PasswordResetHandler struct {
	svc PasswordResetService
}

func NewPasswordResetHandler(svc PasswordResetService) *PasswordResetHandler {
	return &PasswordResetHandler{svc: svc}
}

type forgotRequest struct {
	Email string `json:"email" example:"user@example.com"`
}

type resetRequest struct {
	Token    string `json:"token" example:"a1b2c3..."`
	Password string `json:"password" example:"NewStrongPass!1"`
}

// Forgot godoc
//
//	@Summary		Request a password-reset email
//	@Description	Always returns 204; the response does not disclose whether the address is registered.
//	@Tags			auth
//	@Accept			json
//	@Param			request	body	forgotRequest	true	"Forgot payload"
//	@Success		204	"No Content"
//	@Failure		400	{object}	server.ErrorResponse
//	@Router			/auth/password/forgot [post]
func (h *PasswordResetHandler) Forgot(w http.ResponseWriter, r *http.Request) {
	var req forgotRequest
	if err := server.DecodeJSON(w, r, &req); err != nil {
		server.RespondErr(w, r, apperr.BadRequest(apperr.CodeMalformedJSON, invalidBody))
		return
	}

	req.Email = strings.TrimSpace(strings.ToLower(req.Email))
	if req.Email == "" {
		w.WriteHeader(http.StatusNoContent) // same anti-enumeration policy
		return
	}

	if err := h.svc.RequestPasswordReset(r.Context(), req.Email); err != nil {
		server.RespondErr(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Reset godoc
//
//	@Summary		Consume a reset token and set a new password
//	@Description	Validates token + password, atomically updates the password_hash, revokes all refresh tokens.
//	@Tags			auth
//	@Accept			json
//	@Param			request	body	resetRequest	true	"Reset payload"
//	@Success		204	"No Content"
//	@Failure		400	{object}	server.ErrorResponse	"Invalid input or weak password"
//	@Failure		401	{object}	server.ErrorResponse	"Token invalid/expired/used"
//	@Router			/auth/password/reset [post]
func (h *PasswordResetHandler) Reset(w http.ResponseWriter, r *http.Request) {
	var req resetRequest
	if err := server.DecodeJSON(w, r, &req); err != nil {
		server.RespondErr(w, r, apperr.BadRequest(apperr.CodeMalformedJSON, invalidBody))
		return
	}

	if req.Token == "" {
		server.RespondErr(w, r, apperr.BadRequest(apperr.CodeMissingField, tokenRequired))
		return
	}
	if req.Password == "" {
		server.RespondErr(w, r, apperr.BadRequest(apperr.CodeMissingField, passwordRequired))
		return
	}

	if err := h.svc.ResetPassword(r.Context(), req.Token, req.Password); err != nil {
		server.RespondErr(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
