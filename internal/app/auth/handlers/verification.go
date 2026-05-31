package handlers

import (
	"context"
	stderr "errors"
	"net/http"
	"strings"

	apperr "github.com/Rioverde/zingpass/internal/pkg/errors"
	"github.com/Rioverde/zingpass/internal/pkg/server"
)

// VerificationService is the slice of AuthService used by VerificationHandler.
type VerificationService interface {
	VerifyEmail(ctx context.Context, token string) error
	ResendVerification(ctx context.Context, email string) error
}

type VerificationHandler struct {
	svc VerificationService
}

func NewVerificationHandler(svc VerificationService) *VerificationHandler {
	return &VerificationHandler{svc: svc}
}

type resendRequest struct {
	Email string `json:"email" example:"user@example.com"`
}

// Verify godoc
//
//	@Summary		Verify email via signed token
//	@Description	Consumes a verification token from the email link, marking the user as verified. Always redirects to /login.
//	@Tags			auth
//	@Param			token	query	string	true	"Verification token"
//	@Success		302	"Redirect to /login?verified=1 on success or /login?error=<code> on failure"
//	@Router			/auth/verify [get]
func (h *VerificationHandler) Verify(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Redirect(w, r, "/login?error="+apperr.CodeTokenMissing, http.StatusFound)
		return
	}

	if err := h.svc.VerifyEmail(r.Context(), token); err != nil {
		code := apperr.CodeInternal
		var ae *apperr.Error
		if stderr.As(err, &ae) {
			code = string(ae.Code)
		}
		http.Redirect(w, r, "/login?error="+code, http.StatusFound)
		return
	}

	http.Redirect(w, r, "/login?verified=1", http.StatusFound)
}

// Resend godoc
//
//	@Summary		Resend the verification email
//	@Description	Always returns 204 to avoid disclosing whether the address is registered.
//	@Tags			auth
//	@Accept			json
//	@Param			request	body	resendRequest	true	"Resend payload"
//	@Success		204	"No Content"
//	@Failure		400	{object}	server.ErrorResponse
//	@Router			/auth/verify/resend [post]
func (h *VerificationHandler) Resend(w http.ResponseWriter, r *http.Request) {
	var req resendRequest
	if err := server.DecodeJSON(w, r, &req); err != nil {
		server.RespondErr(w, r, apperr.BadRequest(apperr.CodeMalformedJSON, invalidBody))
		return
	}

	req.Email = strings.TrimSpace(strings.ToLower(req.Email))
	// Silent on missing email — same anti-enumeration policy as ResendVerification.
	if req.Email == "" {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if err := h.svc.ResendVerification(r.Context(), req.Email); err != nil {
		server.RespondErr(w, r, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
