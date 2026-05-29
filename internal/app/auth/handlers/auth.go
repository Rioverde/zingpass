package handlers

import (
	"context"
	"net/http"
	"strings"

	apperr "github.com/Rioverde/zingpass/internal/pkg/errors"
	"github.com/Rioverde/zingpass/internal/pkg/server"
)

const (
	invalidBody      = "invalid request body"
	emailRequired    = "email is required"
	passwordRequired = "password is required"
)

type AuthService interface {
	Register(ctx context.Context, email, password string) (userID string, err error)
	Login(ctx context.Context, email, password string) (token string, err error)
}

type AuthHandler struct {
	svc AuthService
}

func NewAuthHandler(svc AuthService) *AuthHandler {
	return &AuthHandler{svc: svc}
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var creds credentials
	if err := server.DecodeJSON(w, r, &creds); err != nil {
		server.RespondErr(w, apperr.BadRequest(apperr.CodeMalformedJSON, invalidBody))
		return
	}

	userID, err := h.svc.Register(r.Context(), creds.Email, creds.Password)
	if err != nil {
		server.RespondErr(w, err)
		return
	}

	_ = server.WriteJSON(w, http.StatusCreated, map[string]string{"user_id": userID})
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var creds credentials
	if err := server.DecodeJSON(w, r, &creds); err != nil {
		server.RespondErr(w, apperr.BadRequest(apperr.CodeMalformedJSON, invalidBody))
		return
	}

	creds.Email = strings.TrimSpace(strings.ToLower(creds.Email))

	if creds.Email == "" {
		server.RespondErr(w, apperr.BadRequest(apperr.CodeMissingField, emailRequired))
		return
	}
	if creds.Password == "" {
		server.RespondErr(w, apperr.BadRequest(apperr.CodeMissingField, passwordRequired))
		return
	}

	token, err := h.svc.Login(r.Context(), creds.Email, creds.Password)
	if err != nil {
		server.RespondErr(w, err)
		return
	}

	_ = server.WriteJSON(w, http.StatusOK, map[string]string{"token": token})
}
