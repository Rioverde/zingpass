package server

import (
	"encoding/json"
	stderr "errors"
	"fmt"
	"io"
	"net/http"

	"go.uber.org/zap"

	apperr "github.com/Rioverde/zingpass/internal/pkg/errors"
	"github.com/Rioverde/zingpass/internal/pkg/log"
)

const maxBodyBytes = 1 << 20 // 1 MiB

// ErrorBody is the inner payload of an API error response.
type ErrorBody struct {
	Code    string `json:"code" example:"U0001"`
	Message string `json:"message" example:"user with this email already exists"`
}

// ErrorResponse is the JSON envelope for all error responses.
type ErrorResponse struct {
	Error ErrorBody `json:"error"`
}

func WriteJSON(w http.ResponseWriter, status int, v any) error {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(v)
}

func WriteError(w http.ResponseWriter, status int, msg string) {
	_ = WriteJSON(w, status, ErrorResponse{
		Error: ErrorBody{
			Message: msg,
		},
	})
}

func WriteAppError(w http.ResponseWriter, e *apperr.Error) {
	_ = WriteJSON(w, int(e.Status), ErrorResponse{
		Error: ErrorBody{
			Code:    string(e.Code),
			Message: e.Message,
		},
	})
}

func RespondErr(w http.ResponseWriter, r *http.Request, err error) {
	logger := log.From(r.Context())

	var ae *apperr.Error
	if stderr.As(err, &ae) {
		if ae.Err != nil {
			logger.Error("app error",
				zap.String("code", string(ae.Code)),
				zap.Int("status", int(ae.Status)),
				zap.Error(ae.Err),
			)
		}
		WriteAppError(w, ae)
		return
	}

	logger.Error("unexpected error", zap.Error(err))
	WriteAppError(w, apperr.Internal(err))
}

func DecodeJSON(w http.ResponseWriter, r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("decode body: %w", err)
	}

	if err := dec.Decode(&struct{}{}); !stderr.Is(err, io.EOF) {
		return stderr.New("body must contain a single JSON object")
	}

	return nil
}
