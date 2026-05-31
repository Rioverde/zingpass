package services

import (
	"context"
	stderr "errors"
	"time"

	"github.com/jackc/pgx/v4"
	"go.uber.org/zap"

	"github.com/Rioverde/zingpass/internal/app/auth/models"
	"github.com/Rioverde/zingpass/internal/pkg/crypto"
	apperr "github.com/Rioverde/zingpass/internal/pkg/errors"
	"github.com/Rioverde/zingpass/internal/pkg/log"
	"github.com/Rioverde/zingpass/internal/pkg/validator"
)

// PasswordResetStore persists single-use password-reset tokens.
type PasswordResetStore interface {
	Create(ctx context.Context, userID, tokenHash string, expiresAt time.Time) (id string, err error)
	ByHash(ctx context.Context, tokenHash string) (models.PasswordReset, error)
	Consume(ctx context.Context, resetID, userID, newPasswordHash string) error
	InvalidateAllForUser(ctx context.Context, userID string) error
}

// RequestPasswordReset issues a single-use reset token and emails the user a link.
// Returns nil for unknown addresses to prevent enumeration — outwardly indistinguishable
// from a successful send.
func (s *AuthService) RequestPasswordReset(ctx context.Context, email string) error {
	logger := log.From(ctx).With(zap.String("email", email))
	logger.Info("password reset request")

	user, err := s.store.UserByEmail(ctx, email)
	if stderr.Is(err, pgx.ErrNoRows) {
		return nil // silent: anti-enumeration
	}
	if err != nil {
		logger.Error("password reset: db lookup", zap.Error(err))
		return apperr.Internal(err)
	}

	// Invalidate any outstanding link — a new request must supersede prior ones.
	if err := s.passwordReset.InvalidateAllForUser(ctx, user.ID); err != nil {
		logger.Error("password reset: invalidate old", zap.Error(err))
		return apperr.Internal(err)
	}

	token, err := crypto.RandomHex(32)
	if err != nil {
		logger.Error("password reset: random source unavailable", zap.Error(err))
		return apperr.Internal(err)
	}
	if _, err := s.passwordReset.Create(ctx, user.ID, crypto.HashToken(token), time.Now().Add(s.resetTTL)); err != nil {
		logger.Error("password reset: persist token", zap.Error(err))
		return apperr.Internal(err)
	}
	if err := s.mailer.SendPasswordReset(ctx, user.Email, user.Nickname, s.resetURLBase+"?token="+token); err != nil {
		logger.Error("password reset: send mail", zap.Error(err))
		return apperr.Internal(err)
	}

	logger.Info("password reset email sent", zap.String("user_id", user.ID))
	return nil
}

// ResetPassword consumes a reset token and updates the user's password.
// Also revokes every refresh token for the user — sensitive credential changes
// invalidate existing sessions across all devices.
func (s *AuthService) ResetPassword(ctx context.Context, token, newPassword string) error {
	logger := log.From(ctx)
	logger.Info("password reset confirm")

	if err := validator.Password(newPassword); err != nil {
		logger.Warn("reset failed: weak password")
		return err
	}

	row, err := s.passwordReset.ByHash(ctx, crypto.HashToken(token))
	if stderr.Is(err, pgx.ErrNoRows) {
		logger.Warn("reset failed: token not found")
		return apperr.Unauthorized(apperr.CodeTokenInvalid, "invalid reset link")
	}
	if err != nil {
		logger.Error("reset failed: db lookup", zap.Error(err))
		return apperr.Internal(err)
	}

	if row.UsedAt != nil {
		logger.Warn("reset failed: token already used", zap.String("user_id", row.UserID))
		return apperr.Unauthorized(apperr.CodeTokenRevoked, "reset link already used")
	}
	if time.Now().After(row.ExpiresAt) {
		logger.Warn("reset failed: token expired", zap.String("user_id", row.UserID))
		return apperr.Unauthorized(apperr.CodeTokenExpired, "reset link expired")
	}

	newHash, err := crypto.HashPassword(newPassword)
	if err != nil {
		logger.Error("reset failed: hash password", zap.Error(err))
		return apperr.Internal(err)
	}
	if err := s.passwordReset.Consume(ctx, row.ID, row.UserID, newHash); err != nil {
		logger.Error("reset failed: consume", zap.Error(err))
		return apperr.Internal(err)
	}

	// Kill every session — old refresh tokens shouldn't survive a password change.
	if err := s.refresh.RevokeAllForUser(ctx, row.UserID); err != nil {
		logger.Error("reset: revoke sessions", zap.Error(err))
		// not fatal — password is already updated
	}

	logger.Info("password reset success", zap.String("user_id", row.UserID))
	return nil
}
