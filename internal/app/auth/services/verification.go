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
)

// VerificationStore persists email-verification tokens.
type VerificationStore interface {
	Create(ctx context.Context, userID, tokenHash string, expiresAt time.Time) (id string, err error)
	ByHash(ctx context.Context, tokenHash string) (models.EmailVerification, error)
	Consume(ctx context.Context, verificationID, userID string) error
	InvalidateAllForUser(ctx context.Context, userID string) error
}

// sendVerification issues a fresh verification token and asks the mailer to deliver it.
// Called from Register and ResendVerification.
func (s *AuthService) sendVerification(ctx context.Context, userID, email, nickname string) error {
	token, err := crypto.RandomHex(32)
	if err != nil {
		return err
	}
	if _, err := s.verification.Create(ctx, userID, crypto.HashToken(token), time.Now().Add(s.verifyTTL)); err != nil {
		return err
	}
	return s.mailer.SendVerification(ctx, email, nickname, s.verifyURLBase+"?token="+token)
}

// VerifyEmail consumes a verification token, marking the owning user as verified.
// Idempotent failures (invalid/expired/already-used) map to typed apperr codes so the
// frontend can show actionable messages on the /login?error=... redirect.
func (s *AuthService) VerifyEmail(ctx context.Context, token string) error {
	logger := log.From(ctx)
	logger.Info("email verify attempt")

	row, err := s.verification.ByHash(ctx, crypto.HashToken(token))
	if stderr.Is(err, pgx.ErrNoRows) {
		logger.Warn("verify failed: token not found")
		return apperr.Unauthorized(apperr.CodeTokenInvalid, "invalid verification link")
	}
	if err != nil {
		logger.Error("verify failed: db lookup", zap.Error(err))
		return apperr.Internal(err)
	}

	if row.UsedAt != nil {
		logger.Warn("verify failed: token already used", zap.String("user_id", row.UserID))
		return apperr.Unauthorized(apperr.CodeTokenRevoked, "verification link already used")
	}
	if time.Now().After(row.ExpiresAt) {
		logger.Warn("verify failed: token expired", zap.String("user_id", row.UserID))
		return apperr.Unauthorized(apperr.CodeTokenExpired, "verification link expired")
	}

	if err := s.verification.Consume(ctx, row.ID, row.UserID); err != nil {
		logger.Error("verify failed: consume", zap.Error(err))
		return apperr.Internal(err)
	}

	logger.Info("verify success", zap.String("user_id", row.UserID))
	return nil
}

// ResendVerification reissues a verification email.
// Returns nil for unknown or already-verified addresses to prevent user enumeration —
// behaviour is identical regardless of whether the email actually exists.
func (s *AuthService) ResendVerification(ctx context.Context, email string) error {
	logger := log.From(ctx).With(zap.String("email", email))
	logger.Info("resend verification attempt")

	user, err := s.store.UserByEmail(ctx, email)
	if stderr.Is(err, pgx.ErrNoRows) {
		// silent — anti-enumeration
		return nil
	}
	if err != nil {
		logger.Error("resend failed: db lookup", zap.Error(err))
		return apperr.Internal(err)
	}

	if user.EmailStatus.IsVerified() {
		// already verified — nothing to do, but stay silent for the same reason.
		return nil
	}

	if err := s.verification.InvalidateAllForUser(ctx, user.ID); err != nil {
		logger.Error("resend failed: invalidate old tokens", zap.Error(err))
		return apperr.Internal(err)
	}
	if err := s.sendVerification(ctx, user.ID, user.Email, user.Nickname); err != nil {
		logger.Error("resend failed: send mail", zap.Error(err))
		return apperr.Internal(err)
	}

	logger.Info("resend verification success", zap.String("user_id", user.ID))
	return nil
}
