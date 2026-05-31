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

// RefreshTokenProvider defines the contract for refresh token persistence, handling
// token storage, lookup, revocation, and rotation bookkeeping for compromise detection.
type RefreshTokenProvider interface {
	Create(ctx context.Context, userID, tokenHash string, expiresAt time.Time, userAgent, ip string) (id string, err error)
	ByHash(ctx context.Context, tokenHash string) (models.RefreshToken, error)
	Revoke(ctx context.Context, id string) error
	RevokeAllForUser(ctx context.Context, userID string) error
	MarkReplaced(ctx context.Context, oldID, newID string) error
	// Rotate atomically inserts a new refresh row and marks oldID as replaced by it.
	Rotate(ctx context.Context, oldID, userID, newTokenHash string, expiresAt time.Time, userAgent, ip string) (newID string, err error)
}

// Refresh rotates a refresh token to issue a new access-refresh pair.
// It includes reuse detection: if a revoked token that was previously rotated (has ReplacedBy set)
// is presented again, the service assumes compromise and revokes all sessions for that user.
// This is the security teeth of the token rotation scheme. Valid tokens are rotated atomically
// by issuing a new pair before marking the old one as replaced, ensuring continuity across
// concurrent requests.
func (s *AuthService) Refresh(ctx context.Context, refreshToken, userAgent, ip string) (access, newRefresh string, err error) {
	logger := log.From(ctx).With(zap.String("ip", ip))
	logger.Info("refresh attempt")

	// Locate the refresh-token row by its hash.
	row, err := s.refresh.ByHash(ctx, crypto.HashToken(refreshToken))
	if stderr.Is(err, pgx.ErrNoRows) {
		logger.Warn("refresh failed: token not found")
		return "", "", apperr.Unauthorized(apperr.CodeTokenInvalid, invalidRefresh)
	}
	if err != nil {
		logger.Error("refresh failed: db lookup", zap.Error(err))
		return "", "", apperr.Internal(err)
	}

	logger = logger.With(zap.String("user_id", row.UserID))

	// Revocation + reuse detection.
	// If the token is already revoked AND was rotated (replaced_by is set),
	// someone is using a previously-rotated token — assume compromise and
	// invalidate every session for the owning user.
	if row.RevokedAt != nil {
		if row.ReplacedBy != nil {
			logger.Warn("refresh failed: reuse detected, revoking all sessions")
			if err := s.refresh.RevokeAllForUser(ctx, row.UserID); err != nil {
				logger.Error("refresh failed: revoke all", zap.Error(err))
				return "", "", apperr.Internal(err)
			}
		} else {
			logger.Warn("refresh failed: token revoked")
		}
		return "", "", apperr.Unauthorized(apperr.CodeTokenRevoked, invalidRefresh)
	}

	// Expiry check. Reject anything past its TTL.
	if time.Now().After(row.ExpiresAt) {
		logger.Warn("refresh failed: token expired")
		return "", "", apperr.Unauthorized(apperr.CodeTokenExpired, invalidRefresh)
	}

	// Generate the new refresh token.
	newRefresh, err = crypto.RandomHex(32)
	if err != nil {
		logger.Error("refresh failed: random source unavailable", zap.Error(err))
		return "", "", apperr.Internal(err)
	}

	// Atomically insert the new row and mark the old one as replaced.
	// Either both happen or neither — no window in which old stays unrevoked.
	if _, err := s.refresh.Rotate(
		ctx, row.ID, row.UserID, crypto.HashToken(newRefresh),
		time.Now().Add(s.refreshTTL), userAgent, ip,
	); err != nil {
		logger.Error("refresh failed: rotate", zap.Error(err))
		return "", "", apperr.Internal(err)
	}

	// Mint a fresh access JWT.
	access, err = s.signer.Sign(row.UserID, "")
	if err != nil {
		logger.Error("refresh failed: sign access token", zap.Error(err))
		return "", "", apperr.Internal(err)
	}

	logger.Info("refresh success")
	return access, newRefresh, nil
}

// Logout revokes a refresh token, terminating the associated session.
// It is idempotent: if the token does not exist or is already revoked, it returns success.
// This design allows clients to safely retry logout requests without error handling complexity.
func (s *AuthService) Logout(ctx context.Context, refreshToken string) error {
	logger := log.From(ctx)
	logger.Info("logout attempt")

	row, err := s.refresh.ByHash(ctx, crypto.HashToken(refreshToken))
	if stderr.Is(err, pgx.ErrNoRows) {
		logger.Info("logout: token not found (already gone)")
		return nil // idempotent
	}
	if err != nil {
		logger.Error("logout failed: db lookup", zap.Error(err))
		return apperr.Internal(err)
	}

	// Already revoked → idempotent success.
	if row.RevokedAt != nil {
		return nil
	}

	if err := s.refresh.Revoke(ctx, row.ID); err != nil {
		logger.Error("logout failed: revoke", zap.Error(err))
		return apperr.Internal(err)
	}

	logger.Info("logout success", zap.String("user_id", row.UserID))
	return nil
}
