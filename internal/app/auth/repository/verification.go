package repository

import (
	"context"
	"time"

	"github.com/Rioverde/zingpass/internal/app/auth/models"
	"github.com/Rioverde/zingpass/internal/pkg/db"
)

// VerificationRepo persists email verification tokens.
type VerificationRepo struct {
	conn *db.Connection
}

func NewVerificationRepo(conn *db.Connection) *VerificationRepo {
	return &VerificationRepo{conn: conn}
}

// Create inserts a verification token and returns its server-generated id.
func (r *VerificationRepo) Create(ctx context.Context, userID, tokenHash string, expiresAt time.Time) (string, error) {
	var id string
	err := r.conn.Pool().QueryRow(ctx,
		`INSERT INTO email_verifications (user_id, token_hash, expires_at)
		 VALUES ($1, $2, $3) RETURNING id`,
		userID, tokenHash, expiresAt,
	).Scan(&id)
	return id, err
}

// ByHash returns the verification row matching tokenHash.
// Returns pgx.ErrNoRows when no record exists.
func (r *VerificationRepo) ByHash(ctx context.Context, tokenHash string) (models.EmailVerification, error) {
	var v models.EmailVerification
	err := r.conn.Pool().QueryRow(ctx,
		`SELECT id, user_id, token_hash, expires_at, used_at, created_at
		   FROM email_verifications
		  WHERE token_hash = $1`,
		tokenHash,
	).Scan(&v.ID, &v.UserID, &v.TokenHash, &v.ExpiresAt, &v.UsedAt, &v.CreatedAt)
	return v, err
}

// Consume marks the verification as used AND flips users.email_verified=TRUE in
// a single transaction. Either both rows update or neither.
func (r *VerificationRepo) Consume(ctx context.Context, verificationID, userID string) error {
	tx, err := r.conn.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx,
		`UPDATE email_verifications SET used_at = NOW()
		  WHERE id = $1 AND used_at IS NULL`,
		verificationID,
	); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE users SET email_status = 'verified' WHERE id = $1`,
		userID,
	); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// InvalidateAllForUser marks every unused verification for a user as used,
// effectively expiring any outstanding link. Called on resend so old links die.
func (r *VerificationRepo) InvalidateAllForUser(ctx context.Context, userID string) error {
	_, err := r.conn.Pool().Exec(ctx,
		`UPDATE email_verifications SET used_at = NOW()
		  WHERE user_id = $1 AND used_at IS NULL`,
		userID,
	)
	return err
}
