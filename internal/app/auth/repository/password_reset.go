package repository

import (
	"context"
	"time"

	"github.com/Rioverde/zingpass/internal/app/auth/models"
	"github.com/Rioverde/zingpass/internal/pkg/db"
)

// PasswordResetRepo persists password-reset tokens. Mirrors VerificationRepo.
type PasswordResetRepo struct {
	conn *db.Connection
}

func NewPasswordResetRepo(conn *db.Connection) *PasswordResetRepo {
	return &PasswordResetRepo{conn: conn}
}

// Create inserts a reset token and returns its server-generated id.
func (r *PasswordResetRepo) Create(ctx context.Context, userID, tokenHash string, expiresAt time.Time) (string, error) {
	var id string
	err := r.conn.Pool().QueryRow(ctx,
		`INSERT INTO password_resets (user_id, token_hash, expires_at)
		 VALUES ($1, $2, $3) RETURNING id`,
		userID, tokenHash, expiresAt,
	).Scan(&id)
	return id, err
}

// ByHash returns the row matching tokenHash. pgx.ErrNoRows when none.
func (r *PasswordResetRepo) ByHash(ctx context.Context, tokenHash string) (models.PasswordReset, error) {
	var p models.PasswordReset
	err := r.conn.Pool().QueryRow(ctx,
		`SELECT id, user_id, token_hash, expires_at, used_at, created_at
		   FROM password_resets
		  WHERE token_hash = $1`,
		tokenHash,
	).Scan(&p.ID, &p.UserID, &p.TokenHash, &p.ExpiresAt, &p.UsedAt, &p.CreatedAt)
	return p, err
}

// Consume marks the token as used AND updates the user's password_hash in one
// transaction. Either both rows update or neither.
func (r *PasswordResetRepo) Consume(ctx context.Context, resetID, userID, newPasswordHash string) error {
	tx, err := r.conn.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx,
		`UPDATE password_resets SET used_at = NOW()
		  WHERE id = $1 AND used_at IS NULL`,
		resetID,
	); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE users SET password_hash = $1 WHERE id = $2`,
		newPasswordHash, userID,
	); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// InvalidateAllForUser marks every unused reset for a user as used, so any
// previously-mailed link stops working when a fresh request is made.
func (r *PasswordResetRepo) InvalidateAllForUser(ctx context.Context, userID string) error {
	_, err := r.conn.Pool().Exec(ctx,
		`UPDATE password_resets SET used_at = NOW()
		  WHERE user_id = $1 AND used_at IS NULL`,
		userID,
	)
	return err
}
