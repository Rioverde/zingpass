package repository

import (
	"context"
	"time"

	"github.com/Rioverde/zingpass/internal/app/auth/services"
	"github.com/Rioverde/zingpass/internal/pkg/db"
)

type RefreshRepo struct {
	conn *db.Connection
}

func NewRefreshRepo(conn *db.Connection) *RefreshRepo {
	return &RefreshRepo{conn: conn}
}

func (r *RefreshRepo) Create(ctx context.Context, userID, tokenHash string, expiresAt time.Time, userAgent, ip string) (string, error) {
	var id string
	err := r.conn.Pool().QueryRow(ctx,
		`INSERT INTO refresh_tokens (user_id, token_hash, expires_at, user_agent, ip)
        VALUES ($1, $2, $3, $4, $5) RETURNING id`,
		userID, tokenHash, expiresAt, userAgent, ip,
	).Scan(&id)

	return id, err
}

func (r *RefreshRepo) ByHash(ctx context.Context, tokenHash string) (services.RefreshToken, error) {
	var rt services.RefreshToken

	err := r.conn.Pool().QueryRow(ctx,
		`SELECT id, user_id, token_hash, expires_at, created_at,
              revoked_at, replaced_by,
              COALESCE(user_agent, '') AS user_agent,
              COALESCE(ip::text, '')   AS ip
       FROM refresh_tokens WHERE token_hash = $1`,
		tokenHash,
	).Scan(
		&rt.ID,
		&rt.UserID,
		&rt.TokenHash,
		&rt.ExpiresAt,
		&rt.CreatedAt,
		&rt.RevokedAt,
		&rt.ReplacedBy,
		&rt.UserAgent,
		&rt.IP,
	)
	return rt, err
}

func (r *RefreshRepo) Revoke(ctx context.Context, id string) error {
	_, err := r.conn.Pool().Exec(ctx,
		`UPDATE refresh_tokens SET revoked_at = NOW() WHERE id = $1 AND revoked_at IS NULL`,
		id,
	)
	return err
}

func (r *RefreshRepo) RevokeAllForUser(ctx context.Context, userID string) error {
	_, err := r.conn.Pool().Exec(ctx,
		`UPDATE refresh_tokens SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL`,
		userID,
	)
	return err
}

func (r *RefreshRepo) MarkReplaced(ctx context.Context, oldID, newID string) error {
	_, err := r.conn.Pool().Exec(ctx,
		`UPDATE refresh_tokens SET replaced_by = $2, revoked_at = NOW() WHERE id = $1`,
		oldID, newID,
	)
	return err
}
