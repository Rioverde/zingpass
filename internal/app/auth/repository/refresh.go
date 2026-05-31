package repository

import (
	"context"
	"time"

	"github.com/Rioverde/zingpass/internal/app/auth/models"
	"github.com/Rioverde/zingpass/internal/pkg/db"
)

// RefreshRepo provides data access for refresh tokens.
// It wraps a shared *db.Connection and isolates SQL queries related to token
// lifecycle management (creation, lookup, revocation, and rotation).
// Callers should check errors with errors.Is(err, pgx.ErrNoRows) to distinguish
// "token not found" from actual database failures.
type RefreshRepo struct {
	conn *db.Connection
}

// NewRefreshRepo creates a new RefreshRepo with the given database connection.
func NewRefreshRepo(conn *db.Connection) *RefreshRepo {
	return &RefreshRepo{conn: conn}
}

// Create inserts a new refresh token and returns its generated UUID.
// The UUID is generated server-side by Postgres.
func (r *RefreshRepo) Create(ctx context.Context, userID, tokenHash string, expiresAt time.Time, userAgent, ip string) (string, error) {
	var id string
	err := r.conn.Pool().QueryRow(ctx,
		`INSERT INTO refresh_tokens (user_id, token_hash, expires_at, user_agent, ip)
        VALUES ($1, $2, $3, $4, $5) RETURNING id`,
		userID, tokenHash, expiresAt, userAgent, ip,
	).Scan(&id)

	return id, err
}

// ByHash retrieves a refresh token by its token hash.
// Nullable fields (revoked_at, replaced_by, user_agent, ip) are scanned into
// *time.Time and *string pointers for true NULL values. COALESCE is used on string
// fields to avoid pgx scan errors when the database column is NULL, ensuring
// empty strings are returned instead of failing to scan nil into a non-pointer string field.
// Returns pgx.ErrNoRows if the token does not exist.
func (r *RefreshRepo) ByHash(ctx context.Context, tokenHash string) (models.RefreshToken, error) {
	var rt models.RefreshToken

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

// Revoke marks a token as revoked by setting revoked_at to NOW().
// The WHERE clause includes AND revoked_at IS NULL to make the operation idempotent;
// repeated calls are safe and do not error.
func (r *RefreshRepo) Revoke(ctx context.Context, id string) error {
	_, err := r.conn.Pool().Exec(ctx,
		`UPDATE refresh_tokens SET revoked_at = NOW() WHERE id = $1 AND revoked_at IS NULL`,
		id,
	)
	return err
}

// RevokeAllForUser revokes all non-revoked tokens for a given user.
// This is called by the service layer when a reuse-attack is detected, treating
// all tokens for that user as potentially compromised.
func (r *RefreshRepo) RevokeAllForUser(ctx context.Context, userID string) error {
	_, err := r.conn.Pool().Exec(ctx,
		`UPDATE refresh_tokens SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL`,
		userID,
	)
	return err
}

// MarkReplaced marks an old token as replaced by a new one and revokes it atomically.
// This implements token rotation: the old token's replaced_by is set to newID and
// revoked_at is set to NOW() in a single atomic update. Parameter order is critical:
// $1 is oldID (the WHERE clause target) and $2 is newID (the replaced_by value).
func (r *RefreshRepo) MarkReplaced(ctx context.Context, oldID, newID string) error {
	_, err := r.conn.Pool().Exec(ctx,
		`UPDATE refresh_tokens SET replaced_by = $2, revoked_at = NOW() WHERE id = $1`,
		oldID, newID,
	)
	return err
}
