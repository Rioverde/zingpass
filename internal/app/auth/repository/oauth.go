package repository

import (
	"context"

	"github.com/Rioverde/zingpass/internal/app/auth/models"
	"github.com/Rioverde/zingpass/internal/pkg/db"
)

// OAuthRepo provides data access for OAuth account linkage.
// It wraps a shared *db.Connection and isolates SQL queries related to OAuth
// provider integrations and account linking. Callers should check errors with
// errors.Is(err, pgx.ErrNoRows) to distinguish "account not found" from actual
// database failures.
type OAuthRepo struct {
	conn *db.Connection
}

// NewOAuthRepo creates a new OAuthRepo with the given database connection.
func NewOAuthRepo(conn *db.Connection) *OAuthRepo {
	return &OAuthRepo{conn: conn}
}

// FindUserByProvider retrieves the local user ID for an OAuth account.
// The lookup key is the (provider, provider_user_id) tuple, which matches the
// UNIQUE constraint in the database. This allows users to link multiple OAuth
// providers while maintaining a single local user identity.
// Returns pgx.ErrNoRows if no linked account exists for this provider and provider user ID.
func (r *OAuthRepo) FindUserByProvider(ctx context.Context, provider, providerUserID string) (string, error) {
	var userID string
	err := r.conn.Pool().QueryRow(ctx,
		`SELECT user_id FROM oauth_accounts WHERE provider = $1 AND provider_user_id = $2`,
		provider, providerUserID,
	).Scan(&userID)
	return userID, err
}

// LinkAccount creates a new OAuth account link for a user and returns the generated UUID.
// The provider_email and provider_username fields are snapshots of the OAuth provider's
// current user profile data at the time of linking. These values may diverge from the
// user's local email and nickname as the user updates their OAuth provider profile,
// and they are not automatically synchronized.
func (r *OAuthRepo) LinkAccount(ctx context.Context, acc models.OAuthAccount) (string, error) {
	var id string
	err := r.conn.Pool().QueryRow(ctx,
		`INSERT INTO oauth_accounts (user_id, provider, provider_user_id, provider_email, provider_username)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING id`,
		acc.UserID, acc.Provider, acc.ProviderUserID, acc.ProviderEmail, acc.ProviderUsername,
	).Scan(&id)
	return id, err
}

// UnlinkAccount removes an OAuth account link for a user.
// The deletion is identified by the (user_id, provider) pair.
func (r *OAuthRepo) UnlinkAccount(ctx context.Context, userID, provider string) error {
	_, err := r.conn.Pool().Exec(ctx,
		`DELETE FROM oauth_accounts WHERE user_id = $1 AND provider = $2`,
		userID, provider,
	)
	return err
}

// ListAccountsForUser retrieves all OAuth accounts linked to a user, ordered by creation time.
// Provider email and username fields use COALESCE to return empty strings instead of nil
// for null database values, avoiding pgx scan errors on nil pointers to non-pointer string fields.
func (r *OAuthRepo) ListAccountsForUser(ctx context.Context, userID string) ([]models.OAuthAccount, error) {
	rows, err := r.conn.Pool().Query(ctx,
		`SELECT id, user_id, provider, provider_user_id,
		        COALESCE(provider_email, ''), COALESCE(provider_username, ''),
		        created_at, updated_at
		 FROM oauth_accounts
		 WHERE user_id = $1
		 ORDER BY created_at`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var accounts []models.OAuthAccount
	for rows.Next() {
		var acc models.OAuthAccount
		if err := rows.Scan(
			&acc.ID, &acc.UserID, &acc.Provider, &acc.ProviderUserID,
			&acc.ProviderEmail, &acc.ProviderUsername,
			&acc.CreatedAt, &acc.UpdatedAt,
		); err != nil {
			return nil, err
		}
		accounts = append(accounts, acc)
	}
	return accounts, rows.Err()
}
