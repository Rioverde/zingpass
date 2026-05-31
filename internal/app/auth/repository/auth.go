package repository

import (
	"context"

	"github.com/Rioverde/zingpass/internal/app/auth/models"
	"github.com/Rioverde/zingpass/internal/pkg/db"
)

// UserRepo provides data access for user accounts.
// It wraps a shared *db.Connection and isolates SQL queries related to user
// authentication and lookup. Callers should check errors with errors.Is(err, pgx.ErrNoRows)
// to distinguish "user not found" from actual database failures.
type UserRepo struct {
	conn *db.Connection
}

// NewUserRepo creates a new UserRepo with the given database connection.
func NewUserRepo(conn *db.Connection) *UserRepo {
	return &UserRepo{conn: conn}
}

// CreateUser inserts a new user (unverified) and returns its generated UUID.
// The UUID is generated server-side by Postgres, so callers do not provide an id.
// email_status defaults to 'unverified' — sent via the standard /auth/register flow.
func (r *UserRepo) CreateUser(ctx context.Context, email, nickname, hash string) (string, error) {
	var id string
	err := r.conn.Pool().QueryRow(ctx,
		`INSERT INTO users (email, nickname, password_hash) VALUES ($1, $2, $3) RETURNING id`,
		email, nickname, hash,
	).Scan(&id)
	return id, err
}

// CreateVerifiedUser inserts a new user with email_status='verified' and returns its UUID.
// Use for OAuth signup where the provider has already proven email ownership
// (e.g., a verified primary email returned by /user/emails on GitHub).
func (r *UserRepo) CreateVerifiedUser(ctx context.Context, email, nickname, hash string) (string, error) {
	var id string
	err := r.conn.Pool().QueryRow(ctx,
		`INSERT INTO users (email, nickname, password_hash, email_status)
		 VALUES ($1, $2, $3, 'verified') RETURNING id`,
		email, nickname, hash,
	).Scan(&id)
	return id, err
}

// UserByEmail retrieves a user by exact email match.
// Returns pgx.ErrNoRows if the user does not exist.
func (r *UserRepo) UserByEmail(ctx context.Context, email string) (models.User, error) {
	var u models.User
	var nickname *string
	err := r.conn.Pool().QueryRow(ctx,
		`SELECT id, email, nickname, password_hash, email_status FROM users WHERE email = $1`,
		email,
	).Scan(&u.ID, &u.Email, &nickname, &u.PasswordHash, &u.EmailStatus)
	if nickname != nil {
		u.Nickname = *nickname
	}
	return u, err
}

// UserByNickname retrieves a user by case-insensitive nickname match.
// Both the query and the database index use LOWER() to ensure consistent,
// case-insensitive lookups. Returns pgx.ErrNoRows if no user matches the nickname.
func (r *UserRepo) UserByNickname(ctx context.Context, nickname string) (models.User, error) {
	var u models.User
	var nick *string
	err := r.conn.Pool().QueryRow(ctx,
		`SELECT id, email, nickname, password_hash, email_status FROM users WHERE LOWER(nickname) = LOWER($1)`,
		nickname,
	).Scan(&u.ID, &u.Email, &nick, &u.PasswordHash, &u.EmailStatus)
	if nick != nil {
		u.Nickname = *nick
	}
	return u, err
}
