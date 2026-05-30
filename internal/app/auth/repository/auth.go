package repository

import (
	"context"

	"github.com/Rioverde/zingpass/internal/app/auth/services"
	"github.com/Rioverde/zingpass/internal/pkg/db"
)

type UserRepo struct {
	conn *db.Connection
}

func NewUserRepo(conn *db.Connection) *UserRepo {
	return &UserRepo{conn: conn}
}

func (r *UserRepo) CreateUser(ctx context.Context, email, nickname, hash string) (string, error) {
	var id string
	err := r.conn.Pool().QueryRow(ctx,
		`INSERT INTO users (email, nickname, password_hash) VALUES ($1, $2, $3) RETURNING id`,
		email, nickname, hash,
	).Scan(&id)
	return id, err
}

func (r *UserRepo) UserByEmail(ctx context.Context, email string) (services.User, error) {
	var u services.User
	var nickname *string
	err := r.conn.Pool().QueryRow(ctx,
		`SELECT id, email, nickname, password_hash FROM users WHERE email = $1`,
		email,
	).Scan(&u.ID, &u.Email, &nickname, &u.PasswordHash)
	if nickname != nil {
		u.Nickname = *nickname
	}
	return u, err
}

func (r *UserRepo) UserByNickname(ctx context.Context, nickname string) (services.User, error) {
	var u services.User
	var nick *string
	err := r.conn.Pool().QueryRow(ctx,
		`SELECT id, email, nickname, password_hash FROM users WHERE LOWER(nickname) = LOWER($1)`,
		nickname,
	).Scan(&u.ID, &u.Email, &nick, &u.PasswordHash)
	if nick != nil {
		u.Nickname = *nick
	}
	return u, err
}
