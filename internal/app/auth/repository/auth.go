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

func (r *UserRepo) CreateUser(ctx context.Context, email, hash string) (string, error) {
	var id string
	err := r.conn.Pool().QueryRow(ctx,
		`INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id`,
		email, hash,
	).Scan(&id)
	return id, err
}

func (r *UserRepo) UserByEmail(ctx context.Context, email string) (services.User, error) {
	var u services.User
	err := r.conn.Pool().QueryRow(ctx,
		`SELECT id, email, password_hash FROM users WHERE email = $1`,
		email,
	).Scan(&u.ID, &u.Email, &u.PasswordHash)
	return u, err
}
