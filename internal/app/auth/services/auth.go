package services

import (
	"context"
	stderr "errors"

	"github.com/jackc/pgx/v4"
	"golang.org/x/crypto/bcrypt"

	apperr "github.com/Rioverde/zingpass/internal/pkg/errors"
	"github.com/Rioverde/zingpass/internal/pkg/jwt"
	"github.com/Rioverde/zingpass/internal/pkg/validator"
)

const (
	invalidCreds  = "invalid email or password"
	alreadyExists = "user with this email already exists"
)

type User struct {
	ID           string
	Email        string
	PasswordHash string
}

type UserStore interface {
	CreateUser(ctx context.Context, email, passwordHash string) (id string, err error)
	UserByEmail(ctx context.Context, email string) (User, error)
}

type AuthService struct {
	store  UserStore
	signer *jwt.Signer
}

func NewAuthService(store UserStore, signer *jwt.Signer) *AuthService {
	return &AuthService{store: store, signer: signer}
}
func (s *AuthService) Register(ctx context.Context, email, password string) (string, error) {
	if err := validator.Email(email); err != nil {
		return "", err
	}
	if err := validator.Password(password); err != nil {
		return "", err
	}

	_, err := s.store.UserByEmail(ctx, email)
	if err == nil {
		return "", apperr.Conflict(apperr.CodeUserExists, alreadyExists)
	}
	if !stderr.Is(err, pgx.ErrNoRows) {
		return "", apperr.Internal(err)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", apperr.Internal(err)
	}

	id, err := s.store.CreateUser(ctx, email, string(hash))
	if err != nil {
		return "", apperr.Internal(err)
	}

	return id, nil
}

func (s *AuthService) Login(ctx context.Context, email, password string) (string, error) {
	user, err := s.store.UserByEmail(ctx, email)
	if err != nil {
		if stderr.Is(err, pgx.ErrNoRows) {
			return "", apperr.Unauthorized(apperr.CodeInvalidCreds, invalidCreds)
		}
		return "", apperr.Internal(err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return "", apperr.Unauthorized(apperr.CodeInvalidCreds, invalidCreds)
	}

	token, err := s.signer.Sign(user.ID, user.Email)
	if err != nil {
		return "", apperr.Internal(err)
	}

	return token, nil
}
