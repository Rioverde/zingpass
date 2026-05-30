package services

import (
	"context"
	stderr "errors"
	"time"

	"github.com/jackc/pgx/v4"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"

	apperr "github.com/Rioverde/zingpass/internal/pkg/errors"
	"github.com/Rioverde/zingpass/internal/pkg/jwt"
	"github.com/Rioverde/zingpass/internal/pkg/log"
	"github.com/Rioverde/zingpass/internal/pkg/validator"
)

const (
	invalidCreds   = "invalid email or password"
	emailTaken     = "user with this email already exists"
	nicknameTaken  = "this nickname is already taken"
	invalidRefresh = "invalid or expired refresh token"
)

type User struct {
	ID           string
	Email        string
	Nickname     string
	PasswordHash string
}

type UserStore interface {
	CreateUser(ctx context.Context, email, nickname, passwordHash string) (id string, err error)
	UserByEmail(ctx context.Context, email string) (User, error)
	UserByNickname(ctx context.Context, nickname string) (User, error)
}

type AuthService struct {
	store      UserStore
	refresh    RefreshTokenStore
	signer     *jwt.Signer
	refreshTTL time.Duration
}

func NewAuthService(store UserStore, refresh RefreshTokenStore, signer *jwt.Signer, refreshTTL time.Duration) *AuthService {
	return &AuthService{store: store, refresh: refresh, signer: signer, refreshTTL: refreshTTL}
}

func (s *AuthService) Register(ctx context.Context, email, nickname, password string) (string, error) {
	logger := log.From(ctx).With(zap.String("email", email), zap.String("nickname", nickname))
	logger.Info("register attempt")

	if err := validator.Email(email); err != nil {
		logger.Warn("register failed: invalid email")
		return "", err
	}
	if err := validator.Nickname(nickname); err != nil {
		logger.Warn("register failed: invalid nickname")
		return "", err
	}
	if err := validator.Password(password); err != nil {
		logger.Warn("register failed: weak password")
		return "", err
	}

	// Email taken?
	_, err := s.store.UserByEmail(ctx, email)
	if err == nil {
		logger.Warn("register failed: email taken")
		return "", apperr.Conflict(apperr.CodeUserExists, emailTaken)
	}
	if !stderr.Is(err, pgx.ErrNoRows) {
		logger.Error("register failed: email lookup", zap.Error(err))
		return "", apperr.Internal(err)
	}

	// Nickname taken?
	_, err = s.store.UserByNickname(ctx, nickname)
	if err == nil {
		logger.Warn("register failed: nickname taken")
		return "", apperr.Conflict(apperr.CodeNicknameTaken, nicknameTaken)
	}
	if !stderr.Is(err, pgx.ErrNoRows) {
		logger.Error("register failed: nickname lookup", zap.Error(err))
		return "", apperr.Internal(err)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		logger.Error("register failed: encryption", zap.Error(err))
		return "", apperr.Internal(err)
	}

	id, err := s.store.CreateUser(ctx, email, nickname, string(hash))
	if err != nil {
		logger.Error("register failed: db insert", zap.Error(err))
		return "", apperr.Internal(err)
	}

	logger.Info("register success", zap.String("user_id", id))
	return id, nil
}

func (s *AuthService) Login(ctx context.Context, email, password, userAgent, ip string) (access, refresh string, err error) {
	logger := log.From(ctx).With(zap.String("email", email), zap.String("ip", ip))
	logger.Info("login attempt")

	user, err := s.store.UserByEmail(ctx, email)
	if err != nil {
		if stderr.Is(err, pgx.ErrNoRows) {
			logger.Warn("login failed: user not found")
			return "", "", apperr.Unauthorized(apperr.CodeInvalidCreds, invalidCreds)
		}
		logger.Error("login failed: db error", zap.Error(err))
		return "", "", apperr.Internal(err)
	}

	logger = logger.With(zap.String("user_id", user.ID))

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		logger.Warn("login failed: wrong password")
		return "", "", apperr.Unauthorized(apperr.CodeInvalidCreds, invalidCreds)
	}

	access, refresh, _, err = s.issueTokens(ctx, user.ID, user.Email, userAgent, ip)
	if err != nil {
		logger.Error("login failed: issue tokens", zap.Error(err))
		return "", "", err
	}

	logger.Info("login success")
	return access, refresh, nil
}
