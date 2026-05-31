package services

import (
	"context"
	stderr "errors"
	"time"

	"github.com/jackc/pgx/v4"
	"go.uber.org/zap"
	"golang.org/x/oauth2"

	"github.com/Rioverde/zingpass/internal/app/auth/models"
	"github.com/Rioverde/zingpass/internal/pkg/crypto"
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

// UserProvider defines the contract for user persistence. AuthService depends on this interface
// rather than concrete storage implementations, enabling testability and pluggable backends.
type UserProvider interface {
	CreateUser(ctx context.Context, email, nickname, passwordHash string) (id string, err error)
	UserByEmail(ctx context.Context, email string) (models.User, error)
	UserByNickname(ctx context.Context, nickname string) (models.User, error)
}

// AuthService is the core business logic for authentication and authorization.
// It orchestrates user registration, login, token refresh, logout, and OAuth flows
// through pluggable provider interfaces, ensuring the service remains testable and decoupled
// from storage implementation details.
type AuthService struct {
	store        UserProvider
	refresh      RefreshTokenProvider
	signer       *jwt.Signer
	refreshTTL   time.Duration
	oauth        OAuthAccountStore
	githubConfig *oauth2.Config
}

// NewAuthService constructs an AuthService with the given provider implementations and configuration.
// All providers are required and should not be nil.
func NewAuthService(
	store UserProvider,
	refresh RefreshTokenProvider,
	oauth OAuthAccountStore,
	githubConfig *oauth2.Config,
	signer *jwt.Signer,
	refreshTTL time.Duration,
) *AuthService {
	return &AuthService{
		store:        store,
		refresh:      refresh,
		oauth:        oauth,
		githubConfig: githubConfig,
		signer:       signer,
		refreshTTL:   refreshTTL,
	}
}

// Register creates a new local user account with the given credentials.
// It validates email format, nickname format, and password strength before querying the database,
// avoiding wasted lookups on invalid input. Both email and nickname must be globally unique.
// The password is hashed using bcrypt before storage. Returns the created user ID or an error.
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

	hash, err := crypto.HashPassword(password)
	if err != nil {
		logger.Error("register failed: encryption", zap.Error(err))
		return "", apperr.Internal(err)
	}

	id, err := s.store.CreateUser(ctx, email, nickname, hash)
	if err != nil {
		logger.Error("register failed: db insert", zap.Error(err))
		return "", apperr.Internal(err)
	}

	logger.Info("register success", zap.String("user_id", id))
	return id, nil
}

// Login authenticates a user by email and password, returning an access token and refresh token.
// Returns the same generic error ("invalid email or password") whether the user does not exist or
// the password is wrong, preventing attackers from enumerating valid email addresses in the system.
// On success, issues a new access JWT and persists a refresh token row.
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

	if err := crypto.ComparePassword(user.PasswordHash, password); err != nil {
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
