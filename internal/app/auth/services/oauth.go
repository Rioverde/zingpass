package services

import (
	"context"
	"encoding/json"
	stderr "errors"
	"net/http"
	"strconv"

	"github.com/jackc/pgx/v4"
	"go.uber.org/zap"

	"github.com/Rioverde/zingpass/internal/app/auth/models"
	"github.com/Rioverde/zingpass/internal/pkg/crypto"
	apperr "github.com/Rioverde/zingpass/internal/pkg/errors"
	"github.com/Rioverde/zingpass/internal/pkg/log"
)

// GitHub REST API endpoints used by the service.
const (
	githubUserURL   = "https://api.github.com/user"
	githubEmailsURL = "https://api.github.com/user/emails"
)

// githubUser represents the GitHub user response from GET /user.
// Email is only present if the user made it public.
type githubUser struct {
	ID    int64  `json:"id"`
	Email string `json:"email"`
	Login string `json:"login"`
}

// OAuthAccountStore persists links between local users and external OAuth provider identities.
// The same interface serves all providers—only the provider string changes. This design allows
// straightforward addition of new providers without modifying the storage layer.
type OAuthAccountStore interface {
	// FindUserByProvider returns the local user_id linked to (provider, providerUserID).
	// Returns pgx.ErrNoRows if no link exists.
	FindUserByProvider(ctx context.Context, provider, providerUserID string) (userID string, err error)

	// LinkAccount inserts a new (provider, providerUserID) → user link.
	// Returns the link's id.
	LinkAccount(ctx context.Context, acc models.OAuthAccount) (id string, err error)

	// UnlinkAccount removes a single provider link from a user.
	UnlinkAccount(ctx context.Context, userID, provider string) error

	// ListAccountsForUser returns every linked external account for a user.
	ListAccountsForUser(ctx context.Context, userID string) ([]models.OAuthAccount, error)
}

// GithubAuthURL returns the authorization URL for the GitHub OAuth flow.
// The state parameter is round-tripped back to /auth/github/callback for CSRF protection.
// This is a thin wrapper that hides oauth2.Config from handlers.
func (s *AuthService) GithubAuthURL(state string) string {
	return s.githubConfig.AuthCodeURL(state)
}

// LoginViaGithub completes the GitHub OAuth flow, exchanging an authorization code for user identity
// and issuing access and refresh tokens. The lookup order is strict and important: first check if
// the GitHub user_id is already linked to a local account; if not, try matching the GitHub email
// against existing local users (safe because GitHub only returns public emails, which are verified);
// finally, create a brand-new user with a random password hash to ensure the account is OAuth-only
// and cannot be accessed via /auth/login with any password.
func (s *AuthService) LoginViaGithub(ctx context.Context, code, userAgent, ip string) (access, refresh string, err error) {
	logger := log.From(ctx).With(zap.String("ip", ip), zap.String("provider", models.ProviderGithub))
	logger.Info("oauth login attempt")

	// Exchange code → token
	token, err := s.githubConfig.Exchange(ctx, code)
	if err != nil {
		logger.Warn("oauth login failed: invalid code", zap.Error(err))
		return "", "", apperr.Unauthorized(apperr.CodeTokenInvalid, "invalid github code")
	}

	// Fetch github user
	client := s.githubConfig.Client(ctx, token)
	resp, err := client.Get(githubUserURL)
	if err != nil {
		logger.Error("oauth login failed: github api unreachable", zap.Error(err))
		return "", "", apperr.Internal(err)
	}
	defer resp.Body.Close()

	var gh githubUser
	if err := json.NewDecoder(resp.Body).Decode(&gh); err != nil {
		logger.Error("oauth login failed: decode github user", zap.Error(err))
		return "", "", apperr.Internal(err)
	}

	if gh.Email == "" {
		// Public email is hidden; fall back to the user:email scoped endpoint.
		gh.Email, err = fetchGithubPrimaryEmail(client)
		if err != nil {
			logger.Error("oauth login failed: fetch github emails", zap.Error(err))
			return "", "", apperr.Internal(err)
		}
		if gh.Email == "" {
			logger.Warn("oauth login failed: no verified primary email on github")
			return "", "", apperr.BadRequest(apperr.CodeGithubEmailMissing, "no verified primary email on github")
		}
	}

	githubID := strconv.FormatInt(gh.ID, 10)
	logger = logger.With(zap.String("github_id", githubID), zap.String("email", gh.Email))

	// Find by github_id.
	userID, err := s.oauth.FindUserByProvider(ctx, models.ProviderGithub, githubID)
	switch {
	case err == nil:
		// Linked already — straight to token issuance.
	case stderr.Is(err, pgx.ErrNoRows):
		// Not linked. Try matching local user by email; if none, create one.
		existing, lookupErr := s.store.UserByEmail(ctx, gh.Email)
		switch {
		case lookupErr == nil:
			// Email matches an existing local user → link to that user.
			// SECURITY NOTE: only safe if we trust the github email is verified.
			// GET /user only returns email when user made it public; we assume verified.
			userID = existing.ID
			logger.Info("oauth: linking to existing user by email", zap.String("user_id", userID))
		case stderr.Is(lookupErr, pgx.ErrNoRows):
			// Brand new user. Use a random bcrypt hash so /auth/login
			// with any password cannot succeed — this user is OAuth-only.
			pwdHash, hashErr := crypto.RandomPasswordHash()
			if hashErr != nil {
				logger.Error("oauth login failed: random password hash", zap.Error(hashErr))
				return "", "", apperr.Internal(hashErr)
			}
			// GitHub already proved email ownership (public or verified primary in /user/emails),
			// so create the user pre-verified — they should not be forced through /verify.
			userID, err = s.store.CreateVerifiedUser(ctx, gh.Email, gh.Login, pwdHash)
			if err != nil {
				logger.Error("oauth login failed: create user", zap.Error(err))
				return "", "", apperr.Internal(err)
			}
			logger.Info("oauth: created new user", zap.String("user_id", userID))
		default:
			logger.Error("oauth login failed: user lookup", zap.Error(lookupErr))
			return "", "", apperr.Internal(lookupErr)
		}

		// Persist the github → user_id link.
		if _, err = s.oauth.LinkAccount(ctx, models.OAuthAccount{
			UserID:           userID,
			Provider:         models.ProviderGithub,
			ProviderUserID:   githubID,
			ProviderEmail:    gh.Email,
			ProviderUsername: gh.Login,
		}); err != nil {
			logger.Error("oauth login failed: link account", zap.Error(err))
			return "", "", apperr.Internal(err)
		}
	default:
		logger.Error("oauth login failed: provider lookup", zap.Error(err))
		return "", "", apperr.Internal(err)
	}

	access, refresh, _, err = s.issueTokens(ctx, userID, gh.Email, userAgent, ip)
	if err != nil {
		logger.Error("oauth login failed: issue tokens", zap.Error(err))
		return "", "", err
	}

	logger.Info("oauth login success", zap.String("user_id", userID))
	return access, refresh, nil
}

// fetchGithubPrimaryEmail calls GET /user/emails and returns the verified primary email.
// Requires the user:email scope. Returns "" if no email is both primary and verified.
func fetchGithubPrimaryEmail(client *http.Client) (string, error) {
	resp, err := client.Get(githubEmailsURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
		return "", err
	}

	for _, e := range emails {
		if e.Primary && e.Verified {
			return e.Email, nil
		}
	}
	return "", nil
}
