package models

import "time"

// Supported external identity providers. Used as keys in oauth_accounts.provider.
const (
	ProviderGithub   = "github"
	ProviderGoogle   = "google"
	ProviderFacebook = "facebook"
	ProviderApple    = "apple"
)

// OAuthAccount links a local user to one external provider identity.
// ProviderEmail and ProviderUsername are snapshots from the provider at the time
// of linking; they may diverge from the local user's data and are not auto-synced.
type OAuthAccount struct {
	ID               string
	UserID           string
	Provider         string
	ProviderUserID   string
	ProviderEmail    string
	ProviderUsername string
	CreatedAt        time.Time
	UpdatedAt        time.Time
}
