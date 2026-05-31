package models

import "time"

// RefreshToken represents a persisted refresh token row.
// Tokens are revoked by setting RevokedAt; rotated by creating a new token
// and linking the old one via ReplacedBy. Reuse of a token whose ReplacedBy
// is set is treated as compromise and triggers RevokeAllForUser in the service layer.
type RefreshToken struct {
	ID         string
	UserID     string
	TokenHash  string
	ExpiresAt  time.Time
	CreatedAt  time.Time
	RevokedAt  *time.Time
	ReplacedBy *string
	UserAgent  string
	IP         string
}
