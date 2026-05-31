package models

import "time"

// EmailVerification represents a single email-verification token row.
// Tokens are stored as SHA-256 hex hashes; the plaintext only ever lives in
// the user's inbox. UsedAt becomes non-nil after Consume so the link is
// strictly single-use.
type EmailVerification struct {
	ID        string
	UserID    string
	TokenHash string
	ExpiresAt time.Time
	UsedAt    *time.Time
	CreatedAt time.Time
}
