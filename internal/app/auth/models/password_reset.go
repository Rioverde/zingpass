package models

import "time"

// PasswordReset is a one-time, time-bound token a user clicks to set a new password.
// The token's plaintext lives only in the user's inbox; the DB stores its SHA-256.
type PasswordReset struct {
	ID        string
	UserID    string
	TokenHash string
	ExpiresAt time.Time
	UsedAt    *time.Time
	CreatedAt time.Time
}
