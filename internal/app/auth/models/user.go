package models

// EmailStatus is the lifecycle state of a user's email address.
// Stored as TEXT with a CHECK constraint; keep these values in sync with
// the constraint in migration 0005_email_verification.sql.
type EmailStatus string

const (
	// EmailStatusUnverified — fresh signup, no verification link clicked yet.
	EmailStatusUnverified EmailStatus = "unverified"
	// EmailStatusVerified — user proved ownership of the address.
	EmailStatusVerified EmailStatus = "verified"
	// EmailStatusPending — a re-verification email was sent, awaiting click.
	EmailStatusPending EmailStatus = "pending"
	// EmailStatusBounced — the mail provider rejected delivery; do not retry.
	EmailStatusBounced EmailStatus = "bounced"
	// EmailStatusBlocked — admin/anti-abuse hard block; do not send.
	EmailStatusBlocked EmailStatus = "blocked"
)

// IsVerified reports whether the user may sign in with this email.
func (s EmailStatus) IsVerified() bool { return s == EmailStatusVerified }

// User represents a local user account with email-based credentials.
// PasswordHash is the bcrypt hash; never the plaintext password.
type User struct {
	ID           string
	Email        string
	Nickname     string
	PasswordHash string
	EmailStatus  EmailStatus
}
