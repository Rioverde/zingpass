package models

// User represents a local user account with email-based credentials.
// PasswordHash is the bcrypt hash; never the plaintext password.
type User struct {
	ID           string
	Email        string
	Nickname     string
	PasswordHash string
}
