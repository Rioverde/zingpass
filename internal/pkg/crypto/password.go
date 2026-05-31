package crypto

import "golang.org/x/crypto/bcrypt"

// HashPassword bcrypts a plaintext password at the default cost.
// Use for user-provided passwords during Register / password change / reset.
func HashPassword(plaintext string) (string, error) {
	return hashBytes([]byte(plaintext))
}

// RandomPasswordHash returns a bcrypt hash of cryptographically random bytes.
// Use for OAuth-only users so /auth/login with any password cannot succeed.
func RandomPasswordHash() (string, error) {
	buf, err := RandomBytes(32)
	if err != nil {
		return "", err
	}
	return hashBytes(buf)
}

// ComparePassword reports whether the provided plaintext matches the stored bcrypt hash.
func ComparePassword(hash, plaintext string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plaintext))
}

func hashBytes(p []byte) (string, error) {
	h, err := bcrypt.GenerateFromPassword(p, bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(h), nil
}
