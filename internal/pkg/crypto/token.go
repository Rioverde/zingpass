package crypto

import (
	"crypto/sha256"
	"encoding/hex"
)

// HashToken returns the SHA-256 hex digest of an opaque session token
// (refresh tokens, email verification links, password reset codes).
// Stored in the DB so that a leaked database does not expose live tokens.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
