package services

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"time"

	apperr "github.com/Rioverde/zingpass/internal/pkg/errors"
)

// hashToken returns the SHA-256 hex digest of a token.
// Used to look up stored tokens without keeping the plaintext in the DB.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// issueTokens generates a new refresh token, persists it, and signs an access JWT.
// Used by both Login (initial issuance) and Refresh (rotation).
// Returns the access token, plaintext refresh token, and the DB id of the new refresh row.
func (s *AuthService) issueTokens(ctx context.Context, userID, email, userAgent, ip string) (access, refresh, newID string, err error) {
	// Generate a 256-bit random refresh token.
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", "", "", apperr.Internal(err)
	}
	refresh = hex.EncodeToString(buf)

	// Store the hash, not the token itself.
	newID, err = s.refresh.Create(ctx, userID, hashToken(refresh), time.Now().Add(s.refreshTTL), userAgent, ip)
	if err != nil {
		return "", "", "", apperr.Internal(err)
	}

	// Mint a fresh short-lived access JWT.
	access, err = s.signer.Sign(userID, email)
	if err != nil {
		return "", "", "", apperr.Internal(err)
	}

	return access, refresh, newID, nil
}
