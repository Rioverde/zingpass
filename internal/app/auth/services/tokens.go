package services

import (
	"context"
	"time"

	apperr "github.com/Rioverde/zingpass/internal/pkg/errors"
	"github.com/Rioverde/zingpass/internal/pkg/crypto"
)

// issueTokens atomically generates a new refresh token, persists it to the database, and signs an
// access JWT. This is the single place where both Login and Refresh coordinate token issuance,
// ensuring they stay in sync. The refresh token is persisted first (atomically, by the provider)
// before the access token is signed. Returns the access token, plaintext refresh token (to return
// to the client), and the database ID of the new refresh row (for rotation tracking).
func (s *AuthService) issueTokens(ctx context.Context, userID, email, userAgent, ip string) (access, refresh, newID string, err error) {
	refresh, err = crypto.RandomHex(32)
	if err != nil {
		return "", "", "", apperr.Internal(err)
	}

	newID, err = s.refresh.Create(ctx, userID, crypto.HashToken(refresh), time.Now().Add(s.refreshTTL), userAgent, ip)
	if err != nil {
		return "", "", "", apperr.Internal(err)
	}

	access, err = s.signer.Sign(userID, email)
	if err != nil {
		return "", "", "", apperr.Internal(err)
	}

	return access, refresh, newID, nil
}
