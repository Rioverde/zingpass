package crypto

import (
	"crypto/rand"
	"encoding/hex"
)

// RandomBytes fills n bytes from crypto/rand.
func RandomBytes(n int) ([]byte, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// RandomHex returns 2*n hex characters of cryptographically random data.
func RandomHex(n int) (string, error) {
	buf, err := RandomBytes(n)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
