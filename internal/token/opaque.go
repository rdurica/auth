package token

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

func NewOpaque() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate opaque token: %w", err)
	}
	return hex.EncodeToString(buf), nil
}
