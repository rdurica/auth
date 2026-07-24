package httpapi

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
)

type JWKSHandler struct {
	KeyID     string
	PublicKey *rsa.PublicKey
}

func (h *JWKSHandler) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	n := base64.RawURLEncoding.EncodeToString(h.PublicKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(h.PublicKey.E)).Bytes())
	resp := map[string]any{
		"keys": []map[string]string{
			{
				"kty": "RSA",
				"use": "sig",
				"alg": "RS256",
				"kid": h.KeyID,
				"n":   n,
				"e":   e,
			},
		},
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_ = json.NewEncoder(w).Encode(resp)
}
