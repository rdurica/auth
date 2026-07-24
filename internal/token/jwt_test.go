package token_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rdurica/auth/internal/domain"
	"github.com/rdurica/auth/internal/token"
)

func TestJWTIssueAndParse(t *testing.T) {
	dir := t.TempDir()
	privPath, pubPath := writeTempRSAKeys(t, dir)

	svc, err := token.NewJWTService(privPath, pubPath, "auth", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	id := uuid.Must(uuid.NewV7())
	raw, err := svc.Issue(id, []string{domain.RoleUser})
	if err != nil {
		t.Fatal(err)
	}

	claims, err := svc.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if claims.UUID != id.String() {
		t.Fatalf("uuid=%s want %s", claims.UUID, id.String())
	}
	if len(claims.Roles) != 1 || claims.Roles[0] != domain.RoleUser {
		t.Fatalf("roles=%v", claims.Roles)
	}
}

func TestJWTRejectsTampered(t *testing.T) {
	dir := t.TempDir()
	privPath, pubPath := writeTempRSAKeys(t, dir)
	svc, err := token.NewJWTService(privPath, pubPath, "auth", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := svc.Issue(uuid.Must(uuid.NewV7()), nil)
	if err != nil {
		t.Fatal(err)
	}
	tampered := raw + "x"
	if _, err := svc.Parse(tampered); err == nil {
		t.Fatal("expected error")
	}
}

func TestNewOpaqueLength(t *testing.T) {
	tok, err := token.NewOpaque()
	if err != nil {
		t.Fatal(err)
	}
	if len(tok) != 64 {
		t.Fatalf("len=%d", len(tok))
	}
}

func writeTempRSAKeys(t *testing.T, dir string) (string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	privPath := filepath.Join(dir, "private.pem")
	pubPath := filepath.Join(dir, "public.pem")

	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	pubBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})

	if err := os.WriteFile(privPath, privPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pubPath, pubPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	return privPath, pubPath
}
