package domain_test

import (
	"testing"

	"github.com/rdurica/auth/internal/domain"
)

func TestParsePlainPassword(t *testing.T) {
	p, err := domain.ParsePlainPassword("password123")
	if err != nil {
		t.Fatal(err)
	}
	if p.String() != "password123" {
		t.Fatalf("got %q", p.String())
	}
}

func TestParsePlainPasswordInvalid(t *testing.T) {
	if _, err := domain.ParsePlainPassword("short"); err == nil {
		t.Fatal("expected error")
	}
}
