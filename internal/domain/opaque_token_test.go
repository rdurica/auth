package domain_test

import (
	"strings"
	"testing"

	"github.com/rdurica/auth/internal/domain"
)

func TestParseOpaqueToken(t *testing.T) {
	raw := strings.Repeat("ab", 32)
	tok, err := domain.ParseOpaqueToken(raw)
	if err != nil {
		t.Fatal(err)
	}
	if tok.String() != raw {
		t.Fatalf("got %q", tok.String())
	}
}

func TestParseOpaqueTokenInvalid(t *testing.T) {
	if _, err := domain.ParseOpaqueToken("short"); err == nil {
		t.Fatal("expected error")
	}
	if _, err := domain.ParseOpaqueToken(strings.Repeat("ZZ", 32)); err == nil {
		t.Fatal("expected error for non-hex")
	}
}
