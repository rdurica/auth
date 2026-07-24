package domain_test

import (
	"testing"

	"github.com/rdurica/auth/internal/domain"
)

func TestParseEmail(t *testing.T) {
	email, err := domain.ParseEmail("  Test@Example.com ")
	if err != nil {
		t.Fatal(err)
	}
	if email.String() != "test@example.com" {
		t.Fatalf("got %q", email.String())
	}
}

func TestParseEmailInvalid(t *testing.T) {
	cases := []string{"", "nodomain", "@x.com", "a@", "a@b@c.com"}
	for _, raw := range cases {
		if _, err := domain.ParseEmail(raw); err == nil {
			t.Fatalf("expected error for %q", raw)
		}
	}
}
