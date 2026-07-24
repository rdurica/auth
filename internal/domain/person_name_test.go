package domain_test

import (
	"testing"

	"github.com/rdurica/auth/internal/domain"
)

func TestParsePersonName(t *testing.T) {
	n, err := domain.ParsePersonNameField("  Jan  ", "firstName")
	if err != nil {
		t.Fatal(err)
	}
	if n.String() != "Jan" {
		t.Fatalf("got %q", n.String())
	}
}

func TestParsePersonNameInvalid(t *testing.T) {
	if _, err := domain.ParsePersonNameField("A", "firstName"); err == nil {
		t.Fatal("expected error")
	}
	if _, err := domain.ParsePersonNameField("abcdefghijklmnopqrstuvwxyz", "lastName"); err == nil {
		t.Fatal("expected error")
	}
}
