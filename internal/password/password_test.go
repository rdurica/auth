package password_test

import (
	"testing"

	"github.com/rdurica/auth/internal/password"
)

func TestHashAndVerify(t *testing.T) {
	hash, err := password.Hash("secret-password")
	if err != nil {
		t.Fatal(err)
	}
	ok, err := password.Verify(hash, "secret-password")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected match")
	}
	ok, err = password.Verify(hash, "wrong")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected mismatch")
	}
}

func TestDummyHashVerifies(t *testing.T) {
	ok, err := password.Verify(password.DummyHash, "dummy-password-for-timing-safety")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("dummy hash should verify")
	}
}
