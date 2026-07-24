package domain_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/rdurica/auth/internal/domain"
)

func TestRegisterAndVerifyEmail(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	email := domain.MustParseEmail("a@example.com")
	first, _ := domain.ParsePersonNameField("Jan", "firstName")
	last, _ := domain.ParsePersonNameField("Novak", "lastName")
	tok := domain.NewOpaqueToken(strings.Repeat("ab", 32))

	user := domain.RegisterUser(email, "hash", first, last, tok, 3*time.Hour, now)
	if user.IsEmailVerified {
		t.Fatal("expected unverified")
	}
	if user.Verification.Attempts != 1 {
		t.Fatalf("attempts=%d", user.Verification.Attempts)
	}

	if err := user.AssertCanLogin(); !errors.Is(err, domain.ErrEmailNotVerified) {
		t.Fatalf("got %v", err)
	}

	if err := user.VerifyEmail(tok, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if !user.IsEmailVerified || user.Verification.Token != nil {
		t.Fatal("expected verified and cleared token")
	}
	if err := user.AssertCanLogin(); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyEmailExpired(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	email := domain.MustParseEmail("a@example.com")
	first, _ := domain.ParsePersonNameField("Jan", "firstName")
	last, _ := domain.ParsePersonNameField("Novak", "lastName")
	tok := domain.NewOpaqueToken(strings.Repeat("cd", 32))
	user := domain.RegisterUser(email, "hash", first, last, tok, time.Hour, now)

	err := user.VerifyEmail(tok, now.Add(2*time.Hour))
	if !errors.Is(err, domain.ErrVerificationTokenExpired) {
		t.Fatalf("got %v", err)
	}
}

func TestVerificationResendRateLimit(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	email := domain.MustParseEmail("a@example.com")
	first, _ := domain.ParsePersonNameField("Jan", "firstName")
	last, _ := domain.ParsePersonNameField("Novak", "lastName")
	tok := domain.NewOpaqueToken(strings.Repeat("ef", 32))
	user := domain.RegisterUser(email, "hash", first, last, tok, 3*time.Hour, now)

	next := domain.NewOpaqueToken(strings.Repeat("11", 32))
	err := user.RequestVerificationResend(next, 3*time.Hour, now.Add(30*time.Second))
	var rl *domain.RateLimitedError
	if !errors.As(err, &rl) {
		t.Fatalf("got %v", err)
	}
	if rl.WaitSeconds <= 0 {
		t.Fatalf("wait=%d", rl.WaitSeconds)
	}

	if err := user.RequestVerificationResend(next, 3*time.Hour, now.Add(61*time.Second)); err != nil {
		t.Fatal(err)
	}
	if user.Verification.Attempts != 2 {
		t.Fatalf("attempts=%d", user.Verification.Attempts)
	}
}

func TestPasswordResetFlow(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	email := domain.MustParseEmail("a@example.com")
	first, _ := domain.ParsePersonNameField("Jan", "firstName")
	last, _ := domain.ParsePersonNameField("Novak", "lastName")
	vtok := domain.NewOpaqueToken(strings.Repeat("aa", 32))
	user := domain.RegisterUser(email, "hash", first, last, vtok, 3*time.Hour, now)
	_ = user.VerifyEmail(vtok, now)

	rtok := domain.NewOpaqueToken(strings.Repeat("bb", 32))
	if err := user.RequestPasswordReset(rtok, time.Hour, now); err != nil {
		t.Fatal(err)
	}
	if err := user.AssertPasswordResetToken(rtok, now.Add(30*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := user.ConsumePasswordReset(rtok, now.Add(30*time.Minute)); err != nil {
		t.Fatal(err)
	}
	user.SetPasswordAfterReset("newhash")
	if user.Password != "newhash" || user.PasswordReset.Token != nil {
		t.Fatal("password/reset state wrong")
	}
}

func TestDeactivate(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	email := domain.MustParseEmail("a@example.com")
	first, _ := domain.ParsePersonNameField("Jan", "firstName")
	last, _ := domain.ParsePersonNameField("Novak", "lastName")
	tok := domain.NewOpaqueToken(strings.Repeat("cc", 32))
	user := domain.RegisterUser(email, "hash", first, last, tok, 3*time.Hour, now)
	user.Deactivate("dummy")
	if user.IsActive {
		t.Fatal("expected inactive")
	}
	if !strings.HasPrefix(user.Email.String(), "deleted+") {
		t.Fatalf("email=%q", user.Email.String())
	}
}

func TestRefreshTokenRotate(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	userUUID := domain.RegisterUser(
		domain.MustParseEmail("b@example.com"),
		"h",
		mustName(t, "Jan"),
		mustName(t, "Novak"),
		domain.NewOpaqueToken(strings.Repeat("dd", 32)),
		time.Hour,
		now,
	).UUID
	rt := domain.IssueRefreshToken(userUUID, domain.NewOpaqueToken(strings.Repeat("ee", 32)), now, 2*time.Hour)
	if err := rt.AssertActive(now); err != nil {
		t.Fatal(err)
	}
	if rt.ShouldRotate(now, time.Hour) {
		t.Fatal("should not rotate yet")
	}
	if !rt.ShouldRotate(now.Add(70*time.Minute), time.Hour) {
		t.Fatal("expected rotate")
	}
	rt.Revoke(now)
	if err := rt.AssertActive(now); !errors.Is(err, domain.ErrRefreshTokenNotFound) {
		t.Fatalf("got %v", err)
	}
}

func mustName(t *testing.T, s string) domain.PersonName {
	t.Helper()
	n, err := domain.ParsePersonName(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}
