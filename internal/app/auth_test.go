package app_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rdurica/auth/internal/app"
	"github.com/rdurica/auth/internal/domain"
	"github.com/rdurica/auth/internal/mail"
	"github.com/rdurica/auth/internal/password"
)

type memUsers struct {
	byEmail map[string]*domain.User
	byUUID  map[uuid.UUID]*domain.User
	byVTok  map[string]*domain.User
	byRTok  map[string]*domain.User
	seq     int64
}

func newMemUsers() *memUsers {
	return &memUsers{
		byEmail: map[string]*domain.User{},
		byUUID:  map[uuid.UUID]*domain.User{},
		byVTok:  map[string]*domain.User{},
		byRTok:  map[string]*domain.User{},
	}
}

func (m *memUsers) index(u *domain.User) {
	cp := *u
	m.byEmail[u.Email.String()] = &cp
	m.byUUID[u.UUID] = &cp
	if u.Verification.Token != nil {
		m.byVTok[*u.Verification.Token] = &cp
	}
	if u.PasswordReset.Token != nil {
		m.byRTok[*u.PasswordReset.Token] = &cp
	}
}

func (m *memUsers) Create(_ context.Context, u *domain.User) error {
	if _, ok := m.byEmail[u.Email.String()]; ok {
		return domain.ErrUserAlreadyExists
	}
	m.seq++
	u.ID = m.seq
	m.index(u)
	return nil
}

func (m *memUsers) Save(_ context.Context, u *domain.User) error {
	old, ok := m.byUUID[u.UUID]
	if !ok {
		return domain.ErrUserNotFound
	}
	if old.Email.String() != u.Email.String() {
		delete(m.byEmail, old.Email.String())
	}
	if old.Verification.Token != nil {
		delete(m.byVTok, *old.Verification.Token)
	}
	if old.PasswordReset.Token != nil {
		delete(m.byRTok, *old.PasswordReset.Token)
	}
	m.index(u)
	return nil
}

func (m *memUsers) FindByEmail(_ context.Context, email domain.Email) (*domain.User, error) {
	u, ok := m.byEmail[email.String()]
	if !ok {
		return nil, domain.ErrUserNotFound
	}
	cp := *u
	return &cp, nil
}

func (m *memUsers) FindByUUID(_ context.Context, id uuid.UUID) (*domain.User, error) {
	u, ok := m.byUUID[id]
	if !ok {
		return nil, domain.ErrUserNotFound
	}
	cp := *u
	return &cp, nil
}

func (m *memUsers) FindByVerificationToken(_ context.Context, tok string) (*domain.User, error) {
	u, ok := m.byVTok[tok]
	if !ok {
		return nil, domain.ErrVerificationTokenInvalid
	}
	cp := *u
	return &cp, nil
}

func (m *memUsers) FindByPasswordResetToken(_ context.Context, tok string) (*domain.User, error) {
	u, ok := m.byRTok[tok]
	if !ok {
		return nil, domain.ErrPasswordResetTokenInvalid
	}
	cp := *u
	return &cp, nil
}

type memRefresh struct {
	byToken map[string]*domain.RefreshToken
	seq     int64
}

func newMemRefresh() *memRefresh {
	return &memRefresh{byToken: map[string]*domain.RefreshToken{}}
}

func (m *memRefresh) Create(_ context.Context, t *domain.RefreshToken) error {
	m.seq++
	t.ID = m.seq
	cp := *t
	m.byToken[t.Token] = &cp
	return nil
}

func (m *memRefresh) FindByToken(_ context.Context, tok string) (*domain.RefreshToken, error) {
	t, ok := m.byToken[tok]
	if !ok {
		return nil, domain.ErrRefreshTokenNotFound
	}
	cp := *t
	return &cp, nil
}

func (m *memRefresh) FindActiveByUser(_ context.Context, userUUID uuid.UUID, now time.Time) (*domain.RefreshToken, error) {
	var best *domain.RefreshToken
	for _, t := range m.byToken {
		if t.UserUUID == userUUID && t.Active(now) {
			if best == nil || t.IssuedAt.After(best.IssuedAt) {
				cp := *t
				best = &cp
			}
		}
	}
	if best == nil {
		return nil, domain.ErrRefreshTokenNotFound
	}
	return best, nil
}

func (m *memRefresh) Revoke(_ context.Context, id int64, at time.Time) error {
	for _, t := range m.byToken {
		if t.ID == id {
			t.RevokedAt = &at
		}
	}
	return nil
}

func (m *memRefresh) RevokeAllForUser(_ context.Context, userUUID uuid.UUID, at time.Time) error {
	for _, t := range m.byToken {
		if t.UserUUID == userUUID && t.RevokedAt == nil {
			t.RevokedAt = &at
		}
	}
	return nil
}

type stubJWT struct{}

func (stubJWT) Issue(userUUID uuid.UUID, _ []string) (string, error) {
	return "jwt-" + userUUID.String(), nil
}

func newTestService(t *testing.T) (*app.AuthService, *memUsers, *memRefresh) {
	t.Helper()
	users := newMemUsers()
	refresh := newMemRefresh()
	mailer := &mail.Templates{
		WebBaseURL: "http://localhost",
		Sender:     mail.NewLogSender(slog.New(slog.NewTextHandler(io.Discard, nil))),
	}
	svc := app.NewAuthService(users, refresh, stubJWT{}, mailer, 30*24*time.Hour, 3*time.Hour, time.Hour)
	return svc, users, refresh
}

func TestRegisterLoginRequiresVerification(t *testing.T) {
	svc, users, _ := newTestService(t)
	ctx := context.Background()

	res, err := svc.Register(ctx, app.RegisterInput{
		Email: "Test@Example.com", Password: "password123", FirstName: "Jan", LastName: "Novak",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.EmailVerificationRequired {
		t.Fatal("expected verification required")
	}

	_, err = svc.Login(ctx, "test@example.com", "password123")
	if !errors.Is(err, domain.ErrEmailNotVerified) {
		t.Fatalf("got %v", err)
	}

	u, _ := users.FindByEmail(ctx, domain.MustParseEmail("test@example.com"))
	vtok, ok := u.VerificationToken()
	if !ok {
		t.Fatal("missing verification token")
	}
	if err := svc.VerifyEmail(ctx, vtok); err != nil {
		t.Fatal(err)
	}

	pair, err := svc.Login(ctx, "test@example.com", "password123")
	if err != nil {
		t.Fatal(err)
	}
	if pair.AuthenticationToken == "" || pair.RefreshToken == "" {
		t.Fatalf("tokens=%+v", pair)
	}
}

func TestLoginInvalidCredentials(t *testing.T) {
	svc, _, _ := newTestService(t)
	ctx := context.Background()
	_, err := svc.Login(ctx, "missing@example.com", "password123")
	if !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Fatalf("got %v", err)
	}
}

func TestVerifyEmailUnknownToken(t *testing.T) {
	svc, _, _ := newTestService(t)
	ctx := context.Background()
	unknown := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	err := svc.VerifyEmail(ctx, unknown)
	if !errors.Is(err, domain.ErrVerificationTokenInvalid) {
		t.Fatalf("got %v", err)
	}
}

func TestPasswordResetTokenUnknownMapsInvalid(t *testing.T) {
	svc, _, _ := newTestService(t)
	ctx := context.Background()
	unknown := "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	if err := svc.ValidatePasswordResetToken(ctx, unknown); !errors.Is(err, domain.ErrPasswordResetTokenInvalid) {
		t.Fatalf("validate got %v", err)
	}
	if err := svc.SetPassword(ctx, unknown, "password123"); !errors.Is(err, domain.ErrPasswordResetTokenInvalid) {
		t.Fatalf("set got %v", err)
	}
}

// userNotFoundOnTokenLookup wraps memUsers and forces ErrUserNotFound on token lookups
// so app-layer remapping can be verified independently of the repository mapping.
type userNotFoundOnTokenLookup struct {
	*memUsers
}

func (w userNotFoundOnTokenLookup) FindByVerificationToken(context.Context, string) (*domain.User, error) {
	return nil, domain.ErrUserNotFound
}

func (w userNotFoundOnTokenLookup) FindByPasswordResetToken(context.Context, string) (*domain.User, error) {
	return nil, domain.ErrUserNotFound
}

func TestLogoutRevokesRefreshToken(t *testing.T) {
	svc, users, refresh := newTestService(t)
	ctx := context.Background()
	_, err := svc.Register(ctx, app.RegisterInput{
		Email: "logout@example.com", Password: "password123", FirstName: "Jan", LastName: "Novak",
	})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := users.FindByEmail(ctx, domain.MustParseEmail("logout@example.com"))
	vtok, _ := u.VerificationToken()
	if err := svc.VerifyEmail(ctx, vtok); err != nil {
		t.Fatal(err)
	}
	pair, err := svc.Login(ctx, "logout@example.com", "password123")
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Logout(ctx, pair.RefreshToken); err != nil {
		t.Fatal(err)
	}
	rt, err := refresh.FindByToken(ctx, pair.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}
	if rt.RevokedAt == nil {
		t.Fatal("expected refresh token revoked")
	}
	if err := svc.Logout(ctx, pair.RefreshToken); err != nil {
		t.Fatalf("idempotent logout: %v", err)
	}
	if err := svc.Logout(ctx, "missing-token"); err != nil {
		t.Fatalf("logout missing token: %v", err)
	}
}

func TestTokenLookupUserNotFoundRemapped(t *testing.T) {
	users := userNotFoundOnTokenLookup{memUsers: newMemUsers()}
	refresh := newMemRefresh()
	mailer := &mail.Templates{
		WebBaseURL: "http://localhost",
		Sender:     mail.NewLogSender(slog.New(slog.NewTextHandler(io.Discard, nil))),
	}
	svc := app.NewAuthService(users, refresh, stubJWT{}, mailer, 30*24*time.Hour, 3*time.Hour, time.Hour)
	ctx := context.Background()
	tok := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	if err := svc.VerifyEmail(ctx, tok); !errors.Is(err, domain.ErrVerificationTokenInvalid) {
		t.Fatalf("verify got %v", err)
	}
	if err := svc.ValidatePasswordResetToken(ctx, tok); !errors.Is(err, domain.ErrPasswordResetTokenInvalid) {
		t.Fatalf("validate got %v", err)
	}
	if err := svc.SetPassword(ctx, tok, "password123"); !errors.Is(err, domain.ErrPasswordResetTokenInvalid) {
		t.Fatalf("set got %v", err)
	}
}

func TestPasswordHashUsed(t *testing.T) {
	hash, err := password.Hash("password123")
	if err != nil {
		t.Fatal(err)
	}
	ok, err := password.Verify(hash, "password123")
	if err != nil || !ok {
		t.Fatal("hash roundtrip failed")
	}
}
