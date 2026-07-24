package httpapi_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rdurica/auth/internal/app"
	"github.com/rdurica/auth/internal/domain"
	"github.com/rdurica/auth/internal/httpapi"
	"github.com/rdurica/auth/internal/mail"
	"github.com/rdurica/auth/internal/token"
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

func setupHandler(t *testing.T) (http.Handler, *memUsers) {
	t.Helper()
	dir := t.TempDir()
	priv, pub := writeKeys(t, dir)
	jwtSvc, err := token.NewJWTService(priv, pub, "auth", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	users := newMemUsers()
	refresh := newMemRefresh()
	mailer := &mail.Templates{
		WebBaseURL: "http://localhost",
		Sender:     mail.NewLogSender(slog.New(slog.NewTextHandler(io.Discard, nil))),
	}
	svc := app.NewAuthService(users, refresh, jwtSvc, mailer, 30*24*time.Hour, 3*time.Hour, time.Hour)
	h := httpapi.NewRouter(httpapi.Deps{
		Auth:      svc,
		JWT:       jwtSvc,
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		ErrorBase: "https://auth.local/errors",
	})
	return h, users
}

func writeKeys(t *testing.T, dir string) (string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	privPath := filepath.Join(dir, "private.pem")
	pubPath := filepath.Join(dir, "public.pem")
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
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

func TestAuthFlowHTTP(t *testing.T) {
	h, users := setupHandler(t)

	regBody := `{"email":"user@example.com","password":"password123","firstName":"Jan","lastName":"Novak"}`
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/register", bytes.NewBufferString(regBody))
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("register status=%d body=%s", rr.Code, rr.Body.String())
	}

	loginRR := httptest.NewRecorder()
	loginReq := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewBufferString(
		`{"email":"user@example.com","password":"password123"}`,
	))
	h.ServeHTTP(loginRR, loginReq)
	if loginRR.Code != http.StatusForbidden {
		t.Fatalf("login before verify status=%d", loginRR.Code)
	}

	u, err := users.FindByEmail(context.Background(), domain.MustParseEmail("user@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	vtok, ok := u.VerificationToken()
	if !ok {
		t.Fatal("missing verification token")
	}
	verifyRR := httptest.NewRecorder()
	verifyReq := httptest.NewRequest(http.MethodPost, "/api/auth/verify-email", bytes.NewBufferString(
		`{"token":"`+vtok+`"}`,
	))
	h.ServeHTTP(verifyRR, verifyReq)
	if verifyRR.Code != http.StatusOK {
		t.Fatalf("verify status=%d body=%s", verifyRR.Code, verifyRR.Body.String())
	}

	loginRR = httptest.NewRecorder()
	loginReq = httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewBufferString(
		`{"email":"user@example.com","password":"password123"}`,
	))
	h.ServeHTTP(loginRR, loginReq)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login status=%d body=%s", loginRR.Code, loginRR.Body.String())
	}
	var tokens struct {
		AuthenticationToken string `json:"authenticationToken"`
		RefreshToken        string `json:"refreshToken"`
	}
	if err := json.Unmarshal(loginRR.Body.Bytes(), &tokens); err != nil {
		t.Fatal(err)
	}

	profileRR := httptest.NewRecorder()
	profileReq := httptest.NewRequest(http.MethodGet, "/api/user/profile", nil)
	profileReq.Header.Set("Authorization", "Bearer "+tokens.AuthenticationToken)
	h.ServeHTTP(profileRR, profileReq)
	if profileRR.Code != http.StatusOK {
		t.Fatalf("profile status=%d body=%s", profileRR.Code, profileRR.Body.String())
	}

	refreshRR := httptest.NewRecorder()
	refreshReq := httptest.NewRequest(http.MethodPost, "/api/auth/refresh", bytes.NewBufferString(
		`{"refreshToken":"`+tokens.RefreshToken+`"}`,
	))
	h.ServeHTTP(refreshRR, refreshReq)
	if refreshRR.Code != http.StatusOK {
		t.Fatalf("refresh status=%d body=%s", refreshRR.Code, refreshRR.Body.String())
	}

	jwksRR := httptest.NewRecorder()
	jwksReq := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	h.ServeHTTP(jwksRR, jwksReq)
	if jwksRR.Code != http.StatusOK {
		t.Fatalf("jwks status=%d", jwksRR.Code)
	}

	patchRR := httptest.NewRecorder()
	patchReq := httptest.NewRequest(http.MethodPatch, "/api/user/profile", bytes.NewBufferString(
		`{"firstName":"Honza"}`,
	))
	patchReq.Header.Set("Authorization", "Bearer "+tokens.AuthenticationToken)
	patchReq.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(patchRR, patchReq)
	if patchRR.Code != http.StatusOK {
		t.Fatalf("patch profile status=%d body=%s", patchRR.Code, patchRR.Body.String())
	}
	var patchResp map[string]bool
	if err := json.Unmarshal(patchRR.Body.Bytes(), &patchResp); err != nil {
		t.Fatal(err)
	}
	if !patchResp["updated"] {
		t.Fatalf("patch resp=%v", patchResp)
	}

	logoutRR := httptest.NewRecorder()
	logoutReq := httptest.NewRequest(http.MethodPost, "/api/auth/logout", bytes.NewBufferString(
		`{"refreshToken":"`+tokens.RefreshToken+`"}`,
	))
	logoutReq.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(logoutRR, logoutReq)
	if logoutRR.Code != http.StatusNoContent {
		t.Fatalf("logout status=%d body=%s", logoutRR.Code, logoutRR.Body.String())
	}

	refreshAfterLogout := httptest.NewRecorder()
	refreshAfterReq := httptest.NewRequest(http.MethodPost, "/api/auth/refresh", bytes.NewBufferString(
		`{"refreshToken":"`+tokens.RefreshToken+`"}`,
	))
	refreshAfterReq.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(refreshAfterLogout, refreshAfterReq)
	if refreshAfterLogout.Code != http.StatusUnauthorized {
		t.Fatalf("refresh after logout status=%d body=%s", refreshAfterLogout.Code, refreshAfterLogout.Body.String())
	}
}

func TestHealth(t *testing.T) {
	h, _ := setupHandler(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d", rr.Code)
	}
}

func TestNotFoundProblemJSON(t *testing.T) {
	h, _ := setupHandler(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/no-such-route", nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status=%d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Fatalf("Content-Type=%q", ct)
	}
	var problem struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &problem); err != nil {
		t.Fatal(err)
	}
	if problem.Code != "not_found" {
		t.Fatalf("code=%q", problem.Code)
	}
}

func TestMethodNotAllowedProblemJSON(t *testing.T) {
	h, _ := setupHandler(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/health", nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Fatalf("Content-Type=%q", ct)
	}
	var problem struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &problem); err != nil {
		t.Fatal(err)
	}
	if problem.Code != "method_not_allowed" {
		t.Fatalf("code=%q", problem.Code)
	}
}

func TestDeleteAccountNoContent(t *testing.T) {
	h, users := setupHandler(t)
	regBody := `{"email":"del@example.com","password":"password123","firstName":"Jan","lastName":"Novak"}`
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/register", bytes.NewBufferString(regBody))
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("register status=%d", rr.Code)
	}

	u, err := users.FindByEmail(context.Background(), domain.MustParseEmail("del@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	vtok, ok := u.VerificationToken()
	if !ok {
		t.Fatal("missing verification token")
	}
	verifyRR := httptest.NewRecorder()
	verifyReq := httptest.NewRequest(http.MethodPost, "/api/auth/verify-email", bytes.NewBufferString(
		`{"token":"`+vtok+`"}`,
	))
	verifyReq.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(verifyRR, verifyReq)
	if verifyRR.Code != http.StatusOK {
		t.Fatalf("verify status=%d", verifyRR.Code)
	}

	loginRR := httptest.NewRecorder()
	loginReq := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewBufferString(
		`{"email":"del@example.com","password":"password123"}`,
	))
	loginReq.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(loginRR, loginReq)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login status=%d body=%s", loginRR.Code, loginRR.Body.String())
	}
	var tokens struct {
		AuthenticationToken string `json:"authenticationToken"`
	}
	if err := json.Unmarshal(loginRR.Body.Bytes(), &tokens); err != nil {
		t.Fatal(err)
	}

	delRR := httptest.NewRecorder()
	delReq := httptest.NewRequest(http.MethodDelete, "/api/user/account", bytes.NewBufferString(
		`{"confirmation":"DELETE","password":"password123"}`,
	))
	delReq.Header.Set("Authorization", "Bearer "+tokens.AuthenticationToken)
	delReq.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(delRR, delReq)
	if delRR.Code != http.StatusNoContent {
		t.Fatalf("delete status=%d body=%s", delRR.Code, delRR.Body.String())
	}
	if delRR.Body.Len() != 0 {
		t.Fatalf("expected empty body, got %q", delRR.Body.String())
	}
}

func TestAuthNestedRoutePaths(t *testing.T) {
	h, _ := setupHandler(t)

	// New nested paths must be registered (not 404). Empty/invalid bodies still hit the handler.
	for _, path := range []string{
		"/api/auth/verify-email",
		"/api/auth/verify-email/resend",
		"/api/auth/password-reset",
		"/api/auth/password-reset/validate",
		"/api/auth/password-reset/confirm",
	} {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewBufferString(`{}`))
		req.Header.Set("Content-Type", "application/json")
		h.ServeHTTP(rr, req)
		if rr.Code == http.StatusNotFound {
			t.Fatalf("%s: unexpected 404", path)
		}
	}

	// Hard rename: old flat paths must be gone.
	for _, path := range []string{
		"/api/auth/resend-verification",
		"/api/auth/validate-password-reset-token",
		"/api/auth/set-password",
	} {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewBufferString(`{}`))
		req.Header.Set("Content-Type", "application/json")
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("%s: want 404, got %d body=%s", path, rr.Code, rr.Body.String())
		}
	}
}
