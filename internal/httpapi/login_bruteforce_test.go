package httpapi_test

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/rdurica/auth/internal/app"
	"github.com/rdurica/auth/internal/domain"
	"github.com/rdurica/auth/internal/httpapi"
	"github.com/rdurica/auth/internal/mail"
	"github.com/rdurica/auth/internal/password"
	"github.com/rdurica/auth/internal/ratelimit"
	"github.com/rdurica/auth/internal/token"
	"github.com/redis/go-redis/v9"
)

func setupHandlerWithLoginGuard(t *testing.T) (http.Handler, *memUsers, *ratelimit.LoginGuard) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	lim := ratelimit.New(rdb)
	guard := lim.LoginGuard()

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
		Auth:       svc,
		JWT:        jwtSvc,
		Limiter:    lim,
		LoginGuard: guard,
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		ErrorBase:  "https://auth.local/errors",
	})
	return h, users, guard
}

func seedVerifiedUser(t *testing.T, users *memUsers, email, pass string) {
	t.Helper()
	hash, err := password.Hash(pass)
	if err != nil {
		t.Fatal(err)
	}
	u := &domain.User{
		UUID:      uuid.New(),
		Email:     domain.MustParseEmail(email),
		Password:  hash,
		FirstName: "Test",
		LastName:  "User",
		Roles:     []string{domain.RoleUser},
		IsActive:  true,
	}
	u.IsEmailVerified = true
	if err := users.Create(t.Context(), u); err != nil {
		t.Fatal(err)
	}
}

func postLogin(h http.Handler, email, pass, remoteAddr string) *httptest.ResponseRecorder {
	body := `{"email":"` + email + `","password":"` + pass + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = remoteAddr
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func TestLoginBruteForceLocksEmailAfterFailures(t *testing.T) {
	h, users, _ := setupHandlerWithLoginGuard(t)
	const email = "lock@example.com"
	const pass = "password123"
	seedVerifiedUser(t, users, email, pass)

	for i := 0; i < ratelimit.LoginEmailLimit; i++ {
		rr := postLogin(h, email, "wrong-password", "192.0.2.40:1")
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("fail %d: status=%d body=%s", i+1, rr.Code, rr.Body.String())
		}
	}

	rr := postLogin(h, email, pass, "192.0.2.40:1")
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after lockout, got %d body=%s", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("Retry-After") == "" {
		t.Fatal("missing Retry-After")
	}
	var problem struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &problem); err != nil {
		t.Fatal(err)
	}
	if problem.Code != "login_rate_limited" {
		t.Fatalf("code=%q", problem.Code)
	}
}

func TestLoginBruteForceClearsOnSuccess(t *testing.T) {
	h, users, _ := setupHandlerWithLoginGuard(t)
	const email = "clear@example.com"
	const pass = "password123"
	seedVerifiedUser(t, users, email, pass)

	for i := 0; i < 2; i++ {
		rr := postLogin(h, email, "wrong", "192.0.2.41:1")
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("fail %d: status=%d", i+1, rr.Code)
		}
	}

	rr := postLogin(h, email, pass, "192.0.2.41:1")
	if rr.Code != http.StatusOK {
		t.Fatalf("login status=%d body=%s", rr.Code, rr.Body.String())
	}

	rr = postLogin(h, email, "wrong", "192.0.2.41:1")
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("after clear expected 401, got %d", rr.Code)
	}
}

func TestLoginBruteForceNilGuardStillWorks(t *testing.T) {
	h, users := setupHandler(t)
	const email = "noguard@example.com"
	const pass = "password123"
	seedVerifiedUser(t, users, email, pass)

	rr := postLogin(h, email, "wrong", "192.0.2.42:1")
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", rr.Code)
	}
	rr = postLogin(h, email, pass, "192.0.2.42:1")
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}
