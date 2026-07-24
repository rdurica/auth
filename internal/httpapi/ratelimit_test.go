package httpapi_test

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/rdurica/auth/internal/app"
	"github.com/rdurica/auth/internal/httpapi"
	"github.com/rdurica/auth/internal/mail"
	"github.com/rdurica/auth/internal/ratelimit"
	"github.com/rdurica/auth/internal/token"
)

func setupHandlerWithLimiter(t *testing.T, lim httpapi.RateLimiter) (http.Handler, *token.JWTService) {
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
		Limiter:   lim,
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		ErrorBase: "https://auth.local/errors",
	})
	return h, jwtSvc
}

func TestRateLimitSkipsHealthAndRefresh(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	lim := ratelimit.New(rdb)

	// Exhaust anonymous quota for a dummy path to ensure skips are independent.
	ctx := context.Background()
	for i := 0; i < ratelimit.AnonymousLimit; i++ {
		if _, err := lim.Consume(ctx, "ip:192.0.2.1:/api/auth/login", ratelimit.AnonymousLimit); err != nil {
			t.Fatal(err)
		}
	}

	h, _ := setupHandlerWithLimiter(t, lim)

	healthRR := httptest.NewRecorder()
	healthReq := httptest.NewRequest(http.MethodGet, "/health", nil)
	healthReq.RemoteAddr = "192.0.2.1:1234"
	h.ServeHTTP(healthRR, healthReq)
	if healthRR.Code != http.StatusOK {
		t.Fatalf("health status=%d", healthRR.Code)
	}

	jwksRR := httptest.NewRecorder()
	jwksReq := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	jwksReq.RemoteAddr = "192.0.2.1:1234"
	h.ServeHTTP(jwksRR, jwksReq)
	if jwksRR.Code != http.StatusOK {
		t.Fatalf("jwks status=%d", jwksRR.Code)
	}

	refreshRR := httptest.NewRecorder()
	refreshReq := httptest.NewRequest(http.MethodPost, "/api/auth/refresh", bytes.NewBufferString(`{"refreshToken":"x"}`))
	refreshReq.RemoteAddr = "192.0.2.1:1234"
	h.ServeHTTP(refreshRR, refreshReq)
	// Invalid token → 401, not 429 (refresh is skipped by rate limiter).
	if refreshRR.Code == http.StatusTooManyRequests {
		t.Fatalf("refresh should not be rate limited, got 429")
	}
}

func TestRateLimitReturns429(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	lim := ratelimit.New(rdb)
	h, _ := setupHandlerWithLimiter(t, lim)

	body := `{"email":"nobody@example.com","password":"password123"}`
	var last int
	for i := 0; i < ratelimit.AnonymousLimit+1; i++ {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewBufferString(body))
		req.RemoteAddr = "192.0.2.10:9999"
		h.ServeHTTP(rr, req)
		last = rr.Code
		if i < ratelimit.AnonymousLimit {
			if rr.Code == http.StatusTooManyRequests {
				t.Fatalf("request %d unexpectedly rate limited", i+1)
			}
			continue
		}
		if rr.Code != http.StatusTooManyRequests {
			t.Fatalf("request %d status=%d want 429 body=%s", i+1, rr.Code, rr.Body.String())
		}
		if rr.Header().Get("X-RateLimit-Limit") != "60" {
			t.Fatalf("X-RateLimit-Limit=%q", rr.Header().Get("X-RateLimit-Limit"))
		}
		if rr.Header().Get("Retry-After") == "" {
			t.Fatal("missing Retry-After header")
		}
		if ct := rr.Header().Get("Content-Type"); ct != "application/problem+json" {
			t.Fatalf("Content-Type=%q", ct)
		}
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("last status=%d", last)
	}
}

func TestRateLimitUsesXForwardedFor(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	lim := ratelimit.New(rdb)
	h, _ := setupHandlerWithLimiter(t, lim)

	body := `{"email":"a@example.com","password":"password123"}`
	for i := 0; i < ratelimit.AnonymousLimit; i++ {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewBufferString(body))
		req.RemoteAddr = "127.0.0.1:1"
		req.Header.Set("X-Forwarded-For", "203.0.113.5")
		h.ServeHTTP(rr, req)
		if rr.Code == http.StatusTooManyRequests {
			t.Fatalf("exhausted too early at %d", i+1)
		}
	}

	// Same XFF → 429
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewBufferString(body))
	req.RemoteAddr = "127.0.0.1:1"
	req.Header.Set("X-Forwarded-For", "203.0.113.5")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("status=%d want 429", rr.Code)
	}

	// Different IP still allowed
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewBufferString(body))
	req.RemoteAddr = "127.0.0.1:1"
	req.Header.Set("X-Forwarded-For", "203.0.113.6")
	h.ServeHTTP(rr, req)
	if rr.Code == http.StatusTooManyRequests {
		t.Fatal("different XFF should not share bucket")
	}
}
