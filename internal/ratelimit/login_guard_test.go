package ratelimit_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/rdurica/auth/internal/ratelimit"
	"github.com/redis/go-redis/v9"
)

func newTestLoginGuard(t *testing.T) (*ratelimit.LoginGuard, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return ratelimit.NewLoginGuard(rdb), mr
}

func TestLoginGuardAllowsUntilEmailLimit(t *testing.T) {
	g, _ := newTestLoginGuard(t)
	ctx := context.Background()
	ip := "192.0.2.1"
	email := "victim@example.com"

	for i := 0; i < ratelimit.LoginEmailLimit; i++ {
		res, err := g.Allow(ctx, ip, email)
		if err != nil || !res.Allowed {
			t.Fatalf("allow before fail %d: allowed=%v err=%v", i, res.Allowed, err)
		}
		if err := g.RecordFailure(ctx, ip, email); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}

	res, err := g.Allow(ctx, ip, email)
	if err != nil {
		t.Fatal(err)
	}
	if res.Allowed {
		t.Fatal("should block after email limit")
	}
	if res.Limit != ratelimit.LoginEmailLimit {
		t.Fatalf("limit=%d want %d", res.Limit, ratelimit.LoginEmailLimit)
	}
	if res.RetryAfter.IsZero() {
		t.Fatal("expected retry after")
	}
}

func TestLoginGuardBlocksByIPAcrossEmails(t *testing.T) {
	g, _ := newTestLoginGuard(t)
	ctx := context.Background()
	ip := "198.51.100.9"

	for i := 0; i < ratelimit.LoginIPLimit; i++ {
		email := fmt.Sprintf("user%d@example.com", i)
		res, err := g.Allow(ctx, ip, email)
		if err != nil || !res.Allowed {
			t.Fatalf("allow %d: allowed=%v err=%v", i, res.Allowed, err)
		}
		if err := g.RecordFailure(ctx, ip, email); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}

	res, err := g.Allow(ctx, ip, "fresh@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if res.Allowed {
		t.Fatal("should block after IP limit")
	}
	if res.Limit != ratelimit.LoginIPLimit {
		t.Fatalf("limit=%d want %d", res.Limit, ratelimit.LoginIPLimit)
	}
}

func TestLoginGuardClearResetsBuckets(t *testing.T) {
	g, _ := newTestLoginGuard(t)
	ctx := context.Background()
	ip := "203.0.113.1"
	email := "reset@example.com"

	for i := 0; i < ratelimit.LoginEmailLimit; i++ {
		if err := g.RecordFailure(ctx, ip, email); err != nil {
			t.Fatal(err)
		}
	}
	res, err := g.Allow(ctx, ip, email)
	if err != nil || res.Allowed {
		t.Fatalf("expected block before clear: allowed=%v err=%v", res.Allowed, err)
	}

	if err := g.Clear(ctx, ip, email); err != nil {
		t.Fatal(err)
	}
	res, err = g.Allow(ctx, ip, email)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Allowed {
		t.Fatal("should allow after clear")
	}
}

func TestLoginGuardAllowsAgainAfterWindow(t *testing.T) {
	g, mr := newTestLoginGuard(t)
	ctx := context.Background()
	ip := "203.0.113.50"
	email := "window@example.com"

	for i := 0; i < ratelimit.LoginEmailLimit; i++ {
		if err := g.RecordFailure(ctx, ip, email); err != nil {
			t.Fatal(err)
		}
	}
	res, err := g.Allow(ctx, ip, email)
	if err != nil || res.Allowed {
		t.Fatalf("expected block: allowed=%v err=%v", res.Allowed, err)
	}

	mr.FastForward(ratelimit.LoginWindow + time.Second)

	res, err = g.Allow(ctx, ip, email)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Allowed {
		t.Fatal("should allow after window")
	}
}

func TestLoginGuardNormalizesEmail(t *testing.T) {
	g, _ := newTestLoginGuard(t)
	ctx := context.Background()
	ip := "192.0.2.55"

	for i := 0; i < ratelimit.LoginEmailLimit; i++ {
		if err := g.RecordFailure(ctx, ip, "Victim@Example.com"); err != nil {
			t.Fatal(err)
		}
	}
	res, err := g.Allow(ctx, ip, "  victim@example.com ")
	if err != nil {
		t.Fatal(err)
	}
	if res.Allowed {
		t.Fatal("normalized email should share failure bucket")
	}
}
