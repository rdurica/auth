package ratelimit_test

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/rdurica/auth/internal/ratelimit"
)

func newTestLimiter(t *testing.T) (*ratelimit.Limiter, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return ratelimit.New(rdb), mr
}

func TestConsumeAllowsUpToLimit(t *testing.T) {
	lim, _ := newTestLimiter(t)
	ctx := context.Background()
	const limit = 5

	for i := 0; i < limit; i++ {
		res, err := lim.Consume(ctx, "ip:1.2.3.4:/api/auth/login", limit)
		if err != nil {
			t.Fatalf("consume %d: %v", i+1, err)
		}
		if !res.Allowed {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}

	res, err := lim.Consume(ctx, "ip:1.2.3.4:/api/auth/login", limit)
	if err != nil {
		t.Fatal(err)
	}
	if res.Allowed {
		t.Fatal("request beyond limit should be rejected")
	}
	if res.Limit != limit {
		t.Fatalf("limit=%d want %d", res.Limit, limit)
	}
	if res.RetryAfter.IsZero() {
		t.Fatal("expected retry after")
	}
}

func TestConsumeAllowsAgainAfterWindow(t *testing.T) {
	lim, mr := newTestLimiter(t)
	ctx := context.Background()
	const limit = 2
	key := "ip:9.9.9.9:/api/auth/register"

	for i := 0; i < limit; i++ {
		res, err := lim.Consume(ctx, key, limit)
		if err != nil || !res.Allowed {
			t.Fatalf("seed %d: allowed=%v err=%v", i, res.Allowed, err)
		}
	}
	res, err := lim.Consume(ctx, key, limit)
	if err != nil || res.Allowed {
		t.Fatalf("should reject before window: allowed=%v err=%v", res.Allowed, err)
	}

	mr.FastForward(time.Minute + time.Second)

	res, err = lim.Consume(ctx, key, limit)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Allowed {
		t.Fatal("should allow after window")
	}
}

func TestNewFromURL(t *testing.T) {
	mr := miniredis.RunT(t)
	lim, err := ratelimit.NewFromURL("redis://" + mr.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lim.Close() }()

	res, err := lim.Consume(context.Background(), "k", 1)
	if err != nil || !res.Allowed {
		t.Fatalf("allowed=%v err=%v", res.Allowed, err)
	}
}
