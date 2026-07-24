package ratelimit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/redis/go-redis/v9"
)

const (
	LoginEmailLimit = 5
	LoginIPLimit    = 20
	LoginWindow     = 15 * time.Minute
)

// LoginGuard enforces per-IP and per-email failed-login limits in Redis.
type LoginGuard struct {
	rdb *redis.Client
}

func NewLoginGuard(rdb *redis.Client) *LoginGuard {
	return &LoginGuard{rdb: rdb}
}

// LoginGuard returns a guard sharing this limiter's Redis client.
func (l *Limiter) LoginGuard() *LoginGuard {
	if l == nil || l.rdb == nil {
		return nil
	}
	return NewLoginGuard(l.rdb)
}

// checkScript inspects a sliding window without recording a hit.
// KEYS[1] = redis key
// ARGV[1] = now unix nano
// ARGV[2] = window start unix nano
// ARGV[3] = limit
// Returns: {allowed (0|1), limit, retry_after_unix_nano}
var loginCheckScript = redis.NewScript(`
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window_start = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])

redis.call('ZREMRANGEBYSCORE', key, 0, window_start)
local count = redis.call('ZCARD', key)
if count >= limit then
  local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
  local retry_after = now
  if oldest[2] then
    retry_after = tonumber(oldest[2]) + (now - window_start)
  end
  return {0, limit, retry_after}
end
return {1, limit, 0}
`)

// loginRecordScript records one failure in the sliding window.
var loginRecordScript = redis.NewScript(`
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window_start = tonumber(ARGV[2])
local expire_sec = tonumber(ARGV[3])

redis.call('ZREMRANGEBYSCORE', key, 0, window_start)
local count = redis.call('ZCARD', key)
redis.call('ZADD', key, now, tostring(now) .. '-' .. tostring(count))
redis.call('EXPIRE', key, expire_sec)
return 1
`)

// Allow reports whether a login attempt may proceed for the given IP and email.
// It does not record a failure.
func (g *LoginGuard) Allow(ctx context.Context, ip, email string) (Result, error) {
	if g == nil || g.rdb == nil {
		return Result{Allowed: true}, nil
	}
	now := time.Now()
	windowStart := now.Add(-LoginWindow)

	emailRes, err := g.check(ctx, g.emailKey(email), LoginEmailLimit, now, windowStart)
	if err != nil {
		return Result{}, err
	}
	ipRes, err := g.check(ctx, g.ipKey(ip), LoginIPLimit, now, windowStart)
	if err != nil {
		return Result{}, err
	}

	if !emailRes.Allowed {
		return emailRes, nil
	}
	if !ipRes.Allowed {
		return ipRes, nil
	}
	return Result{Allowed: true, Limit: LoginEmailLimit}, nil
}

// RecordFailure increments failed-login counters for IP and email.
func (g *LoginGuard) RecordFailure(ctx context.Context, ip, email string) error {
	if g == nil || g.rdb == nil {
		return nil
	}
	now := time.Now()
	windowStart := now.Add(-LoginWindow)
	expireSec := int((LoginWindow + time.Second).Seconds())

	if err := g.record(ctx, g.emailKey(email), now, windowStart, expireSec); err != nil {
		return err
	}
	return g.record(ctx, g.ipKey(ip), now, windowStart, expireSec)
}

// Clear removes the email failure counter after a successful login.
// The IP bucket is left intact so a successful login on one account cannot
// reset spray limits against other emails from the same IP.
func (g *LoginGuard) Clear(ctx context.Context, _, email string) error {
	if g == nil || g.rdb == nil {
		return nil
	}
	return g.rdb.Del(ctx, g.emailKey(email)).Err()
}

func (g *LoginGuard) check(ctx context.Context, key string, limit int, now, windowStart time.Time) (Result, error) {
	res, err := loginCheckScript.Run(ctx, g.rdb, []string{key},
		now.UnixNano(),
		windowStart.UnixNano(),
		limit,
	).Int64Slice()
	if err != nil {
		return Result{}, err
	}
	if len(res) < 3 {
		return Result{}, fmt.Errorf("unexpected redis login check result")
	}
	allowed := res[0] == 1
	retryAfter := time.Time{}
	if !allowed && res[2] > 0 {
		retryAfter = time.Unix(0, res[2])
	}
	return Result{
		Allowed:    allowed,
		Limit:      int(res[1]),
		RetryAfter: retryAfter,
	}, nil
}

func (g *LoginGuard) record(ctx context.Context, key string, now, windowStart time.Time, expireSec int) error {
	return loginRecordScript.Run(ctx, g.rdb, []string{key},
		now.UnixNano(),
		windowStart.UnixNano(),
		expireSec,
	).Err()
}

func (g *LoginGuard) ipKey(ip string) string {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		ip = "unknown"
	}
	return "login:fail:ip:" + ip
}

func (g *LoginGuard) emailKey(email string) string {
	sum := sha256.Sum256([]byte(normalizeLoginEmail(email)))
	return "login:fail:email:" + hex.EncodeToString(sum[:])
}

func normalizeLoginEmail(email string) string {
	email = strings.TrimSpace(email)
	email = strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, email)
	return strings.ToLower(email)
}
