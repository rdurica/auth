package ratelimit

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	AnonymousLimit     = 60
	AuthenticatedLimit = 300
	Window             = time.Minute
)

// Result is the outcome of a single Consume call.
type Result struct {
	Allowed    bool
	Limit      int
	RetryAfter time.Time
}

// Limiter is a sliding-window rate limiter backed by Redis sorted sets.
type Limiter struct {
	rdb *redis.Client
}

func New(rdb *redis.Client) *Limiter {
	return &Limiter{rdb: rdb}
}

func NewFromURL(redisURL string) (*Limiter, error) {
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("parse redis url: %w", err)
	}
	rdb := redis.NewClient(opts)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		_ = rdb.Close()
		return nil, fmt.Errorf("redis ping: %w", err)
	}
	return New(rdb), nil
}

func (l *Limiter) Close() error {
	if l == nil || l.rdb == nil {
		return nil
	}
	return l.rdb.Close()
}

// consumeScript atomically enforces a sliding window.
// KEYS[1] = redis key
// ARGV[1] = now unix nano
// ARGV[2] = window start unix nano
// ARGV[3] = limit
// ARGV[4] = expire seconds
// Returns: {allowed (0|1), limit, retry_after_unix_nano}
var consumeScript = redis.NewScript(`
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window_start = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local expire_sec = tonumber(ARGV[4])

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

redis.call('ZADD', key, now, tostring(now) .. '-' .. tostring(count))
redis.call('EXPIRE', key, expire_sec)
return {1, limit, 0}
`)

// Consume records one hit for key under the given limit within a 1-minute sliding window.
func (l *Limiter) Consume(ctx context.Context, key string, limit int) (Result, error) {
	if limit <= 0 {
		limit = AnonymousLimit
	}
	now := time.Now()
	windowStart := now.Add(-Window)
	redisKey := "rl:" + key

	res, err := consumeScript.Run(ctx, l.rdb, []string{redisKey},
		now.UnixNano(),
		windowStart.UnixNano(),
		limit,
		int((Window + time.Second).Seconds()),
	).Int64Slice()
	if err != nil {
		return Result{}, err
	}
	if len(res) < 3 {
		return Result{}, fmt.Errorf("unexpected redis script result")
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
