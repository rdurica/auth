package httpapi

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/rdurica/auth/internal/ratelimit"
)

// RateLimiter is the sliding-window backend used by RateLimit middleware.
type RateLimiter interface {
	Consume(ctx context.Context, key string, limit int) (ratelimit.Result, error)
}

func RateLimit(limiter RateLimiter, jwt JWTParser, problems ProblemWriter, log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if limiter == nil || !shouldRateLimit(r) {
				next.ServeHTTP(w, r)
				return
			}

			clientID, limit := resolveClient(r, jwt)
			key := clientID + ":" + r.URL.Path
			result, err := limiter.Consume(r.Context(), key, limit)
			if err != nil {
				log.Warn("rate limiter error", "err", err, "path", r.URL.Path)
				next.ServeHTTP(w, r)
				return
			}
			if !result.Allowed {
				log.Warn("rate limit exceeded",
					"client", clientID,
					"path", r.URL.Path,
					"limit", result.Limit,
					"retry_after", result.RetryAfter.Unix(),
				)
				w.Header().Set("X-RateLimit-Limit", strconv.Itoa(result.Limit))
				if !result.RetryAfter.IsZero() {
					w.Header().Set("X-RateLimit-Retry-After", strconv.FormatInt(result.RetryAfter.Unix(), 10))
					sec := int(time.Until(result.RetryAfter).Seconds())
					if sec < 0 {
						sec = 0
					}
					w.Header().Set("Retry-After", strconv.Itoa(sec))
				}
				problems.Write(w, http.StatusTooManyRequests, "rate_limit_exceeded", "too many requests", nil, nil)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func shouldRateLimit(r *http.Request) bool {
	if r.Method == http.MethodOptions {
		return false
	}
	path := r.URL.Path
	if path == "/health" || path == "/.well-known/jwks.json" {
		return false
	}
	if !strings.HasPrefix(path, "/api") {
		return false
	}
	if r.Method == http.MethodPost && path == "/api/auth/refresh" {
		return false
	}
	return true
}

func resolveClient(r *http.Request, jwt JWTParser) (clientID string, limit int) {
	if jwt != nil {
		header := r.Header.Get("Authorization")
		if strings.HasPrefix(header, "Bearer ") {
			raw := strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
			if claims, err := jwt.Parse(raw); err == nil && claims.UUID != "" {
				return "user:" + claims.UUID, ratelimit.AuthenticatedLimit
			}
		}
	}
	return "ip:" + clientIP(r), ratelimit.AnonymousLimit
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if ip := strings.TrimSpace(parts[0]); ip != "" {
			return ip
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
