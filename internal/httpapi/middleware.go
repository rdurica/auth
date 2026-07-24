package httpapi

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rdurica/auth/internal/domain"
	"github.com/rdurica/auth/internal/token"
)

type ctxKey int

const userUUIDKey ctxKey = 1

func UserUUIDFromContext(ctx context.Context) (uuid.UUID, bool) {
	v, ok := ctx.Value(userUUIDKey).(uuid.UUID)
	return v, ok
}

func withUserUUID(ctx context.Context, id uuid.UUID) context.Context {
	return context.WithValue(ctx, userUUIDKey, id)
}

func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if id == "" {
			id = uuid.NewString()
		}
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r)
	})
}

func Recover(log *slog.Logger, problems ProblemWriter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					log.Error("panic", "err", rec)
					problems.Write(w, http.StatusInternalServerError, "internal_error", "internal server error", nil, nil)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

func AccessLog(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rw := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rw, r)
			attrs := []any{
				"method", r.Method,
				"path", r.URL.Path,
				"status", rw.status,
			}
			if rw.code != "" {
				attrs = append(attrs, "code", rw.code)
			}
			attrs = append(attrs, "duration_ms", float64(time.Since(start).Microseconds())/1000)
			log.Info("request", attrs...)
		})
	}
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	code   string
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *statusRecorder) SetProblemCode(code string) {
	r.code = code
}

type JWTParser interface {
	Parse(tokenString string) (*token.Claims, error)
}

func RequireAuth(jwt JWTParser, problems ProblemWriter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			header := r.Header.Get("Authorization")
			if !strings.HasPrefix(header, "Bearer ") {
				problems.FromError(w, domain.ErrUnauthorized)
				return
			}
			raw := strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
			claims, err := jwt.Parse(raw)
			if err != nil {
				problems.FromError(w, domain.ErrUnauthorized)
				return
			}
			id, err := uuid.Parse(claims.UUID)
			if err != nil {
				problems.FromError(w, domain.ErrUnauthorized)
				return
			}
			next.ServeHTTP(w, r.WithContext(withUserUUID(r.Context(), id)))
		})
	}
}
