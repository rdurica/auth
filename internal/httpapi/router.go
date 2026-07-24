package httpapi

import (
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/rdurica/auth/internal/app"
	"github.com/rdurica/auth/internal/token"
)

type Deps struct {
	Auth       *app.AuthService
	JWT        *token.JWTService
	Limiter    RateLimiter
	LoginGuard LoginBruteForce
	Logger     *slog.Logger
	ErrorBase  string
}

func NewRouter(d Deps) http.Handler {
	problems := ProblemWriter{BaseURL: d.ErrorBase}
	authAPI := &AuthAPI{svc: d.Auth, problems: problems, loginGuard: d.LoginGuard, log: d.Logger}
	userAPI := &UserAPI{svc: d.Auth, problems: problems}
	jwks := &JWKSHandler{KeyID: d.JWT.KeyID(), PublicKey: d.JWT.PublicKey()}

	r := chi.NewRouter()
	r.Use(
		RequestID,
		AccessLog(d.Logger),
		RateLimit(d.Limiter, d.JWT, problems, d.Logger),
		Recover(d.Logger, problems),
	)
	r.NotFound(func(w http.ResponseWriter, _ *http.Request) {
		problems.Write(w, http.StatusNotFound, "not_found", "resource not found", nil, nil)
	})
	r.MethodNotAllowed(func(w http.ResponseWriter, _ *http.Request) {
		problems.Write(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed", nil, nil)
	})

	r.Get("/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	r.Method(http.MethodGet, "/.well-known/jwks.json", jwks)

	r.Route("/api/auth", func(r chi.Router) {
		r.Post("/register", authAPI.Register)
		r.Post("/login", authAPI.Login)
		r.Post("/refresh", authAPI.Refresh)
		r.Post("/logout", authAPI.Logout)
		r.Route("/verify-email", func(r chi.Router) {
			r.Post("/", authAPI.VerifyEmail)
			r.Post("/resend", authAPI.ResendVerification)
		})
		r.Route("/password-reset", func(r chi.Router) {
			r.Post("/", authAPI.PasswordReset)
			r.Post("/validate", authAPI.ValidatePasswordResetToken)
			r.Post("/confirm", authAPI.SetPassword)
		})
	})

	r.Route("/api/user", func(r chi.Router) {
		r.Use(RequireAuth(d.JWT, problems))
		r.Get("/profile", userAPI.GetProfile)
		r.Patch("/profile", userAPI.UpdateProfile)
		r.Put("/profile", userAPI.UpdateProfile) // alias for partial update (compat)
		r.Put("/password", userAPI.ChangePassword)
		r.Delete("/account", userAPI.DeleteAccount)
	})

	return r
}
