package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/rdurica/auth/internal/app"
	"github.com/rdurica/auth/internal/domain"
	"github.com/rdurica/auth/internal/ratelimit"
)

// LoginBruteForce protects POST /login against credential stuffing.
type LoginBruteForce interface {
	Allow(ctx context.Context, ip, email string) (ratelimit.Result, error)
	RecordFailure(ctx context.Context, ip, email string) error
	Clear(ctx context.Context, ip, email string) error
}

type AuthAPI struct {
	svc        *app.AuthService
	problems   ProblemWriter
	loginGuard LoginBruteForce
	log        *slog.Logger
}

func (a *AuthAPI) Register(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email     string `json:"email"`
		Password  string `json:"password"`
		FirstName string `json:"firstName"`
		LastName  string `json:"lastName"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeDecodeError(a.problems, w, err)
		return
	}
	result, err := a.svc.Register(r.Context(), app.RegisterInput{
		Email: body.Email, Password: body.Password, FirstName: body.FirstName, LastName: body.LastName,
	})
	if err != nil {
		a.problems.FromError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"uuid":                      result.UUID,
		"emailVerificationRequired": result.EmailVerificationRequired,
	})
}

func (a *AuthAPI) Login(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeDecodeError(a.problems, w, err)
		return
	}

	ip := clientIP(r)
	if a.loginGuard != nil {
		res, err := a.loginGuard.Allow(r.Context(), ip, body.Email)
		if err != nil {
			if a.log != nil {
				a.log.Warn("login brute-force check error", "err", err)
			}
		} else if !res.Allowed {
			a.writeLoginRateLimited(w, res)
			return
		}
	}

	result, err := a.svc.Login(r.Context(), body.Email, body.Password)
	if err != nil {
		if errors.Is(err, domain.ErrInvalidCredentials) && a.loginGuard != nil {
			if recErr := a.loginGuard.RecordFailure(r.Context(), ip, body.Email); recErr != nil && a.log != nil {
				a.log.Warn("login brute-force record error", "err", recErr)
			}
		}
		a.problems.FromError(w, err)
		return
	}
	if a.loginGuard != nil {
		if clearErr := a.loginGuard.Clear(r.Context(), ip, body.Email); clearErr != nil && a.log != nil {
			a.log.Warn("login brute-force clear error", "err", clearErr)
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"authenticationToken": result.AuthenticationToken,
		"refreshToken":        result.RefreshToken,
	})
}

func (a *AuthAPI) writeLoginRateLimited(w http.ResponseWriter, res ratelimit.Result) {
	w.Header().Set("X-RateLimit-Limit", strconv.Itoa(res.Limit))
	var wait *int
	if !res.RetryAfter.IsZero() {
		w.Header().Set("X-RateLimit-Retry-After", strconv.FormatInt(res.RetryAfter.Unix(), 10))
		sec := int(time.Until(res.RetryAfter).Seconds())
		if sec < 0 {
			sec = 0
		}
		w.Header().Set("Retry-After", strconv.Itoa(sec))
		wait = &sec
	}
	a.problems.Write(w, http.StatusTooManyRequests, "login_rate_limited", "too many login attempts", nil, wait)
}

func (a *AuthAPI) Refresh(w http.ResponseWriter, r *http.Request) {
	var body struct {
		RefreshToken string `json:"refreshToken"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeDecodeError(a.problems, w, err)
		return
	}
	result, err := a.svc.Refresh(r.Context(), body.RefreshToken)
	if err != nil {
		a.problems.FromError(w, err)
		return
	}
	resp := map[string]string{"authenticationToken": result.AuthenticationToken}
	if result.RefreshToken != "" {
		resp["refreshToken"] = result.RefreshToken
	}
	writeJSON(w, http.StatusOK, resp)
}

func (a *AuthAPI) Logout(w http.ResponseWriter, r *http.Request) {
	var body struct {
		RefreshToken string `json:"refreshToken"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeDecodeError(a.problems, w, err)
		return
	}
	if err := a.svc.Logout(r.Context(), body.RefreshToken); err != nil {
		a.problems.FromError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *AuthAPI) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token string `json:"token"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeDecodeError(a.problems, w, err)
		return
	}
	if err := a.svc.VerifyEmail(r.Context(), body.Token); err != nil {
		a.problems.FromError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"verified": true})
}

func (a *AuthAPI) ResendVerification(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email string `json:"email"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeDecodeError(a.problems, w, err)
		return
	}
	if err := a.svc.ResendVerification(r.Context(), body.Email); err != nil {
		a.problems.FromError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"emailSent": true})
}

func (a *AuthAPI) PasswordReset(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email string `json:"email"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeDecodeError(a.problems, w, err)
		return
	}
	if err := a.svc.RequestPasswordReset(r.Context(), body.Email); err != nil {
		a.problems.FromError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"emailSent": true})
}

func (a *AuthAPI) ValidatePasswordResetToken(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token string `json:"token"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeDecodeError(a.problems, w, err)
		return
	}
	if err := a.svc.ValidatePasswordResetToken(r.Context(), body.Token); err != nil {
		a.problems.FromError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"valid": true})
}

func (a *AuthAPI) SetPassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeDecodeError(a.problems, w, err)
		return
	}
	if err := a.svc.SetPassword(r.Context(), body.Token, body.Password); err != nil {
		a.problems.FromError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"passwordChanged": true})
}

func decodeJSON(r *http.Request, dst any) error {
	defer r.Body.Close()
	ct := r.Header.Get("Content-Type")
	if ct != "" {
		mediaType, _, _ := strings.Cut(ct, ";")
		if strings.TrimSpace(mediaType) != "application/json" {
			return errUnsupportedMediaType
		}
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}

var errUnsupportedMediaType = errors.New("unsupported media type")

func writeDecodeError(problems ProblemWriter, w http.ResponseWriter, err error) {
	if errors.Is(err, errUnsupportedMediaType) {
		problems.Write(w, http.StatusUnsupportedMediaType, "invalid_content", "content-type must be application/json", nil, nil)
		return
	}
	problems.Write(w, http.StatusBadRequest, "invalid_content", "invalid json body", nil, nil)
}
