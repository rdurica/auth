package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/rdurica/auth/internal/domain"
)

type Problem struct {
	Type        string              `json:"type"`
	Code        string              `json:"code"`
	Title       string              `json:"title"`
	Status      int                 `json:"status"`
	Detail      string              `json:"detail,omitempty"`
	Errors      []domain.FieldError `json:"errors,omitempty"`
	WaitSeconds *int                `json:"waitSeconds,omitempty"`
}

type ProblemWriter struct {
	BaseURL string
}

func (p ProblemWriter) Write(w http.ResponseWriter, status int, code, detail string, fields []domain.FieldError, wait *int) {
	problem := Problem{
		Type:        strings.TrimRight(p.BaseURL, "/") + "/" + code,
		Code:        code,
		Title:       humanize(code),
		Status:      status,
		Detail:      detail,
		Errors:      fields,
		WaitSeconds: wait,
	}
	if pc, ok := w.(interface{ SetProblemCode(string) }); ok {
		pc.SetProblemCode(code)
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(problem)
}

func (p ProblemWriter) FromError(w http.ResponseWriter, err error) {
	var rate *domain.RateLimitedError
	if errors.As(err, &rate) {
		wait := rate.WaitSeconds
		p.Write(w, http.StatusTooManyRequests, rate.Code, "rate limited", nil, &wait)
		return
	}

	var validation *domain.ValidationError
	if errors.As(err, &validation) {
		p.Write(w, http.StatusBadRequest, "invalid_content", "validation failed", validation.Fields, nil)
		return
	}

	switch {
	case errors.Is(err, domain.ErrInvalidCredentials):
		p.Write(w, http.StatusUnauthorized, "invalid_credentials", "invalid credentials", nil, nil)
	case errors.Is(err, domain.ErrEmailNotVerified):
		p.Write(w, http.StatusForbidden, "email_not_verified", "email is not verified", nil, nil)
	case errors.Is(err, domain.ErrUserDisabled):
		p.Write(w, http.StatusForbidden, "user_disabled", "user is disabled", nil, nil)
	case errors.Is(err, domain.ErrUserAlreadyExists):
		p.Write(w, http.StatusConflict, "user_already_exists", "user already exists", nil, nil)
	case errors.Is(err, domain.ErrUserNotFound):
		p.Write(w, http.StatusNotFound, "user_not_found", "user not found", nil, nil)
	case errors.Is(err, domain.ErrRefreshTokenNotFound):
		p.Write(w, http.StatusUnauthorized, "refresh_token_not_found", "refresh token not found", nil, nil)
	case errors.Is(err, domain.ErrVerificationTokenInvalid):
		p.Write(w, http.StatusBadRequest, "verification_token_invalid", "verification token is invalid", nil, nil)
	case errors.Is(err, domain.ErrVerificationTokenExpired):
		p.Write(w, http.StatusBadRequest, "verification_token_expired", "verification token expired", nil, nil)
	case errors.Is(err, domain.ErrPasswordResetTokenInvalid):
		p.Write(w, http.StatusBadRequest, "password_reset_token_invalid", "password reset token is invalid", nil, nil)
	case errors.Is(err, domain.ErrPasswordResetTokenExpired):
		p.Write(w, http.StatusBadRequest, "password_reset_token_expired", "password reset token expired", nil, nil)
	case errors.Is(err, domain.ErrUnauthorized):
		p.Write(w, http.StatusUnauthorized, "unauthorized", "unauthorized", nil, nil)
	default:
		p.Write(w, http.StatusInternalServerError, "internal_error", "internal server error", nil, nil)
	}
}

func humanize(code string) string {
	parts := strings.Split(code, "_")
	for i, part := range parts {
		if part == "" {
			continue
		}
		parts[i] = strings.ToUpper(part[:1]) + part[1:]
	}
	return strings.Join(parts, " ")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
