package domain

import "errors"

var (
	ErrInvalidCredentials        = errors.New("invalid_credentials")
	ErrEmailNotVerified          = errors.New("email_not_verified")
	ErrUserDisabled              = errors.New("user_disabled")
	ErrUserAlreadyExists         = errors.New("user_already_exists")
	ErrUserNotFound              = errors.New("user_not_found")
	ErrRefreshTokenNotFound      = errors.New("refresh_token_not_found")
	ErrVerificationTokenInvalid  = errors.New("verification_token_invalid")
	ErrVerificationTokenExpired  = errors.New("verification_token_expired")
	ErrPasswordResetTokenInvalid = errors.New("password_reset_token_invalid")
	ErrPasswordResetTokenExpired = errors.New("password_reset_token_expired")
	ErrResendRateLimited         = errors.New("resend_rate_limited")
	ErrPasswordResetRateLimited  = errors.New("password_reset_rate_limited")
	ErrInvalidContent            = errors.New("invalid_content")
	ErrUnauthorized              = errors.New("unauthorized")
)

type RateLimitedError struct {
	Code        string
	WaitSeconds int
}

func (e *RateLimitedError) Error() string {
	return e.Code
}

func (e *RateLimitedError) Unwrap() error {
	switch e.Code {
	case "resend_rate_limited":
		return ErrResendRateLimited
	case "password_reset_rate_limited":
		return ErrPasswordResetRateLimited
	default:
		return errors.New(e.Code)
	}
}

type ValidationError struct {
	Fields []FieldError
}

type FieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

func (e *ValidationError) Error() string {
	return "invalid_content"
}

func (e *ValidationError) Unwrap() error {
	return ErrInvalidContent
}
