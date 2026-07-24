package domain

import "time"

// Password reset: first 2 free, then progressive up to 8h.
var passwordResetDelays = []time.Duration{
	0,
	0,
	60 * time.Second,
	5 * time.Minute,
	30 * time.Minute,
	2 * time.Hour,
	4 * time.Hour,
	8 * time.Hour,
}

// PasswordReset holds pending password-reset state on a User.
type PasswordReset struct {
	Token      *string
	ExpiresAt  *time.Time
	LastSentAt *time.Time
	Attempts   int
}

func (r PasswordReset) checkRateLimit(now time.Time) error {
	if r.LastSentAt == nil || r.Attempts <= 0 {
		return nil
	}
	idx := r.Attempts
	if idx >= len(passwordResetDelays) {
		idx = len(passwordResetDelays) - 1
	}
	delay := passwordResetDelays[idx]
	if delay == 0 {
		return nil
	}
	waitUntil := r.LastSentAt.Add(delay)
	if now.Before(waitUntil) {
		return &RateLimitedError{
			Code:        "password_reset_rate_limited",
			WaitSeconds: int(waitUntil.Sub(now).Seconds()) + 1,
		}
	}
	return nil
}

func (r PasswordReset) isValid(token OpaqueToken, now time.Time) error {
	if r.Token == nil || !token.Equal(*r.Token) {
		return ErrPasswordResetTokenInvalid
	}
	if r.ExpiresAt == nil || !r.ExpiresAt.After(now) {
		return ErrPasswordResetTokenExpired
	}
	return nil
}

func startPasswordReset(token OpaqueToken, ttl time.Duration, now time.Time, prevAttempts int) PasswordReset {
	tok := token.String()
	expires := now.Add(ttl)
	return PasswordReset{
		Token:      &tok,
		ExpiresAt:  &expires,
		LastSentAt: &now,
		Attempts:   prevAttempts + 1,
	}
}
