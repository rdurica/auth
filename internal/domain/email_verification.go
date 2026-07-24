package domain

import "time"

// Verification resend delays: 60s → 5m → 10m → 30m (capped).
var verificationDelays = []time.Duration{
	60 * time.Second,
	5 * time.Minute,
	10 * time.Minute,
	30 * time.Minute,
}

// EmailVerification holds pending e-mail verification state on a User.
type EmailVerification struct {
	Token      *string
	ExpiresAt  *time.Time
	LastSentAt *time.Time
	Attempts   int
}

func (v EmailVerification) checkRateLimit(now time.Time) error {
	if v.LastSentAt == nil || v.Attempts <= 0 {
		return nil
	}
	idx := v.Attempts - 1
	if idx >= len(verificationDelays) {
		idx = len(verificationDelays) - 1
	}
	waitUntil := v.LastSentAt.Add(verificationDelays[idx])
	if now.Before(waitUntil) {
		return &RateLimitedError{
			Code:        "resend_rate_limited",
			WaitSeconds: int(waitUntil.Sub(now).Seconds()) + 1,
		}
	}
	return nil
}

func (v EmailVerification) isValid(token OpaqueToken, now time.Time) error {
	if v.Token == nil || !token.Equal(*v.Token) {
		return ErrVerificationTokenInvalid
	}
	if v.ExpiresAt == nil || !v.ExpiresAt.After(now) {
		return ErrVerificationTokenExpired
	}
	return nil
}

func startVerification(token OpaqueToken, ttl time.Duration, now time.Time, prevAttempts int) EmailVerification {
	tok := token.String()
	expires := now.Add(ttl)
	return EmailVerification{
		Token:      &tok,
		ExpiresAt:  &expires,
		LastSentAt: &now,
		Attempts:   prevAttempts + 1,
	}
}
