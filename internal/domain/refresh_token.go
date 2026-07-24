package domain

import (
	"time"

	"github.com/google/uuid"
)

type RefreshToken struct {
	ID        int64
	UserUUID  uuid.UUID
	Token     string
	IssuedAt  time.Time
	ExpiresAt time.Time
	RevokedAt *time.Time
}

func IssueRefreshToken(userUUID uuid.UUID, opaque OpaqueToken, now time.Time, ttl time.Duration) *RefreshToken {
	return &RefreshToken{
		UserUUID:  userUUID,
		Token:     opaque.String(),
		IssuedAt:  now,
		ExpiresAt: now.Add(ttl),
	}
}

func (t *RefreshToken) Active(now time.Time) bool {
	if t.RevokedAt != nil {
		return false
	}
	return t.ExpiresAt.After(now)
}

func (t *RefreshToken) AssertActive(now time.Time) error {
	if !t.Active(now) {
		return ErrRefreshTokenNotFound
	}
	return nil
}

func (t *RefreshToken) Revoke(now time.Time) {
	t.RevokedAt = &now
}

func (t *RefreshToken) ShouldRotate(now time.Time, window time.Duration) bool {
	return t.ExpiresAt.After(now) && !t.ExpiresAt.After(now.Add(window))
}
