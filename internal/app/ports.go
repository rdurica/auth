package app

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/rdurica/auth/internal/domain"
)

type UserRepository interface {
	Create(ctx context.Context, u *domain.User) error
	Save(ctx context.Context, u *domain.User) error
	FindByEmail(ctx context.Context, email domain.Email) (*domain.User, error)
	FindByUUID(ctx context.Context, id uuid.UUID) (*domain.User, error)
	FindByVerificationToken(ctx context.Context, token string) (*domain.User, error)
	FindByPasswordResetToken(ctx context.Context, token string) (*domain.User, error)
}

type RefreshTokenRepository interface {
	Create(ctx context.Context, t *domain.RefreshToken) error
	FindByToken(ctx context.Context, token string) (*domain.RefreshToken, error)
	FindActiveByUser(ctx context.Context, userUUID uuid.UUID, now time.Time) (*domain.RefreshToken, error)
	Revoke(ctx context.Context, id int64, at time.Time) error
	RevokeAllForUser(ctx context.Context, userUUID uuid.UUID, at time.Time) error
}

type JWTIssuer interface {
	Issue(userUUID uuid.UUID, roles []string) (string, error)
}
