package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rdurica/auth/internal/domain"
	"github.com/rdurica/auth/internal/store/postgres/sqlc"
)

type RefreshTokenRepo struct {
	q *sqlc.Queries
}

func NewRefreshTokenRepo(pool *pgxpool.Pool) *RefreshTokenRepo {
	return &RefreshTokenRepo{q: sqlc.New(pool)}
}

func (r *RefreshTokenRepo) Create(ctx context.Context, t *domain.RefreshToken) error {
	id, err := r.q.CreateRefreshToken(ctx, sqlc.CreateRefreshTokenParams{
		UserUuid:  t.UserUUID,
		Token:     t.Token,
		IssuedAt:  t.IssuedAt,
		ExpiresAt: t.ExpiresAt,
	})
	if err != nil {
		return fmt.Errorf("create refresh token: %w", err)
	}
	t.ID = id
	return nil
}

func (r *RefreshTokenRepo) FindByToken(ctx context.Context, token string) (*domain.RefreshToken, error) {
	row, err := r.q.GetRefreshTokenByToken(ctx, token)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrRefreshTokenNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("find refresh token: %w", err)
	}
	return refreshToDomain(row), nil
}

func (r *RefreshTokenRepo) FindActiveByUser(ctx context.Context, userUUID uuid.UUID, now time.Time) (*domain.RefreshToken, error) {
	row, err := r.q.GetActiveRefreshTokenByUser(ctx, sqlc.GetActiveRefreshTokenByUserParams{
		UserUuid:  userUUID,
		ExpiresAt: now,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrRefreshTokenNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("find active refresh token: %w", err)
	}
	return refreshToDomain(row), nil
}

func (r *RefreshTokenRepo) Revoke(ctx context.Context, id int64, at time.Time) error {
	return r.q.RevokeRefreshToken(ctx, sqlc.RevokeRefreshTokenParams{
		ID:        id,
		RevokedAt: &at,
	})
}

func (r *RefreshTokenRepo) RevokeAllForUser(ctx context.Context, userUUID uuid.UUID, at time.Time) error {
	return r.q.RevokeAllRefreshTokensForUser(ctx, sqlc.RevokeAllRefreshTokensForUserParams{
		UserUuid:  userUUID,
		RevokedAt: &at,
	})
}
