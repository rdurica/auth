package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rdurica/auth/internal/domain"
	"github.com/rdurica/auth/internal/store/postgres/sqlc"
)

type UserRepo struct {
	q *sqlc.Queries
}

func NewUserRepo(pool *pgxpool.Pool) *UserRepo {
	return &UserRepo{q: sqlc.New(pool)}
}

func (r *UserRepo) Create(ctx context.Context, u *domain.User) error {
	roles, err := marshalRoles(u.Roles)
	if err != nil {
		return err
	}
	id, err := r.q.CreateUser(ctx, sqlc.CreateUserParams{
		Uuid:                            u.UUID,
		Email:                           u.Email.String(),
		PasswordHash:                    u.Password,
		FirstName:                       u.FirstName,
		LastName:                        u.LastName,
		Phone:                           u.Phone,
		Roles:                           roles,
		IsActive:                        u.IsActive,
		IsEmailVerified:                 u.IsEmailVerified,
		EmailVerificationToken:          u.Verification.Token,
		EmailVerificationTokenExpiresAt: u.Verification.ExpiresAt,
		LastVerificationEmailSentAt:     u.Verification.LastSentAt,
		VerificationEmailAttempts:       int32(u.Verification.Attempts),
		CreatedAt:                       u.CreatedAt,
	})
	if err != nil {
		if isUniqueViolation(err) {
			return domain.ErrUserAlreadyExists
		}
		return fmt.Errorf("create user: %w", err)
	}
	u.ID = id
	return nil
}

func (r *UserRepo) Save(ctx context.Context, u *domain.User) error {
	roles, err := marshalRoles(u.Roles)
	if err != nil {
		return err
	}
	err = r.q.UpdateUser(ctx, sqlc.UpdateUserParams{
		ID:                              u.ID,
		Email:                           u.Email.String(),
		PasswordHash:                    u.Password,
		FirstName:                       u.FirstName,
		LastName:                        u.LastName,
		Phone:                           u.Phone,
		Roles:                           roles,
		IsActive:                        u.IsActive,
		IsEmailVerified:                 u.IsEmailVerified,
		EmailVerificationToken:          u.Verification.Token,
		EmailVerificationTokenExpiresAt: u.Verification.ExpiresAt,
		LastVerificationEmailSentAt:     u.Verification.LastSentAt,
		VerificationEmailAttempts:       int32(u.Verification.Attempts),
		PasswordResetToken:              u.PasswordReset.Token,
		PasswordResetTokenExpiresAt:     u.PasswordReset.ExpiresAt,
		LastPasswordResetEmailSentAt:    u.PasswordReset.LastSentAt,
		PasswordResetAttempts:           int32(u.PasswordReset.Attempts),
	})
	if err != nil {
		if isUniqueViolation(err) {
			return domain.ErrUserAlreadyExists
		}
		return fmt.Errorf("save user: %w", err)
	}
	return nil
}

func (r *UserRepo) FindByEmail(ctx context.Context, email domain.Email) (*domain.User, error) {
	row, err := r.q.GetUserByEmail(ctx, email.String())
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("find user by email: %w", err)
	}
	return userToDomain(row)
}

func (r *UserRepo) FindByUUID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	row, err := r.q.GetUserByUUID(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("find user by uuid: %w", err)
	}
	return userToDomain(row)
}

func (r *UserRepo) FindByVerificationToken(ctx context.Context, token string) (*domain.User, error) {
	row, err := r.q.GetUserByVerificationToken(ctx, &token)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrVerificationTokenInvalid
	}
	if err != nil {
		return nil, fmt.Errorf("find user by verification token: %w", err)
	}
	return userToDomain(row)
}

func (r *UserRepo) FindByPasswordResetToken(ctx context.Context, token string) (*domain.User, error) {
	row, err := r.q.GetUserByPasswordResetToken(ctx, &token)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrPasswordResetTokenInvalid
	}
	if err != nil {
		return nil, fmt.Errorf("find user by password reset token: %w", err)
	}
	return userToDomain(row)
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == pgerrcode.UniqueViolation
}
