package postgres

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/rdurica/auth/internal/domain"
	"github.com/rdurica/auth/internal/store/postgres/sqlc"
)

func userToDomain(row sqlc.AuthUser) (*domain.User, error) {
	email, err := domain.ParseEmail(row.Email)
	if err != nil {
		return nil, fmt.Errorf("decode email: %w", err)
	}
	var roles []string
	if err := json.Unmarshal(row.Roles, &roles); err != nil {
		return nil, fmt.Errorf("decode roles: %w", err)
	}
	return &domain.User{
		ID:              row.ID,
		UUID:            row.Uuid,
		Email:           email,
		Password:        row.PasswordHash,
		FirstName:       row.FirstName,
		LastName:        row.LastName,
		Phone:           row.Phone,
		Roles:           roles,
		IsActive:        row.IsActive,
		IsEmailVerified: row.IsEmailVerified,
		Verification: domain.EmailVerification{
			Token:      trimToken(row.EmailVerificationToken),
			ExpiresAt:  row.EmailVerificationTokenExpiresAt,
			LastSentAt: row.LastVerificationEmailSentAt,
			Attempts:   int(row.VerificationEmailAttempts),
		},
		PasswordReset: domain.PasswordReset{
			Token:      trimToken(row.PasswordResetToken),
			ExpiresAt:  row.PasswordResetTokenExpiresAt,
			LastSentAt: row.LastPasswordResetEmailSentAt,
			Attempts:   int(row.PasswordResetAttempts),
		},
		CreatedAt: row.CreatedAt,
	}, nil
}

func refreshToDomain(row sqlc.AuthRefreshToken) *domain.RefreshToken {
	return &domain.RefreshToken{
		ID:        row.ID,
		UserUUID:  row.UserUuid,
		Token:     strings.TrimSpace(row.Token),
		IssuedAt:  row.IssuedAt,
		ExpiresAt: row.ExpiresAt,
		RevokedAt: row.RevokedAt,
	}
}

func marshalRoles(roles []string) (json.RawMessage, error) {
	if roles == nil {
		roles = []string{}
	}
	return json.Marshal(roles)
}

func trimToken(tok *string) *string {
	if tok == nil {
		return nil
	}
	s := strings.TrimSpace(*tok)
	if s == "" {
		return nil
	}
	return &s
}
