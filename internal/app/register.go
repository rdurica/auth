package app

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/rdurica/auth/internal/domain"
	"github.com/rdurica/auth/internal/password"
	"github.com/rdurica/auth/internal/token"
)

type RegisterInput struct {
	Email     string
	Password  string
	FirstName string
	LastName  string
}

type RegisterResult struct {
	UUID                      uuid.UUID
	EmailVerificationRequired bool
}

func (s *AuthService) Register(ctx context.Context, in RegisterInput) (*RegisterResult, error) {
	var fields []domain.FieldError

	email, err := domain.ParseEmail(in.Email)
	if err != nil {
		fields = append(fields, domain.FieldError{Field: "email", Message: "invalid email"})
	}
	plain, err := domain.ParsePlainPassword(in.Password)
	if err != nil {
		var ve *domain.ValidationError
		if errors.As(err, &ve) {
			fields = append(fields, ve.Fields...)
		}
	}
	firstName, err := domain.ParsePersonNameField(in.FirstName, "firstName")
	if err != nil {
		var ve *domain.ValidationError
		if errors.As(err, &ve) {
			fields = append(fields, ve.Fields...)
		}
	}
	lastName, err := domain.ParsePersonNameField(in.LastName, "lastName")
	if err != nil {
		var ve *domain.ValidationError
		if errors.As(err, &ve) {
			fields = append(fields, ve.Fields...)
		}
	}
	if len(fields) > 0 {
		return nil, &domain.ValidationError{Fields: fields}
	}

	hash, err := password.Hash(plain.String())
	if err != nil {
		return nil, err
	}
	rawToken, err := token.NewOpaque()
	if err != nil {
		return nil, err
	}
	verifyToken := domain.NewOpaqueToken(rawToken)
	now := s.now()
	user := domain.RegisterUser(email, hash, firstName, lastName, verifyToken, s.emailVerifyTTL, now)

	if err := s.users.Create(ctx, user); err != nil {
		return nil, err
	}
	if err := s.mail.SendVerification(ctx, user.Email.String(), verifyToken.String()); err != nil {
		return nil, fmt.Errorf("send verification email: %w", err)
	}
	return &RegisterResult{
		UUID:                      user.UUID,
		EmailVerificationRequired: true,
	}, nil
}
