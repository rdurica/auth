package app

import (
	"context"
	"errors"
	"fmt"

	"github.com/rdurica/auth/internal/domain"
	"github.com/rdurica/auth/internal/password"
	"github.com/rdurica/auth/internal/token"
)

func (s *AuthService) VerifyEmail(ctx context.Context, verifyToken string) error {
	tok, err := domain.ParseOpaqueToken(verifyToken)
	if err != nil {
		return domain.ErrVerificationTokenInvalid
	}
	user, err := s.users.FindByVerificationToken(ctx, tok.String())
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return domain.ErrVerificationTokenInvalid
		}
		return err
	}
	if err := user.VerifyEmail(tok, s.now()); err != nil {
		return err
	}
	return s.users.Save(ctx, user)
}

func (s *AuthService) ResendVerification(ctx context.Context, rawEmail string) error {
	email, err := domain.ParseEmail(rawEmail)
	if err != nil {
		return nil // anti-enumeration
	}
	user, err := s.users.FindByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return nil
		}
		return err
	}
	if user.IsEmailVerified {
		return nil
	}
	rawToken, err := token.NewOpaque()
	if err != nil {
		return err
	}
	verifyToken := domain.NewOpaqueToken(rawToken)
	if err := user.RequestVerificationResend(verifyToken, s.emailVerifyTTL, s.now()); err != nil {
		return err
	}
	if err := s.users.Save(ctx, user); err != nil {
		return err
	}
	if err := s.mail.SendVerification(ctx, user.Email.String(), verifyToken.String()); err != nil {
		return fmt.Errorf("send verification email: %w", err)
	}
	return nil
}

func (s *AuthService) RequestPasswordReset(ctx context.Context, rawEmail string) error {
	email, err := domain.ParseEmail(rawEmail)
	if err != nil {
		return nil
	}
	user, err := s.users.FindByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return nil
		}
		return err
	}
	if !user.IsActive {
		return nil
	}
	rawToken, err := token.NewOpaque()
	if err != nil {
		return err
	}
	resetToken := domain.NewOpaqueToken(rawToken)
	if err := user.RequestPasswordReset(resetToken, s.passwordResetTTL, s.now()); err != nil {
		return err
	}
	if err := s.users.Save(ctx, user); err != nil {
		return err
	}
	if err := s.mail.SendPasswordReset(ctx, user.Email.String(), resetToken.String()); err != nil {
		return fmt.Errorf("send password reset email: %w", err)
	}
	return nil
}

func (s *AuthService) ValidatePasswordResetToken(ctx context.Context, resetToken string) error {
	tok, err := domain.ParseOpaqueToken(resetToken)
	if err != nil {
		return domain.ErrPasswordResetTokenInvalid
	}
	user, err := s.users.FindByPasswordResetToken(ctx, tok.String())
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return domain.ErrPasswordResetTokenInvalid
		}
		return err
	}
	return user.AssertPasswordResetToken(tok, s.now())
}

func (s *AuthService) SetPassword(ctx context.Context, resetToken, newPassword string) error {
	plain, err := domain.ParsePlainPassword(newPassword)
	if err != nil {
		return err
	}
	tok, err := domain.ParseOpaqueToken(resetToken)
	if err != nil {
		return domain.ErrPasswordResetTokenInvalid
	}
	user, err := s.users.FindByPasswordResetToken(ctx, tok.String())
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return domain.ErrPasswordResetTokenInvalid
		}
		return err
	}
	now := s.now()
	if err := user.ConsumePasswordReset(tok, now); err != nil {
		return err
	}
	hash, err := password.Hash(plain.String())
	if err != nil {
		return err
	}
	user.SetPasswordAfterReset(hash)
	if err := s.users.Save(ctx, user); err != nil {
		return err
	}
	return s.refresh.RevokeAllForUser(ctx, user.UUID, now)
}
