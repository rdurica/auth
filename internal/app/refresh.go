package app

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/rdurica/auth/internal/domain"
	"github.com/rdurica/auth/internal/token"
)

type RefreshResult struct {
	AuthenticationToken string
	RefreshToken        string // empty if not rotated
}

// Logout revokes the given refresh token. Missing or already-revoked tokens are
// treated as success (idempotent).
func (s *AuthService) Logout(ctx context.Context, refreshToken string) error {
	if refreshToken == "" {
		return nil
	}
	rt, err := s.refresh.FindByToken(ctx, refreshToken)
	if err != nil {
		if errors.Is(err, domain.ErrRefreshTokenNotFound) {
			return nil
		}
		return err
	}
	if rt.RevokedAt != nil {
		return nil
	}
	return s.refresh.Revoke(ctx, rt.ID, s.now())
}

func (s *AuthService) Refresh(ctx context.Context, refreshToken string) (*RefreshResult, error) {
	if refreshToken == "" {
		return nil, domain.ErrRefreshTokenNotFound
	}
	rt, err := s.refresh.FindByToken(ctx, refreshToken)
	if err != nil {
		return nil, err
	}
	now := s.now()
	if err := rt.AssertActive(now); err != nil {
		return nil, err
	}

	user, err := s.users.FindByUUID(ctx, rt.UserUUID)
	if err != nil {
		return nil, err
	}
	if err := user.AssertActive(); err != nil {
		_ = s.refresh.RevokeAllForUser(ctx, user.UUID, now)
		return nil, err
	}

	roles := user.Roles
	if len(roles) == 0 {
		roles = []string{domain.RoleUser}
	}
	access, err := s.jwt.Issue(user.UUID, roles)
	if err != nil {
		return nil, err
	}

	result := &RefreshResult{AuthenticationToken: access}
	if rt.ShouldRotate(now, time.Hour) {
		if err := s.refresh.Revoke(ctx, rt.ID, now); err != nil {
			return nil, err
		}
		newToken, err := s.createRefresh(ctx, user.UUID, now)
		if err != nil {
			return nil, err
		}
		result.RefreshToken = newToken
	}
	return result, nil
}

func (s *AuthService) issueOrReuseRefresh(ctx context.Context, userUUID uuid.UUID) (string, error) {
	now := s.now()
	existing, err := s.refresh.FindActiveByUser(ctx, userUUID, now)
	if err == nil && !existing.ShouldRotate(now, time.Hour) {
		return existing.Token, nil
	}
	if err == nil && existing.ShouldRotate(now, time.Hour) {
		_ = s.refresh.Revoke(ctx, existing.ID, now)
	}
	if err != nil && !errors.Is(err, domain.ErrRefreshTokenNotFound) {
		return "", err
	}
	return s.createRefresh(ctx, userUUID, now)
}

func (s *AuthService) createRefresh(ctx context.Context, userUUID uuid.UUID, now time.Time) (string, error) {
	opaque, err := token.NewOpaque()
	if err != nil {
		return "", err
	}
	rt := domain.IssueRefreshToken(userUUID, domain.NewOpaqueToken(opaque), now, s.refreshTTL)
	if err := s.refresh.Create(ctx, rt); err != nil {
		return "", err
	}
	return opaque, nil
}
