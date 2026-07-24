package app

import (
	"context"
	"errors"

	"github.com/rdurica/auth/internal/domain"
	"github.com/rdurica/auth/internal/password"
)

type TokenPair struct {
	AuthenticationToken string
	RefreshToken        string
}

func (s *AuthService) Login(ctx context.Context, rawEmail, pass string) (*TokenPair, error) {
	email, parseErr := domain.ParseEmail(rawEmail)
	hash := password.DummyHash
	var user *domain.User
	if parseErr == nil {
		var err error
		user, err = s.users.FindByEmail(ctx, email)
		if err == nil {
			hash = user.Password
		} else if !errors.Is(err, domain.ErrUserNotFound) {
			return nil, err
		}
	}

	ok, verifyErr := password.Verify(hash, pass)
	if verifyErr != nil || !ok || user == nil {
		return nil, domain.ErrInvalidCredentials
	}
	if err := user.AssertCanLogin(); err != nil {
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
	refresh, err := s.issueOrReuseRefresh(ctx, user.UUID)
	if err != nil {
		return nil, err
	}
	return &TokenPair{
		AuthenticationToken: access,
		RefreshToken:        refresh,
	}, nil
}
