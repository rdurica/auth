package app

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/rdurica/auth/internal/domain"
	"github.com/rdurica/auth/internal/password"
)

type Profile struct {
	UUID      uuid.UUID `json:"uuid"`
	Email     string    `json:"email"`
	FirstName string    `json:"firstName,omitempty"`
	LastName  string    `json:"lastName,omitempty"`
	Phone     *string   `json:"phone,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
}

func (s *AuthService) GetProfile(ctx context.Context, userUUID uuid.UUID) (*Profile, error) {
	user, err := s.users.FindByUUID(ctx, userUUID)
	if err != nil {
		return nil, err
	}
	if err := user.AssertActive(); err != nil {
		return nil, err
	}
	return &Profile{
		UUID:      user.UUID,
		Email:     user.Email.String(),
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Phone:     user.Phone,
		CreatedAt: user.CreatedAt,
	}, nil
}

type UpdateProfileInput struct {
	FirstName *string
	LastName  *string
	Phone     *string
	PhoneSet  bool // true if phone key was present (including null/empty to clear)
}

func (s *AuthService) UpdateProfile(ctx context.Context, userUUID uuid.UUID, in UpdateProfileInput) error {
	user, err := s.users.FindByUUID(ctx, userUUID)
	if err != nil {
		return err
	}
	if err := user.AssertActive(); err != nil {
		return err
	}

	var firstName, lastName *domain.PersonName
	if in.FirstName != nil {
		n, err := domain.ParsePersonNameField(*in.FirstName, "firstName")
		if err != nil {
			return err
		}
		firstName = &n
	}
	if in.LastName != nil {
		n, err := domain.ParsePersonNameField(*in.LastName, "lastName")
		if err != nil {
			return err
		}
		lastName = &n
	}

	var phone *string
	if in.PhoneSet {
		if in.Phone == nil {
			phone = nil
		} else {
			phone, err = domain.ParsePhone(*in.Phone)
			if err != nil {
				return err
			}
		}
	}

	if err := user.UpdateProfile(firstName, lastName, phone, in.PhoneSet); err != nil {
		return err
	}
	return s.users.Save(ctx, user)
}

func (s *AuthService) ChangePassword(ctx context.Context, userUUID uuid.UUID, currentPassword, newPassword string) error {
	plain, err := domain.ParsePlainPasswordField(newPassword, "newPassword")
	if err != nil {
		return err
	}
	user, err := s.users.FindByUUID(ctx, userUUID)
	if err != nil {
		return err
	}
	if err := user.AssertActive(); err != nil {
		return err
	}
	ok, err := password.Verify(user.Password, currentPassword)
	if err != nil || !ok {
		return &domain.ValidationError{Fields: []domain.FieldError{
			{Field: "currentPassword", Message: "invalid credentials"},
		}}
	}
	hash, err := password.Hash(plain.String())
	if err != nil {
		return err
	}
	user.ChangePassword(hash)
	if err := s.users.Save(ctx, user); err != nil {
		return err
	}
	return s.refresh.RevokeAllForUser(ctx, user.UUID, s.now())
}

func (s *AuthService) DeleteAccount(ctx context.Context, userUUID uuid.UUID, confirmation, pass string) error {
	if confirmation != "DELETE" {
		return &domain.ValidationError{Fields: []domain.FieldError{
			{Field: "confirmation", Message: `must be "DELETE"`},
		}}
	}
	user, err := s.users.FindByUUID(ctx, userUUID)
	if err != nil {
		return err
	}
	if err := user.AssertActive(); err != nil {
		return err
	}
	ok, err := password.Verify(user.Password, pass)
	if err != nil || !ok {
		return &domain.ValidationError{Fields: []domain.FieldError{
			{Field: "password", Message: "invalid credentials"},
		}}
	}
	now := s.now()
	if err := s.refresh.RevokeAllForUser(ctx, user.UUID, now); err != nil {
		return err
	}
	hash, err := password.Hash(uuid.NewString())
	if err != nil {
		return err
	}
	user.Deactivate(hash)
	return s.users.Save(ctx, user)
}
