package domain

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

const RoleUser = "USER"

type User struct {
	ID        int64
	UUID      uuid.UUID
	Email     Email
	Password  string
	FirstName string
	LastName  string
	Phone     *string
	Roles     []string

	IsActive        bool
	IsEmailVerified bool

	Verification  EmailVerification
	PasswordReset PasswordReset

	CreatedAt time.Time
}

func RegisterUser(
	email Email,
	passwordHash string,
	firstName, lastName PersonName,
	verifyToken OpaqueToken,
	verifyTTL time.Duration,
	now time.Time,
) *User {
	return &User{
		UUID:            uuid.Must(uuid.NewV7()),
		Email:           email,
		Password:        passwordHash,
		FirstName:       firstName.String(),
		LastName:        lastName.String(),
		Roles:           []string{RoleUser},
		IsActive:        true,
		IsEmailVerified: false,
		Verification:    startVerification(verifyToken, verifyTTL, now, 0),
		CreatedAt:       now,
	}
}

func (u *User) LoginCapable() bool {
	return u.IsActive && u.IsEmailVerified
}

func (u *User) AssertCanLogin() error {
	if !u.IsActive {
		return ErrUserDisabled
	}
	if !u.IsEmailVerified {
		return ErrEmailNotVerified
	}
	return nil
}

func (u *User) AssertActive() error {
	if !u.IsActive {
		return ErrUserDisabled
	}
	return nil
}

func (u *User) VerifyEmail(token OpaqueToken, now time.Time) error {
	if err := u.Verification.isValid(token, now); err != nil {
		return err
	}
	u.IsEmailVerified = true
	u.Verification.Token = nil
	u.Verification.ExpiresAt = nil
	return nil
}

func (u *User) RequestVerificationResend(token OpaqueToken, ttl time.Duration, now time.Time) error {
	if u.IsEmailVerified {
		return nil
	}
	if err := u.Verification.checkRateLimit(now); err != nil {
		return err
	}
	u.Verification = startVerification(token, ttl, now, u.Verification.Attempts)
	return nil
}

func (u *User) RequestPasswordReset(token OpaqueToken, ttl time.Duration, now time.Time) error {
	if !u.IsActive {
		return nil
	}
	if err := u.PasswordReset.checkRateLimit(now); err != nil {
		return err
	}
	u.PasswordReset = startPasswordReset(token, ttl, now, u.PasswordReset.Attempts)
	return nil
}

func (u *User) AssertPasswordResetToken(token OpaqueToken, now time.Time) error {
	return u.PasswordReset.isValid(token, now)
}

func (u *User) ConsumePasswordReset(token OpaqueToken, now time.Time) error {
	if err := u.PasswordReset.isValid(token, now); err != nil {
		return err
	}
	u.PasswordReset.Token = nil
	u.PasswordReset.ExpiresAt = nil
	return nil
}

func (u *User) SetPasswordAfterReset(passwordHash string) {
	u.Password = passwordHash
	u.PasswordReset.Token = nil
	u.PasswordReset.ExpiresAt = nil
}

func (u *User) ChangePassword(passwordHash string) {
	u.Password = passwordHash
}

func (u *User) UpdateProfile(firstName, lastName *PersonName, phone *string, phoneSet bool) error {
	if err := u.AssertActive(); err != nil {
		return err
	}
	if firstName != nil {
		u.FirstName = firstName.String()
	}
	if lastName != nil {
		u.LastName = lastName.String()
	}
	if phoneSet {
		u.Phone = phone
	}
	return nil
}

func (u *User) Deactivate(dummyHash string) {
	u.IsActive = false
	u.Email = MustParseEmail(fmt.Sprintf("deleted+%s@deleted.local", u.UUID.String()))
	u.Password = dummyHash
	u.FirstName = "Deleted"
	u.LastName = "User"
	u.Phone = nil
	u.Verification.Token = nil
	u.Verification.ExpiresAt = nil
	u.PasswordReset.Token = nil
	u.PasswordReset.ExpiresAt = nil
}

// VerificationToken returns the current verification token string if present.
func (u *User) VerificationToken() (string, bool) {
	if u.Verification.Token == nil {
		return "", false
	}
	return *u.Verification.Token, true
}

// PasswordResetTokenString returns the current reset token string if present.
func (u *User) PasswordResetTokenString() (string, bool) {
	if u.PasswordReset.Token == nil {
		return "", false
	}
	return *u.PasswordReset.Token, true
}
