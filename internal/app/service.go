package app

import (
	"time"

	"github.com/rdurica/auth/internal/mail"
)

// AuthService is a thin application facade over auth use-cases.
type AuthService struct {
	users            UserRepository
	refresh          RefreshTokenRepository
	jwt              JWTIssuer
	mail             *mail.Templates
	refreshTTL       time.Duration
	emailVerifyTTL   time.Duration
	passwordResetTTL time.Duration
	now              func() time.Time
}

func NewAuthService(
	users UserRepository,
	refresh RefreshTokenRepository,
	jwt JWTIssuer,
	mailer *mail.Templates,
	refreshTTL, emailVerifyTTL, passwordResetTTL time.Duration,
) *AuthService {
	return &AuthService{
		users:            users,
		refresh:          refresh,
		jwt:              jwt,
		mail:             mailer,
		refreshTTL:       refreshTTL,
		emailVerifyTTL:   emailVerifyTTL,
		passwordResetTTL: passwordResetTTL,
		now:              time.Now,
	}
}
