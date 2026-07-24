package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	HTTPAddr string

	DatabaseURL string
	RedisURL    string

	JWTPrivateKeyPath string
	JWTPublicKeyPath  string
	JWTTTL            time.Duration
	JWTIssuer         string

	RefreshTokenTTL      time.Duration
	EmailVerificationTTL time.Duration
	PasswordResetTTL     time.Duration

	MailDriver   string
	SMTPHost     string
	SMTPPort     int
	SMTPUser     string
	SMTPPassword string
	MailFrom     string
	WebBaseURL   string

	ErrorTypeBaseURL string
}

func Load() (Config, error) {
	cfg := Config{
		HTTPAddr:          getenv("HTTP_ADDR", ":8080"),
		DatabaseURL:       getenv("DATABASE_URL", "postgres://root:password@localhost:5432/auth?sslmode=disable"),
		RedisURL:          getenv("REDIS_URL", "redis://localhost:6379"),
		JWTPrivateKeyPath: getenv("JWT_PRIVATE_KEY_PATH", "keys/jwt-private.pem"),
		JWTPublicKeyPath:  getenv("JWT_PUBLIC_KEY_PATH", "keys/jwt-public.pem"),
		JWTIssuer:         getenv("JWT_ISSUER", "auth"),
		MailDriver:        getenv("MAIL_DRIVER", "smtp"),
		SMTPHost:          getenv("SMTP_HOST", "localhost"),
		SMTPUser:          os.Getenv("SMTP_USER"),
		SMTPPassword:      os.Getenv("SMTP_PASSWORD"),
		MailFrom:          getenv("MAIL_FROM", "noreply@auth.local"),
		WebBaseURL:        getenv("WEB_BASE_URL", "http://localhost:3000"),
		ErrorTypeBaseURL:  getenv("ERROR_TYPE_BASE_URL", "https://auth.local/errors"),
	}

	ttlSec, err := getenvInt("JWT_TTL_SECONDS", 3600)
	if err != nil {
		return Config{}, err
	}
	cfg.JWTTTL = time.Duration(ttlSec) * time.Second

	refreshDays, err := getenvInt("REFRESH_TOKEN_TTL_DAYS", 30)
	if err != nil {
		return Config{}, err
	}
	cfg.RefreshTokenTTL = time.Duration(refreshDays) * 24 * time.Hour

	verifyHours, err := getenvInt("EMAIL_VERIFICATION_TTL_HOURS", 3)
	if err != nil {
		return Config{}, err
	}
	cfg.EmailVerificationTTL = time.Duration(verifyHours) * time.Hour

	resetHours, err := getenvInt("PASSWORD_RESET_TTL_HOURS", 1)
	if err != nil {
		return Config{}, err
	}
	cfg.PasswordResetTTL = time.Duration(resetHours) * time.Hour

	smtpPort, err := getenvInt("SMTP_PORT", 1025)
	if err != nil {
		return Config{}, err
	}
	cfg.SMTPPort = smtpPort

	return cfg, nil
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getenvInt(key string, fallback int) (int, error) {
	v := os.Getenv(key)
	if v == "" {
		return fallback, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("invalid %s: %w", key, err)
	}
	return n, nil
}
