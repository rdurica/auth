package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/joho/godotenv"
	"github.com/rdurica/auth/internal/app"
	"github.com/rdurica/auth/internal/config"
	"github.com/rdurica/auth/internal/httpapi"
	"github.com/rdurica/auth/internal/mail"
	"github.com/rdurica/auth/internal/ratelimit"
	"github.com/rdurica/auth/internal/store/postgres"
	"github.com/rdurica/auth/internal/token"
)

func main() {
	_ = godotenv.Load()

	logLevel := slog.LevelInfo
	switch strings.ToLower(os.Getenv("LOG_LEVEL")) {
	case "debug":
		logLevel = slog.LevelDebug
	case "warn", "warning":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel}))

	cfg, err := config.Load()
	if err != nil {
		log.Error("config", "err", err)
		os.Exit(1)
	}

	ctx := context.Background()
	pool, err := postgres.NewPool(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Error("database", "err", err)
		os.Exit(1)
	}
	defer pool.Close()

	jwtSvc, err := token.NewJWTService(cfg.JWTPrivateKeyPath, cfg.JWTPublicKeyPath, cfg.JWTIssuer, cfg.JWTTTL)
	if err != nil {
		log.Error("jwt", "err", err)
		os.Exit(1)
	}

	var sender mail.Sender
	switch cfg.MailDriver {
	case "smtp":
		sender = mail.NewSMTPSender(cfg.SMTPHost, cfg.SMTPPort, cfg.SMTPUser, cfg.SMTPPassword, cfg.MailFrom)
	default:
		sender = mail.NewLogSender(log)
	}
	mailer := &mail.Templates{WebBaseURL: cfg.WebBaseURL, Sender: sender}

	limiter, err := ratelimit.NewFromURL(cfg.RedisURL)
	if err != nil {
		log.Error("redis", "err", err)
		os.Exit(1)
	}
	defer func() { _ = limiter.Close() }()

	users := postgres.NewUserRepo(pool)
	refresh := postgres.NewRefreshTokenRepo(pool)
	authSvc := app.NewAuthService(
		users, refresh, jwtSvc, mailer,
		cfg.RefreshTokenTTL, cfg.EmailVerificationTTL, cfg.PasswordResetTTL,
	)

	handler := httpapi.NewRouter(httpapi.Deps{
		Auth:       authSvc,
		JWT:        jwtSvc,
		Limiter:    limiter,
		LoginGuard: limiter.LoginGuard(),
		Logger:     log,
		ErrorBase:  cfg.ErrorTypeBaseURL,
	})

	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		log.Info("listening", "addr", cfg.HTTPAddr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("server", "err", err)
			os.Exit(1)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Error("shutdown", "err", err)
		os.Exit(1)
	}
	log.Info("stopped")
}
