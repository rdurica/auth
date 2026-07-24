package mail

import (
	"context"
	"fmt"
	"log/slog"
	"net/smtp"
	"strings"
)

type Message struct {
	To      string
	Subject string
	Body    string
}

type Sender interface {
	Send(ctx context.Context, msg Message) error
}

type LogSender struct {
	log *slog.Logger
}

func NewLogSender(log *slog.Logger) *LogSender {
	return &LogSender{log: log}
}

func (s *LogSender) Send(_ context.Context, msg Message) error {
	s.log.Info("email",
		"to", msg.To,
		"subject", msg.Subject,
		"body", msg.Body,
	)
	return nil
}

type SMTPSender struct {
	host     string
	port     int
	username string
	password string
	from     string
}

func NewSMTPSender(host string, port int, username, password, from string) *SMTPSender {
	return &SMTPSender{
		host:     host,
		port:     port,
		username: username,
		password: password,
		from:     from,
	}
}

func (s *SMTPSender) Send(_ context.Context, msg Message) error {
	addr := fmt.Sprintf("%s:%d", s.host, s.port)
	var auth smtp.Auth
	// Mailpit and similar local SMTP accept unauthenticated mail.
	if s.username != "" {
		auth = smtp.PlainAuth("", s.username, s.password, s.host)
	}
	payload := strings.Join([]string{
		"From: " + s.from,
		"To: " + msg.To,
		"Subject: " + msg.Subject,
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=UTF-8",
		"",
		msg.Body,
	}, "\r\n")
	return smtp.SendMail(addr, auth, s.from, []string{msg.To}, []byte(payload))
}

type Templates struct {
	WebBaseURL string
	Sender     Sender
}

func (t *Templates) SendVerification(ctx context.Context, to, token string) error {
	link := fmt.Sprintf("%s/verify-email?token=%s", strings.TrimRight(t.WebBaseURL, "/"), token)
	return t.Sender.Send(ctx, Message{
		To:      to,
		Subject: "Verify your email",
		Body:    fmt.Sprintf("Please verify your email by opening:\n\n%s\n\nOr use token: %s\n", link, token),
	})
}

func (t *Templates) SendPasswordReset(ctx context.Context, to, token string) error {
	link := fmt.Sprintf("%s/reset-password?token=%s", strings.TrimRight(t.WebBaseURL, "/"), token)
	return t.Sender.Send(ctx, Message{
		To:      to,
		Subject: "Reset your password",
		Body:    fmt.Sprintf("Reset your password by opening:\n\n%s\n\nOr use token: %s\n", link, token),
	})
}
