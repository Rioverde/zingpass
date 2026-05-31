package mailer

import (
	"bytes"
	"context"
	"embed"
	"fmt"
	"html/template"
	"net/smtp"
)

//go:embed templates/*.html
var templatesFS embed.FS

type SMTPConfig struct {
	Host string
	Port int
	User string
	Pass string
	From string
}

// SMTPMailer is a minimal SMTP implementation of Mailer.
// For local dev it points at Mailhog (no auth). For prod, swap in your provider.
type SMTPMailer struct {
	cfg       SMTPConfig
	templates *template.Template
}

func NewSMTP(cfg SMTPConfig) (*SMTPMailer, error) {
	t, err := template.ParseFS(templatesFS, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("parse templates: %w", err)
	}
	return &SMTPMailer{cfg: cfg, templates: t}, nil
}

// Template payload structs. Keeping them typed catches field-name typos at compile time,
// unlike the equivalent map[string]string which would silently render an empty value.

type verifyTemplateData struct {
	Nickname  string
	VerifyURL string
}

type resetTemplateData struct {
	Nickname string
	ResetURL string
}

func (m *SMTPMailer) SendVerification(_ context.Context, to, nickname, verifyURL string) error {
	var body bytes.Buffer
	if err := m.templates.ExecuteTemplate(&body, "verify.html", verifyTemplateData{
		Nickname:  nickname,
		VerifyURL: verifyURL,
	}); err != nil {
		return fmt.Errorf("render verify.html: %w", err)
	}

	return m.send(to, "Verify your email", body.String())
}

func (m *SMTPMailer) SendPasswordReset(_ context.Context, to, nickname, resetURL string) error {
	var body bytes.Buffer
	if err := m.templates.ExecuteTemplate(&body, "reset_password.html", resetTemplateData{
		Nickname: nickname,
		ResetURL: resetURL,
	}); err != nil {
		return fmt.Errorf("render reset_password.html: %w", err)
	}

	return m.send(to, "Reset your password", body.String())
}

func (m *SMTPMailer) send(to, subject, htmlBody string) error {
	addr := fmt.Sprintf("%s:%d", m.cfg.Host, m.cfg.Port)
	msg := buildMessage(m.cfg.From, to, subject, htmlBody)

	var auth smtp.Auth
	if m.cfg.User != "" {
		auth = smtp.PlainAuth("", m.cfg.User, m.cfg.Pass, m.cfg.Host)
	}
	return smtp.SendMail(addr, auth, m.cfg.From, []string{to}, []byte(msg))
}

func buildMessage(from, to, subject, htmlBody string) string {
	return fmt.Sprintf(
		"From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n%s",
		from, to, subject, htmlBody,
	)
}
