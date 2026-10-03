package notify

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/milliebillie/patchtacio/internal/advice"
	"github.com/milliebillie/patchtacio/internal/config"
)

// Email sends alerts over SMTP: implicit TLS ("tls"), STARTTLS ("starttls",
// required, never skipped), or plaintext only to a server on localhost
// ("none"). The password comes from PATCHTACIO_SMTP_PASSWORD.
type Email struct {
	Config config.Email
	Getenv func(string) string
	Now    func() time.Time

	tlsConfig *tls.Config // nil = system roots; tests set their own
	timeout   time.Duration
}

// NewEmail returns an email channel for a validated configuration.
func NewEmail(cfg config.Email, getenv func(string) string) *Email {
	return &Email{Config: cfg, Getenv: getenv, Now: time.Now, timeout: 2 * time.Minute}
}

// Name implements Channel.
func (e *Email) Name() string { return config.ChannelEmail }

// Destination implements Channel: the recipients, in any order or case.
func (e *Email) Destination() []string {
	to := make([]string, 0, len(e.Config.To))
	for _, a := range e.Config.To {
		if addr, err := mail.ParseAddress(a); err == nil {
			a = addr.Address
		}
		to = append(to, strings.ToLower(strings.TrimSpace(a)))
	}
	slices.Sort(to)
	return to
}

// Send implements Channel.
func (e *Email) Send(ctx context.Context, m advice.Message) error {
	subject, body, err := advice.Email(m)
	if err != nil {
		return err
	}
	return e.send(ctx, subject, body)
}

// SendNotice implements Channel.
func (e *Email) SendNotice(ctx context.Context, n advice.Notice) error {
	return e.send(ctx, n.Subject, n.Body)
}

func (e *Email) send(ctx context.Context, subject, body string) error {
	c := e.Config
	from, err := mail.ParseAddress(c.From)
	if err != nil {
		return fmt.Errorf("email.from: %w", err)
	}
	var to []*mail.Address
	for _, a := range c.To {
		addr, err := mail.ParseAddress(a)
		if err != nil {
			return fmt.Errorf("email.to %q: %w", a, err)
		}
		to = append(to, addr)
	}
	var password string
	if c.Username != "" {
		if password = e.Getenv(config.EnvSMTPPassword); password == "" {
			return fmt.Errorf("email.username is set, so set %s to the mail account's password, or save it with `patchtacio secret set smtp-password`", config.EnvSMTPPassword)
		}
	}
	msg, err := e.compose(from, to, subject, body)
	if err != nil {
		return err
	}

	client, err := e.connect(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()
	if c.Username != "" {
		if ok, _ := client.Extension("AUTH"); !ok {
			return fmt.Errorf("mail server %s does not offer login (AUTH); remove email.username or check the server", c.Host)
		}
		// PlainAuth itself refuses to send the password without TLS unless
		// the server is on localhost.
		if err := client.Auth(smtp.PlainAuth("", c.Username, password, c.Host)); err != nil {
			return fmt.Errorf("mail server %s refused the login for %s: %w", c.Host, c.Username, err)
		}
	}
	if err := client.Mail(from.Address); err != nil {
		return fmt.Errorf("mail server %s refused the sender %s: %w", c.Host, from.Address, err)
	}
	for _, a := range to {
		if err := client.Rcpt(a.Address); err != nil {
			return fmt.Errorf("mail server %s refused the recipient %s: %w", c.Host, a.Address, err)
		}
	}
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("mail server %s: %w", c.Host, err)
	}
	if _, err := w.Write(msg); err != nil {
		_ = w.Close()
		return fmt.Errorf("send to %s: %w", c.Host, err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("mail server %s did not accept the message: %w", c.Host, err)
	}
	_ = client.Quit()
	return nil
}

// connect dials the server and secures the connection as configured.
func (e *Email) connect(ctx context.Context) (*smtp.Client, error) {
	c := e.Config
	addr := net.JoinHostPort(c.Host, strconv.Itoa(c.Port))
	tlsConf := e.tlsConfig
	if tlsConf == nil {
		tlsConf = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	tlsConf = tlsConf.Clone()
	tlsConf.ServerName = c.Host

	d := &net.Dialer{Timeout: 30 * time.Second}
	var conn net.Conn
	var err error
	switch c.Security {
	case "tls":
		conn, err = (&tls.Dialer{NetDialer: d, Config: tlsConf}).DialContext(ctx, "tcp", addr)
	case "starttls":
		conn, err = d.DialContext(ctx, "tcp", addr)
	case "none":
		if !config.IsLoopback(c.Host) { // Validate already refuses this; never rely on one check
			return nil, errors.New("plaintext email is only allowed to a server on this computer")
		}
		conn, err = d.DialContext(ctx, "tcp", addr)
	default:
		return nil, fmt.Errorf("unknown email.security %q", c.Security)
	}
	if err != nil {
		return nil, fmt.Errorf("could not connect to mail server %s: %w", addr, err)
	}
	_ = conn.SetDeadline(time.Now().Add(e.timeout))
	client, err := smtp.NewClient(conn, c.Host)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("mail server %s: %w", addr, err)
	}
	if c.Security == "starttls" {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			_ = client.Close()
			return nil, fmt.Errorf("mail server %s does not offer STARTTLS, so Patchtacio will not send (or log in) unencrypted; "+
				"use security: tls if it supports that", addr)
		}
		if err := client.StartTLS(tlsConf); err != nil {
			_ = client.Close()
			return nil, fmt.Errorf("could not secure the connection to %s: %w", addr, err)
		}
	}
	return client, nil
}

// compose builds the message: plain-text UTF-8, quoted-printable, marked as
// automatic so auto-responders stay quiet (RFC 3834).
func (e *Email) compose(from *mail.Address, to []*mail.Address, subject, body string) ([]byte, error) {
	var b bytes.Buffer
	header := func(k, v string) {
		// Values are built here from parsed addresses and one-line text;
		// dropping CR and LF guards against header injection regardless.
		v = strings.NewReplacer("\r", "", "\n", " ").Replace(v)
		b.WriteString(k + ": " + v + "\r\n")
	}
	addrs := make([]string, len(to))
	for i, a := range to {
		addrs[i] = a.String()
	}
	id := make([]byte, 12)
	if _, err := rand.Read(id); err != nil {
		return nil, fmt.Errorf("make message ID: %w", err)
	}
	domain := "patchtacio.invalid"
	if _, d, ok := strings.Cut(from.Address, "@"); ok && d != "" {
		domain = d
	}
	header("From", from.String())
	header("To", strings.Join(addrs, ", "))
	header("Subject", mime.QEncoding.Encode("utf-8", subject))
	header("Date", e.Now().Format(time.RFC1123Z))
	header("Message-ID", "<"+hex.EncodeToString(id)+"@"+domain+">")
	header("MIME-Version", "1.0")
	header("Content-Type", "text/plain; charset=utf-8")
	header("Content-Transfer-Encoding", "quoted-printable")
	header("Auto-Submitted", "auto-generated")
	header("X-Mailer", "Patchtacio")
	b.WriteString("\r\n")
	qp := quotedprintable.NewWriter(&b)
	if _, err := qp.Write([]byte(body)); err != nil {
		return nil, fmt.Errorf("encode email body: %w", err)
	}
	if err := qp.Close(); err != nil {
		return nil, fmt.Errorf("encode email body: %w", err)
	}
	return b.Bytes(), nil
}
