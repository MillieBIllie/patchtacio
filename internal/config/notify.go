package config

import (
	"fmt"
	"net"
	"net/mail"
	"strings"
)

// Notify configures alerts. A channel is on when its section is present.
// Secrets never go here: they come from environment variables, read when an
// alert is sent (EnvSMTPPassword, EnvWebhookURL, EnvNtfyURL, EnvNtfyToken).
type Notify struct {
	Digest  string   `yaml:"digest,omitempty"` // "off" (default), "daily" or "weekly"
	Email   *Email   `yaml:"email,omitempty"`
	Webhook *Webhook `yaml:"webhook,omitempty"`
	Ntfy    *Ntfy    `yaml:"ntfy,omitempty"`
	Desktop bool     `yaml:"desktop,omitempty"`
}

// Environment variables holding notification secrets.
const (
	EnvSMTPPassword = "PATCHTACIO_SMTP_PASSWORD" //nolint:gosec // a variable name, not a credential
	EnvWebhookURL   = "PATCHTACIO_WEBHOOK_URL"   // the URL is the secret: it carries the token
	EnvNtfyURL      = "PATCHTACIO_NTFY_URL"      // topic URL; on ntfy.sh the topic name works like a password
	EnvNtfyToken    = "PATCHTACIO_NTFY_TOKEN"    //nolint:gosec // a variable name; the optional access token
)

// Email sends alerts over SMTP.
type Email struct {
	Host     string   `yaml:"host"`
	Port     int      `yaml:"port,omitempty"`     // default 587 (465 when security is tls)
	Security string   `yaml:"security,omitempty"` // "starttls" (default), "tls", or "none" (localhost only)
	Username string   `yaml:"username,omitempty"` // password from PATCHTACIO_SMTP_PASSWORD
	From     string   `yaml:"from"`
	To       []string `yaml:"to"`
}

// Webhook posts alerts to a chat channel.
type Webhook struct {
	Kind string `yaml:"kind"` // "slack", "teams" (Workflows webhook) or "discord"
}

// Ntfy pushes alerts to the ntfy app (ntfy.sh or a self-hosted server).
type Ntfy struct {
	Priority int `yaml:"priority,omitempty"` // 1 (min) to 5 (max); default 4 (high)
}

// Channel names, as deliveries are recorded.
const (
	ChannelEmail   = "email"
	ChannelWebhook = "webhook"
	ChannelNtfy    = "ntfy"
	ChannelDesktop = "desktop"
)

// Channels lists the configured channels, in a fixed order.
func (n *Notify) Channels() []string {
	if n == nil {
		return nil
	}
	var out []string
	if n.Email != nil {
		out = append(out, ChannelEmail)
	}
	if n.Webhook != nil {
		out = append(out, ChannelWebhook)
	}
	if n.Ntfy != nil {
		out = append(out, ChannelNtfy)
	}
	if n.Desktop {
		out = append(out, ChannelDesktop)
	}
	return out
}

// Validate checks the settings, filling in defaults. It does not look at
// environment variables; the notifiers do, when they send.
func (n *Notify) Validate() []string {
	if n == nil {
		return nil
	}
	var problems []string
	bad := func(format string, args ...any) { problems = append(problems, "notify: "+fmt.Sprintf(format, args...)) }

	switch n.Digest {
	case "":
		n.Digest = "off"
	case "off", "daily", "weekly":
	default:
		bad("digest must be off, daily or weekly, not %q", n.Digest)
	}

	if e := n.Email; e != nil {
		if e.Host == "" {
			bad("email.host is required")
		}
		switch e.Security {
		case "":
			e.Security = "starttls"
		case "starttls", "tls":
		case "none":
			if !IsLoopback(e.Host) {
				bad("email.security none (no encryption) is only allowed for a mail server on this computer (localhost); use starttls or tls")
			}
		default:
			bad("email.security must be starttls, tls or none, not %q", e.Security)
		}
		if e.Port == 0 {
			e.Port = 587
			if e.Security == "tls" {
				e.Port = 465
			}
		}
		if e.Port < 1 || e.Port > 65535 {
			bad("email.port %d is not a valid port", e.Port)
		}
		if _, err := mail.ParseAddress(e.From); err != nil {
			bad("email.from %q is not an email address", e.From)
		}
		if len(e.To) == 0 {
			bad("email.to needs at least one address")
		}
		for _, to := range e.To {
			if _, err := mail.ParseAddress(to); err != nil {
				bad("email.to %q is not an email address", to)
			}
		}
	}
	if w := n.Webhook; w != nil {
		switch w.Kind {
		case "slack", "teams", "discord":
		default:
			bad("webhook.kind must be slack, teams or discord, not %q (the URL goes in the %s environment variable)", w.Kind, EnvWebhookURL)
		}
	}
	if t := n.Ntfy; t != nil {
		if t.Priority == 0 {
			t.Priority = 4
		}
		if t.Priority < 1 || t.Priority > 5 {
			bad("ntfy.priority must be 1 to 5, not %d", t.Priority)
		}
	}
	return problems
}

// IsLoopback reports whether host names this computer.
func IsLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}
