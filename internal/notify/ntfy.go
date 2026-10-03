package notify

import (
	"context"
	"fmt"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"github.com/milliebillie/patchtacio/internal/advice"
	"github.com/milliebillie/patchtacio/internal/config"
)

// Ntfy pushes alerts to the ntfy app. The topic URL comes from
// PATCHTACIO_NTFY_URL (on ntfy.sh, anyone who knows the topic can read it),
// and an optional access token from PATCHTACIO_NTFY_TOKEN.
type Ntfy struct {
	Priority int
	Getenv   func(string) string
	p        *poster
}

// NewNtfy returns an ntfy channel.
func NewNtfy(priority int, getenv func(string) string) *Ntfy {
	return &Ntfy{Priority: priority, Getenv: getenv, p: newPoster()}
}

// Name implements Channel.
func (n *Ntfy) Name() string { return config.ChannelNtfy }

// Destination implements Channel: the topic URL.
func (n *Ntfy) Destination() []string {
	return []string{strings.TrimSpace(n.Getenv(config.EnvNtfyURL))}
}

// ntfyLimit keeps messages under ntfy's 4,096 bytes, above which it turns
// them into attachments.
const ntfyLimit = 3500

// Send implements Channel.
func (n *Ntfy) Send(ctx context.Context, m advice.Message) error {
	c, err := advice.ChatMessage(m)
	if err != nil {
		return err
	}
	return n.post(ctx, c.Title, truncateBytes(c.Body, ntfyLimit), n.Priority, "warning")
}

// SendNotice implements Channel. Tests go at default priority.
func (n *Ntfy) SendNotice(ctx context.Context, no advice.Notice) error {
	if no.Test {
		return n.post(ctx, no.Subject, no.Body, 3, "white_check_mark")
	}
	return n.post(ctx, no.Subject, truncateBytes(no.Body, ntfyLimit), n.Priority, "warning")
}

func (n *Ntfy) post(ctx context.Context, title, body string, priority int, tag string) error {
	raw := n.Getenv(config.EnvNtfyURL)
	if raw == "" {
		return fmt.Errorf("set %s to your ntfy topic URL (e.g. https://ntfy.sh/<your-secret-topic>), or save it with `patchtacio secret set ntfy-url`", config.EnvNtfyURL)
	}
	u, err := checkURL(raw, config.EnvNtfyURL)
	if err != nil {
		return err
	}
	h := http.Header{
		"Content-Type": {"text/plain; charset=utf-8"},
		// RFC 2047, as ntfy documents, for non-ASCII titles.
		"Title":    {mime.BEncoding.Encode("UTF-8", title)},
		"Priority": {strconv.Itoa(priority)},
		"Tags":     {tag},
	}
	if tok := n.Getenv(config.EnvNtfyToken); tok != "" {
		h.Set("Authorization", "Bearer "+tok)
	}
	return n.p.post(ctx, u, h, []byte(body))
}
