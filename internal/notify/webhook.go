package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/milliebillie/patchtacio/internal/advice"
	"github.com/milliebillie/patchtacio/internal/config"
)

// Webhook posts alerts to Slack, Microsoft Teams (a Workflows "When a Teams
// webhook request is received" URL) or Discord. The URL carries the token, so
// it comes from PATCHTACIO_WEBHOOK_URL, never the config file.
type Webhook struct {
	Kind   string // "slack", "teams" or "discord"
	Getenv func(string) string
	p      *poster
}

// NewWebhook returns a webhook channel of the given kind.
func NewWebhook(kind string, getenv func(string) string) *Webhook {
	return &Webhook{Kind: kind, Getenv: getenv, p: newPoster()}
}

// Name implements Channel.
func (w *Webhook) Name() string { return config.ChannelWebhook }

// Key implements Channel: the kind and URL.
func (w *Webhook) Key() string {
	return destinationKey(config.ChannelWebhook, w.Kind, strings.TrimSpace(w.Getenv(config.EnvWebhookURL)))
}

// Send implements Channel.
func (w *Webhook) Send(ctx context.Context, m advice.Message) error {
	c, err := advice.ChatMessage(m)
	if err != nil {
		return err
	}
	return w.post(ctx, c)
}

// SendNotice implements Channel.
func (w *Webhook) SendNotice(ctx context.Context, n advice.Notice) error {
	return w.post(ctx, advice.Chat{Title: n.Subject, Body: n.Body})
}

func (w *Webhook) post(ctx context.Context, c advice.Chat) error {
	u, err := checkURL(w.Getenv(config.EnvWebhookURL), config.EnvWebhookURL)
	if err != nil {
		if w.Getenv(config.EnvWebhookURL) == "" {
			return fmt.Errorf("set %s to the %s webhook URL", config.EnvWebhookURL, w.Kind)
		}
		return err
	}
	payload, err := webhookPayload(w.Kind, c)
	if err != nil {
		return err
	}
	return w.p.post(ctx, u, http.Header{"Content-Type": {"application/json"}}, payload)
}

// Size limits per service, with room to spare.
const (
	slackTextLimit      = 35000 // Slack truncates messages after 40,000 characters
	discordTitleLimit   = 256
	discordDescLimit    = 4000 // embed description: 4,096
	teamsBodyLimit      = 20000
	shortenedNote       = "\n… (shortened: run `patchtacio check` for everything)"
	patchtacioAccent    = "attention"
	discordWarningColor = 0xD9822B
)

func webhookPayload(kind string, c advice.Chat) ([]byte, error) {
	var v any
	switch kind {
	case "slack":
		// Escaping & < > stops feed text from becoming a link or an
		// @channel mention.
		text := "*" + slackEscape(c.Title) + "*\n" + slackEscape(c.Body)
		v = map[string]any{"text": truncate(text, slackTextLimit)}
	case "discord":
		v = map[string]any{
			"username": "Patchtacio",
			"embeds": []map[string]any{{
				"title":       noMaskedLinks(truncate(c.Title, discordTitleLimit)),
				"description": noMaskedLinks(truncate(c.Body, discordDescLimit)),
				"color":       discordWarningColor,
			}},
			// Never ping anyone, whatever the text says.
			"allowed_mentions": map[string]any{"parse": []string{}},
		}
	case "teams":
		body := []map[string]any{{
			"type": "TextBlock", "text": noMaskedLinks(c.Title), "weight": "bolder", "size": "medium",
			"wrap": true, "color": patchtacioAccent,
		}}
		gap := false
		for line := range strings.SplitSeq(truncate(c.Body, teamsBodyLimit), "\n") {
			if strings.TrimSpace(line) == "" {
				gap = true
				continue
			}
			b := map[string]any{"type": "TextBlock", "text": noMaskedLinks(line), "wrap": true, "spacing": "none"}
			if gap {
				b["spacing"] = "medium"
				gap = false
			}
			body = append(body, b)
		}
		v = map[string]any{
			"type": "message",
			"attachments": []map[string]any{{
				"contentType": "application/vnd.microsoft.card.adaptive",
				"content": map[string]any{
					"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
					"type":    "AdaptiveCard",
					"version": "1.4",
					"body":    body,
				},
			}},
		}
	default:
		return nil, fmt.Errorf("unknown webhook kind %q", kind)
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("encode %s message: %w", kind, err)
	}
	return b, nil
}

// noMaskedLinks stops text forming a markdown link, [shown text](target),
// which Discord embeds and Teams cards render with only the shown text
// visible: feed text could display one address and link to another. A
// zero-width space between "]" and "(" breaks the syntax without changing
// what the reader sees; plain URLs are still linked.
func noMaskedLinks(s string) string {
	return strings.ReplaceAll(s, "](", "]\u200b(")
}

func slackEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

// truncate cuts s to at most limit characters at a line break if it can,
// saying that it did.
func truncate(s string, limit int) string {
	if utf8.RuneCountInString(s) <= limit {
		return s
	}
	keep := limit - utf8.RuneCountInString(shortenedNote)
	r := []rune(s)[:max(keep, 0)]
	cut := string(r)
	if i := strings.LastIndexByte(cut, '\n'); i > len(cut)/2 {
		cut = cut[:i]
	}
	return cut + shortenedNote
}

// truncateBytes is truncate for limits counted in bytes.
func truncateBytes(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	n := utf8.RuneCountInString(s)
	for len(s) > limit && n > 0 {
		n -= max((len(s)-limit)/4, 1)
		s = truncate(s, n)
	}
	return s
}
