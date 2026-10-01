package logging

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"testing"
)

func TestLevel(t *testing.T) {
	tests := []struct {
		verbosity int
		quiet     bool
		want      slog.Level
	}{
		{0, false, slog.LevelWarn},
		{1, false, slog.LevelInfo},
		{2, false, slog.LevelDebug},
		{5, false, slog.LevelDebug},
		{2, true, slog.LevelError},
	}
	for _, tt := range tests {
		if got := Level(tt.verbosity, tt.quiet); got != tt.want {
			t.Errorf("Level(%d, %v) = %v, want %v", tt.verbosity, tt.quiet, got, tt.want)
		}
	}
}

func TestNewFiltersByLevel(t *testing.T) {
	var buf bytes.Buffer
	log := New(&buf, slog.LevelWarn)
	log.Info("hidden")
	log.Warn("shown")
	out := buf.String()
	if strings.Contains(out, "hidden") || !strings.Contains(out, "shown") {
		t.Errorf("unexpected output: %q", out)
	}
	if strings.Contains(out, "time=") {
		t.Errorf("timestamps should be omitted: %q", out)
	}
}

func TestSecretNeverLeaks(t *testing.T) {
	const raw = "hunter2-very-secret"
	s := Secret(raw)
	var buf bytes.Buffer
	New(&buf, slog.LevelDebug).Warn("sending", "webhook", s, slog.Group("smtp", "pw", s))
	for _, out := range []string{
		buf.String(),
		fmt.Sprintf("%s %v %+v %#v %q", s, s, s, s, s),
		fmt.Sprint(struct{ S Secret }{s}),
	} {
		if strings.Contains(out, raw) {
			t.Errorf("secret leaked: %q", out)
		}
	}
	js, err := json.Marshal(struct{ S Secret }{s})
	if err != nil || strings.Contains(string(js), raw) {
		t.Errorf("secret leaked through JSON: %s, %v", js, err)
	}
	if s.Reveal() != raw {
		t.Errorf("Reveal() = %q", s.Reveal())
	}
}

func TestSensitiveKeysRedacted(t *testing.T) {
	var buf bytes.Buffer
	New(&buf, slog.LevelDebug).Warn("x", "smtp_password", "pw1", "NVD_API_KEY", "key1", "Authorization", "Bearer abc")
	out := buf.String()
	for _, leak := range []string{"pw1", "key1", "abc"} {
		if strings.Contains(out, leak) {
			t.Errorf("%q leaked: %s", leak, out)
		}
	}
}

func TestRedactString(t *testing.T) {
	tests := []struct{ in, want string }{
		{"no urls here", "no urls here"},
		{"https://example.com/a/b", "https://example.com/a/b"},
		{"https://example.com/hook?token=abc&x=1", "https://example.com/hook?[REDACTED]"},
		{"https://user:pass@example.com/x", "https://[REDACTED]@example.com/x"},
		{"https://example.com/x#frag", "https://example.com/x"},
		{
			`Get "https://ntfy.sh/topic?auth=s3cret": dial tcp: lookup ntfy.sh: no such host`,
			`Get "https://ntfy.sh/topic?[REDACTED]": dial tcp: lookup ntfy.sh: no such host`,
		},
	}
	for _, tt := range tests {
		if got := RedactString(tt.in); got != tt.want {
			t.Errorf("RedactString(%q)\n got %q\nwant %q", tt.in, got, tt.want)
		}
	}
}

func TestClean(t *testing.T) {
	bidi := string([]rune{0x202e, 0x2066, 0x2069}) // RLO, LRI, PDI
	in := "2026.09.30\x1b]0;pwned\x07\x1b[31m red " + bidi + "evil é"
	got := Clean(in)
	if strings.ContainsAny(got, "\x1b\x07"+bidi) {
		t.Errorf("Clean(%q) = %q", in, got)
	}
	if !strings.Contains(got, "é") || !strings.Contains(got, "red") {
		t.Errorf("Clean removed ordinary text: %q", got)
	}
}

func TestRedactAttrValues(t *testing.T) {
	u, err := url.Parse("https://u:p@example.com/x?k=v")
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	New(&buf, slog.LevelDebug).Error("fetch failed",
		"url", u,
		"err", fmt.Errorf("fetch: %w", errors.New(`Get "https://example.com/?api=1": EOF`)),
	)
	out := buf.String()
	for _, leak := range []string{"u:p", "k=v", "api=1"} {
		if strings.Contains(out, leak) {
			t.Errorf("%q leaked: %s", leak, out)
		}
	}
}
