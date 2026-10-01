// Package logging builds the slog logger Patchtacio writes diagnostics with.
//
// Diagnostics go to stderr; command output goes to stdout. Every record passes
// through redaction, so secrets never reach a terminal, a CI log, or (in M4) a
// log file:
//
//   - values of type Secret always render as [REDACTED];
//   - attributes whose key names a credential (password, token, ...) are redacted;
//   - URLs anywhere in a string or error lose their userinfo and query string.
//
// URL redaction cannot know which path segments are secret (Slack webhook
// tokens live in the path), so webhook URLs must be wrapped in Secret.
//
// Stale-data warnings are not log records: commands print them directly so
// that --quiet cannot hide them.
package logging

import (
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"regexp"
	"strings"
)

// Redacted is what every redacted value renders as.
const Redacted = "[REDACTED]"

// Secret is a string that never appears in logs or formatted output.
// Use Reveal to get the value where it is actually needed.
type Secret string

// LogValue implements slog.LogValuer.
func (Secret) LogValue() slog.Value { return slog.StringValue(Redacted) }

// String implements fmt.Stringer so %s and %v cannot leak the value.
func (Secret) String() string { return Redacted }

// GoString implements fmt.GoStringer so %#v cannot leak the value.
func (Secret) GoString() string { return Redacted }

// Reveal returns the underlying value.
func (s Secret) Reveal() string { return string(s) }

// Level maps CLI flags to a slog level: --quiet shows errors only, the default
// shows warnings, -v info, -vv (or more) debug.
func Level(verbosity int, quiet bool) slog.Level {
	switch {
	case quiet:
		return slog.LevelError
	case verbosity <= 0:
		return slog.LevelWarn
	case verbosity == 1:
		return slog.LevelInfo
	default:
		return slog.LevelDebug
	}
}

// New returns a text logger writing to w at the given level, with redaction.
// Timestamps are omitted: on a terminal they are noise.
func New(w io.Writer, level slog.Level) *slog.Logger {
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{
		Level: level,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 && a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return Redact(a)
		},
	}))
}

var sensitiveKey = regexp.MustCompile(`(?i)(password|passwd|secret|token|api[_-]?key|authorization|cookie)`)

// Redact applies the redaction rules to one attribute. It is exported so
// other handlers (the M4 log file) apply exactly the same rules.
func Redact(a slog.Attr) slog.Attr {
	if sensitiveKey.MatchString(a.Key) {
		return slog.String(a.Key, Redacted)
	}
	v := a.Value.Resolve()
	switch v.Kind() {
	case slog.KindString:
		return slog.String(a.Key, RedactString(v.String()))
	case slog.KindAny:
		switch x := v.Any().(type) {
		case *url.URL:
			return slog.String(a.Key, RedactURL(x))
		case error:
			return slog.String(a.Key, RedactString(x.Error()))
		case fmt.Stringer:
			return slog.String(a.Key, RedactString(x.String()))
		}
	case slog.KindGroup:
		attrs := v.Group()
		out := make([]any, 0, len(attrs))
		for _, ga := range attrs {
			out = append(out, Redact(ga))
		}
		return slog.Group(a.Key, out...)
	}
	return slog.Attr{Key: a.Key, Value: v}
}

// urlPattern matches absolute URLs embedded in free text, such as the
// `Get "https://...": dial tcp ...` errors net/http returns.
var urlPattern = regexp.MustCompile(`[a-zA-Z][a-zA-Z0-9+.-]*://[^\s"'<>]+`)

// RedactString redacts every URL found in s.
func RedactString(s string) string {
	if !strings.Contains(s, "://") {
		return s
	}
	return urlPattern.ReplaceAllStringFunc(s, func(raw string) string {
		u, err := url.Parse(raw)
		if err != nil {
			return Redacted
		}
		return RedactURL(u)
	})
}

// RedactURL drops userinfo, query and fragment, keeping scheme, host and path.
func RedactURL(u *url.URL) string {
	if u == nil {
		return ""
	}
	c := *u
	hadUser, hadQuery := c.User != nil, c.RawQuery != ""
	c.User, c.RawQuery, c.ForceQuery = nil, "", false
	c.Fragment, c.RawFragment = "", ""
	s := c.String()
	if hadUser {
		s = strings.Replace(s, "://", "://"+Redacted+"@", 1)
	}
	if hadQuery {
		s += "?" + Redacted
	}
	return s
}
