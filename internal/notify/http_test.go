package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/milliebillie/patchtacio/internal/advice"
	"github.com/milliebillie/patchtacio/internal/config"
)

// recorder is a fake webhook/ntfy server on 127.0.0.1.
type recorder struct {
	mu      sync.Mutex
	headers []http.Header
	bodies  [][]byte
	status  []int // answered in order; then 200
}

func (r *recorder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	b, _ := io.ReadAll(req.Body)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.headers = append(r.headers, req.Header.Clone())
	r.bodies = append(r.bodies, b)
	code := http.StatusOK
	if len(r.status) > 0 {
		code, r.status = r.status[0], r.status[1:]
	}
	switch code {
	case http.StatusTooManyRequests:
		w.Header().Set("Retry-After", "0")
	case http.StatusFound:
		w.Header().Set("Location", "http://127.0.0.1:1/elsewhere")
	}
	w.WriteHeader(code)
	// Some servers echo the request in error pages.
	_, _ = w.Write([]byte("error from server: cannot POST " + req.URL.Path + " with " + req.Header.Get("Authorization")))
}

func (r *recorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.bodies)
}

// serve starts a fake server; its URL ends in a path that stands for the
// secret token a real webhook URL carries.
func serve(t *testing.T, status ...int) (*recorder, string) {
	t.Helper()
	rec := &recorder{status: status}
	srv := httptest.NewServer(rec)
	t.Cleanup(srv.Close)
	return rec, srv.URL + "/services/T000/B000/SECRETTOKEN"
}

func env(vars map[string]string) func(string) string {
	return func(k string) string { return vars[k] }
}

func sample() advice.Message {
	return advice.Message{Today: time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC), Items: []advice.Item{{
		Kind: advice.KindNew, CVE: "CVE-2026-1", Name: "Acme <!channel> & @everyone Flaw",
		Products: []advice.Product{{Display: "Acme Widget"}},
		DueDate:  time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC),
	}}}
}

func TestWebhookPayloads(t *testing.T) {
	for _, kind := range []string{"slack", "teams", "discord"} {
		t.Run(kind, func(t *testing.T) {
			rec, u := serve(t)
			w := NewWebhook(kind, env(map[string]string{config.EnvWebhookURL: u}))
			if err := w.Send(context.Background(), sample()); err != nil {
				t.Fatal(err)
			}
			if rec.count() != 1 {
				t.Fatalf("%d requests", rec.count())
			}
			if ct := rec.headers[0].Get("Content-Type"); ct != "application/json" {
				t.Errorf("Content-Type %q", ct)
			}
			if ua := rec.headers[0].Get("User-Agent"); !strings.HasPrefix(ua, "patchtacio/") {
				t.Errorf("User-Agent %q", ua)
			}
			var v map[string]any
			if err := json.Unmarshal(rec.bodies[0], &v); err != nil {
				t.Fatal(err)
			}
			raw := string(rec.bodies[0])
			switch kind {
			case "slack":
				text, _ := v["text"].(string)
				if !strings.HasPrefix(text, "*[Action needed by 12 Oct 2026]") || strings.Contains(text, "<!channel>") ||
					!strings.Contains(text, "&lt;!channel&gt; &amp;") {
					t.Errorf("slack text not escaped or titled: %q", text)
				}
			case "discord":
				am, _ := v["allowed_mentions"].(map[string]any)
				if parse, ok := am["parse"].([]any); !ok || len(parse) != 0 {
					t.Errorf("discord must never ping: %s", raw)
				}
			case "teams":
				if v["type"] != "message" || !strings.Contains(raw, `"contentType":"application/vnd.microsoft.card.adaptive"`) ||
					!strings.Contains(raw, `"type":"AdaptiveCard"`) || !strings.Contains(raw, "CVE-2026-1") {
					t.Errorf("teams payload: %s", raw)
				}
			}
		})
	}
}

// Feed text must not become a disguised link in Discord or Teams.
func TestWebhookNoMaskedLinks(t *testing.T) {
	for _, kind := range []string{"discord", "teams"} {
		rec, u := serve(t)
		m := sample()
		m.Items[0].Name = "Acme Flaw, see [https://vendor.example/fix](https://evil.example/x)"
		if err := NewWebhook(kind, env(map[string]string{config.EnvWebhookURL: u})).Send(context.Background(), m); err != nil {
			t.Fatal(err)
		}
		var v any
		if err := json.Unmarshal(rec.bodies[0], &v); err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(v) // decoded, so \u200b is compared as the character
		if strings.Contains(string(raw), "](") {
			t.Errorf("%s payload still has a markdown link: %s", kind, raw)
		}
	}
}

func TestWebhookTest(t *testing.T) {
	rec, u := serve(t)
	if err := NewWebhook("slack", env(map[string]string{config.EnvWebhookURL: u})).SendNotice(context.Background(), advice.TestNotice()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rec.bodies[0]), "test") {
		t.Errorf("test message does not say it is a test: %s", rec.bodies[0])
	}
}

func TestNtfy(t *testing.T) {
	rec, u := serve(t)
	n := NewNtfy(4, env(map[string]string{config.EnvNtfyURL: u, config.EnvNtfyToken: "tk_secret"}))
	m := sample()
	m.Items[0].Products[0].Display = "Ünïcode Widget"
	if err := n.Send(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	h := rec.headers[0]
	if h.Get("Authorization") != "Bearer tk_secret" || h.Get("Priority") != "4" || h.Get("Tags") != "warning" {
		t.Errorf("headers: %v", h)
	}
	if title := strings.ToUpper(h.Get("Title")); !strings.HasPrefix(title, "=?UTF-8?B?") {
		t.Errorf("non-ASCII title not RFC 2047 encoded: %q", h.Get("Title"))
	}
	if !strings.Contains(string(rec.bodies[0]), "CVE-2026-1") {
		t.Errorf("body: %s", rec.bodies[0])
	}
}

func TestHTTPErrorsNeverShowTheSecretURL(t *testing.T) {
	ctx := context.Background()
	check := func(name string, err error) {
		t.Helper()
		if err == nil {
			t.Errorf("%s: want an error", name)
			return
		}
		if strings.Contains(err.Error(), "SECRETTOKEN") || strings.Contains(err.Error(), "services/T000") {
			t.Errorf("%s: error leaks the URL: %v", name, err)
		}
	}

	// Server error: status and body shown, URL not.
	_, u := serve(t, http.StatusInternalServerError)
	err := NewWebhook("slack", env(map[string]string{config.EnvWebhookURL: u})).SendNotice(ctx, advice.TestNotice())
	check("500", err)
	if err != nil && !strings.Contains(err.Error(), "HTTP 500") {
		t.Errorf("500: %v", err)
	}

	// An error page echoing the path and token: both scrubbed.
	_, u = serve(t, http.StatusNotFound)
	err = NewNtfy(4, env(map[string]string{config.EnvNtfyURL: u, config.EnvNtfyToken: "tk_SECRETTOKEN"})).SendNotice(ctx, advice.TestNotice())
	check("echo", err)
	if err != nil && strings.Contains(err.Error(), "tk_") {
		t.Errorf("echo: token leaked: %v", err)
	}

	// Plain http to "localhost" by name is refused: DNS could send it elsewhere.
	check("localhost name", NewWebhook("slack", env(map[string]string{
		config.EnvWebhookURL: "http://localhost:1/services/T000/B000/SECRETTOKEN"})).SendNotice(ctx, advice.TestNotice()))

	// Redirect: not followed, so the token never travels elsewhere.
	rec, u := serve(t, http.StatusFound)
	check("redirect", NewWebhook("slack", env(map[string]string{config.EnvWebhookURL: u})).SendNotice(ctx, advice.TestNotice()))
	if rec.count() != 1 {
		t.Errorf("redirect: %d requests", rec.count())
	}

	// Unreachable server.
	check("unreachable", NewWebhook("slack", env(map[string]string{
		config.EnvWebhookURL: "http://127.0.0.1:1/services/T000/B000/SECRETTOKEN"})).SendNotice(ctx, advice.TestNotice()))

	// Plain http to another computer is refused before anything is sent.
	check("http remote", NewWebhook("slack", env(map[string]string{
		config.EnvWebhookURL: "http://hooks.example.com/services/T000/B000/SECRETTOKEN"})).SendNotice(ctx, advice.TestNotice()))

	// A missing variable is named.
	err = NewNtfy(4, env(nil)).SendNotice(ctx, advice.TestNotice())
	if err == nil || !strings.Contains(err.Error(), config.EnvNtfyURL) {
		t.Errorf("missing URL: %v", err)
	}
}

func TestRateLimitRetriedOnce(t *testing.T) {
	rec, u := serve(t, http.StatusTooManyRequests)
	if err := NewWebhook("discord", env(map[string]string{config.EnvWebhookURL: u})).SendNotice(context.Background(), advice.TestNotice()); err != nil {
		t.Fatal(err)
	}
	if rec.count() != 2 {
		t.Errorf("%d requests, want 2", rec.count())
	}
	rec, u = serve(t, http.StatusTooManyRequests, http.StatusTooManyRequests)
	err := NewWebhook("discord", env(map[string]string{config.EnvWebhookURL: u})).SendNotice(context.Background(), advice.TestNotice())
	if err == nil || rec.count() != 2 {
		t.Errorf("a second 429 must fail without a third try: %v, %d requests", err, rec.count())
	}
}

func TestTruncate(t *testing.T) {
	long := strings.Repeat("line of text\n", 1000)
	got := truncate(long, 500)
	if n := utf8.RuneCountInString(got); n > 500 || !strings.HasSuffix(got, shortenedNote) {
		t.Errorf("truncate: %d characters", n)
	}
	wide := strings.Repeat("ü", 3000) // 2 bytes each
	if b := truncateBytes(wide, 3500); len(b) > 3500 || !utf8.ValidString(b) {
		t.Errorf("truncateBytes: %d bytes, valid %v", len(b), utf8.ValidString(b))
	}
	if truncate("short", 10) != "short" {
		t.Error("short text changed")
	}
}

func TestScrub(t *testing.T) {
	u, err := url.Parse("https://prod-12.westeurope.logic.azure.com/workflows/0a1b2c3d4e5f60718293a4b5c6d7e8f9/triggers/manual/paths/invoke?api-version=2016-06-01&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=AbCdEfGhIjKlMnOpQrStUvWxYz0123456789")
	if err != nil {
		t.Fatal(err)
	}
	h := http.Header{"Authorization": {"Bearer tk_abcdef123456"}}
	for _, echoed := range []string{
		"bad signature AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
		"no flow 0a1b2c3d4e5f60718293a4b5c6d7e8f9",
		"sp=/triggers/manual/run rejected",
		"token tk_abcdef123456 expired",
	} {
		got := scrub(echoed, u, h)
		for _, secret := range []string{"AbCdEfGhIjKl", "0a1b2c3d4e5f", "tk_abcdef", "/triggers/manual/run"} {
			if strings.Contains(got, secret) {
				t.Errorf("scrub(%q) = %q still contains %q", echoed, got, secret)
			}
		}
	}
	// Fixed words stay, so the message still means something.
	if got := scrub("the workflow trigger is disabled", u, h); got != "the workflow trigger is disabled" {
		t.Errorf("over-redacted: %q", got)
	}
}
