package ui

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/milliebillie/patchtacio/internal/advice"
	"github.com/milliebillie/patchtacio/internal/catalog"
	"github.com/milliebillie/patchtacio/internal/config"
)

// fake is an in-memory Backend.
type fake struct {
	mu       sync.Mutex
	file     *config.Config
	version  int // the file's "hash"
	problem  string
	secrets  map[string]string
	report   *Report
	feeds    []FeedStatus
	updated  int
	acked    map[string]string
	tested   []string
	testErr  map[string]error
	sched    Schedule
	setErr   error
	failSave error
}

func newFake() *fake {
	return &fake{
		file:    &config.Config{Version: config.SchemaVersion},
		secrets: map[string]string{},
		acked:   map[string]string{},
		testErr: map[string]error{},
		report:  &Report{Feed: "CISA KEV catalog 2026.10.02"},
	}
}

func (f *fake) hash() string {
	if f.version == 0 {
		return ""
	}
	return "v" + strconv.Itoa(f.version)
}

func (f *fake) Config(context.Context) (*Config, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := *f.file
	cp.Products = append([]config.Product(nil), f.file.Products...)
	return &Config{
		Path: "/home/u/.config/patchtacio/config.yaml", Hash: f.hash(), Problem: f.problem, File: &cp,
		Products: []catalog.Product{
			{ID: "fortinet-fortios", Display: "Fortinet FortiOS", Category: "firewall-vpn", EOLSlug: "fortios", AliasesSearch: []string{"FortiGate"}},
			{ID: "microsoft-exchange-server", Display: "Microsoft Exchange Server", Category: "email"},
			{ID: "ivanti-connect-secure", Display: "Ivanti Connect Secure", Category: "remote-access"},
		},
	}, nil
}

func (f *fake) SaveConfig(_ context.Context, hash string, c *config.Config) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failSave != nil {
		return f.failSave
	}
	if hash != f.hash() {
		return ErrConflict
	}
	f.file = c
	f.version++
	return nil
}

func (f *fake) Secrets(context.Context) []Secret {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []Secret
	for _, env := range []string{config.EnvSMTPPassword, config.EnvWebhookURL, config.EnvNtfyURL, config.EnvNtfyToken} {
		s := Secret{Env: env, What: secretLabel(env)}
		if _, ok := f.secrets[env]; ok {
			s.Source = "keychain"
		}
		out = append(out, s)
	}
	return out
}

func (f *fake) CheckSecret(env, value string) error {
	if env == config.EnvWebhookURL && !strings.HasPrefix(value, "https://") {
		return errors.New("the webhook URL must be an https:// URL")
	}
	return nil
}

func (f *fake) SetSecret(_ context.Context, env, value string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.setErr != nil {
		return f.setErr
	}
	f.secrets[env] = value
	return nil
}

func (f *fake) DeleteSecret(_ context.Context, env string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.secrets, env)
	return nil
}

func (f *fake) Test(_ context.Context, channel string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tested = append(f.tested, channel)
	return f.testErr[channel]
}

func (f *fake) Report(_ context.Context, update bool) (*Report, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if update {
		f.updated++
	}
	r := *f.report
	r.Findings = append([]Finding(nil), f.report.Findings...)
	for i := range r.Findings {
		_, r.Findings[i].Acked = f.acked[r.Findings[i].ID]
	}
	return &r, nil
}

func (f *fake) Ack(_ context.Context, ids []string, note string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, id := range ids {
		f.acked[id] = note
	}
	return nil
}

func (f *fake) Unack(_ context.Context, ids []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, id := range ids {
		delete(f.acked, id)
	}
	return nil
}

func (f *fake) Feeds(context.Context) ([]FeedStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.feeds, nil
}

func (f *fake) Schedule(context.Context) (*Schedule, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := f.sched
	return &s, nil
}

func (f *fake) InstallSchedule(_ context.Context, at string) (*ScheduleSetup, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if at == "" {
		at = "08:17"
	}
	f.sched = Schedule{Installed: true, Method: "Task Scheduler", At: at, LastRun: "not yet", LogFile: "/tmp/patchtacio.log"}
	return &ScheduleSetup{Method: "Task Scheduler", At: at, NextRun: "Mon 5 Oct 2026 " + at, LogFile: "/tmp/patchtacio.log"}, nil
}

func (f *fake) UninstallSchedule(context.Context) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.sched.Installed {
		return nil, nil
	}
	f.sched = Schedule{}
	return []string{"task"}, nil
}

func (f *fake) RunScheduleNow(context.Context) (string, error) { return "/tmp/patchtacio.log", nil }

// harness runs a server and a browser-like client.
type harness struct {
	t      *testing.T
	s      *Server
	b      *fake
	base   string
	client *http.Client
	csrf   string
	now    time.Time

	mu   sync.Mutex
	told []string // what the server told the terminal
}

func (h *harness) tells() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return strings.Join(h.told, "|")
}

func start(t *testing.T) *harness {
	t.Helper()
	h := &harness{t: t, b: newFake(), now: time.Date(2026, 10, 4, 9, 0, 0, 0, time.UTC)}
	s, err := New(h.b, Options{Version: "test", Now: func() time.Time { return h.now }, Tell: func(m string) {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.told = append(h.told, m)
	}})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := s.Listen(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Serve: %v", err)
		}
	})
	jar, _ := cookiejar.New(nil)
	h.s, h.base = s, strings.TrimSuffix(s.URL(), "/")
	h.client = &http.Client{Jar: jar, Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return h
}

// login opens the launch link, as the browser does.
func (h *harness) login() {
	h.t.Helper()
	resp := h.get(h.s.LaunchURL())
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/" {
		h.t.Fatalf("login: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	body := h.page("/")
	h.csrf = csrfFrom(h.t, body)
}

// result is a response, read and closed.
type result struct {
	StatusCode int
	Header     http.Header
	Body       string
}

func (h *harness) do(req *http.Request) *result {
	h.t.Helper()
	resp, err := h.client.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		h.t.Fatal(err)
	}
	return &result{StatusCode: resp.StatusCode, Header: resp.Header, Body: string(b)}
}

func (h *harness) get(u string) *result {
	h.t.Helper()
	if strings.HasPrefix(u, "/") {
		u = h.base + u
	}
	req, _ := http.NewRequestWithContext(h.t.Context(), http.MethodGet, u, nil)
	return h.do(req)
}

// page GETs path and returns the body, failing unless it is 200.
func (h *harness) page(path string) string {
	h.t.Helper()
	resp := h.get(path)
	if resp.StatusCode != http.StatusOK {
		h.t.Fatalf("GET %s: %d\n%s", path, resp.StatusCode, resp.Body)
	}
	return resp.Body
}

// post submits a form with the session's CSRF token, as the page does.
func (h *harness) post(path string, form url.Values) *result {
	h.t.Helper()
	if form == nil {
		form = url.Values{}
	}
	if form.Get("csrf") == "" {
		form.Set("csrf", h.csrf)
	}
	req, _ := http.NewRequestWithContext(h.t.Context(), http.MethodPost, h.base+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", h.base)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	return h.do(req)
}

// postOK posts and follows the redirect, returning the next page.
func (h *harness) postOK(path string, form url.Values) string {
	h.t.Helper()
	resp := h.post(path, form)
	if resp.StatusCode != http.StatusSeeOther {
		h.t.Fatalf("POST %s: %d\n%s", path, resp.StatusCode, resp.Body)
	}
	return h.page(resp.Header.Get("Location"))
}

var csrfField = regexp.MustCompile(`name="csrf" value="([0-9a-f]{64})"`)

func csrfFrom(t *testing.T, body string) string {
	t.Helper()
	m := csrfField.FindStringSubmatch(body)
	if m == nil {
		t.Fatal("no CSRF token in the page")
	}
	return m[1]
}

func TestListensOnLoopbackOnly(t *testing.T) {
	h := start(t)
	u, _ := url.Parse(h.base)
	if host, _, _ := net.SplitHostPort(u.Host); host != "127.0.0.1" {
		t.Fatalf("listening on %s", u.Host)
	}
}

func TestEveryPageNeedsTheSession(t *testing.T) {
	h := start(t)
	for _, p := range []string{"/", "/products", "/alerts", "/findings", "/schedule"} {
		resp := h.get(p)
		b := resp.Body
		if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(b, "patchtacio ui") {
			t.Errorf("GET %s without session: %d", p, resp.StatusCode)
		}
	}
	// A guessed cookie does not count.
	u, _ := url.Parse(h.base)
	_, port, _ := net.SplitHostPort(u.Host)
	h.client.Jar.SetCookies(u, []*http.Cookie{{Name: "patchtacio_" + port, Value: strings.Repeat("0", 64)}})
	if resp := h.get("/"); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("guessed cookie: %d", resp.StatusCode)
	}
	if resp := h.post("/quit", url.Values{"csrf": {"x"}}); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("POST without session: %d", resp.StatusCode)
	}
}

func TestLaunchLinkWorksOnceAndExpires(t *testing.T) {
	h := start(t)
	link := h.s.LaunchURL()
	h.login()

	// Another browser (no cookie) cannot reuse the link.
	other := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, link, nil)
	resp, err := other.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("second use of the launch link: %d", resp.StatusCode)
	}
	if resp := h.get("/login?token="); resp.StatusCode != http.StatusForbidden {
		t.Errorf("empty token: %d", resp.StatusCode)
	}

	h2 := start(t)
	h2.now = h2.now.Add(3 * time.Minute)
	if resp := h2.get(h2.s.LaunchURL()); resp.StatusCode != http.StatusForbidden {
		t.Errorf("expired launch link: %d", resp.StatusCode)
	}
	h2.now = h2.now.Add(-3 * time.Minute)
	if resp := h2.get(strings.Replace(h2.s.LaunchURL(), "token=", "token=00", 1)); resp.StatusCode != http.StatusForbidden {
		t.Errorf("wrong token: %d", resp.StatusCode)
	}
	if resp := h2.get(h2.s.LaunchURL()); resp.StatusCode != http.StatusSeeOther {
		t.Errorf("a wrong guess must not burn the real link: %d", resp.StatusCode)
	}
}

func TestSessionCookieAttributes(t *testing.T) {
	h := start(t)
	resp := h.get(h.s.LaunchURL())
	c := resp.Header.Get("Set-Cookie")
	for _, want := range []string{"HttpOnly", "SameSite=Strict", "Path=/"} {
		if !strings.Contains(c, want) {
			t.Errorf("cookie %q lacks %s", c, want)
		}
	}
	if strings.Contains(strings.ToLower(c), "domain=") || strings.Contains(c, "Max-Age") || strings.Contains(c, "Expires") {
		t.Errorf("cookie must be a host-only session cookie: %q", c)
	}
}

func TestOtherHostNamesAreRefused(t *testing.T) {
	h := start(t)
	h.login()
	u, _ := url.Parse(h.base)
	_, port, _ := net.SplitHostPort(u.Host)
	for _, host := range []string{"evil.example:" + port, "localhost:" + port, "127.0.0.1", "127.0.0.1:1", "[::1]:" + port} {
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, h.base+"/", nil)
		req.Host = host
		resp, err := h.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusMisdirectedRequest {
			t.Errorf("Host %s: %d", host, resp.StatusCode)
		}
	}
}

func TestPostsNeedTheCSRFTokenAndOurOrigin(t *testing.T) {
	h := start(t)
	h.login()
	send := func(token string, hdr map[string]string) int {
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, h.base+"/schedule/uninstall", strings.NewReader("csrf="+token))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := h.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	if c := send("", nil); c != http.StatusForbidden {
		t.Errorf("no token: %d", c)
	}
	if c := send(strings.Repeat("a", 64), nil); c != http.StatusForbidden {
		t.Errorf("wrong token: %d", c)
	}
	if c := send(h.csrf, map[string]string{"Origin": "https://evil.example"}); c != http.StatusForbidden {
		t.Errorf("foreign Origin: %d", c)
	}
	if c := send(h.csrf, map[string]string{"Origin": "null"}); c != http.StatusForbidden {
		t.Errorf("null Origin: %d", c)
	}
	if c := send(h.csrf, map[string]string{"Sec-Fetch-Site": "cross-site"}); c != http.StatusForbidden {
		t.Errorf("cross-site fetch: %d", c)
	}
	if c := send(h.csrf, map[string]string{"Sec-Fetch-Site": "same-site"}); c != http.StatusForbidden {
		t.Errorf("same-site (another port) fetch: %d", c)
	}
	if c := send(h.csrf, map[string]string{"Origin": h.base, "Sec-Fetch-Site": "same-origin"}); c != http.StatusSeeOther {
		t.Errorf("the page's own form: %d", c)
	}
}

func TestBodyLimit(t *testing.T) {
	h := start(t)
	h.login()
	resp := h.post("/products", url.Values{"notes.x": {strings.Repeat("a", maxBody)}})
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized form: %d", resp.StatusCode)
	}
}

func TestSecurityHeaders(t *testing.T) {
	h := start(t)
	for _, p := range []string{"/", "/static/style.css"} {
		resp := h.get(p)
		for k, want := range map[string]string{
			"Content-Security-Policy": "default-src 'none'",
			"X-Frame-Options":         "DENY",
			"X-Content-Type-Options":  "nosniff",
			"Referrer-Policy":         "no-referrer",
			"Cache-Control":           "no-store",
		} {
			if got := resp.Header.Get(k); !strings.Contains(got, want) {
				t.Errorf("%s: %s = %q, want %q", p, k, got, want)
			}
		}
	}
	if resp := h.get("/static/app.js"); resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/javascript") {
		t.Errorf("app.js: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	for _, p := range []string{"/static/", "/static/../templates/layout.html", "/static/nope.css"} {
		if resp := h.get(p); resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s: %d", p, resp.StatusCode)
		}
	}
}

func TestSaveProducts(t *testing.T) {
	h := start(t)
	h.login()
	body := h.page("/products")
	if !strings.Contains(body, "Fortinet FortiOS") || !strings.Contains(body, `data-search="fortinet fortios fortinet-fortios fortigate"`) {
		t.Fatalf("picker rows missing:\n%s", body)
	}
	next := h.postOK("/products", url.Values{
		"hash":                              {""},
		"pick":                              {"ivanti-connect-secure", "fortinet-fortios"},
		"version.fortinet-fortios":          {" 7.4.2 "},
		"notes.fortinet-fortios":            {"head office"},
		"version.microsoft-exchange-server": {"2019"}, // not ticked: ignored
	})
	if !strings.Contains(next, "Saved 2 products.") || !strings.Contains(next, "Next: choose how Patchtacio should alert you.") {
		t.Errorf("after saving:\n%s", next)
	}
	got := h.b.file.Products
	want := []config.Product{{ID: "fortinet-fortios", Version: "7.4.2", Notes: "head office"}, {ID: "ivanti-connect-secure"}}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("saved %v, want %v (picker order)", got, want)
	}

	// A form from before the file changed is refused.
	next = h.postOK("/products", url.Values{"hash": {""}, "pick": {"fortinet-fortios"}})
	if !strings.Contains(next, "was changed") || len(h.b.file.Products) != 2 {
		t.Errorf("stale form saved:\n%s", next)
	}
	// Nothing ticked, an unknown ID, or a two-line version: nothing saved.
	for _, form := range []url.Values{
		{"hash": {"v1"}},
		{"hash": {"v1"}, "pick": {"fortinet-fortios", "no-such-product"}},
		{"hash": {"v1"}, "pick": {"fortinet-fortios"}, "version.fortinet-fortios": {"7.4\nproducts: []"}},
		{"hash": {"v1"}, "pick": {"fortinet-fortios"}, "notes.fortinet-fortios": {strings.Repeat("x", maxNotes+1)}},
	} {
		next = h.postOK("/products", form)
		if !strings.Contains(next, "Nothing was saved") || h.b.version != 1 {
			t.Errorf("form %v was saved", form)
		}
	}
	// Existing products keep their place; new ones follow.
	h.postOK("/products", url.Values{"hash": {"v1"}, "pick": {"microsoft-exchange-server", "ivanti-connect-secure", "fortinet-fortios"}})
	if ids := h.b.file.IDs(); strings.Join(ids, ",") != "fortinet-fortios,ivanti-connect-secure,microsoft-exchange-server" {
		t.Errorf("order %v", ids)
	}
}

func TestUnusableConfigIsNeverOverwritten(t *testing.T) {
	h := start(t)
	h.b.problem = "configuration file config.yaml is not valid: line 3"
	h.login()
	body := h.page("/products")
	if !strings.Contains(body, "cannot change the settings file") || !strings.Contains(body, "line 3") {
		t.Errorf("problem not shown:\n%s", body)
	}
	h.postOK("/products", url.Values{"pick": {"fortinet-fortios"}})
	h.postOK("/alerts", url.Values{"desktop": {"on"}})
	if h.b.version != 0 {
		t.Error("an unusable configuration was overwritten")
	}
}

func TestAlertsSaveTestAndSecretsNeverShown(t *testing.T) {
	h := start(t)
	h.login()
	const password = "hunter2-very-secret"
	const hook = "https://example.webhook.office.com/workflows/abc?sig=TOKEN123"
	next := h.postOK("/alerts", url.Values{
		"hash":  {""},
		"email": {"on"}, "host": {"smtp.example.org"}, "security": {"starttls"}, "username": {"alerts"},
		"from": {"patchtacio@example.org"}, "to": {"it@example.org\nhead@example.org"},
		"secret." + config.EnvSMTPPassword: {password},
		"webhook":                          {"on"}, "kind": {"teams"},
		"secret." + config.EnvWebhookURL: {hook},
		"secret." + config.EnvNtfyURL:    {"https://ntfy.sh/ignored-because-ntfy-is-off"},
		"desktop":                        {"on"}, "digest": {"daily"}, "priority": {"4"},
	})
	if !strings.Contains(next, "Saved the alert settings.") || !strings.Contains(next, "Saved the email password in the keychain.") {
		t.Errorf("after saving:\n%s", next)
	}
	n := h.b.file.Notify
	if n == nil || n.Email == nil || n.Email.Port != 587 || len(n.Email.To) != 2 || n.Webhook.Kind != "teams" || !n.Desktop || n.Digest != "daily" || n.Ntfy != nil {
		t.Fatalf("saved %+v", n)
	}
	if h.b.secrets[config.EnvSMTPPassword] != password || h.b.secrets[config.EnvWebhookURL] != hook {
		t.Errorf("secrets %v", h.b.secrets)
	}
	if _, ok := h.b.secrets[config.EnvNtfyURL]; ok {
		t.Error("a secret for a channel that is off was saved")
	}
	for _, p := range []string{"/", "/alerts", "/schedule", "/findings", "/products"} {
		body := h.page(p)
		for _, secret := range []string{password, "TOKEN123", "webhook.office.com"} {
			if strings.Contains(body, secret) {
				t.Errorf("%s shows a secret", p)
			}
		}
	}
	if body := h.page("/alerts"); !strings.Contains(body, "Saved in this computer's keychain.") {
		t.Errorf("secret state not shown:\n%s", body)
	}

	// The test buttons.
	h.b.testErr[config.ChannelWebhook] = errors.New("the webhook answered 404")
	next = h.postOK("/alerts/test", url.Values{"channel": {"all"}})
	if strings.Join(h.b.tested, ",") != "email,webhook,desktop" {
		t.Errorf("tested %v", h.b.tested)
	}
	for _, want := range []string{"Test message sent", "Check the inbox of it@example.org, head@example.org", "Test message failed", "the webhook answered 404"} {
		if !strings.Contains(next, want) {
			t.Errorf("test result lacks %q", want)
		}
	}
	next = h.postOK("/alerts/test", url.Values{"channel": {"ntfy"}})
	if !strings.Contains(next, "That channel is not set up") {
		t.Error("testing a channel that is not set up")
	}

	// Invalid settings are shown with the form as typed, and nothing is saved.
	resp := h.post("/alerts", url.Values{"hash": {"v1"}, "email": {"on"}, "host": {""}, "from": {"not an address"}, "secret." + config.EnvSMTPPassword: {"new-password"}})
	b := resp.Body
	if resp.StatusCode != http.StatusOK || !strings.Contains(b, "Nothing was saved") || !strings.Contains(b, "Email.host is required") {
		t.Errorf("invalid form: %d\n%s", resp.StatusCode, b)
	}
	if h.b.version != 1 || h.b.secrets[config.EnvSMTPPassword] != password {
		t.Error("an invalid form changed something")
	}

	// Remove a secret.
	h.postOK("/alerts/secret/delete", url.Values{"env": {config.EnvWebhookURL}})
	if _, ok := h.b.secrets[config.EnvWebhookURL]; ok {
		t.Error("secret not removed")
	}
	if resp := h.post("/alerts/secret/delete", url.Values{"env": {"PATH"}}); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("deleting an unknown secret: %d", resp.StatusCode)
	}
	if body := h.page("/"); !strings.Contains(body, "Still needed: webhook URL") {
		t.Errorf("setup page does not say the webhook URL is missing:\n%s", body)
	}
}

func TestKeychainFailureIsReported(t *testing.T) {
	h := start(t)
	h.login()
	h.b.setErr = errors.New("the keychain is locked")
	next := h.postOK("/alerts", url.Values{"hash": {""}, "webhook": {"on"}, "kind": {"slack"}, "secret." + config.EnvWebhookURL: {"https://hooks.slack.com/x"}})
	if !strings.Contains(next, "Some secrets were not saved") || !strings.Contains(next, "the keychain is locked") {
		t.Errorf("keychain failure not shown:\n%s", next)
	}
}

func card(headline string) advice.Card {
	return advice.Card{Headline: headline, Affected: []string{"Fortinet FortiOS"}, Why: []string{"Attackers are already using this flaw."},
		ToDo: "What to do", Steps: []string{"Update: check the vendor advisory for the fixed version: https://fortiguard.example/psirt/1."},
		Links: []advice.Link{{Label: "NVD", URL: "https://nvd.nist.gov/vuln/detail/CVE-2026-1"}, {Label: "Bad", URL: "javascript:alert(1)"}}}
}

func TestFindingsAndAck(t *testing.T) {
	h := start(t)
	h.b.file.Products = []config.Product{{ID: "fortinet-fortios"}}
	h.b.version = 1
	h.b.report.Findings = []Finding{
		{ID: "kev/fortinet-fortios/CVE-2026-1", CVE: "CVE-2026-1", Card: card("[Action needed by 12 Oct 2026] Fortinet FortiOS: <b>flaw</b>")},
		{ID: "kev/fortinet-fortios/CVE-2026-2", CVE: "CVE-2026-2", Card: card("[Action needed now] Fortinet FortiOS: older flaw")},
	}
	h.b.report.EOL = []EOLEntry{{ID: "eol/fortinet-fortios/7.2", Product: "Fortinet FortiOS", Release: "7.2", Card: &advice.Card{Headline: "[End of life on 30 Nov 2026] Fortinet FortiOS 7.2"}}}
	h.login()
	body := h.page("/findings")
	for _, want := range []string{
		"&lt;b&gt;flaw&lt;/b&gt;", // feed text is escaped
		`<a href="https://fortiguard.example/psirt/1" rel="noopener noreferrer" target="_blank">https://fortiguard.example/psirt/1</a>.`,
		"2 entries on CISA", "Mark as dealt with", "[End of life on 30 Nov 2026] Fortinet FortiOS 7.2",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("findings page lacks %q", want)
		}
	}
	if strings.Contains(body, "javascript:") {
		t.Error("a javascript: link reached the page")
	}

	next := h.postOK("/findings/ack", url.Values{"id": {"kev/fortinet-fortios/CVE-2026-1"}, "note": {"updated to 7.4.3"}})
	if h.b.acked["kev/fortinet-fortios/CVE-2026-1"] != "updated to 7.4.3" || !strings.Contains(next, "Marked as dealt with.") ||
		!strings.Contains(next, "Dealt with (1)") || !strings.Contains(next, "1 entry on CISA") {
		t.Errorf("after ack: %v\n%s", h.b.acked, next)
	}
	h.postOK("/findings/unack", url.Values{"id": {"kev/fortinet-fortios/CVE-2026-1"}})
	if len(h.b.acked) != 0 {
		t.Error("unack did not reach the backend")
	}
	for _, id := range []string{"CVE-2026-1", "../etc", strings.Repeat("kev/", 100)} {
		if resp := h.post("/findings/ack", url.Values{"id": {id}}); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("ack %q: %d", id, resp.StatusCode)
		}
	}
	next = h.postOK("/findings/ack", url.Values{"id": {"kev/fortinet-fortios/CVE-2026-1"}, "note": {"a\nb"}})
	if !strings.Contains(next, "Not acknowledged") {
		t.Error("two-line note accepted")
	}

	h.postOK("/findings/update", nil)
	if h.b.updated != 1 {
		t.Error("update did not download")
	}
}

// Rule 3: no data must never look like "nothing found".
func TestNoDataIsNeverAnAllClear(t *testing.T) {
	h := start(t)
	h.b.file.Products = []config.Product{{ID: "fortinet-fortios"}}
	h.b.version = 1
	h.b.report = &Report{NoData: true, Warnings: []string{"Cannot check your products: no saved copy of the CISA KEV catalog"}}
	h.login()
	body := h.page("/findings")
	if !strings.Contains(body, "no vulnerability data yet") || !strings.Contains(body, "no saved copy") {
		t.Errorf("no-data page:\n%s", body)
	}
	if strings.Contains(body, "None of your products") {
		t.Error("no data shown as no findings")
	}
	next := h.postOK("/findings/update", nil)
	if !strings.Contains(next, "Could not download the data, and there is no saved copy") {
		t.Errorf("after update:\n%s", next)
	}
	if body := h.page("/"); strings.Contains(body, "Nothing open") {
		t.Error("setup page calls no data an all clear")
	}
}

func TestStaleDataWarningShown(t *testing.T) {
	h := start(t)
	h.b.file.Products = []config.Product{{ID: "fortinet-fortios"}}
	h.b.version = 1
	h.b.report.Warnings = []string{"Warning: the CISA KEV catalog is out of date (last checked 3 days ago)"}
	h.login()
	body := h.page("/findings")
	if !strings.Contains(body, "Read this before relying on the list below") || !strings.Contains(body, "out of date") ||
		!strings.Contains(body, "This is not an all clear") {
		t.Errorf("stale page:\n%s", body)
	}
}

func TestSchedule(t *testing.T) {
	h := start(t)
	h.login()
	body := h.page("/schedule")
	if !strings.Contains(body, "Not set up") || !strings.Contains(body, "Choose your products first.") || strings.Contains(body, "/schedule/install") {
		t.Errorf("schedule page before setup:\n%s", body)
	}
	h.b.file = &config.Config{Version: 1, Products: []config.Product{{ID: "fortinet-fortios"}}, Notify: &config.Notify{Desktop: true}}
	next := h.postOK("/schedule/install", url.Values{"at": {"07:30"}})
	if !strings.Contains(next, "The daily check is set up: every day at 07:30.") || !strings.Contains(next, "Run it now") {
		t.Errorf("after install:\n%s", next)
	}
	next = h.postOK("/schedule/run", nil)
	if !strings.Contains(next, "Started the daily check.") {
		t.Errorf("after run now:\n%s", next)
	}
	next = h.postOK("/schedule/uninstall", nil)
	if !strings.Contains(next, "Removed the daily check.") || h.b.sched.Installed {
		t.Errorf("after uninstall:\n%s", next)
	}
	if resp := h.post("/schedule/install", url.Values{"at": {"07:30; rm -rf /"}}); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("long time value: %d", resp.StatusCode)
	}
}

func TestStop(t *testing.T) {
	h := start(t)
	h.login()
	resp := h.post("/quit", nil)
	b := resp.Body
	if resp.StatusCode != http.StatusOK || !strings.Contains(b, "Patchtacio has stopped") {
		t.Errorf("quit: %d\n%s", resp.StatusCode, b)
	}
	select {
	case <-h.s.Stopped():
	case <-time.After(5 * time.Second):
		t.Fatal("server did not stop")
	}
}

func TestMethodsAndUnknownPaths(t *testing.T) {
	h := start(t)
	h.login()
	if resp := h.get("/nope"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown path: %d", resp.StatusCode)
	}
	if resp := h.get("/quit"); resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET /quit: %d", resp.StatusCode)
	}
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPut, h.base+"/products", nil)
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("PUT: %d", resp.StatusCode)
	}
}

func TestLinkify(t *testing.T) {
	for in, want := range map[string]string{
		"see https://a.example/x?y=1&z=2.": `see <a href="https://a.example/x?y=1&amp;z=2" rel="noopener noreferrer" target="_blank">https://a.example/x?y=1&amp;z=2</a>.`,
		"<script>alert(1)</script>":        "&lt;script&gt;alert(1)&lt;/script&gt;",
		"javascript:alert(1)":              "javascript:alert(1)",
		`https://a.example/"onmouseover=x`: `<a href="https://a.example/" rel="noopener noreferrer" target="_blank">https://a.example/</a>&#34;onmouseover=x`,
	} {
		if got := string(linkify(in)); got != want {
			t.Errorf("linkify(%q)\n got %s\nwant %s", in, got, want)
		}
	}
}

func TestOpenBrowserRefusesOtherLinks(t *testing.T) {
	for _, u := range []string{"https://evil.example/", "file:///etc/passwd", "http://127.0.0.1:1/ --flag", "http://127.0.0.1.evil.example/"} {
		if err := OpenBrowser(u); err == nil {
			t.Errorf("OpenBrowser(%q) was allowed", u)
		}
	}
}

// A launch link used a second time may have been stolen: the session ends.
func TestReusedLaunchLinkEndsTheSession(t *testing.T) {
	h := start(t)
	link := h.s.LaunchURL()
	h.login()
	if !strings.Contains(h.tells(), "A browser opened Patchtacio at 09:00:00") {
		t.Errorf("session start not told: %q", h.tells())
	}
	other := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, link, nil)
	resp, err := other.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(body), "closed the browser session") {
		t.Errorf("reused link: %d\n%s", resp.StatusCode, body)
	}
	if r := h.get("/"); r.StatusCode != http.StatusUnauthorized {
		t.Errorf("the first session still works after the link was reused: %d", r.StatusCode)
	}
	if r := h.get(link); r.StatusCode != http.StatusForbidden {
		t.Errorf("third use: %d", r.StatusCode)
	}
	if !strings.Contains(h.tells(), "opened a second time") {
		t.Errorf("reuse not told: %q", h.tells())
	}
}

func TestIdleTimeoutStops(t *testing.T) {
	var mu sync.Mutex
	var told []string
	s, err := New(newFake(), Options{IdleTimeout: 40 * time.Millisecond, Tell: func(m string) {
		mu.Lock()
		defer mu.Unlock()
		told = append(told, m)
	}})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := s.Listen(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Serve(t.Context(), ln) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("did not stop when idle")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(told) != 1 || !strings.Contains(told[0], "has not been used") {
		t.Errorf("told %q", told)
	}
}

// Rule 3 on the first page too: data problems are never a finished step.
func TestSetupPageShowsDataProblems(t *testing.T) {
	h := start(t)
	h.b.file.Products = []config.Product{{ID: "fortinet-fortios"}}
	h.b.version = 1
	h.b.report.Warnings = []string{"Warning: CISA KEV catalog data is out of date because it could not be downloaded."}
	h.login()
	body := h.page("/")
	if !strings.Contains(body, "The data has problems, so findings may be missing") || !strings.Contains(body, "out of date") {
		t.Errorf("setup page:\n%s", body)
	}
	if strings.Contains(body, "Nothing open in the data") {
		t.Error("stale data shown as nothing open")
	}
	if strings.Count(body, `class="done"`) != 1 { // only the products step
		t.Errorf("steps marked done: %d", strings.Count(body, `class="done"`))
	}
}

// A server's reply quoted in an error must not become a link in our page.
func TestErrorTextIsNotLinked(t *testing.T) {
	h := start(t)
	h.b.file = &config.Config{Version: 1, Notify: &config.Notify{Desktop: true}}
	h.b.version = 1
	h.b.testErr[config.ChannelDesktop] = errors.New("server said: log in at https://phish.example/now")
	h.login()
	page := h.postOK("/alerts/test", url.Values{"channel": {"all"}})
	if !strings.Contains(page, "log in at https://phish.example/now") || strings.Contains(page, `href="https://phish.example`) {
		t.Errorf("error text linked:\n%s", page)
	}
}

func TestBadSecretIsRefusedBeforeSaving(t *testing.T) {
	h := start(t)
	h.login()
	resp := h.post("/alerts", url.Values{"hash": {""}, "webhook": {"on"}, "kind": {"slack"}, "secret." + config.EnvWebhookURL: {"http://hooks.example/x"}})
	if resp.StatusCode != http.StatusOK || !strings.Contains(resp.Body, "Nothing was saved") || !strings.Contains(resp.Body, "https://") {
		t.Errorf("bad URL: %d\n%s", resp.StatusCode, resp.Body)
	}
	if h.b.version != 0 || len(h.b.secrets) != 0 {
		t.Error("something was saved")
	}
}

func TestPeerUID(t *testing.T) {
	table := []byte(`  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:3B6D 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 1 1 0000000000000000 100 0 0 10 0
   1: 0100007F:D431 0100007F:3B6D 01 00000000:00000000 00:00000000 00000000  1001        0 2 1 0000000000000000 20 4 30 10 -1
   2: 0100007F:3B6D 0100007F:D431 01 00000000:00000000 00:00000000 00000000  1000        0 3 1 0000000000000000 20 4 30 10 -1
`)
	server := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0x3B6D}
	client := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0xD431}
	if binary.NativeEndian.Uint16([]byte{1, 0}) != 1 {
		t.Skip("fixtures are from a little-endian machine")
	}
	if uid, ok := peerUID(table, client, server, false); !ok || uid != 1001 {
		t.Errorf("peer uid = %d, %v; want 1001 (the client's socket, not ours)", uid, ok)
	}
	if _, ok := peerUID(table, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}, server, false); ok {
		t.Error("found a socket that is not there")
	}
	if _, ok := peerUID(table, &net.TCPAddr{IP: net.IPv6loopback, Port: 1}, server, false); ok {
		t.Error("an IPv6 address matched")
	}
	// An IPv6 socket connected to ::ffff:127.0.0.1 is listed in tcp6.
	table6 := []byte(`  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0000000000000000FFFF00000100007F:D431 0000000000000000FFFF00000100007F:3B6D 01 00000000:00000000 00:00000000 00000000  1002        0 9 1
`)
	if binary.NativeEndian.Uint16([]byte{1, 0}) == 1 { // the fixture is little-endian
		if uid, ok := peerUID(table6, client, server, true); !ok || uid != 1002 {
			t.Errorf("tcp6 peer uid = %d, %v; want 1002", uid, ok)
		}
		if _, ok := peerUID(table6, client, server, false); ok {
			t.Error("tcp6 row matched as tcp")
		}
	}
}

func TestBrowserEnvHasNoSecrets(t *testing.T) {
	t.Setenv(config.EnvWebhookURL, "https://hooks.example/secret")
	t.Setenv("NVD_API_KEY", "k")
	t.Setenv("PATCHTACIO_TEST_KEEP", "yes")
	env := strings.Join(browserEnv(), "\n")
	if strings.Contains(env, "hooks.example") || strings.Contains(env, "NVD_API_KEY") || !strings.Contains(env, "PATCHTACIO_TEST_KEEP=yes") {
		t.Errorf("browser environment:\n%s", env)
	}
}

func TestBulkAck(t *testing.T) {
	h := start(t)
	h.b.file.Products = []config.Product{{ID: "microsoft-windows-server"}, {ID: "fortinet-fortios"}}
	h.b.version = 1
	win := func(cve string, recent bool) Finding {
		return Finding{ID: "kev/microsoft-windows-server/" + cve, ProductID: "microsoft-windows-server", Product: "Microsoft Windows Server",
			CVE: cve, Recent: recent, Card: card("[Action needed now] Windows Server: " + cve)}
	}
	h.b.report.Findings = []Finding{
		win("CVE-2026-1", true), win("CVE-2019-2", false), win("CVE-2017-3", false),
		{ID: "kev/fortinet-fortios/CVE-2026-9", ProductID: "fortinet-fortios", Product: "Fortinet FortiOS", CVE: "CVE-2026-9", Card: card("FortiOS")},
	}
	h.login()
	body := h.page("/findings")
	if !strings.Contains(body, "Microsoft Windows Server (3 open, 2 older than 30 days)") || !strings.Contains(body, `action="/findings/ack-bulk"`) {
		t.Fatalf("bulk form missing:\n%s", body)
	}

	// Safeguards: a note and the confirmation are required.
	for _, form := range []url.Values{
		{"product": {"microsoft-windows-server"}, "scope": {"older"}, "note": {"patched"}},
		{"product": {"microsoft-windows-server"}, "scope": {"older"}, "confirm": {"yes"}},
		{"product": {"microsoft-windows-server"}, "scope": {"everything"}, "note": {"patched"}, "confirm": {"yes"}},
	} {
		if next := h.postOK("/findings/ack-bulk", form); !strings.Contains(next, "Nothing was marked") || len(h.b.acked) != 0 {
			t.Errorf("form %v marked something", form)
		}
	}

	// Older only: the recent one stays open, FortiOS is untouched.
	next := h.postOK("/findings/ack-bulk", url.Values{"product": {"microsoft-windows-server"}, "scope": {"older"},
		"note": {"cumulative update 2026-09"}, "confirm": {"yes"}})
	if !strings.Contains(next, "Marked 2 entries for Microsoft Windows Server as dealt with.") || len(h.b.acked) != 2 ||
		h.b.acked["kev/microsoft-windows-server/CVE-2019-2"] != "cumulative update 2026-09" {
		t.Errorf("older only: %v\n%s", h.b.acked, next)
	}
	if !strings.Contains(next, `action="/findings/unack-bulk"`) || !strings.Contains(next, "Microsoft Windows Server (2)") {
		t.Error("no way to move them all back")
	}
	h.postOK("/findings/ack-bulk", url.Values{"product": {"microsoft-windows-server"}, "scope": {"all"}, "note": {"x"}, "confirm": {"yes"}})
	if len(h.b.acked) != 3 {
		t.Errorf("all: %v", h.b.acked)
	}
	next = h.postOK("/findings/unack-bulk", url.Values{"product": {"microsoft-windows-server"}})
	if !strings.Contains(next, "Moved 3 entries for Microsoft Windows Server back to the open list.") || len(h.b.acked) != 0 {
		t.Errorf("unack all: %v", h.b.acked)
	}
	// A product with nothing to mark, or one that is not listed.
	if next := h.postOK("/findings/unack-bulk", url.Values{"product": {"fortinet-fortios"}}); !strings.Contains(next, "No matching entries") {
		t.Error("unack of nothing")
	}
	if next := h.postOK("/findings/ack-bulk", url.Values{"product": {"../x"}, "scope": {"all"}, "note": {"x"}, "confirm": {"yes"}}); !strings.Contains(next, "No matching entries") {
		t.Error("unknown product")
	}
}

func TestDataSources(t *testing.T) {
	h := start(t)
	h.b.feeds = []FeedStatus{
		{Title: "CISA KEV catalog", State: "out of date", Saved: "1,733 entries", Checked: "1 Oct 2026 (3 days ago)",
			Reason: "it has not been checked for more than 48 hours", Problem: "could not reach www.cisa.gov"},
		{Title: "endoflife.date", State: "missing", Checked: "never"},
	}
	h.login()
	body := h.page("/findings")
	for _, want := range []string{"Data sources", "<strong class=\"bad\">out of date</strong>", "Out of date because it has not been checked for more than 48 hours.",
		"Last problem: could not reach www.cisa.gov", "<td>none</td>"} {
		if !strings.Contains(body, want) {
			t.Errorf("data sources lack %q", want)
		}
	}
}
