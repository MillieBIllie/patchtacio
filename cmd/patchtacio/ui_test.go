package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zalando/go-keyring"

	"github.com/milliebillie/patchtacio/internal/config"
	"github.com/milliebillie/patchtacio/internal/paths"
	"github.com/milliebillie/patchtacio/internal/secrets"
)

// uiClient is a browser for the end-to-end test.
type uiClient struct {
	t      *testing.T
	base   string
	client *http.Client
	csrf   string
}

var (
	uiCSRF   = regexp.MustCompile(`name="csrf" value="([0-9a-f]{64})"`)
	uiAckIDs = regexp.MustCompile(`action="/findings/ack"[^>]*>\s*<input type="hidden" name="csrf" value="[0-9a-f]+"><input type="hidden" name="id" value="([^"]+)"`)
)

func (c *uiClient) do(req *http.Request) (int, string, string) {
	c.t.Helper()
	resp, err := c.client.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header.Get("Location"), string(b)
}

func (c *uiClient) get(path string) string {
	c.t.Helper()
	req, _ := http.NewRequestWithContext(c.t.Context(), http.MethodGet, c.base+path, nil)
	code, _, body := c.do(req)
	if code != http.StatusOK {
		c.t.Fatalf("GET %s: %d\n%s", path, code, body)
	}
	if m := uiCSRF.FindStringSubmatch(body); m != nil {
		c.csrf = m[1]
	}
	return body
}

// post submits a form as the page does and returns the page it leads to.
func (c *uiClient) post(path string, form url.Values) string {
	c.t.Helper()
	form.Set("csrf", c.csrf)
	req, _ := http.NewRequestWithContext(c.t.Context(), http.MethodPost, c.base+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", c.base)
	code, loc, body := c.do(req)
	if code == http.StatusOK {
		return body // stopped page, or a form shown again with its problems
	}
	if code != http.StatusSeeOther {
		c.t.Fatalf("POST %s: %d\n%s", path, code, body)
	}
	return c.get(loc)
}

// The whole setup, as a tester would do it, without the CLI: open the
// link, tick products, set up and test alerts, download the data, see and
// acknowledge a finding, set up the daily check, stop.
func TestUIEndToEnd(t *testing.T) {
	e := newTestEnv(t)
	t.Setenv(config.EnvWebhookURL, "")
	t.Setenv(config.EnvSMTPPassword, "")
	sched, _ := e.useFakeScheduler(t)
	chans := e.useFakeChannels() // after the scheduler's, which sets its own
	e.app.secrets = secrets.Mock(os.Getenv(paths.EnvConfigDir), os.Getenv)

	links := make(chan string, 1)
	e.app.openBrowser = func(u string) error { links <- u; return nil }
	var out, errOut bytes.Buffer
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var runErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		runErr = e.app.runUI(ctx, &out, &errOut, false)
	}()

	var link string
	select {
	case link = <-links:
	case <-time.After(10 * time.Second):
		t.Fatal("the browser was not opened")
	}
	u, _ := url.Parse(link)
	jar, _ := cookiejar.New(nil)
	c := &uiClient{t: t, base: "http://" + u.Host, client: &http.Client{Jar: jar, Timeout: time.Minute,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, link, nil)
	if code, loc, _ := c.do(req); code != http.StatusSeeOther || loc != "/" {
		t.Fatalf("launch link: %d %s", code, loc)
	}
	home := c.get("/")
	requireContains(t, home, "No products chosen yet.", "Not set up")

	// Products.
	page := c.get("/products")
	requireContains(t, page, "Citrix NetScaler", `name="pick" value="citrix-netscaler"`)
	page = c.post("/products", url.Values{
		"hash": {""}, "pick": {"citrix-netscaler", "vmware-vcenter"},
		"notes.citrix-netscaler": {"remote access gateway"},
	})
	requireContains(t, page, "Saved 2 products.", "Next: choose how Patchtacio should alert you.")
	path := filepath.Join(os.Getenv(paths.EnvConfigDir), config.FileName)
	cfg, err := config.Load(path)
	if err != nil || strings.Join(cfg.IDs(), ",") != "citrix-netscaler,vmware-vcenter" || cfg.Products[0].Notes != "remote access gateway" {
		t.Fatalf("saved configuration: %+v, %v", cfg, err)
	}

	// Alerts, with the webhook URL going to the keychain only.
	const hook = "https://hooks.slack.com/services/T0/B0/UISECRETTOKEN"
	page = c.post("/alerts", url.Values{
		"hash": {hashOf(t, path)}, "webhook": {"on"}, "kind": {"slack"}, "desktop": {"on"},
		"secret." + config.EnvWebhookURL: {hook}, "digest": {"off"}, "priority": {"4"},
	})
	requireContains(t, page, "Saved the alert settings.", "Saved the webhook URL in the keychain.", "Saved in this computer's keychain.")
	if v, _ := keyring.Get(secrets.Service, config.EnvWebhookURL); v != hook {
		t.Errorf("keychain holds %q", v)
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), "UISECRETTOKEN") || !strings.Contains(string(raw), "kind: slack") {
		t.Errorf("configuration file:\n%s", raw)
	}
	// A URL Patchtacio would refuse to post to is not saved.
	page = c.post("/alerts", url.Values{
		"hash": {hashOf(t, path)}, "webhook": {"on"}, "kind": {"slack"}, "desktop": {"on"},
		"secret." + config.EnvWebhookURL: {"http://hooks.example.com/x"},
	})
	requireContains(t, page, "Nothing was saved", "must be an https:// URL")
	if v, _ := keyring.Get(secrets.Service, config.EnvWebhookURL); v != hook {
		t.Errorf("a refused URL replaced the saved one: %q", v)
	}

	page = c.post("/alerts/test", url.Values{"channel": {"all"}})
	requireContains(t, page, "Test message sent", "Check the slack channel.", "A notification should have appeared")
	if strings.Join(chans.tests, ",") != "webhook,desktop" {
		t.Errorf("tests sent: %v", chans.tests)
	}

	// Findings: no data until downloaded, and never "nothing found".
	page = c.get("/findings")
	requireContains(t, page, "no vulnerability data yet")
	if strings.Contains(page, "None of your products") {
		t.Error("no data shown as no findings")
	}
	page = c.post("/findings/update", url.Values{})
	requireContains(t, page, "Downloaded the latest data and checked your products.",
		"CVE-2026-88772", "Known exploited vulnerabilities: CISA KEV catalog, 19 entries",
		"Patchtacio matched this by product name", "your note: remote access gateway")
	ids := uiAckIDs.FindAllStringSubmatch(page, -1)
	if len(ids) != 3 {
		t.Fatalf("want 3 acknowledge buttons, got %d", len(ids))
	}
	id := ids[0][1]
	page = c.post("/findings/ack", url.Values{"id": {id}, "note": {"patched on 2 Oct"}})
	requireContains(t, page, "Marked as dealt with.", "Dealt with (1)")
	// The CLI sees the same acknowledgement.
	stdout, _, _ := e.exec(t, "check", "--json", "--offline")
	if !strings.Contains(stdout, `"acknowledged": true`) {
		t.Errorf("check does not show the acknowledgement:\n%s", stdout)
	}

	// Daily check.
	page = c.get("/schedule")
	requireContains(t, page, "Not set up", "Set up the daily check")
	page = c.post("/schedule/install", url.Values{"at": {"07:30"}})
	requireContains(t, page, "The daily check is set up: every day at 07:30.", "Run it now")
	if !sched.installed || sched.job.Hour != 7 || sched.job.Minute != 30 {
		t.Errorf("scheduler: %+v", sched)
	}
	page = c.post("/schedule/run", url.Values{})
	requireContains(t, page, "Started the daily check.")
	if sched.runs != 1 {
		t.Errorf("run now: %d runs", sched.runs)
	}
	home = c.get("/")
	requireContains(t, home, "2 products chosen.", "Alerts go by: webhook, desktop.", "need your attention", "every day at 07:30")

	// No page ever carries the secret.
	for _, p := range []string{"/", "/products", "/alerts", "/findings", "/schedule"} {
		if strings.Contains(c.get(p), "UISECRETTOKEN") {
			t.Errorf("%s shows the webhook URL", p)
		}
	}

	page = c.post("/quit", url.Values{})
	requireContains(t, page, "Patchtacio has stopped")
	wg.Wait()
	if runErr != nil {
		t.Errorf("runUI: %v", runErr)
	}
	requireContains(t, out.String(), "Patchtacio is running at http://127.0.0.1:", "It should now be open in your web browser.",
		link, "Patchtacio has stopped.")
	if strings.Contains(out.String()+errOut.String(), "UISECRETTOKEN") {
		t.Error("the terminal shows the webhook URL")
	}
}

func TestUIWithoutBrowser(t *testing.T) {
	e := newTestEnv(t)
	e.app.openBrowser = func(string) error { t.Error("--no-browser opened a browser"); return nil }
	var out, errOut lockedBuffer
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- e.app.runUI(ctx, &out, &errOut, true) }()
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(out.String(), "Keep this window open") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	requireContains(t, out.String(), "Go to this address in your web browser", "/login?token=")
}

func hashOf(t *testing.T, path string) string {
	t.Helper()
	h, err := currentHash(path)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// lockedBuffer is a bytes.Buffer safe to read while another goroutine writes.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}
