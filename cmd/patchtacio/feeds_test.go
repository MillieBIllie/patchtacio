package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/milliebillie/patchtacio/internal/advice"
	"github.com/milliebillie/patchtacio/internal/catalog"
	"github.com/milliebillie/patchtacio/internal/config"
	"github.com/milliebillie/patchtacio/internal/feeds"
	"github.com/milliebillie/patchtacio/internal/feeds/eol"
	"github.com/milliebillie/patchtacio/internal/feeds/kev"
	"github.com/milliebillie/patchtacio/internal/httpcache"
	"github.com/milliebillie/patchtacio/internal/notify"
	"github.com/milliebillie/patchtacio/internal/paths"
)

// fakeFeed serves a fixture with validators and honors conditional requests.
// It can be switched to fail with a status code.
type fakeFeed struct {
	body         []byte
	failWith     atomic.Int32 // 0 = serve normally
	etagOverride atomic.Bool  // true = ignore validators (content changed)
	requests     atomic.Int32
}

const fixedLastModified = "Wed, 30 Sep 2026 16:59:23 GMT"

func (f *fakeFeed) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.requests.Add(1)
	if code := f.failWith.Load(); code != 0 {
		w.WriteHeader(int(code))
		return
	}
	const etag = `"fixture-ssl"`
	if !f.etagOverride.Load() && (r.Header.Get("If-None-Match") == etag || r.Header.Get("If-Modified-Since") == fixedLastModified) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("ETag", etag)
	w.Header().Set("Last-Modified", fixedLastModified)
	_, _ = w.Write(f.body)
}

type testEnv struct {
	app         *app
	clock       time.Time
	kev, mirror *fakeFeed
	eol         *fakeFeed
	kevSrc      *kev.Source
}

func readFixture(t *testing.T, parts ...string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(append([]string{"..", "..", "testdata", "feeds"}, parts...)...))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	base := t.TempDir()
	t.Setenv(paths.EnvConfigDir, filepath.Join(base, "config"))
	t.Setenv(paths.EnvCacheDir, filepath.Join(base, "cache"))
	t.Setenv(paths.EnvDataDir, filepath.Join(base, "data"))

	e := &testEnv{
		clock:  time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC),
		kev:    &fakeFeed{body: readFixture(t, "kev", "known_exploited_vulnerabilities.json")},
		mirror: &fakeFeed{body: readFixture(t, "kev", "known_exploited_vulnerabilities.json")},
		eol:    &fakeFeed{body: readFixture(t, "eol", "products_full.json")},
	}
	e.mirror.failWith.Store(http.StatusServiceUnavailable)
	kevSrv := httptest.NewTLSServer(e.kev)
	mirrorSrv := httptest.NewTLSServer(e.mirror)
	eolSrv := httptest.NewTLSServer(e.eol)
	t.Cleanup(kevSrv.Close)
	t.Cleanup(mirrorSrv.Close)
	t.Cleanup(eolSrv.Close)

	e.kevSrc = &kev.Source{PrimaryURL: kevSrv.URL + "/kev.json", MirrorURL: mirrorSrv.URL + "/kev.json"}
	eolSrc := &eol.Source{URL: eolSrv.URL + "/products/full"}
	e.app = &app{
		now:     func() time.Time { return e.clock },
		loc:     time.UTC,
		sources: func() []feeds.Source { return []feeds.Source{e.kevSrc, eolSrc} },
		newClient: func(l *slog.Logger) *httpcache.Client {
			c := httpcache.New("patchtacio/test", l)
			c.HTTP.Transport = kevSrv.Client().Transport // httptest servers share one certificate
			c.BaseBackoff = time.Millisecond
			return c
		},
		isTerminal: func() bool { return false },
		pick: func(context.Context, []catalog.Product, []string) ([]string, error) {
			return nil, errors.New("test did not set a picker")
		},
		// Never real channels in tests: no desktop pop-ups, no network.
		channels: func(*config.Notify) ([]notify.Channel, error) {
			return nil, errors.New("test did not set channels (call useFakeChannels)")
		},
		// Never a real desktop pop-up from a test.
		desktopNotice: func(context.Context, advice.Notice) error { return errors.New("test did not set desktopNotice") },
		log:           slog.New(slog.DiscardHandler),
	}
	return e
}

// exec runs the CLI like main does and returns stdout, stderr and exit code.
func (e *testEnv) exec(t *testing.T, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	return e.execIn(t, "", args...)
}

// execIn is exec with stdin.
func (e *testEnv) execIn(t *testing.T, stdin string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	var out, errOut bytes.Buffer
	cmd := newRootCmd(e.app)
	cmd.SetIn(strings.NewReader(stdin))
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetArgs(args)
	err := cmd.Execute()
	if err != nil && !isOutcome(err) {
		fmt.Fprintf(&errOut, "Error: %v\n", err)
	}
	return out.String(), errOut.String(), exitCodeFor(err)
}

func (e *testEnv) setDown(code int) {
	e.kev.failWith.Store(int32(code))
	e.eol.failWith.Store(int32(code))
}

func requireCode(t *testing.T, got, want int, stdout, stderr string) {
	t.Helper()
	if got != want {
		t.Fatalf("exit code %d, want %d\nstdout:\n%s\nstderr:\n%s", got, want, stdout, stderr)
	}
}

func requireContains(t *testing.T, s string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(s, w) {
			t.Errorf("output missing %q:\n%s", w, s)
		}
	}
}

func TestFeedsUpdateOnlineThenUnchangedThenOffline(t *testing.T) {
	e := newTestEnv(t)

	out, errOut, code := e.exec(t, "feeds", "update")
	requireCode(t, code, exitOK, out, errOut)
	requireContains(t, out,
		"CISA KEV catalog: updated. 19 entries, catalog 2026.09.30, published 30 Sep 2026.",
		"endoflife.date: updated. 9 products, published 1 Oct 2026.")
	if errOut != "" {
		t.Errorf("unexpected stderr: %s", errOut)
	}

	e.clock = e.clock.Add(2 * time.Hour)
	out, errOut, code = e.exec(t, "feeds", "update")
	requireCode(t, code, exitOK, out, errOut)
	requireContains(t, out, "CISA KEV catalog: up to date (no changes since the last check)")

	before := e.kev.requests.Load() + e.eol.requests.Load()
	out, errOut, code = e.exec(t, "feeds", "update", "--offline")
	requireCode(t, code, exitOK, out, errOut)
	requireContains(t, out, "CISA KEV catalog: not checked (offline). Saved copy: 19 entries")
	if after := e.kev.requests.Load() + e.eol.requests.Load(); after != before {
		t.Errorf("--offline made %d requests", after-before)
	}
}

func TestFeedsUpdateSourceDownUsesSavedCopy(t *testing.T) {
	e := newTestEnv(t)
	e.exec(t, "feeds", "update")

	e.setDown(http.StatusServiceUnavailable)
	e.clock = e.clock.Add(3 * time.Hour)
	out, errOut, code := e.exec(t, "feeds", "update")
	requireCode(t, code, exitStale, out, errOut)
	requireContains(t, errOut,
		"Warning: CISA KEV catalog could not be updated, so Patchtacio is using the saved copy last checked 1 Oct 2026 09:00 UTC (3 hours ago).",
		"Reason: CISA:",
		"503",
		"Warning: endoflife.date could not be updated")
	if strings.Contains(out+errOut, "all clear") {
		t.Error("never say all clear")
	}

	// Two days later, still down: the KEV copy is now stale (48h), EOL is not (7 days).
	e.clock = e.clock.Add(48 * time.Hour)
	out, errOut, code = e.exec(t, "feeds", "update")
	requireCode(t, code, exitStale, out, errOut)
	requireContains(t, errOut, "Warning: CISA KEV catalog data is out of date because it has not been checked for more than 2 days. "+
		"Last checked 1 Oct 2026 09:00 UTC (2 days ago).")
	if strings.Contains(errOut, "endoflife.date data is out of date") {
		t.Errorf("endoflife.date is within its 7-day threshold:\n%s", errOut)
	}

	out, errOut, code = e.exec(t, "feeds", "status")
	requireCode(t, code, exitStale, out, errOut)
	requireContains(t, out, "CISA KEV catalog  out of date", "endoflife.date    up to date")
	// endoflife.date is within its limit, but status must not hide that the last attempt failed.
	requireContains(t, errOut, "Note: the last update attempt for endoflife.date", "503")
}

func TestFeedsRejectedDataIsOutOfDate(t *testing.T) {
	e := newTestEnv(t)
	e.exec(t, "feeds", "update")

	// endoflife.date starts answering with something that is not valid data.
	e.eol.body = []byte(`<!DOCTYPE html><html>Something went wrong</html>`)
	e.eol.failWith.Store(0)
	e.clock = e.clock.Add(time.Hour)
	// Make the conditional request miss so the bad body is actually served.
	e.eol.etagOverride.Store(true)

	out, errOut, code := e.exec(t, "feeds", "update")
	requireCode(t, code, exitStale, out, errOut)
	requireContains(t, errOut, "endoflife.date could not be updated", "rejected new data")

	out, errOut, code = e.exec(t, "feeds", "status")
	requireCode(t, code, exitStale, out, errOut)
	requireContains(t, out, "endoflife.date    out of date")
	requireContains(t, errOut, "the newest download was rejected")
}

func TestFeedsAcceptShrink(t *testing.T) {
	e := newTestEnv(t)
	e.exec(t, "feeds", "update")

	// endoflife.date now publishes a valid but much smaller dataset.
	e.eol.body = []byte(`{"schema_version":"1.2.1","generated_at":"2026-10-01T12:00:00+00:00","total":1,"result":[
	 {"name":"acme-os","label":"Acme OS","category":"os","links":{"html":"https://endoflife.date/acme-os"},
	  "releases":[{"name":"2","label":"2","releaseDate":"2024-01-01","isEol":false,"eolFrom":null}]}]}`)
	e.eol.etagOverride.Store(true)
	e.clock = e.clock.Add(time.Hour)

	out, errOut, code := e.exec(t, "feeds", "update")
	requireCode(t, code, exitStale, out, errOut)
	requireContains(t, errOut, "far fewer entries", "patchtacio feeds update --accept-shrink eol")

	out, errOut, code = e.exec(t, "feeds", "update", "--accept-shrink", "eol")
	requireCode(t, code, exitOK, out, errOut)
	requireContains(t, out, "endoflife.date: updated. 1 products")
	requireContains(t, errOut, "accepted a smaller endoflife.date dataset as you asked with --accept-shrink: 9 -> 1 products")

	out, errOut, code = e.exec(t, "feeds", "update", "--accept-shrink", "kve")
	requireCode(t, code, exitToolError, out, errOut)
	requireContains(t, errOut, `unknown source "kve"`, "kev, eol")
}

func TestCleanStripsControlCharacters(t *testing.T) {
	in := "2026.09.30\x1b]0;pwned\x07\x1b[31m red"
	if got := clean(in); strings.ContainsAny(got, "\x1b\x07") {
		t.Errorf("clean(%q) = %q", in, got)
	}
	long := strings.Repeat("é", 400)
	if got := firstLine(long); !utf8.ValidString(got) {
		t.Errorf("firstLine split a character: %q", got)
	}
}

func TestFeedsMirrorFallback(t *testing.T) {
	e := newTestEnv(t)
	e.kev.failWith.Store(http.StatusForbidden)
	e.mirror.failWith.Store(0)

	out, errOut, code := e.exec(t, "feeds", "update")
	requireCode(t, code, exitOK, out, errOut)
	requireContains(t, out, "19 entries, catalog 2026.09.30, published 30 Sep 2026, via GitHub mirror")
	requireContains(t, errOut, "downloaded from its official GitHub mirror")
}

func TestFeedsNoDataAnywhere(t *testing.T) {
	e := newTestEnv(t)

	out, errOut, code := e.exec(t, "feeds", "update", "--offline")
	requireCode(t, code, exitToolError, out, errOut)
	requireContains(t, errOut, "there is no saved copy of CISA KEV catalog", "there is no saved copy of endoflife.date")

	e.setDown(http.StatusServiceUnavailable)
	out, errOut, code = e.exec(t, "feeds", "update")
	requireCode(t, code, exitToolError, out, errOut)
	requireContains(t, errOut, "CISA KEV catalog could not be downloaded and there is no saved copy", "HTTPS_PROXY")

	out, errOut, code = e.exec(t, "feeds", "status", "--json")
	requireCode(t, code, exitToolError, out, errOut)
	var sts []feeds.Status
	if err := json.Unmarshal([]byte(out), &sts); err != nil {
		t.Fatalf("status --json is not JSON: %v\n%s", err, out)
	}
	if len(sts) != 2 || sts[0].State != feeds.Missing || sts[0].LastError == "" {
		t.Errorf("unexpected status: %+v", sts)
	}
}

func TestFeedsQuietStillWarns(t *testing.T) {
	e := newTestEnv(t)
	out, errOut, code := e.exec(t, "--quiet", "feeds", "update")
	requireCode(t, code, exitOK, out, errOut)
	if out != "" {
		t.Errorf("--quiet printed success output: %q", out)
	}

	e.setDown(http.StatusServiceUnavailable)
	e.clock = e.clock.Add(72 * time.Hour)
	_, errOut, code = e.exec(t, "--quiet", "feeds", "update")
	requireCode(t, code, exitStale, "", errOut)
	requireContains(t, errOut, "CISA KEV catalog data is out of date")
}

func TestFeedsStatusJSON(t *testing.T) {
	e := newTestEnv(t)
	e.exec(t, "feeds", "update")
	out, errOut, code := e.exec(t, "feeds", "status", "--json")
	requireCode(t, code, exitOK, out, errOut)
	var sts []feeds.Status
	if err := json.Unmarshal([]byte(out), &sts); err != nil {
		t.Fatal(err)
	}
	if sts[0].Name != "kev" || sts[0].State != feeds.Fresh || sts[0].Count != 19 || sts[0].Version != "2026.09.30" {
		t.Errorf("unexpected: %+v", sts[0])
	}
}

func TestHelpers(t *testing.T) {
	if got := thousands(1730); got != "1,730" {
		t.Errorf("thousands = %q", got)
	}
	if got := thousands(1234567); got != "1,234,567" {
		t.Errorf("thousands = %q", got)
	}
	for d, want := range map[time.Duration]string{
		10 * time.Second: "just now",
		time.Minute:      "1 minute ago",
		47 * time.Hour:   "47 hours ago",
		72 * time.Hour:   "3 days ago",
	} {
		if got := age(d); got != want {
			t.Errorf("age(%v) = %q, want %q", d, got, want)
		}
	}
	if worse(exitStale, exitToolError) != exitToolError || worse(exitToolError, exitStale) != exitToolError || worse(exitOK, exitStale) != exitStale {
		t.Error("worse ranks missing > stale > ok")
	}
}
