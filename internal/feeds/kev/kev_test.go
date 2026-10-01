package kev

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/milliebillie/patchtacio/internal/feeds"
	"github.com/milliebillie/patchtacio/internal/httpcache"
	"github.com/milliebillie/patchtacio/internal/testutil"
)

var fixtureDir = filepath.Join("..", "..", "..", "testdata", "feeds", "kev")

func fixture(t *testing.T) []byte {
	return testutil.ReadFile(t, filepath.Join(fixtureDir, "known_exploited_vulnerabilities.json"))
}

func TestParseFixtureGolden(t *testing.T) {
	cat, err := ParseCatalog(fixture(t))
	if err != nil {
		t.Fatalf("ParseCatalog: %v", err)
	}
	testutil.Golden(t, filepath.Join(fixtureDir, "golden.json"), cat)

	// The fixture was chosen to cover these cases; fail loudly if a re-record loses one.
	has := func(pred func(Vulnerability) bool) bool { return slices.ContainsFunc(cat.Vulnerabilities, pred) }
	for name, ok := range map[string]bool{
		"ransomware":      has(func(v Vulnerability) bool { return v.KnownRansomware }),
		"forensic triage": has(func(v Vulnerability) bool { return v.ForensicTriage }),
		"no CWEs":         has(func(v Vulnerability) bool { return len(v.CWEs) == 0 }),
		"non-ASCII": has(func(v Vulnerability) bool {
			return strings.ContainsFunc(v.ShortDescription+strings.Join(v.Notes, ""), func(r rune) bool { return r > 127 })
		}),
	} {
		if !ok {
			t.Errorf("fixture has no entry covering %s", name)
		}
	}
}

func TestSummary(t *testing.T) {
	sum, err := New().Parse(fixture(t))
	if err != nil {
		t.Fatal(err)
	}
	if sum.Count != 19 || sum.Version != "2026.09.30" || sum.PublishedAt.IsZero() {
		t.Errorf("Summary = %+v", sum)
	}
}

const validDoc = `{"title":"t","catalogVersion":"2026.10.01","dateReleased":"2026-10-01T10:00:00.1Z","count":1,
 "vulnerabilities":[{"cveID":"CVE-2026-0001","vendorProject":"Acme","product":"Gateway","vulnerabilityName":"n",
 "dateAdded":"2026-10-01","shortDescription":"d","requiredAction":"a","dueDate":"2026-10-22",
 "knownRansomwareCampaignUse":"Unknown","notes":"","cwes":[],"futureField":{"x":1}}]}`

func TestParseAcceptsUnknownFields(t *testing.T) {
	cat, err := ParseCatalog([]byte(validDoc))
	if err != nil {
		t.Fatalf("ParseCatalog: %v", err)
	}
	v := cat.Vulnerabilities[0]
	if v.DueDate.String() != "2026-10-22" || v.KnownRansomware || v.ForensicTriage || len(v.Notes) != 0 {
		t.Errorf("unexpected %+v", v)
	}
}

func TestParseRejects(t *testing.T) {
	tests := map[string]string{
		"html page":          "<html><body>Access Denied</body></html>",
		"truncated":          validDoc[:200],
		"count mismatch":     strings.Replace(validDoc, `"count":1`, `"count":2`, 1),
		"no version":         strings.Replace(validDoc, `"catalogVersion":"2026.10.01",`, "", 1),
		"no vulnerabilities": `{"catalogVersion":"x","dateReleased":"2026-10-01T10:00:00Z","count":0}`,
		"bad release time":   strings.Replace(validDoc, "2026-10-01T10:00:00.1Z", "yesterday", 1),
		"US-style due date":  strings.Replace(validDoc, `"dueDate":"2026-10-22"`, `"dueDate":"10/22/2026"`, 1),
		"bad CVE ID":         strings.Replace(validDoc, "CVE-2026-0001", "2026-0001", 1),
		"no product":         strings.Replace(validDoc, `"product":"Gateway"`, `"product":" "`, 1),
	}
	for name, doc := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseCatalog([]byte(doc)); err == nil {
				t.Error("want error")
			}
		})
	}
}

func TestParseRejectsDuplicates(t *testing.T) {
	v := validDoc[strings.Index(validDoc, `{"cveID"`):strings.LastIndex(validDoc, "]")]
	doc := strings.Replace(validDoc, `"count":1`, `"count":2`, 1)
	doc = strings.Replace(doc, v, v+","+v, 1)
	if _, err := ParseCatalog([]byte(doc)); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("want duplicate error, got %v", err)
	}
}

func TestSplitNotes(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{"", []string{}},
		{"https://a.example/x ; ; https://nvd.nist.gov/vuln/detail/CVE-1", []string{"https://a.example/x", "https://nvd.nist.gov/vuln/detail/CVE-1"}},
		{"https://a.example/x;jsessionid=1 ; https://b.example", []string{"https://a.example/x;jsessionid=1", "https://b.example"}},
		{"https://a.example ; ", []string{"https://a.example"}},
		{"BOD 26-04: https://cisa.gov/bod ; Forensics: https://cisa.gov/f", []string{"BOD 26-04: https://cisa.gov/bod", "Forensics: https://cisa.gov/f"}},
	}
	for _, tt := range tests {
		if got := splitNotes(tt.in); !slices.Equal(got, tt.want) {
			t.Errorf("splitNotes(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// servers returns a primary and a mirror TLS server with the given handlers,
// and a client that trusts both.
func servers(t *testing.T, primary, mirror http.HandlerFunc) (*Source, *httpcache.Client) {
	t.Helper()
	p := httptest.NewTLSServer(primary)
	m := httptest.NewTLSServer(mirror)
	t.Cleanup(p.Close)
	t.Cleanup(m.Close)
	c := httpcache.New("test", nil)
	// Both test servers share httptest's certificate, so one transport trusts both.
	c.HTTP.Transport = p.Client().Transport
	return &Source{PrimaryURL: p.URL + "/kev.json", MirrorURL: m.URL + "/kev.json"}, c
}

func serve(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(body)) }
}

func status(code int) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(code) }
}

func TestFetchPrimary(t *testing.T) {
	var mirrorHits atomic.Int32
	src, c := servers(t, serve(validDoc), func(w http.ResponseWriter, _ *http.Request) { mirrorHits.Add(1) })
	f, err := src.Fetch(context.Background(), c, httpcache.Validators{})
	if err != nil || f.Via != feeds.ViaPrimary || mirrorHits.Load() != 0 {
		t.Fatalf("Fetch = %+v, %v; mirror hits %d", f, err, mirrorHits.Load())
	}
}

func TestFetchNotModifiedSkipsMirror(t *testing.T) {
	var mirrorHits atomic.Int32
	var gotIMS string
	src, c := servers(t, func(w http.ResponseWriter, r *http.Request) {
		gotIMS = r.Header.Get("If-Modified-Since")
		w.WriteHeader(http.StatusNotModified)
	}, func(w http.ResponseWriter, _ *http.Request) { mirrorHits.Add(1) })
	f, err := src.Fetch(context.Background(), c, httpcache.Validators{LastModified: "Wed, 30 Sep 2026 16:59:23 GMT"})
	if err != nil || !f.NotModified || mirrorHits.Load() != 0 || gotIMS == "" {
		t.Fatalf("Fetch = %+v, %v; mirror hits %d; If-Modified-Since %q", f, err, mirrorHits.Load(), gotIMS)
	}
}

func TestFetchFallsBackToMirror(t *testing.T) {
	tests := map[string]http.HandlerFunc{
		"forbidden":      status(http.StatusForbidden),
		"challenge page": serve("<html>Please enable JavaScript</html>"),
	}
	for name, primary := range tests {
		t.Run(name, func(t *testing.T) {
			src, c := servers(t, primary, serve(validDoc))
			f, err := src.Fetch(context.Background(), c, httpcache.Validators{})
			if err != nil || f.Via != feeds.ViaMirror || string(f.Body) != validDoc {
				t.Fatalf("Fetch = %+v, %v", f, err)
			}
		})
	}
}

func TestFetchBothFail(t *testing.T) {
	src, c := servers(t, status(http.StatusForbidden), status(http.StatusNotFound))
	_, err := src.Fetch(context.Background(), c, httpcache.Validators{})
	if err == nil || !strings.Contains(err.Error(), "CISA") || !strings.Contains(err.Error(), "mirror") {
		t.Fatalf("want an error naming both sources, got %v", err)
	}
}

func TestFetchInvalidPrimaryAndMirrorDownIsRejection(t *testing.T) {
	src, c := servers(t, serve(`{"catalogVersion":"x"}`), status(http.StatusNotFound))
	_, err := src.Fetch(context.Background(), c, httpcache.Validators{})
	if !errors.Is(err, feeds.ErrRejected) {
		t.Fatalf("want ErrRejected, got %v", err)
	}
}

func TestFetchMirrorGetsNoValidators(t *testing.T) {
	var got http.Header
	src, c := servers(t, status(http.StatusForbidden), func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		_, _ = w.Write([]byte(validDoc))
	})
	if _, err := src.Fetch(context.Background(), c, httpcache.Validators{ETag: `"cisa"`, LastModified: "Wed, 30 Sep 2026 16:59:23 GMT"}); err != nil {
		t.Fatal(err)
	}
	if got.Get("If-None-Match") != "" || got.Get("If-Modified-Since") != "" {
		t.Errorf("CISA validators sent to the mirror: %v", got)
	}
}

func TestFetchWithoutMirror(t *testing.T) {
	src, c := servers(t, status(http.StatusForbidden), serve(validDoc))
	src.MirrorURL = ""
	if _, err := src.Fetch(context.Background(), c, httpcache.Validators{}); err == nil {
		t.Fatal("want error when the mirror is disabled")
	}
}
