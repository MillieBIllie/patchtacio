package httpcache

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testUA = "patchtacio/test (+https://github.com/milliebillie/patchtacio)"

// newTestClient returns a client that trusts srv's certificate and records
// waits instead of sleeping.
func newTestClient(t *testing.T, srv *httptest.Server) (*Client, *[]time.Duration) {
	t.Helper()
	c := New(testUA, nil)
	c.HTTP.Transport = srv.Client().Transport
	waits := &[]time.Duration{}
	c.sleep = func(ctx context.Context, d time.Duration) error {
		*waits = append(*waits, d)
		return ctx.Err()
	}
	return c, waits
}

func TestGetOKSendsHeadersAndCapturesValidators(t *testing.T) {
	var got http.Header
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.Header().Set("ETag", `"abc-ssl"`)
		w.Header().Set("Last-Modified", "Wed, 30 Sep 2026 16:59:23 GMT")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	c, _ := newTestClient(t, srv)

	resp, err := c.Get(context.Background(), srv.URL+"/feed.json", Validators{ETag: `"old"`, LastModified: "Tue, 29 Sep 2026 00:00:00 GMT"})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if resp.NotModified || string(resp.Body) != `{"ok":true}` {
		t.Errorf("unexpected response: %+v", resp)
	}
	if resp.ETag != `"abc-ssl"` || resp.LastModified != "Wed, 30 Sep 2026 16:59:23 GMT" {
		t.Errorf("validators not captured verbatim: %+v", resp)
	}
	for k, want := range map[string]string{
		"User-Agent":        testUA,
		"If-None-Match":     `"old"`,
		"If-Modified-Since": "Tue, 29 Sep 2026 00:00:00 GMT",
		"Accept":            "application/json",
	} {
		if got.Get(k) != want {
			t.Errorf("header %s = %q, want %q", k, got.Get(k), want)
		}
	}
}

func TestGetNotModified(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotModified)
	}))
	defer srv.Close()
	c, _ := newTestClient(t, srv)

	resp, err := c.Get(context.Background(), srv.URL, Validators{ETag: `"e1"`, LastModified: "lm"})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !resp.NotModified || resp.Body != nil {
		t.Errorf("want NotModified with no body, got %+v", resp)
	}
	if resp.ETag != `"e1"` || resp.LastModified != "lm" {
		t.Errorf("304 without headers should keep the sent validators, got %+v", resp)
	}
}

func TestGetRetriesThenSucceeds(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if n.Add(1) <= 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	c, waits := newTestClient(t, srv)
	c.BaseBackoff = 100 * time.Millisecond

	resp, err := c.Get(context.Background(), srv.URL, Validators{})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if resp.Attempts != 3 || n.Load() != 3 || len(*waits) != 2 {
		t.Fatalf("attempts=%d requests=%d waits=%v", resp.Attempts, n.Load(), *waits)
	}
	// Exponential with up to 50% jitter: [100ms,150ms] then [200ms,300ms].
	if w := (*waits)[0]; w < 100*time.Millisecond || w > 150*time.Millisecond {
		t.Errorf("first wait %v out of range", w)
	}
	if w := (*waits)[1]; w < 200*time.Millisecond || w > 300*time.Millisecond {
		t.Errorf("second wait %v out of range", w)
	}
}

func TestGetHonorsRetryAfterWithCap(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		switch n.Add(1) {
		case 1:
			w.Header().Set("Retry-After", "7")
			w.WriteHeader(http.StatusTooManyRequests)
		case 2:
			w.Header().Set("Retry-After", "3600")
			w.WriteHeader(http.StatusTooManyRequests)
		default:
			_, _ = w.Write([]byte("ok"))
		}
	}))
	defer srv.Close()
	c, waits := newTestClient(t, srv)

	if _, err := c.Get(context.Background(), srv.URL, Validators{}); err != nil {
		t.Fatalf("Get: %v", err)
	}
	want := []time.Duration{7 * time.Second, DefaultMaxRetryAfter}
	if len(*waits) != 2 || (*waits)[0] != want[0] || (*waits)[1] != want[1] {
		t.Errorf("waits = %v, want %v", *waits, want)
	}
}

func TestGetDoesNotRetryClientErrors(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n.Add(1)
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("<html>not found</html>"))
	}))
	defer srv.Close()
	c, _ := newTestClient(t, srv)

	_, err := c.Get(context.Background(), srv.URL, Validators{})
	se, ok := errors.AsType[*StatusError](err)
	if !ok || se.Code != http.StatusNotFound {
		t.Fatalf("want StatusError 404, got %v", err)
	}
	if n.Load() != 1 {
		t.Errorf("404 was retried: %d requests", n.Load())
	}
}

func TestGetGivesUp(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()
	c, _ := newTestClient(t, srv)

	_, err := c.Get(context.Background(), srv.URL, Validators{})
	if err == nil || !strings.Contains(err.Error(), "giving up after 4 attempts") {
		t.Fatalf("want give-up error, got %v", err)
	}
	if n.Load() != int32(DefaultMaxRetries+1) {
		t.Errorf("requests = %d, want %d", n.Load(), DefaultMaxRetries+1)
	}
}

func TestGetRetriesNetworkErrors(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if n.Add(1) == 1 {
			hj, ok := w.(http.Hijacker)
			if !ok {
				t.Error("no hijacker")
				return
			}
			conn, _, err := hj.Hijack()
			if err == nil {
				_ = conn.Close() // drop the connection mid-request
			}
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	c, _ := newTestClient(t, srv)

	resp, err := c.Get(context.Background(), srv.URL, Validators{})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if resp.Attempts != 2 {
		t.Errorf("attempts = %d, want 2", resp.Attempts)
	}
}

func TestGetBodyTooLarge(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n.Add(1)
		_, _ = w.Write([]byte(strings.Repeat("x", 2048)))
	}))
	defer srv.Close()
	c, _ := newTestClient(t, srv)
	c.MaxBytes = 1024

	_, err := c.Get(context.Background(), srv.URL, Validators{})
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("want ErrTooLarge, got %v", err)
	}
	if n.Load() != 1 {
		t.Errorf("oversized body was retried")
	}
}

func TestGetRefusesPlainHTTP(t *testing.T) {
	c := New(testUA, nil)
	_, err := c.Get(context.Background(), "http://example.com/feed.json", Validators{})
	if !errors.Is(err, ErrInsecureURL) {
		t.Fatalf("want ErrInsecureURL, got %v", err)
	}
}

func TestGetRefusesRedirectToHTTP(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("should not be reached"))
	}))
	defer plain.Close()
	srv := httptest.NewTLSServer(http.RedirectHandler(plain.URL, http.StatusFound))
	defer srv.Close()
	c, _ := newTestClient(t, srv)

	_, err := c.Get(context.Background(), srv.URL, Validators{})
	if !errors.Is(err, ErrInsecureURL) {
		t.Fatalf("want ErrInsecureURL, got %v", err)
	}
}

func TestGetFollowsHTTPSRedirect(t *testing.T) {
	mux := http.NewServeMux()
	mux.Handle("/old", http.RedirectHandler("/new", http.StatusMovedPermanently))
	mux.HandleFunc("/new", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("moved")) })
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	c, _ := newTestClient(t, srv)

	resp, err := c.Get(context.Background(), srv.URL+"/old", Validators{})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(resp.Body) != "moved" || !strings.HasSuffix(resp.URL, "/new") {
		t.Errorf("got body %q url %q", resp.Body, resp.URL)
	}
}

func TestGetStopsOnCancel(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	c, _ := newTestClient(t, srv)
	ctx, cancel := context.WithCancel(context.Background())
	c.sleep = func(context.Context, time.Duration) error { cancel(); return context.Canceled }

	_, err := c.Get(ctx, srv.URL, Validators{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		in   string
		want time.Duration
		ok   bool
	}{
		{"", 0, false},
		{"5", 5 * time.Second, true},
		{"-1", 0, false},
		{"99999999999999999", 24 * time.Hour, true},
		{"Thu, 01 Oct 2026 12:00:30 GMT", 30 * time.Second, true},
		{"Thu, 01 Oct 2026 11:00:00 GMT", 0, true},
		{"soon", 0, false},
	}
	for _, tt := range tests {
		got, ok := parseRetryAfter(tt.in, now)
		if got != tt.want || ok != tt.ok {
			t.Errorf("parseRetryAfter(%q) = %v, %v; want %v, %v", tt.in, got, ok, tt.want, tt.ok)
		}
	}
}
