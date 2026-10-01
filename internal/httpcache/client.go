// Package httpcache is the one HTTP client every feed adapter uses. It makes
// Patchtacio a polite client (CLAUDE.md rule 2):
//
//   - an identifying User-Agent;
//   - a timeout per attempt and an overall deadline per call;
//   - retries with exponential backoff and jitter on network errors, 5xx and
//     429, honoring Retry-After (capped); other 4xx are never retried;
//   - conditional requests (If-None-Match / If-Modified-Since), with 304
//     reported as success;
//   - HTTPS only, including redirects (at most 5);
//   - a hard cap on the (decompressed) body size.
//
// It deals with HTTP only. Storing responses and deciding what is stale is the
// job of internal/feeds and internal/store.
package httpcache

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// Defaults agreed in docs/decisions/0001-m1-data-layer.md.
const (
	DefaultAttemptTimeout = 30 * time.Second
	DefaultTotalTimeout   = 2 * time.Minute
	DefaultMaxRetries     = 3
	DefaultMaxRetryAfter  = 60 * time.Second
	DefaultBaseBackoff    = time.Second
	DefaultMaxBytes       = 32 << 20
	maxRedirects          = 5
)

// ErrTooLarge is returned when a response body exceeds Client.MaxBytes.
var ErrTooLarge = errors.New("response body too large")

// ErrInsecureURL is returned for a non-HTTPS URL or redirect.
var ErrInsecureURL = errors.New("refusing non-HTTPS URL")

// StatusError is an HTTP status the client will not retry or has given up on.
type StatusError struct {
	Code int
	URL  string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("GET %s: HTTP %d %s", e.URL, e.Code, http.StatusText(e.Code))
}

// Validators are the cache validators from a previous response.
type Validators struct {
	ETag         string
	LastModified string
}

// Response is a successful fetch: either new content or "not modified".
type Response struct {
	NotModified  bool
	Body         []byte // nil when NotModified
	ETag         string
	LastModified string
	URL          string // final URL after redirects
	Attempts     int
}

// Client is safe for concurrent use. Zero-valued limit fields fall back to the
// defaults above.
type Client struct {
	HTTP           *http.Client
	UserAgent      string
	AttemptTimeout time.Duration
	TotalTimeout   time.Duration
	MaxRetries     int
	MaxRetryAfter  time.Duration
	BaseBackoff    time.Duration
	MaxBytes       int64
	Logger         *slog.Logger

	// sleep waits between attempts; tests replace it.
	sleep func(ctx context.Context, d time.Duration) error
}

// New returns a client with the default limits. It honors the standard proxy
// environment variables (HTTPS_PROXY, NO_PROXY), which schools and councils
// often require.
func New(userAgent string, logger *slog.Logger) *Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Client{
		HTTP:      &http.Client{Transport: tr, CheckRedirect: checkRedirect},
		UserAgent: userAgent,
		Logger:    logger,
	}
}

func checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return fmt.Errorf("stopped after %d redirects", maxRedirects)
	}
	if req.URL.Scheme != "https" {
		return fmt.Errorf("redirect to %s: %w", req.URL.Redacted(), ErrInsecureURL)
	}
	return nil
}

// Get fetches rawURL, sending v as conditional request headers.
func (c *Client) Get(ctx context.Context, rawURL string, v Validators) (*Response, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse URL: %w", err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("%s: %w", u.Redacted(), ErrInsecureURL)
	}

	ctx, cancel := context.WithTimeout(ctx, orDefault(c.TotalTimeout, DefaultTotalTimeout))
	defer cancel()

	retries := c.MaxRetries
	if retries == 0 {
		retries = DefaultMaxRetries
	}
	var lastErr error
	for attempt := 0; attempt <= retries; attempt++ {
		if attempt > 0 {
			wait := c.backoff(attempt, lastErr)
			c.Log().Info("retrying", "url", u, "attempt", attempt+1, "wait", wait, "err", lastErr)
			if err := c.wait(ctx, wait); err != nil {
				return nil, fmt.Errorf("GET %s: %w (last error: %w)", u.Redacted(), err, lastErr)
			}
		}
		resp, err := c.attempt(ctx, u, v)
		if err == nil {
			resp.Attempts = attempt + 1
			return resp, nil
		}
		lastErr = err
		if !retryable(err) || ctx.Err() != nil {
			return nil, err
		}
	}
	return nil, fmt.Errorf("giving up after %d attempts: %w", retries+1, lastErr)
}

// retryAfterError carries a server-requested wait from a 429/503.
type retryAfterError struct {
	*StatusError
	after time.Duration
}

func (e *retryAfterError) Unwrap() error { return e.StatusError }

// transientError marks network and read failures worth retrying.
type transientError struct{ err error }

func (e *transientError) Error() string { return e.err.Error() }
func (e *transientError) Unwrap() error { return e.err }

func retryable(err error) bool {
	if _, ok := errors.AsType[*transientError](err); ok {
		return true
	}
	if se, ok := errors.AsType[*StatusError](err); ok {
		return se.Code == http.StatusTooManyRequests || se.Code >= 500
	}
	return false
}

func (c *Client) attempt(ctx context.Context, u *url.URL, v Validators) (*Response, error) {
	actx, cancel := context.WithTimeout(ctx, orDefault(c.AttemptTimeout, DefaultAttemptTimeout))
	defer cancel()

	req, err := http.NewRequestWithContext(actx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", c.UserAgent)
	req.Header.Set("Accept", "application/json")
	if v.ETag != "" {
		req.Header.Set("If-None-Match", v.ETag)
	}
	if v.LastModified != "" {
		req.Header.Set("If-Modified-Since", v.LastModified)
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		// *url.Error repeats the method and URL; we add our own (redacted) prefix.
		if ue, ok := errors.AsType[*url.Error](err); ok {
			err = ue.Err
		}
		if errors.Is(err, ErrInsecureURL) || ctx.Err() != nil {
			return nil, fmt.Errorf("GET %s: %w", u.Redacted(), err)
		}
		return nil, &transientError{fmt.Errorf("GET %s: %w", u.Redacted(), err)}
	}
	defer func() { _ = resp.Body.Close() }()

	final := resp.Request.URL.Redacted()
	switch resp.StatusCode {
	case http.StatusNotModified:
		return &Response{
			NotModified:  true,
			ETag:         firstNonEmpty(resp.Header.Get("ETag"), v.ETag),
			LastModified: firstNonEmpty(resp.Header.Get("Last-Modified"), v.LastModified),
			URL:          final,
		}, nil
	case http.StatusOK:
	default:
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10)) // allow connection reuse
		se := &StatusError{Code: resp.StatusCode, URL: final}
		if d, ok := parseRetryAfter(resp.Header.Get("Retry-After"), time.Now()); ok {
			return nil, &retryAfterError{StatusError: se, after: d}
		}
		return nil, se
	}

	limit := c.MaxBytes
	if limit == 0 {
		limit = DefaultMaxBytes
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, &transientError{fmt.Errorf("read %s: %w", final, err)}
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("GET %s: %w (limit %d bytes)", final, ErrTooLarge, limit)
	}
	return &Response{
		Body:         body,
		ETag:         resp.Header.Get("ETag"),
		LastModified: resp.Header.Get("Last-Modified"),
		URL:          final,
	}, nil
}

// backoff returns the wait before the given retry attempt (1-based).
func (c *Client) backoff(attempt int, lastErr error) time.Duration {
	if ra, ok := errors.AsType[*retryAfterError](lastErr); ok {
		return min(ra.after, orDefault(c.MaxRetryAfter, DefaultMaxRetryAfter))
	}
	base := orDefault(c.BaseBackoff, DefaultBaseBackoff)
	d := base << (attempt - 1)
	// Jitter spreads retries from many installs; it needs no crypto randomness.
	return d + rand.N(d/2+1) //nolint:gosec // G404: jitter, not security-sensitive
}

func (c *Client) wait(ctx context.Context, d time.Duration) error {
	if c.sleep != nil {
		return c.sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// parseRetryAfter accepts delay-seconds or an HTTP date.
func parseRetryAfter(h string, now time.Time) (time.Duration, bool) {
	if h == "" {
		return 0, false
	}
	if secs, err := strconv.Atoi(h); err == nil && secs >= 0 {
		return time.Duration(secs) * time.Second, true
	}
	if t, err := http.ParseTime(h); err == nil {
		return max(t.Sub(now), 0), true
	}
	return 0, false
}

func orDefault(d, def time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return def
}

// Log returns the client's logger, or a discarding one if none was set.
func (c *Client) Log() *slog.Logger {
	if c.Logger != nil {
		return c.Logger
	}
	return slog.New(slog.DiscardHandler)
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
