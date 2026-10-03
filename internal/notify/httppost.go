package notify

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/milliebillie/patchtacio/internal/config"
	"github.com/milliebillie/patchtacio/internal/logging"
	"github.com/milliebillie/patchtacio/internal/version"
)

// poster sends one HTTP POST to a URL that is itself a secret (a webhook or
// ntfy topic URL). It never follows redirects, so the request and its token
// cannot be bounced elsewhere, and its errors never contain the URL.
type poster struct {
	client *http.Client
	// maxWait caps how long a 429's Retry-After is honored.
	maxWait time.Duration
}

func newPoster() *poster {
	return &poster{
		client: &http.Client{
			Timeout: 30 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		maxWait: 30 * time.Second,
	}
}

// checkURL accepts https URLs, and http only for this computer (a local
// ntfy server, or a test).
func checkURL(raw, envName string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("%s is not a valid URL", envName)
	}
	switch {
	case u.Scheme == "https":
	case u.Scheme == "http" && config.IsLoopback(u.Hostname()):
	default:
		return nil, fmt.Errorf("%s must be an https:// URL (http:// only for a server on this computer, as http://127.0.0.1)", envName)
	}
	if u.User != nil {
		return nil, fmt.Errorf("%s must not contain a user name or password; use the token variable instead", envName)
	}
	return u, nil
}

// post sends body and returns an error unless the server answers 2xx. A 429
// is retried once after Retry-After (capped); nothing else is retried, since
// the server may have posted the message already.
func (p *poster) post(ctx context.Context, u *url.URL, header http.Header, body []byte) error {
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
		if err != nil {
			return errors.New("could not build the request")
		}
		maps.Copy(req.Header, header)
		req.Header.Set("User-Agent", version.UserAgent())
		resp, err := p.client.Do(req)
		if err != nil {
			return fmt.Errorf("could not reach %s: %s", u.Hostname(), describe(err))
		}
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		_ = resp.Body.Close()
		switch {
		case resp.StatusCode >= 200 && resp.StatusCode < 300:
			return nil
		case resp.StatusCode == http.StatusTooManyRequests && attempt == 0:
			wait := retryAfter(resp.Header.Get("Retry-After"), p.maxWait)
			t := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				t.Stop()
				return fmt.Errorf("%s asked us to slow down: %w", u.Hostname(), ctx.Err())
			case <-t.C:
			}
			continue
		case resp.StatusCode >= 300 && resp.StatusCode < 400:
			return fmt.Errorf("%s answered with a redirect (HTTP %d), which Patchtacio does not follow for a secret URL; check the URL", u.Hostname(), resp.StatusCode)
		default:
			msg := strings.Join(strings.Fields(scrub(logging.Clean(string(snippet)), u, header)), " ")
			if len(msg) > 200 {
				msg = msg[:200] + "…"
			}
			if msg != "" {
				msg = ": " + msg
			}
			return fmt.Errorf("%s answered HTTP %d%s", u.Hostname(), resp.StatusCode, msg)
		}
	}
}

// scrub removes the secret parts of the request (the URL's path and query,
// which carry webhook tokens and ntfy topics, and any bearer token) from
// text a server sent back, in case it echoed them.
func scrub(s string, u *url.URL, header http.Header) string {
	s = logging.RedactString(s)
	secrets := []string{u.RawQuery, strings.TrimPrefix(header.Get("Authorization"), "Bearer ")}
	if p := strings.Trim(u.Path, "/"); p != "" {
		secrets = append(secrets, p)
		for part := range strings.SplitSeq(p, "/") {
			secrets = append(secrets, part)
		}
	}
	for _, sec := range secrets {
		if len(sec) >= 4 {
			s = strings.ReplaceAll(s, sec, logging.Redacted)
		}
	}
	return s
}

// describe returns a network error without the URL that *url.Error carries.
func describe(err error) string {
	if ue, ok := errors.AsType[*url.Error](err); ok {
		err = ue.Err
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timed out"
	}
	return logging.RedactString(err.Error())
}

func retryAfter(v string, limit time.Duration) time.Duration {
	if s, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && s >= 0 {
		return min(time.Duration(s)*time.Second, limit)
	}
	if t, err := http.ParseTime(v); err == nil {
		return min(max(time.Until(t), 0), limit)
	}
	return min(2*time.Second, limit)
}
