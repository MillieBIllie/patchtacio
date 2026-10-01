//go:build integration

package kev

import (
	"context"
	"testing"
	"time"

	"github.com/milliebillie/patchtacio/internal/httpcache"
	"github.com/milliebillie/patchtacio/internal/version"
)

// TestLive fetches the real catalog from CISA and from the GitHub mirror and
// checks they still parse. It runs weekly in CI to catch format changes.
//
//	go test -tags integration ./internal/feeds/...
func TestLive(t *testing.T) {
	c := httpcache.New(version.UserAgent(), nil)
	for name, url := range map[string]string{"cisa": PrimaryURL, "mirror": MirrorURL} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()
			resp, err := c.Get(ctx, url, httpcache.Validators{})
			if err != nil {
				t.Fatalf("fetch: %v", err)
			}
			cat, err := ParseCatalog(resp.Body)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if len(cat.Vulnerabilities) < 1 || cat.Version == "" {
				t.Fatalf("implausible catalog: version %q, %d entries", cat.Version, len(cat.Vulnerabilities))
			}
			if age := time.Since(cat.Released); age > 30*24*time.Hour {
				t.Errorf("catalog released %s ago; is the feed still maintained?", age.Round(time.Hour))
			}
			t.Logf("%s: catalog %s, %d entries, Last-Modified %q, ETag %q",
				name, cat.Version, len(cat.Vulnerabilities), resp.LastModified, resp.ETag)
		})
	}
}
