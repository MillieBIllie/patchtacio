//go:build integration

package eol

import (
	"context"
	"testing"
	"time"

	"github.com/milliebillie/patchtacio/internal/httpcache"
	"github.com/milliebillie/patchtacio/internal/version"
)

// TestLive fetches the real bulk endpoint and checks it still parses, then
// that a conditional request with its ETag is answered with 304.
//
//	go test -tags integration ./internal/feeds/...
func TestLive(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	c := httpcache.New(version.UserAgent(), nil)

	resp, err := c.Get(ctx, ProductsFullURL, httpcache.Validators{})
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	cat, err := ParseCatalog(resp.Body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(cat.Products) < 1 {
		t.Fatal("no products")
	}
	t.Logf("schema %s, %d products, generated %s, ETag %q",
		cat.SchemaVersion, len(cat.Products), cat.GeneratedAt.Format(time.RFC3339), resp.ETag)

	if resp.ETag == "" {
		t.Skip("no ETag returned; conditional request check skipped")
	}
	again, err := c.Get(ctx, ProductsFullURL, httpcache.Validators{ETag: resp.ETag})
	if err != nil {
		t.Fatalf("conditional fetch: %v", err)
	}
	if !again.NotModified {
		t.Errorf("If-None-Match with the ETag just received did not return 304; caching would not work")
	}
}
