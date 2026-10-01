package eol

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/milliebillie/patchtacio/internal/httpcache"
	"github.com/milliebillie/patchtacio/internal/testutil"
)

var fixtureDir = filepath.Join("..", "..", "..", "testdata", "feeds", "eol")

func fixture(t *testing.T) []byte {
	return testutil.ReadFile(t, filepath.Join(fixtureDir, "products_full.json"))
}

func TestParseFixtureGolden(t *testing.T) {
	cat, err := ParseCatalog(fixture(t))
	if err != nil {
		t.Fatalf("ParseCatalog: %v", err)
	}
	testutil.Golden(t, filepath.Join(fixtureDir, "golden.json"), cat)

	var releases []Release
	for _, p := range cat.Products {
		releases = append(releases, p.Releases...)
	}
	has := func(pred func(Release) bool) bool { return slices.ContainsFunc(releases, pred) }
	for name, ok := range map[string]bool{
		"LTS":               has(func(r Release) bool { return r.IsLTS != nil && *r.IsLTS }),
		"already EOL":       has(func(r Release) bool { return r.IsEOL != nil && *r.IsEOL && !r.EOLFrom.IsZero() }),
		"no EOL date":       has(func(r Release) bool { return r.EOLFrom.IsZero() }),
		"extended support":  has(func(r Release) bool { return !r.EOESFrom.IsZero() }),
		"extended unstated": has(func(r Release) bool { return r.IsEOES == nil }),
		"discontinued":      has(func(r Release) bool { return r.IsDiscontinued != nil && *r.IsDiscontinued }),
		"windows-server":    slices.ContainsFunc(cat.Products, func(p Product) bool { return p.Name == "windows-server" }),
	} {
		if !ok {
			t.Errorf("fixture has no release covering %q", name)
		}
	}
}

func TestSummary(t *testing.T) {
	sum, err := New().Parse(fixture(t))
	if err != nil {
		t.Fatal(err)
	}
	if sum.Count != 9 || sum.Version != "schema 1.2.1" || sum.PublishedAt.IsZero() {
		t.Errorf("Summary = %+v", sum)
	}
}

const validDoc = `{"schema_version":"1.2.1","generated_at":"2026-10-01T00:08:50+00:00","total":1,"result":[
 {"name":"acme-os","label":"Acme OS","category":"os","aliases":[],"tags":[],"identifiers":[],
  "links":{"html":"https://endoflife.date/acme-os","releasePolicy":null},
  "releases":[{"name":"2","label":"2","releaseDate":"2024-01-01","isLts":false,"ltsFrom":null,
   "isEol":false,"eolFrom":null,"isEoes":null,"latest":null,"futureField":true}]}]}`

func TestParseKeepsUnstatedAsNil(t *testing.T) {
	cat, err := ParseCatalog([]byte(validDoc))
	if err != nil {
		t.Fatalf("ParseCatalog: %v", err)
	}
	r := cat.Products[0].Releases[0]
	if r.IsEOES != nil || r.IsMaintained != nil || r.IsEOAS != nil || r.Latest != nil {
		t.Errorf("unstated fields must stay nil: %+v", r)
	}
	if r.IsEOL == nil || *r.IsEOL || !r.EOLFrom.IsZero() {
		t.Errorf("isEol=false with no date: %+v", r)
	}
}

func TestParseRejects(t *testing.T) {
	tests := map[string]string{
		"html 404 page":   "<!DOCTYPE html><html><title>404</title></html>",
		"truncated":       validDoc[:150],
		"schema 2":        strings.Replace(validDoc, `"1.2.1"`, `"2.0.0"`, 1),
		"total mismatch":  strings.Replace(validDoc, `"total":1`, `"total":478`, 1),
		"no result":       `{"schema_version":"1.2.1","generated_at":"2026-10-01T00:08:50+00:00"}`,
		"bad date":        strings.Replace(validDoc, `"2024-01-01"`, `"2024-13-01"`, 1),
		"release no name": strings.Replace(validDoc, `{"name":"2",`, `{"name":"",`, 1),
	}
	for name, doc := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseCatalog([]byte(doc)); err == nil {
				t.Error("want error")
			}
		})
	}
}

func TestFetchSendsETagVerbatim(t *testing.T) {
	var got string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("If-None-Match")
		w.WriteHeader(http.StatusNotModified)
	}))
	defer srv.Close()
	c := httpcache.New("test", nil)
	c.HTTP.Transport = srv.Client().Transport

	f, err := (&Source{URL: srv.URL}).Fetch(context.Background(), c, httpcache.Validators{ETag: `"8f3c-ssl"`})
	if err != nil || !f.NotModified {
		t.Fatalf("Fetch = %+v, %v", f, err)
	}
	if got != `"8f3c-ssl"` {
		t.Errorf("If-None-Match = %q, want the ETag exactly as received", got)
	}
}
