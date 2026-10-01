// Package eol reads end-of-life data from endoflife.date (API v1).
//
// Source:  https://endoflife.date
// API:     https://endoflife.date/docs/api/v1/ (OpenAPI: /docs/api/v1/openapi.yml)
// License: MIT (the endoflife.date project); keep the notice with copies.
//
// Notes, checked 2026-10-01:
//   - We fetch /api/v1/products/full: every product and release in one
//     request (about 2.8 MB), revalidated with an ETag so most runs get a 304.
//     The spec suggests /products where possible; we have asked the
//     maintainers whether a daily bulk fetch is OK and will switch to
//     per-product requests if they prefer.
//   - Netlify serves it with an ETag (suffixed "-ssl"; send it back verbatim)
//     and no Last-Modified. 429 may carry Retry-After. Renamed products
//     answer 301. A 404 is an HTML page, not JSON.
//   - Envelope: schema_version, generated_at, total, result[].
//   - Releases use explicit flags with optional dates: isEol/eolFrom,
//     isEoas/eoasFrom (end of active support), isEoes/eoesFrom (extended
//     support), isDiscontinued/discontinuedFrom, isLts/ltsFrom, isMaintained,
//     latest{name,date,link}. Dates are YYYY-MM-DD or null. A flag that is
//     absent or null means "not stated", which we keep as nil, never false.
package eol

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/milliebillie/patchtacio/internal/feeds"
	"github.com/milliebillie/patchtacio/internal/httpcache"
)

// ProductsFullURL is the bulk endpoint.
const ProductsFullURL = "https://endoflife.date/api/v1/products/full"

// StaleAfter: end-of-life dates change slowly.
const StaleAfter = 7 * 24 * time.Hour

// supportedSchemaMajor is the API schema major version this parser knows.
const supportedSchemaMajor = "1"

// Catalog is the normalized endoflife.date data.
type Catalog struct {
	SchemaVersion string    `json:"schemaVersion"`
	GeneratedAt   time.Time `json:"generatedAt"`
	Products      []Product `json:"products"`
}

// Product is one endoflife.date product.
type Product struct {
	Name          string       `json:"name"` // the slug the catalog refers to
	Label         string       `json:"label"`
	Category      string       `json:"category"`
	Aliases       []string     `json:"aliases"`
	Tags          []string     `json:"tags"`
	Identifiers   []Identifier `json:"identifiers"`
	Link          string       `json:"link"`          // endoflife.date page
	ReleasePolicy string       `json:"releasePolicy"` // vendor lifecycle page, if listed
	Releases      []Release    `json:"releases"`
}

// Identifier maps a product to an external ID (purl, cpe, repology).
type Identifier struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// Release is one release cycle of a product.
type Release struct {
	Name             string     `json:"name"`
	Codename         string     `json:"codename,omitempty"`
	Label            string     `json:"label"`
	ReleaseDate      feeds.Date `json:"releaseDate"`
	IsLTS            *bool      `json:"isLts"`
	LTSFrom          feeds.Date `json:"ltsFrom"`
	IsEOAS           *bool      `json:"isEoas"` // end of active support reached
	EOASFrom         feeds.Date `json:"eoasFrom"`
	IsEOL            *bool      `json:"isEol"` // end of (security) support reached
	EOLFrom          feeds.Date `json:"eolFrom"`
	IsEOES           *bool      `json:"isEoes"` // end of extended support reached
	EOESFrom         feeds.Date `json:"eoesFrom"`
	IsDiscontinued   *bool      `json:"isDiscontinued"`
	DiscontinuedFrom feeds.Date `json:"discontinuedFrom"`
	IsMaintained     *bool      `json:"isMaintained"`
	Latest           *Latest    `json:"latest"`
}

// Latest is the newest version in a release cycle.
type Latest struct {
	Name string     `json:"name"`
	Date feeds.Date `json:"date"`
	Link string     `json:"link,omitempty"`
}

// Source fetches endoflife.date.
type Source struct {
	URL string
}

// New returns a Source using the default URL.
func New() *Source { return &Source{URL: ProductsFullURL} }

// Name implements feeds.Source.
func (*Source) Name() string { return "eol" }

// Title implements feeds.Source.
func (*Source) Title() string { return "endoflife.date" }

// StaleAfter implements feeds.Source.
func (*Source) StaleAfter() time.Duration { return StaleAfter }

// Fetch implements feeds.Source.
func (s *Source) Fetch(ctx context.Context, c *httpcache.Client, prev httpcache.Validators) (*feeds.Fetched, error) {
	resp, err := c.Get(ctx, s.URL, prev)
	if err != nil {
		return nil, err
	}
	return &feeds.Fetched{Response: resp, Via: feeds.ViaPrimary}, nil
}

// Parse implements feeds.Source.
func (*Source) Parse(raw []byte) (feeds.Summary, error) {
	cat, err := ParseCatalog(raw)
	if err != nil {
		return feeds.Summary{}, err
	}
	return feeds.Summary{Count: len(cat.Products), Version: "schema " + cat.SchemaVersion, PublishedAt: cat.GeneratedAt}, nil
}

type rawEnvelope struct {
	SchemaVersion *string       `json:"schema_version"`
	GeneratedAt   *string       `json:"generated_at"`
	Total         *int          `json:"total"`
	Result        *[]rawProduct `json:"result"`
}

type rawProduct struct {
	Name        string       `json:"name"`
	Aliases     []string     `json:"aliases"`
	Label       string       `json:"label"`
	Category    string       `json:"category"`
	Tags        []string     `json:"tags"`
	Identifiers []Identifier `json:"identifiers"`
	Links       struct {
		HTML          string `json:"html"`
		ReleasePolicy string `json:"releasePolicy"`
	} `json:"links"`
	Releases []rawRelease `json:"releases"`
}

type rawRelease struct {
	Name             string  `json:"name"`
	Codename         *string `json:"codename"`
	Label            string  `json:"label"`
	ReleaseDate      *string `json:"releaseDate"`
	IsLTS            *bool   `json:"isLts"`
	LTSFrom          *string `json:"ltsFrom"`
	IsEOAS           *bool   `json:"isEoas"`
	EOASFrom         *string `json:"eoasFrom"`
	IsEOL            *bool   `json:"isEol"`
	EOLFrom          *string `json:"eolFrom"`
	IsEOES           *bool   `json:"isEoes"`
	EOESFrom         *string `json:"eoesFrom"`
	IsDiscontinued   *bool   `json:"isDiscontinued"`
	DiscontinuedFrom *string `json:"discontinuedFrom"`
	IsMaintained     *bool   `json:"isMaintained"`
	Latest           *struct {
		Name string  `json:"name"`
		Date *string `json:"date"`
		Link *string `json:"link"`
	} `json:"latest"`
}

// ParseCatalog parses and checks a /products/full response. Dates are parsed
// strictly and unknown fields are ignored. A malformed product rejects the
// whole document rather than silently dropping its end-of-life dates.
func ParseCatalog(raw []byte) (*Catalog, error) {
	var env rawEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("not a valid endoflife.date JSON document: %w", err)
	}
	if env.SchemaVersion == nil || env.GeneratedAt == nil || env.Result == nil {
		return nil, errors.New("endoflife.date response is missing schema_version, generated_at or result")
	}
	if major, _, _ := strings.Cut(*env.SchemaVersion, "."); major != supportedSchemaMajor {
		return nil, fmt.Errorf("endoflife.date API schema %s is not supported (need %s.x); update patchtacio", *env.SchemaVersion, supportedSchemaMajor)
	}
	generated, err := time.Parse(time.RFC3339, *env.GeneratedAt)
	if err != nil {
		return nil, fmt.Errorf("invalid generated_at %q: %w", *env.GeneratedAt, err)
	}
	products := *env.Result
	if env.Total != nil && *env.Total != len(products) {
		return nil, fmt.Errorf("endoflife.date says it has %d products but contains %d (truncated or inconsistent)", *env.Total, len(products))
	}

	cat := &Catalog{SchemaVersion: *env.SchemaVersion, GeneratedAt: generated.UTC(), Products: make([]Product, 0, len(products))}
	seen := make(map[string]bool, len(products))
	var errs []error
	for i, rp := range products {
		p, err := normalizeProduct(rp)
		if err != nil {
			errs = append(errs, fmt.Errorf("product %d (%s): %w", i, rp.Name, err))
			continue
		}
		if seen[p.Name] {
			errs = append(errs, fmt.Errorf("product %d: duplicate %s", i, p.Name))
			continue
		}
		seen[p.Name] = true
		cat.Products = append(cat.Products, p)
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf("endoflife.date has %d malformed products: %w", len(errs), errors.Join(errs...))
	}
	return cat, nil
}

func normalizeProduct(rp rawProduct) (Product, error) {
	if rp.Name == "" {
		return Product{}, errors.New("missing name")
	}
	p := Product{
		Name:          rp.Name,
		Label:         rp.Label,
		Category:      rp.Category,
		Aliases:       nonNil(rp.Aliases),
		Tags:          nonNil(rp.Tags),
		Identifiers:   nonNil(rp.Identifiers),
		Link:          rp.Links.HTML,
		ReleasePolicy: rp.Links.ReleasePolicy,
		Releases:      make([]Release, 0, len(rp.Releases)),
	}
	for _, rr := range rp.Releases {
		r, err := normalizeRelease(rr)
		if err != nil {
			return Product{}, fmt.Errorf("release %q: %w", rr.Name, err)
		}
		p.Releases = append(p.Releases, r)
	}
	return p, nil
}

func normalizeRelease(rr rawRelease) (Release, error) {
	if rr.Name == "" {
		return Release{}, errors.New("missing name")
	}
	r := Release{
		Name:           rr.Name,
		Label:          rr.Label,
		IsLTS:          rr.IsLTS,
		IsEOAS:         rr.IsEOAS,
		IsEOL:          rr.IsEOL,
		IsEOES:         rr.IsEOES,
		IsDiscontinued: rr.IsDiscontinued,
		IsMaintained:   rr.IsMaintained,
	}
	if rr.Codename != nil {
		r.Codename = *rr.Codename
	}
	dates := []struct {
		field string
		src   *string
		dst   *feeds.Date
	}{
		{"releaseDate", rr.ReleaseDate, &r.ReleaseDate},
		{"ltsFrom", rr.LTSFrom, &r.LTSFrom},
		{"eoasFrom", rr.EOASFrom, &r.EOASFrom},
		{"eolFrom", rr.EOLFrom, &r.EOLFrom},
		{"eoesFrom", rr.EOESFrom, &r.EOESFrom},
		{"discontinuedFrom", rr.DiscontinuedFrom, &r.DiscontinuedFrom},
	}
	for _, d := range dates {
		v, err := feeds.ParseOptionalDate(d.src)
		if err != nil {
			return Release{}, fmt.Errorf("%s: %w", d.field, err)
		}
		*d.dst = v
	}
	if rr.Latest != nil {
		date, err := feeds.ParseOptionalDate(rr.Latest.Date)
		if err != nil {
			return Release{}, fmt.Errorf("latest.date: %w", err)
		}
		r.Latest = &Latest{Name: rr.Latest.Name, Date: date}
		if rr.Latest.Link != nil {
			r.Latest.Link = *rr.Latest.Link
		}
	}
	return r, nil
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
