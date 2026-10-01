// Package kev reads the CISA Known Exploited Vulnerabilities (KEV) catalog.
//
// Source: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
// JSON:   https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
// Schema: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities_schema.json
// Mirror: https://github.com/cisagov/kev-data (official, synced within minutes)
// License: CC0 1.0.
//
// Notes, checked 2026-10-01:
//   - One JSON document of about 1.7 MB (200 KB gzipped), no pagination or auth.
//   - CISA honors If-Modified-Since (304) but ignores If-None-Match.
//   - Top level: catalogVersion, dateReleased (RFC 3339), count, vulnerabilities.
//   - Records: cveID, vendorProject, product, vulnerabilityName, dateAdded and
//     dueDate (YYYY-MM-DD), shortDescription, requiredAction, and optional
//     knownRansomwareCampaignUse ("Known"/"Unknown"), forensicTriage ("Yes"/"No"),
//     notes (URLs separated by " ; ", sometimes with empty segments), cwes.
//   - vendorProject and product are free text: matching is the catalog's job.
package kev

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

// Default URLs.
const (
	PrimaryURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	MirrorURL  = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"
)

// StaleAfter: CISA adds entries most weekdays, sometimes several times a day.
const StaleAfter = 48 * time.Hour

// Catalog is the normalized KEV catalog.
type Catalog struct {
	Title           string          `json:"title"`
	Version         string          `json:"catalogVersion"`
	Released        time.Time       `json:"dateReleased"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

// Vulnerability is one KEV entry.
type Vulnerability struct {
	CVEID            string     `json:"cveID"`
	VendorProject    string     `json:"vendorProject"`
	Product          string     `json:"product"`
	Name             string     `json:"vulnerabilityName"`
	DateAdded        feeds.Date `json:"dateAdded"`
	DueDate          feeds.Date `json:"dueDate"`
	ShortDescription string     `json:"shortDescription"`
	RequiredAction   string     `json:"requiredAction"`
	KnownRansomware  bool       `json:"knownRansomware"` // true only when CISA says "Known"
	ForensicTriage   bool       `json:"forensicTriage"`  // true only when CISA says "Yes"
	Notes            []string   `json:"notes"`           // non-empty segments, in order (vendor advisory first)
	CWEs             []string   `json:"cwes"`
}

// Source fetches KEV, falling back to the GitHub mirror.
type Source struct {
	PrimaryURL string
	MirrorURL  string // "" disables the fallback
}

// New returns a Source using the default URLs.
func New() *Source { return &Source{PrimaryURL: PrimaryURL, MirrorURL: MirrorURL} }

// Name implements feeds.Source.
func (*Source) Name() string { return "kev" }

// Title implements feeds.Source.
func (*Source) Title() string { return "CISA KEV catalog" }

// StaleAfter implements feeds.Source.
func (*Source) StaleAfter() time.Duration { return StaleAfter }

// Fetch implements feeds.Source. The mirror is tried only when the primary
// fails after its retries, or answers with something that is not a valid
// catalog (such as a bot-challenge page). The Updater separately refuses a
// mirror copy older than the cached one.
func (s *Source) Fetch(ctx context.Context, c *httpcache.Client, prev httpcache.Validators) (*feeds.Fetched, error) {
	resp, err := c.Get(ctx, s.PrimaryURL, prev)
	if err == nil && !resp.NotModified {
		if _, perr := ParseCatalog(resp.Body); perr != nil {
			err = fmt.Errorf("primary returned an invalid catalog: %w", perr)
		}
	}
	if err == nil {
		return &feeds.Fetched{Response: resp, Via: feeds.ViaPrimary}, nil
	}
	if s.MirrorURL == "" || ctx.Err() != nil {
		return nil, err
	}
	c.Log().Warn("CISA did not answer; trying the official GitHub mirror", "err", err)
	mresp, merr := c.Get(ctx, s.MirrorURL, prev)
	if merr != nil {
		return nil, fmt.Errorf("CISA: %w; mirror: %w", err, merr)
	}
	return &feeds.Fetched{Response: mresp, Via: feeds.ViaMirror}, nil
}

// Parse implements feeds.Source.
func (*Source) Parse(raw []byte) (feeds.Summary, error) {
	cat, err := ParseCatalog(raw)
	if err != nil {
		return feeds.Summary{}, err
	}
	return feeds.Summary{Count: len(cat.Vulnerabilities), Version: cat.Version, PublishedAt: cat.Released}, nil
}

type rawCatalog struct {
	Title           string     `json:"title"`
	CatalogVersion  *string    `json:"catalogVersion"`
	DateReleased    *string    `json:"dateReleased"`
	Count           *int       `json:"count"`
	Vulnerabilities *[]rawVuln `json:"vulnerabilities"`
}

type rawVuln struct {
	CVEID                      string   `json:"cveID"`
	VendorProject              string   `json:"vendorProject"`
	Product                    string   `json:"product"`
	VulnerabilityName          string   `json:"vulnerabilityName"`
	DateAdded                  string   `json:"dateAdded"`
	ShortDescription           string   `json:"shortDescription"`
	RequiredAction             string   `json:"requiredAction"`
	DueDate                    string   `json:"dueDate"`
	KnownRansomwareCampaignUse string   `json:"knownRansomwareCampaignUse"`
	ForensicTriage             string   `json:"forensicTriage"`
	Notes                      string   `json:"notes"`
	CWEs                       []string `json:"cwes"`
}

// ParseCatalog parses and checks a KEV JSON document. Dates are parsed
// strictly; unknown fields are ignored. Any malformed entry rejects the whole
// document: silently dropping an entry could hide an exploited product.
func ParseCatalog(raw []byte) (*Catalog, error) {
	var rc rawCatalog
	if err := json.Unmarshal(raw, &rc); err != nil {
		return nil, fmt.Errorf("not a valid KEV JSON document: %w", err)
	}
	var missing []string
	if rc.CatalogVersion == nil || *rc.CatalogVersion == "" {
		missing = append(missing, "catalogVersion")
	}
	if rc.DateReleased == nil {
		missing = append(missing, "dateReleased")
	}
	if rc.Count == nil {
		missing = append(missing, "count")
	}
	if rc.Vulnerabilities == nil {
		missing = append(missing, "vulnerabilities")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("KEV document is missing %s", strings.Join(missing, ", "))
	}
	released, err := time.Parse(time.RFC3339Nano, *rc.DateReleased)
	if err != nil {
		return nil, fmt.Errorf("invalid dateReleased %q: %w", *rc.DateReleased, err)
	}
	vulns := *rc.Vulnerabilities
	if *rc.Count != len(vulns) {
		return nil, fmt.Errorf("KEV says it has %d entries but contains %d (truncated or inconsistent)", *rc.Count, len(vulns))
	}

	cat := &Catalog{
		Title:           rc.Title,
		Version:         *rc.CatalogVersion,
		Released:        released.UTC(),
		Vulnerabilities: make([]Vulnerability, 0, len(vulns)),
	}
	seen := make(map[string]bool, len(vulns))
	var errs []error
	for i, rv := range vulns {
		v, err := normalize(rv)
		if err != nil {
			errs = append(errs, fmt.Errorf("entry %d (%s): %w", i, rv.CVEID, err))
			continue
		}
		if seen[v.CVEID] {
			errs = append(errs, fmt.Errorf("entry %d: duplicate %s", i, v.CVEID))
			continue
		}
		seen[v.CVEID] = true
		cat.Vulnerabilities = append(cat.Vulnerabilities, v)
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf("KEV has %d malformed entries: %w", len(errs), errors.Join(errs...))
	}
	return cat, nil
}

func normalize(rv rawVuln) (Vulnerability, error) {
	if !strings.HasPrefix(rv.CVEID, "CVE-") {
		return Vulnerability{}, fmt.Errorf("invalid cveID %q", rv.CVEID)
	}
	if strings.TrimSpace(rv.VendorProject) == "" || strings.TrimSpace(rv.Product) == "" {
		return Vulnerability{}, errors.New("missing vendorProject or product")
	}
	added, err := feeds.ParseDate(rv.DateAdded)
	if err != nil {
		return Vulnerability{}, fmt.Errorf("dateAdded: %w", err)
	}
	due, err := feeds.ParseDate(rv.DueDate)
	if err != nil {
		return Vulnerability{}, fmt.Errorf("dueDate: %w", err)
	}
	cwes := rv.CWEs
	if cwes == nil {
		cwes = []string{}
	}
	return Vulnerability{
		CVEID:            rv.CVEID,
		VendorProject:    strings.TrimSpace(rv.VendorProject),
		Product:          strings.TrimSpace(rv.Product),
		Name:             rv.VulnerabilityName,
		DateAdded:        added,
		DueDate:          due,
		ShortDescription: rv.ShortDescription,
		RequiredAction:   rv.RequiredAction,
		KnownRansomware:  strings.EqualFold(rv.KnownRansomwareCampaignUse, "Known"),
		ForensicTriage:   strings.EqualFold(rv.ForensicTriage, "Yes"),
		Notes:            splitNotes(rv.Notes),
		CWEs:             cwes,
	}, nil
}

// splitNotes splits KEV's " ; "-separated notes, dropping empty segments.
// A ';' with no whitespace on either side is part of a URL, not a separator.
func splitNotes(s string) []string {
	parts := strings.Split(s, ";")
	var merged []string
	for i, p := range parts {
		if i > 0 && len(merged) > 0 {
			prev := merged[len(merged)-1]
			if prev != "" && p != "" && !endsSpace(prev) && !startsSpace(p) {
				merged[len(merged)-1] = prev + ";" + p
				continue
			}
		}
		merged = append(merged, p)
	}
	out := []string{}
	for _, p := range merged {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func startsSpace(s string) bool { return s != "" && strings.ContainsAny(s[:1], " \t\r\n") }
func endsSpace(s string) bool   { return s != "" && strings.ContainsAny(s[len(s)-1:], " \t\r\n") }
