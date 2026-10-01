// Package feeds downloads, validates, caches and reports on Patchtacio's data
// sources. Each source lives in its own sub-package (kev, eol, ...) and only
// fetches and parses; this package owns everything else:
//
//   - conditional requests from the cached copy's validators;
//   - validation before a new copy may replace the cached one;
//   - atomic cache writes plus metadata in internal/store;
//   - honest freshness: Fresh, Stale or Missing, never an empty "all clear";
//   - one update at a time across processes.
//
// See docs/decisions/0001-m1-data-layer.md for the reasoning.
package feeds

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"

	"github.com/milliebillie/patchtacio/internal/httpcache"
)

// Where a cached copy came from.
const (
	ViaPrimary = "primary"
	ViaMirror  = "mirror"
)

// Source is one data source. Implementations must not cache, store or decide
// freshness; the Updater does that.
type Source interface {
	// Name is a short stable ID ("kev", "eol"), used for the cache file name.
	Name() string
	// Title is the human name used in CLI output ("CISA KEV catalog").
	Title() string
	// StaleAfter is how long after the last successful contact the cached
	// copy counts as stale.
	StaleAfter() time.Duration
	// Fetch downloads the feed, trying mirrors itself if it has any. prev holds
	// the cached copy's validators (empty if there is no cache).
	Fetch(ctx context.Context, c *httpcache.Client, prev httpcache.Validators) (*Fetched, error)
	// Parse checks the raw bytes are a complete, well-formed feed and
	// summarises them. It must reject truncated bodies, HTML error pages and
	// internally inconsistent data.
	Parse(raw []byte) (Summary, error)
}

// Fetched is a successful download (possibly "not modified").
type Fetched struct {
	*httpcache.Response
	Via string // ViaPrimary or ViaMirror
}

// Summary describes a parsed feed.
type Summary struct {
	Count       int       // number of records
	Version     string    // the feed's own version label, if it has one
	PublishedAt time.Time // the feed's own release time, if it has one
}

// MaxShrink is the largest drop in record count accepted from one update to
// the next. Feeds like KEV almost never remove entries, so a large drop
// means a broken or truncated response, not real data.
const MaxShrink = 0.10

// ErrRejected marks a download that was refused before it could replace the
// cached copy.
var ErrRejected = errors.New("rejected new data")

// ErrShrunk marks a rejection caused only by the record count falling more
// than MaxShrink. It always comes wrapped together with ErrRejected.
var ErrShrunk = errors.New("record count fell too far")

// Validate applies the checks every source shares. prev is nil on first fetch,
// when only structural checks apply.
func Validate(prev *Summary, next Summary) error { return validateFor(prev, next, false) }

// validateFor is Validate, optionally skipping the shrink check (and only
// that check) for a reduction the user confirmed with --accept-shrink.
func validateFor(prev *Summary, next Summary, acceptShrink bool) error {
	if next.Count < 1 {
		return fmt.Errorf("%w: it has no records", ErrRejected)
	}
	if prev == nil {
		return nil
	}
	if !acceptShrink && prev.Count > 0 && float64(prev.Count-next.Count) > MaxShrink*float64(prev.Count) {
		return fmt.Errorf("%w: %w: from %d to %d (more than %.0f%%)",
			ErrRejected, ErrShrunk, prev.Count, next.Count, MaxShrink*100)
	}
	if !prev.PublishedAt.IsZero() && !next.PublishedAt.IsZero() && next.PublishedAt.Before(prev.PublishedAt) {
		return fmt.Errorf("%w: it is older (published %s) than the cached copy (published %s)",
			ErrRejected, next.PublishedAt.UTC().Format(time.RFC3339), prev.PublishedAt.UTC().Format(time.RFC3339))
	}
	return nil
}

// JoinFirst joins at most n errors and says how many more there were, so one
// broken document cannot produce an unbounded error message.
func JoinFirst(errs []error, n int) error {
	if len(errs) <= n {
		return errors.Join(errs...)
	}
	return errors.Join(append(slices.Clone(errs[:n]), fmt.Errorf("and %d more", len(errs)-n))...)
}

var validName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

func checkSources(srcs []Source) error {
	seen := map[string]bool{}
	for _, s := range srcs {
		if !validName.MatchString(s.Name()) {
			return fmt.Errorf("invalid source name %q", s.Name())
		}
		if seen[s.Name()] {
			return fmt.Errorf("duplicate source %q", s.Name())
		}
		seen[s.Name()] = true
	}
	return nil
}
