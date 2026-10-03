package match

import (
	"strings"
	"time"

	"github.com/milliebillie/patchtacio/internal/catalog"
	"github.com/milliebillie/patchtacio/internal/feeds/eol"
)

// EOLWarnDays is how far ahead an end-of-life date becomes a finding.
const EOLWarnDays = 90

// EOLState says what is known about one product's end of life.
type EOLState string

// EOL states. Ended and Ending are findings; the rest say why there is none,
// so a missing answer is never shown as "supported".
const (
	EOLEnded      EOLState = "ended"       // security support has ended
	EOLEnding     EOLState = "ending"      // ends within EOLWarnDays
	EOLSupported  EOLState = "supported"   // ends later, or no end date announced
	EOLNoVersion  EOLState = "no-version"  // the user gave no version
	EOLNoMatch    EOLState = "no-match"    // the version matches no release on endoflife.date
	EOLNoData     EOLState = "no-data"     // the catalog's slug is not in the saved data
	EOLNotTracked EOLState = "not-tracked" // endoflife.date does not track this product
)

// IsFinding reports whether the state should be alerted.
func (s EOLState) IsFinding() bool { return s == EOLEnded || s == EOLEnding }

// Ticked is a product the user runs, with the version they gave.
type Ticked struct {
	ID      string
	Version string
}

// EOLStatus is one product's end-of-life answer.
type EOLStatus struct {
	Product   catalog.Product
	Version   string
	State     EOLState
	Release   *eol.Release // the matching release, if any
	Successor *eol.Release // newest supported release listed, if any
	Page      string       // the product's endoflife.date page
	Policy    string       // the vendor's lifecycle page, if listed
	Releases  []string     // release names, newest first (for "no-match" hints)
}

// EOL works out end of life for each ticked product from endoflife.date data
// (ec may be nil when there is none). A version matches a release only
// exactly ("2022", or "2012 R2" for "2012-r2") or as a dotted prefix
// ("7.2.8" is release "7.2", never "7.20"; the longest match wins). Nothing
// is guessed: no match is reported as such.
func EOL(cat *catalog.Catalog, ec *eol.Catalog, ticked []Ticked, today time.Time) []EOLStatus {
	byName := map[string]*eol.Product{}
	if ec != nil {
		for i := range ec.Products {
			byName[ec.Products[i].Name] = &ec.Products[i]
		}
	}
	var out []EOLStatus
	for _, t := range ticked {
		cp, ok := cat.Get(t.ID)
		if !ok {
			continue
		}
		st := EOLStatus{Product: cp, Version: strings.TrimSpace(t.Version)}
		ep := byName[cp.EOLSlug]
		switch {
		case cp.EOLSlug == "":
			st.State = EOLNotTracked
		case ep == nil:
			st.State = EOLNoData
		default:
			st.Page, st.Policy = ep.Link, ep.ReleasePolicy
			for _, r := range ep.Releases {
				st.Releases = append(st.Releases, r.Name)
			}
			switch r := matchRelease(ep.Releases, st.Version); {
			case st.Version == "":
				st.State = EOLNoVersion
			case r == nil:
				st.State = EOLNoMatch
			default:
				st.Release = r
				st.State = releaseState(r, today)
				st.Successor = successor(ep.Releases, r, today)
			}
		}
		out = append(out, st)
	}
	return out
}

func matchRelease(rs []eol.Release, version string) *eol.Release {
	// "2012 R2" is written "2012-r2" on endoflife.date: spaces become
	// hyphens. That is spelling, not guessing; nothing else is loosened.
	v := strings.TrimPrefix(strings.ToLower(strings.Join(strings.Fields(version), "-")), "v")
	if v == "" {
		return nil
	}
	var best *eol.Release
	for i := range rs {
		name := strings.ToLower(rs[i].Name)
		if name == "" || (v != name && !strings.HasPrefix(v, name+".")) {
			continue
		}
		if best == nil || len(name) > len(best.Name) {
			best = &rs[i]
		}
	}
	return best
}

// releaseState trusts an explicit isEol, then the date. A date in the past
// counts as ended even if the flag lags behind.
func releaseState(r *eol.Release, today time.Time) EOLState {
	switch {
	case r.IsEOL != nil && *r.IsEOL:
		return EOLEnded
	case r.EOLFrom.IsZero():
		return EOLSupported
	case r.EOLFrom.Before(today):
		return EOLEnded
	case !r.EOLFrom.After(today.AddDate(0, 0, EOLWarnDays)):
		return EOLEnding
	default:
		return EOLSupported
	}
}

// successor is the newest listed release that is still supported and is not
// cur itself; endoflife.date lists releases newest first.
func successor(rs []eol.Release, cur *eol.Release, today time.Time) *eol.Release {
	for i := range rs {
		r := &rs[i]
		if r.Name == cur.Name {
			return nil // nothing newer is supported
		}
		if releaseState(r, today) == EOLSupported || releaseState(r, today) == EOLEnding {
			if !r.ReleaseDate.IsZero() && !cur.ReleaseDate.IsZero() && r.ReleaseDate.Before(cur.ReleaseDate.Time) {
				continue
			}
			return r
		}
	}
	return nil
}
