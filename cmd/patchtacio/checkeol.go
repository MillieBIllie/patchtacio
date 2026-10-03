package main

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/milliebillie/patchtacio/internal/catalog"
	"github.com/milliebillie/patchtacio/internal/config"
	"github.com/milliebillie/patchtacio/internal/feeds"
	"github.com/milliebillie/patchtacio/internal/match"
	"github.com/milliebillie/patchtacio/internal/store"
)

// eolEntry is one product's end-of-life answer in check's report; its JSON
// form is public.
type eolEntry struct {
	ID              string         `json:"id,omitempty"` // finding ID when ended or ending: eol/<product>/<release>
	ProductID       string         `json:"productId"`
	Product         string         `json:"product"`
	Version         string         `json:"version,omitempty"`
	State           match.EOLState `json:"state"`
	Release         string         `json:"release,omitempty"`
	EOLDate         feeds.Date     `json:"eolDate,omitzero"` // end of security support, if given
	ExtendedUntil   feeds.Date     `json:"extendedUntil,omitzero"`
	Successor       string         `json:"successor,omitempty"` // newest supported release listed
	SuccessorLatest string         `json:"successorLatest,omitempty"`
	Page            string         `json:"page,omitempty"`
	Policy          string         `json:"policy,omitempty"`
	Releases        []string       `json:"releases,omitempty"` // for state no-match: the names that would match
	Acknowledged    bool           `json:"acknowledged"`
}

// wantsEOL reports whether any configured product has a version and an
// endoflife.date slug, so end of life can be looked up.
func wantsEOL(cat *catalog.Catalog, cfg *config.Config) bool {
	for _, p := range cfg.Products {
		if cp, ok := cat.Get(p.ID); ok && cp.EOLSlug != "" && strings.TrimSpace(p.Version) != "" {
			return true
		}
	}
	return false
}

func ticked(cfg *config.Config) []match.Ticked {
	out := make([]match.Ticked, len(cfg.Products))
	for i, p := range cfg.Products {
		out[i] = match.Ticked{ID: p.ID, Version: p.Version}
	}
	return out
}

func (a *app) today() time.Time {
	now := a.now().In(a.loc)
	return time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
}

func staleWhy(st feeds.Status) string {
	if st.StaleReason != "" {
		return st.StaleReason
	}
	return st.LastError
}

// eolReport builds the report's end-of-life entries. Without any version to
// look up (looked == false) it still lists tracked products as no-version,
// so the user learns that adding versions would turn the check on.
func (a *app) eolReport(cat *catalog.Catalog, cfg *config.Config, sts []match.EOLStatus, looked bool) []eolEntry {
	if !looked {
		sts = nil
		for _, p := range cfg.Products {
			if cp, ok := cat.Get(p.ID); ok && cp.EOLSlug != "" {
				sts = append(sts, match.EOLStatus{Product: cp, Version: p.Version, State: match.EOLNoVersion})
			}
		}
	}
	out := []eolEntry{}
	for _, s := range sts {
		if s.State == match.EOLNotTracked {
			continue
		}
		e := eolEntry{
			ProductID: s.Product.ID, Product: s.Product.Display, Version: s.Version, State: s.State,
			Page: s.Page, Policy: s.Policy,
		}
		if s.Release != nil {
			e.Release = s.Release.Name
			e.EOLDate = s.Release.EOLFrom
			if !s.Release.EOESFrom.IsZero() {
				e.ExtendedUntil = s.Release.EOESFrom
			}
			if s.State.IsFinding() {
				e.ID = store.FindingID("eol", s.Product.ID, s.Release.Name)
			}
		}
		if s.Successor != nil {
			e.Successor = s.Successor.Name
			if s.Successor.Latest != nil {
				e.SuccessorLatest = s.Successor.Latest.Name
			}
		}
		if s.State == match.EOLNoMatch {
			e.Releases = s.Releases
		}
		out = append(out, e)
	}
	return out
}

// printEOL prints the end-of-life section. It never calls anything
// "supported" without a date from endoflife.date to say until when.
func (a *app) printEOL(w io.Writer, rep checkReport) {
	if len(rep.EndOfLife) == 0 {
		return
	}
	_, _ = fmt.Fprintln(w, "\nEnd of life (security support dates from endoflife.date):")
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	noVersion := 0
	for _, e := range rep.EndOfLife {
		name := clean(shortName(e.Product))
		if e.Version != "" {
			name += " " + clean(e.Version)
		}
		var what string
		switch e.State {
		case match.EOLEnded:
			what = "security updates have stopped"
			if !e.EOLDate.IsZero() {
				what = "security updates stopped on " + calDate(e.EOLDate)
			}
			what += upgradeHint(e)
		case match.EOLEnding:
			days := int(e.EOLDate.Sub(rep.today).Hours() / 24)
			what = fmt.Sprintf("security updates stop on %s (in %d days)", calDate(e.EOLDate), days) + upgradeHint(e)
		case match.EOLSupported:
			what = "no end date announced on endoflife.date"
			if !e.EOLDate.IsZero() {
				what = "security updates until " + calDate(e.EOLDate)
			}
		case match.EOLNoVersion:
			noVersion++
			what = "no version in your configuration, so end of life is not checked"
		case match.EOLNoMatch:
			what = "version matches no release on endoflife.date; use one of: " + strings.Join(firstN(e.Releases, 8), ", ")
		case match.EOLNoData:
			what = "no saved endoflife.date data for it; run patchtacio feeds update"
		}
		rel := ""
		if e.Release != "" {
			rel = "release " + clean(e.Release)
		}
		ack := ""
		if e.Acknowledged {
			ack = "ACK yes"
		}
		_, _ = fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\n", name, rel, clean(what), ack)
	}
	_ = tw.Flush()
	if rep.eolFindings > 0 {
		_, _ = fmt.Fprintln(w, "When you have dealt with one, run: patchtacio ack eol/<product>/<release> (see check --json for the IDs).")
	}
	if noVersion > 0 {
		_, _ = fmt.Fprintln(w, "To check end of life, add version: to those products in your configuration (e.g. version: \"7.4.2\").")
	}
}

func upgradeHint(e eolEntry) string {
	if e.Successor == "" {
		return "; check the vendor's lifecycle page for supported releases"
	}
	return "; newest supported release: " + clean(e.Successor)
}

func firstN(s []string, n int) []string {
	if len(s) > n {
		return append(s[:n:n], "…")
	}
	return s
}
