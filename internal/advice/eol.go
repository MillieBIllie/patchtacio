package advice

import (
	"fmt"
	"strings"
	"time"
)

// EOLItem is a release the user runs that is at or near end of life: the
// date its vendor stops security updates, from endoflife.date. Every date and
// release name comes from that data; nothing is inferred.
type EOLItem struct {
	Kind          string
	Product       Product
	Release       string    // endoflife.date release (cycle) name, e.g. "7.2"
	EOLDate       time.Time // end of security support; zero if ended but no date given
	Ended         bool      // endoflife.date says it has ended
	ExtendedUntil time.Time // end of extended (often paid) support, if listed and later
	Successor     string    // newest supported release listed, "" if none
	SuccessorAt   string    // its latest version, "" if not listed
	Page          string    // the product's endoflife.date page
	Policy        string    // the vendor's lifecycle page, if listed
	AckID         string    // what `patchtacio ack` takes: eol/<product>/<release>
}

type eolView struct {
	Kind, Headline, Name, Release, Product, Date, Extended string
	Successor, SuccessorAt, Page, Policy, AckID            string
	ProductLine                                            string
	Ended                                                  bool
	DaysLeft                                               int
	date                                                   time.Time
}

func newEOLView(it EOLItem, today time.Time) eolView {
	short := shortName(clean(it.Product.Display))
	v := eolView{
		Kind:      it.Kind,
		Release:   oneLine(it.Release),
		Product:   short,
		Ended:     it.Ended,
		Successor: oneLine(it.Successor), SuccessorAt: oneLine(it.SuccessorAt),
		AckID: clean(it.AckID),
		date:  day(it.EOLDate),
	}
	v.Name = short + " " + v.Release
	// Feed links: https only.
	if l := clean(it.Page); isWebLink(l) && strings.HasPrefix(l, "https://") {
		v.Page = l
	}
	if l := clean(it.Policy); isWebLink(l) && strings.HasPrefix(l, "https://") {
		v.Policy = l
	}
	switch {
	case it.EOLDate.IsZero():
	case it.Ended && v.date.After(today):
		// Marked ended but dated in the future: the data disagrees with
		// itself, so say it has ended without a date that contradicts it.
		v.date = time.Time{}
	default:
		v.Date = date(it.EOLDate)
		v.DaysLeft = int(v.date.Sub(today).Hours() / 24)
		if v.date.Before(today) {
			v.Ended = true
		}
	}
	if !it.ExtendedUntil.IsZero() && it.ExtendedUntil.After(it.EOLDate) {
		v.Extended = date(it.ExtendedUntil)
	}
	line := clean(it.Product.Display)
	if it.Product.Version != "" {
		line += ", version " + oneLine(it.Product.Version)
	}
	if it.Product.Notes != "" {
		line += " (your note: " + oneLine(it.Product.Notes) + ")"
	}
	v.ProductLine = line

	var tag string
	switch {
	case v.Ended && v.Date == "":
		tag = "End of life reached"
	case v.Ended && it.Kind == KindOverdue:
		tag = "Reminder: end of life since " + v.Date
	case v.Ended:
		tag = "End of life since " + v.Date
	case it.Kind == KindDueSoon:
		tag = "Reminder: end of life on " + v.Date
	default:
		tag = "End of life on " + v.Date
	}
	v.Headline = fmt.Sprintf("[%s] %s: security updates %s", tag, v.Name, map[bool]string{true: "have stopped", false: "stop"}[v.Ended])
	return v
}

func (v eolView) short() string {
	what := "reaches end of life on " + v.Date + ": security updates stop. Plan the upgrade"
	if v.Ended {
		what = "is past end of life: no more security updates. Upgrade"
		if v.Date != "" {
			what = "reached end of life on " + v.Date + ": no more security updates. Upgrade"
		}
	}
	return fitName("Patchtacio: %s "+what+". Details: patchtacio check", v.Name)
}

// eolRank sorts ended releases first (most recently ended first), then the
// soonest to end.
func eolLess(a, b eolView) int {
	switch {
	case a.Ended != b.Ended:
		if a.Ended {
			return -1
		}
		return 1
	case a.Ended:
		return b.date.Compare(a.date)
	default:
		return a.date.Compare(b.date)
	}
}
