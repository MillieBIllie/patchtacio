// Package notify decides which alerts are due and delivers them: once per
// finding and channel, with reminders as CISA's deadline approaches and
// passes, and an optional daily or weekly digest. Each run sends at most one
// message per channel; several findings become one summary (internal/advice).
//
// Delivery state lives in internal/store. A channel that fails records
// nothing, so the next run retries it without repeating what the other
// channels already delivered.
package notify

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/milliebillie/patchtacio/internal/advice"
	"github.com/milliebillie/patchtacio/internal/store"
)

// Channel is one way of delivering alerts.
type Channel interface {
	// Name is the stable name deliveries are recorded under: "email",
	// "webhook", "ntfy" or "desktop".
	Name() string
	// Send delivers one message.
	Send(ctx context.Context, m advice.Message) error
	// SendTest delivers a message that says it is a test.
	SendTest(ctx context.Context) error
}

// Candidate is one current finding: a KEV entry matching one of the user's
// products. Item holds that one product.
type Candidate struct {
	ID   string // store finding ID
	Item advice.Item
}

// Digest modes.
const (
	DigestOff    = "off"
	DigestDaily  = "daily"
	DigestWeekly = "weekly"
)

// DueSoonDays is how close CISA's deadline must be for the due-soon reminder.
const DueSoonDays = 3

// Store is the part of internal/store the dispatcher uses.
type Store interface {
	States(ctx context.Context, ids []string) (map[string]store.State, error)
	RecordDeliveries(ctx context.Context, ds []store.Delivery) error
	LastDelivery(ctx context.Context, channel string) (time.Time, error)
}

// Dispatcher sends what is due on each channel.
type Dispatcher struct {
	Store    Store
	Channels []Channel
	Digest   string           // DigestOff (default), DigestDaily or DigestWeekly
	Now      func() time.Time // defaults to time.Now
	Location *time.Location   // the reader's time zone, for calendar dates
}

// Result is what happened on one channel.
type Result struct {
	Channel   string
	Sent      int       // findings delivered (one message)
	Held      int       // findings waiting for the next digest
	NextAfter time.Time // when a held digest may go
	Err       error
}

// Run delivers what is due for the current findings and returns one result
// per channel. The error is non-nil if any channel failed.
func (d *Dispatcher) Run(ctx context.Context, cands []Candidate) ([]Result, error) {
	now := d.now()
	today := calendarDay(now, d.Location)
	ids := make([]string, len(cands))
	for i, c := range cands {
		ids[i] = c.ID
	}
	states, err := d.Store.States(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("read alert state: %w", err)
	}

	var results []Result
	var errs []error
	for _, ch := range d.Channels {
		r := Result{Channel: ch.Name()}
		due := Plan(ch.Name(), cands, states, today)
		if len(due) == 0 {
			results = append(results, r)
			continue
		}
		if next, hold, err := d.holdForDigest(ctx, ch.Name(), now); err != nil {
			r.Err = err
		} else if hold {
			r.Held, r.NextAfter = len(due), next
			results = append(results, r)
			continue
		}
		if r.Err == nil {
			r.Err = ch.Send(ctx, advice.Message{Items: Group(due), Today: today})
		}
		if r.Err == nil {
			r.Err = d.Store.RecordDeliveries(ctx, deliveries(ch.Name(), due))
			if r.Err != nil {
				// Sent but not recorded: the next run repeats this alert,
				// which beats losing one.
				r.Err = fmt.Errorf("sent, but could not record it (it may be sent again): %w", r.Err)
			}
		}
		if r.Err == nil {
			r.Sent = len(due)
		} else {
			errs = append(errs, fmt.Errorf("%s: %w", ch.Name(), r.Err))
		}
		results = append(results, r)
	}
	return results, errors.Join(errs...)
}

// holdForDigest reports whether a digest channel already sent within its
// period. Periods are an hour short, so a check scheduled at the same time
// each day or week is not held back by a few minutes of drift.
func (d *Dispatcher) holdForDigest(ctx context.Context, channel string, now time.Time) (time.Time, bool, error) {
	var period time.Duration
	switch d.Digest {
	case DigestDaily:
		period = 24 * time.Hour
	case DigestWeekly:
		period = 7 * 24 * time.Hour
	default:
		return time.Time{}, false, nil
	}
	last, err := d.Store.LastDelivery(ctx, channel)
	if err != nil {
		return time.Time{}, false, err
	}
	next := last.Add(period - time.Hour)
	if last.IsZero() || !now.Before(next) {
		return time.Time{}, false, nil
	}
	return next, true, nil
}

func (d *Dispatcher) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

// Due is a finding to alert about on a channel, and the alert kinds that
// delivering it covers.
type Due struct {
	Candidate
	Kind   string
	Covers []string
}

// Plan returns what is due on channel. A finding that was acknowledged gets
// nothing. One not yet alerted on this channel is new; a new alert also
// covers the reminders its deadline already calls for, so a finding first
// seen past its deadline is not followed by an overdue reminder. Otherwise a
// reminder is due once when the deadline is DueSoonDays away or nearer, and
// once after it passes.
func Plan(channel string, cands []Candidate, states map[string]store.State, today time.Time) []Due {
	var out []Due
	for _, c := range cands {
		st := states[c.ID] // a finding not yet recorded has no deliveries
		if st.Acked() {
			continue
		}
		dueSoon, passed := deadline(c.Item.DueDate, today)
		var d Due
		switch {
		case !st.Sent(channel, store.KindNew):
			d = Due{Candidate: c, Kind: advice.KindNew, Covers: []string{store.KindNew}}
			if dueSoon || passed {
				d.Covers = append(d.Covers, store.KindDueSoon)
			}
			if passed {
				d.Covers = append(d.Covers, store.KindOverdue)
			}
		case passed && !st.Sent(channel, store.KindOverdue):
			d = Due{Candidate: c, Kind: advice.KindOverdue, Covers: []string{store.KindOverdue, store.KindDueSoon}}
		case dueSoon && !st.Sent(channel, store.KindDueSoon):
			d = Due{Candidate: c, Kind: advice.KindDueSoon, Covers: []string{store.KindDueSoon}}
		default:
			continue
		}
		out = append(out, d)
	}
	return out
}

// deadline reports whether due is DueSoonDays or fewer days ahead (today
// included) and whether it has passed. A zero due date is neither.
func deadline(due, today time.Time) (soon, passed bool) {
	if due.IsZero() {
		return false, false
	}
	due = time.Date(due.Year(), due.Month(), due.Day(), 0, 0, 0, 0, time.UTC)
	if due.Before(today) {
		return false, true
	}
	return !due.After(today.AddDate(0, 0, DueSoonDays)), false
}

// Group merges due findings by CVE into one advice item each, listing every
// affected product. The item is new if any of its findings is new, else an
// overdue reminder over a due-soon one.
func Group(due []Due) []advice.Item {
	var order []string
	byCVE := map[string]*advice.Item{}
	for _, d := range due {
		key := strings.ToUpper(d.Item.CVE)
		it, ok := byCVE[key]
		if !ok {
			cp := d.Item
			cp.Kind = d.Kind
			cp.Products = slices.Clone(d.Item.Products)
			byCVE[key] = &cp
			order = append(order, key)
			continue
		}
		it.Products = append(it.Products, d.Item.Products...)
		if kindRank(d.Kind) < kindRank(it.Kind) {
			it.Kind = d.Kind
		}
	}
	out := make([]advice.Item, 0, len(order))
	for _, k := range order {
		out = append(out, *byCVE[k])
	}
	return out
}

func kindRank(kind string) int {
	switch kind {
	case advice.KindNew:
		return 0
	case advice.KindOverdue:
		return 1
	default:
		return 2
	}
}

func deliveries(channel string, due []Due) []store.Delivery {
	var ds []store.Delivery
	for _, d := range due {
		for _, k := range d.Covers {
			ds = append(ds, store.Delivery{FindingID: d.ID, Channel: channel, Kind: k})
		}
	}
	return ds
}

// calendarDay is t's date in loc, as UTC midnight (how feed dates are kept).
func calendarDay(t time.Time, loc *time.Location) time.Time {
	if loc != nil {
		t = t.In(loc)
	}
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
}
