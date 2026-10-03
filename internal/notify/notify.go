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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
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
	// Name is the channel type: "email", "webhook", "ntfy" or "desktop".
	Name() string
	// Destination describes where the channel delivers (the recipients, or
	// the URL); nil for this computer. Deliveries are recorded under a keyed
	// hash of it: a new address or URL is a new destination that has heard
	// nothing yet, so it gets everything again rather than silently missing
	// what went elsewhere.
	Destination() []string
	// Send delivers one message.
	Send(ctx context.Context, m advice.Message) error
	// SendNotice delivers a message that is not about a finding: a test, or
	// a warning that alerts may be missing.
	SendNotice(ctx context.Context, n advice.Notice) error
}

// Candidate is one current finding: a KEV entry matching one of the user's
// products. Item holds that one product.
type Candidate struct {
	ID   string // store finding ID
	Item advice.Item
	// EOL, when set, makes this an end-of-life candidate instead: its
	// deadline is the end-of-life date, and Item is unused.
	EOL *advice.EOLItem
}

// EOLSoonDays is how close an end-of-life date must be for its reminder.
const EOLSoonDays = 30

// deadline returns the candidate's date, whether it has passed (an ended
// release with no date given counts), and its reminder window.
func (c Candidate) deadline() (due time.Time, ended bool, soonDays int) {
	if c.EOL != nil {
		return c.EOL.EOLDate, c.EOL.Ended, EOLSoonDays
	}
	return c.Item.DueDate, false, DueSoonDays
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
	LastNotice(ctx context.Context, channel, kind string) (time.Time, error)
	RecordNotice(ctx context.Context, channel, kind string) error
}

// Dispatcher sends what is due on each channel.
type Dispatcher struct {
	Store    Store
	Channels []Channel
	Digest   string           // DigestOff (default), DigestDaily or DigestWeekly
	Now      func() time.Time // defaults to time.Now
	Location *time.Location   // the reader's time zone, for calendar dates
	// Secret keys the destination hashes (store.InstallSecret). Required.
	Secret []byte
}

// Result is what happened on one channel.
type Result struct {
	Channel   string
	Sent      int       // findings delivered (one message)
	Vulns     int       // distinct vulnerabilities in that message
	EOL       int       // end-of-life releases in that message
	Held      int       // findings waiting for the next digest
	NextAfter time.Time // when a held digest may go
	Err       error
}

// Run delivers what is due for the current findings and returns one result
// per channel. The error is non-nil if any channel failed.
func (d *Dispatcher) Run(ctx context.Context, cands []Candidate) ([]Result, error) {
	if len(d.Secret) == 0 {
		return nil, errors.New("notify: dispatcher has no install secret")
	}
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
		key := d.key(ch)
		due := Plan(key, cands, states, today)
		if len(due) == 0 {
			results = append(results, r)
			continue
		}
		if next, hold, err := d.holdForDigest(ctx, key, now); err != nil {
			r.Err = err
		} else if hold {
			r.Held, r.NextAfter = len(due), next
			results = append(results, r)
			continue
		}
		items, eols := Group(due)
		if r.Err == nil {
			r.Err = ch.Send(ctx, advice.Message{Items: items, EOL: eols, Today: today})
		}
		if r.Err == nil {
			r.Err = d.Store.RecordDeliveries(ctx, deliveries(key, due))
			if r.Err != nil {
				// Sent but not recorded: the next run repeats this alert,
				// which beats losing one.
				r.Err = fmt.Errorf("sent, but could not record it (it may be sent again): %w", r.Err)
			}
		}
		if r.Err == nil {
			r.Sent, r.Vulns, r.EOL = len(due), len(items), len(eols)
		} else {
			errs = append(errs, fmt.Errorf("%s: %w", ch.Name(), r.Err))
		}
		results = append(results, r)
	}
	return results, errors.Join(errs...)
}

// Notice sends n on every channel whose destination has not had a notice of
// this kind within every (less an hour for schedule drift), and records it.
// Use it for problems that last, such as a feed that cannot be updated. Held
// channels report Held = 1.
func (d *Dispatcher) Notice(ctx context.Context, kind string, n advice.Notice, every time.Duration) ([]Result, error) {
	if len(d.Secret) == 0 {
		return nil, errors.New("notify: dispatcher has no install secret")
	}
	now := d.now()
	var results []Result
	var errs []error
	for _, ch := range d.Channels {
		r := Result{Channel: ch.Name()}
		key := d.key(ch)
		last, err := d.Store.LastNotice(ctx, key, kind)
		last = notInFuture(last, now)
		switch {
		case err != nil:
			r.Err = err
		case !last.IsZero() && now.Before(last.Add(every-time.Hour)):
			r.Held, r.NextAfter = 1, last.Add(every-time.Hour)
		default:
			if r.Err = ch.SendNotice(ctx, n); r.Err == nil {
				r.Err = d.Store.RecordNotice(ctx, key, kind)
			}
			if r.Err == nil {
				r.Sent = 1
			}
		}
		if r.Err != nil {
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
	last = notInFuture(last, now)
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
		due, ended, soonDays := c.deadline()
		dueSoon, passed := deadline(due, today, soonDays)
		passed = passed || ended
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

// deadline reports whether due is soonDays or fewer days ahead (today
// included) and whether it has passed. A zero due date is neither.
func deadline(due, today time.Time, soonDays int) (soon, passed bool) {
	if due.IsZero() {
		return false, false
	}
	due = time.Date(due.Year(), due.Month(), due.Day(), 0, 0, 0, 0, time.UTC)
	if due.Before(today) {
		return false, true
	}
	return !due.After(today.AddDate(0, 0, soonDays)), false
}

// Group merges due KEV findings by CVE into one advice item each, listing
// every affected product (the item is new if any of its findings is new,
// else an overdue reminder over a due-soon one), and returns end-of-life
// candidates as their own items.
func Group(due []Due) ([]advice.Item, []advice.EOLItem) {
	var order []string
	byCVE := map[string]*advice.Item{}
	var eols []advice.EOLItem
	for _, d := range due {
		if d.EOL != nil {
			e := *d.EOL
			e.Kind = d.Kind
			eols = append(eols, e)
			continue
		}
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
	return out, eols
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

// notInFuture treats a time more than an hour ahead of now as never: it was
// recorded while the clock was wrong, and trusting it would hold digests or
// "alerts may be missing" notices until that date.
func notInFuture(t, now time.Time) time.Time {
	if t.After(now.Add(time.Hour)) {
		return time.Time{}
	}
	return t
}

// key is the name deliveries to ch are recorded under: the channel type and
// a short HMAC-SHA-256 of its destination, keyed with the install secret.
// Only the hash is stored, so no token reaches the database, and without the
// secret a guessed topic or URL cannot be checked against it.
func (d *Dispatcher) key(ch Channel) string {
	parts := ch.Destination()
	if len(parts) == 0 {
		return ch.Name()
	}
	mac := hmac.New(sha256.New, d.Secret)
	mac.Write([]byte(strings.Join(parts, "\x00")))
	return ch.Name() + "/" + hex.EncodeToString(mac.Sum(nil)[:8])
}

// calendarDay is t's date in loc, as UTC midnight (how feed dates are kept).
func calendarDay(t time.Time, loc *time.Location) time.Time {
	if loc != nil {
		t = t.In(loc)
	}
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
}
