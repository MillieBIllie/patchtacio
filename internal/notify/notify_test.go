package notify

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/milliebillie/patchtacio/internal/advice"
	"github.com/milliebillie/patchtacio/internal/config"
	"github.com/milliebillie/patchtacio/internal/store"
)

// memStore is an in-memory Store with a clock the test controls.
type memStore struct {
	now     *time.Time
	acked   map[string]bool
	sent    map[string]map[string]map[string]time.Time // id -> channel -> kind
	notices map[string]time.Time                       // channel + "|" + kind
}

func (m *memStore) LastNotice(_ context.Context, channel, kind string) (time.Time, error) {
	return m.notices[channel+"|"+kind], nil
}

func (m *memStore) RecordNotice(_ context.Context, channel, kind string) error {
	m.notices[channel+"|"+kind] = *m.now
	return nil
}

func newMemStore(now *time.Time) *memStore {
	return &memStore{now: now, acked: map[string]bool{}, sent: map[string]map[string]map[string]time.Time{}, notices: map[string]time.Time{}}
}

func (m *memStore) States(_ context.Context, ids []string) (map[string]store.State, error) {
	out := map[string]store.State{}
	for _, id := range ids {
		st := store.State{Finding: store.Finding{ID: id}, Delivered: m.sent[id]}
		if m.acked[id] {
			st.AckedAt = *m.now
		}
		out[id] = st
	}
	return out, nil
}

func (m *memStore) RecordDeliveries(_ context.Context, ds []store.Delivery) error {
	for _, d := range ds {
		if m.sent[d.FindingID] == nil {
			m.sent[d.FindingID] = map[string]map[string]time.Time{}
		}
		if m.sent[d.FindingID][d.Channel] == nil {
			m.sent[d.FindingID][d.Channel] = map[string]time.Time{}
		}
		if _, ok := m.sent[d.FindingID][d.Channel][d.Kind]; !ok {
			m.sent[d.FindingID][d.Channel][d.Kind] = *m.now
		}
	}
	return nil
}

func (m *memStore) LastDelivery(_ context.Context, channel string) (time.Time, error) {
	var last time.Time
	for _, chs := range m.sent {
		for _, t := range chs[channel] {
			if t.After(last) {
				last = t
			}
		}
	}
	return last, nil
}

// fakeChannel records messages; fail makes Send fail.
type fakeChannel struct {
	name    string
	key     string // destination; defaults to name
	fail    bool
	msgs    []advice.Message
	notices []advice.Notice
}

func (f *fakeChannel) Name() string { return f.name }
func (f *fakeChannel) Key() string {
	if f.key != "" {
		return f.key
	}
	return f.name
}
func (f *fakeChannel) Send(_ context.Context, m advice.Message) error {
	if f.fail {
		return errors.New("connection refused")
	}
	f.msgs = append(f.msgs, m)
	return nil
}
func (f *fakeChannel) SendNotice(_ context.Context, n advice.Notice) error {
	if f.fail {
		return errors.New("connection refused")
	}
	f.notices = append(f.notices, n)
	return nil
}

func cand(product, cve, due string) Candidate {
	it := advice.Item{CVE: cve, Products: []advice.Product{{Display: product}}}
	if due != "" {
		it.DueDate, _ = time.Parse(time.DateOnly, due)
	}
	return Candidate{ID: store.FindingID("kev", product, cve), Item: it}
}

func cves(m advice.Message) []string {
	var out []string
	for _, it := range m.Items {
		out = append(out, it.Kind+":"+it.CVE)
	}
	slices.Sort(out)
	return out
}

func setup(t *testing.T, digest string, channels ...*fakeChannel) (*Dispatcher, *time.Time, *memStore) {
	t.Helper()
	now := time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC)
	ms := newMemStore(&now)
	d := &Dispatcher{Store: ms, Digest: digest, Now: func() time.Time { return now }, Location: time.UTC}
	for _, c := range channels {
		d.Channels = append(d.Channels, c)
	}
	return d, &now, ms
}

// The milestone's "done when": a new KEV entry for a ticked product produces
// exactly one alert, and nothing is repeated.
func TestOneAlertPerNewEntry(t *testing.T) {
	ctx := context.Background()
	ch := &fakeChannel{name: "webhook"}
	d, now, _ := setup(t, DigestOff, ch)
	existing := []Candidate{
		cand("fortios", "CVE-2024-21762", "2024-02-16"), // long past due
		cand("exchange", "CVE-2023-21529", "2026-04-27"),
	}

	// First run: everything already on the list arrives as one summary.
	if _, err := d.Run(ctx, existing); err != nil {
		t.Fatal(err)
	}
	if len(ch.msgs) != 1 || len(ch.msgs[0].Items) != 2 {
		t.Fatalf("first run sent %d messages: %+v", len(ch.msgs), ch.msgs)
	}

	// Same data again: nothing, not even an overdue reminder for entries
	// that were already past due when first sent.
	*now = now.Add(24 * time.Hour)
	if _, err := d.Run(ctx, existing); err != nil {
		t.Fatal(err)
	}
	if len(ch.msgs) != 1 {
		t.Fatalf("a repeat run sent %v", cves(ch.msgs[len(ch.msgs)-1]))
	}

	// One new entry: exactly one alert, about it alone.
	newEntry := cand("fortios", "CVE-2026-24858", "2026-10-25")
	res, err := d.Run(ctx, append(existing, newEntry))
	if err != nil {
		t.Fatal(err)
	}
	if len(ch.msgs) != 2 || !slices.Equal(cves(ch.msgs[1]), []string{"new:CVE-2026-24858"}) {
		t.Fatalf("new entry: got %d messages, last %v", len(ch.msgs), cves(ch.msgs[len(ch.msgs)-1]))
	}
	if res[0].Sent != 1 {
		t.Errorf("result says %d sent", res[0].Sent)
	}
	if _, err := d.Run(ctx, append(existing, newEntry)); err != nil || len(ch.msgs) != 2 {
		t.Errorf("the new entry was alerted twice (%d messages, %v)", len(ch.msgs), err)
	}
}

func TestReminders(t *testing.T) {
	ctx := context.Background()
	ch := &fakeChannel{name: "email"}
	d, now, _ := setup(t, DigestOff, ch)
	c := []Candidate{cand("fortios", "CVE-2026-24858", "2026-10-12")}

	run := func(day string) []string {
		t.Helper()
		*now, _ = time.Parse(time.DateOnly, day)
		*now = now.Add(9 * time.Hour)
		before := len(ch.msgs)
		if _, err := d.Run(ctx, c); err != nil {
			t.Fatal(err)
		}
		if len(ch.msgs) == before {
			return nil
		}
		return cves(ch.msgs[len(ch.msgs)-1])
	}
	steps := []struct {
		day  string
		want []string
	}{
		{"2026-10-03", []string{"new:CVE-2026-24858"}},
		{"2026-10-08", nil},                                 // 4 days left: quiet
		{"2026-10-09", []string{"due-soon:CVE-2026-24858"}}, // 3 days left
		{"2026-10-12", nil},                                 // due today: not passed
		{"2026-10-13", []string{"overdue:CVE-2026-24858"}},
		{"2026-10-20", nil}, // then quiet
	}
	for _, s := range steps {
		if got := run(s.day); !slices.Equal(got, s.want) {
			t.Errorf("%s: sent %v, want %v", s.day, got, s.want)
		}
	}
}

func TestFirstAlertNearDeadlineCoversDueSoon(t *testing.T) {
	ctx := context.Background()
	ch := &fakeChannel{name: "ntfy"}
	d, now, _ := setup(t, DigestOff, ch)
	c := []Candidate{cand("fortios", "CVE-2026-1", "2026-10-05")} // 2 days left
	if _, err := d.Run(ctx, c); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(24 * time.Hour)
	if _, err := d.Run(ctx, c); err != nil {
		t.Fatal(err)
	}
	if len(ch.msgs) != 1 {
		t.Errorf("a due-soon reminder followed the first alert: %v", cves(ch.msgs[len(ch.msgs)-1]))
	}
}

func TestAcknowledgedGetsNothing(t *testing.T) {
	ctx := context.Background()
	ch := &fakeChannel{name: "webhook"}
	d, _, ms := setup(t, DigestOff, ch)
	c := cand("fortios", "CVE-2026-1", "2026-10-04")
	ms.acked[c.ID] = true
	if _, err := d.Run(ctx, []Candidate{c}); err != nil {
		t.Fatal(err)
	}
	if len(ch.msgs) != 0 {
		t.Errorf("an acknowledged finding was alerted: %v", cves(ch.msgs[0]))
	}
}

// A channel that fails is retried next run; the one that worked is not
// repeated.
func TestFailedChannelRetriedAlone(t *testing.T) {
	ctx := context.Background()
	good := &fakeChannel{name: "email"}
	bad := &fakeChannel{name: "webhook", fail: true}
	d, _, _ := setup(t, DigestOff, good, bad)
	c := []Candidate{cand("fortios", "CVE-2026-1", "")}

	res, err := d.Run(ctx, c)
	if err == nil {
		t.Fatal("want an error when a channel fails")
	}
	if res[0].Sent != 1 || res[1].Err == nil || res[1].Sent != 0 {
		t.Errorf("results: %+v", res)
	}
	bad.fail = false
	if _, err := d.Run(ctx, c); err != nil {
		t.Fatal(err)
	}
	if len(good.msgs) != 1 || len(bad.msgs) != 1 {
		t.Errorf("email got %d messages (want 1), webhook %d (want 1)", len(good.msgs), len(bad.msgs))
	}
}

// KEV does not say Windows desktop or server, so one CVE matching both is
// one alert naming both.
func TestGroupedByCVE(t *testing.T) {
	ctx := context.Background()
	ch := &fakeChannel{name: "webhook"}
	d, _, _ := setup(t, DigestOff, ch)
	c := []Candidate{cand("Windows", "CVE-2026-81963", "2026-10-20"), cand("Windows Server", "CVE-2026-81963", "2026-10-20")}
	if _, err := d.Run(ctx, c); err != nil {
		t.Fatal(err)
	}
	if len(ch.msgs) != 1 || len(ch.msgs[0].Items) != 1 || len(ch.msgs[0].Items[0].Products) != 2 {
		t.Errorf("want one item with two products, got %+v", ch.msgs)
	}
}

// A new destination (other recipients, another webhook URL) has heard
// nothing, so it gets everything; the old one is not repeated.
func TestNewDestinationGetsEverything(t *testing.T) {
	ctx := context.Background()
	ch := &fakeChannel{name: "email", key: "email/old"}
	d, _, _ := setup(t, DigestOff, ch)
	c := []Candidate{cand("fortios", "CVE-2026-1", "2024-01-01"), cand("exchange", "CVE-2026-2", "")}
	if _, err := d.Run(ctx, c); err != nil || len(ch.msgs) != 1 {
		t.Fatalf("first: %d messages, %v", len(ch.msgs), err)
	}
	ch.key = "email/new"
	if _, err := d.Run(ctx, c); err != nil || len(ch.msgs) != 2 || len(ch.msgs[1].Items) != 2 {
		t.Fatalf("new destination: %d messages, %v", len(ch.msgs), err)
	}
	if _, err := d.Run(ctx, c); err != nil || len(ch.msgs) != 2 {
		t.Errorf("repeated to the new destination: %d messages", len(ch.msgs))
	}
}

func TestDestinationKeys(t *testing.T) {
	e1 := NewEmail(config.Email{To: []string{"IT <it@example.org>", "head@example.org"}}, env(nil))
	e2 := NewEmail(config.Email{To: []string{"head@example.org", "it@EXAMPLE.org"}}, env(nil))
	e3 := NewEmail(config.Email{To: []string{"it@example.org"}}, env(nil))
	if e1.Key() != e2.Key() || e1.Key() == e3.Key() || !strings.HasPrefix(e1.Key(), "email/") {
		t.Errorf("email keys: %s %s %s", e1.Key(), e2.Key(), e3.Key())
	}
	w := NewWebhook("slack", env(map[string]string{config.EnvWebhookURL: "https://hooks.slack.com/services/T/B/SECRETTOKEN"}))
	if k := w.Key(); strings.Contains(k, "SECRET") || !strings.HasPrefix(k, "webhook/") {
		t.Errorf("webhook key %q", k)
	}
	w2 := NewWebhook("slack", env(map[string]string{config.EnvWebhookURL: "https://hooks.slack.com/services/T/B/OTHER"}))
	if w.Key() == w2.Key() {
		t.Error("two webhook URLs share a key")
	}
}

func TestDigestHoldsUntilPeriodEnds(t *testing.T) {
	ctx := context.Background()
	ch := &fakeChannel{name: "email"}
	d, now, _ := setup(t, DigestDaily, ch)
	first := []Candidate{cand("fortios", "CVE-2026-1", "")}
	if _, err := d.Run(ctx, first); err != nil || len(ch.msgs) != 1 {
		t.Fatalf("the first digest must go at once: %d messages, %v", len(ch.msgs), err)
	}
	both := append(first, cand("exchange", "CVE-2026-2", ""))
	*now = now.Add(6 * time.Hour)
	res, err := d.Run(ctx, both)
	if err != nil || len(ch.msgs) != 1 || res[0].Held != 1 {
		t.Fatalf("within the day: %d messages, held %d, %v", len(ch.msgs), res[0].Held, err)
	}
	*now = now.Add(17*time.Hour + 30*time.Minute) // 23.5 h after the first: within drift allowance
	if _, err := d.Run(ctx, both); err != nil || len(ch.msgs) != 2 || !slices.Equal(cves(ch.msgs[1]), []string{"new:CVE-2026-2"}) {
		t.Errorf("next day: %d messages, %v", len(ch.msgs), err)
	}
}

// A lasting problem is reported at most once a day per destination, and a
// failed send is retried next run.
func TestNoticeOncePerDay(t *testing.T) {
	ctx := context.Background()
	good := &fakeChannel{name: "email"}
	bad := &fakeChannel{name: "webhook", fail: true}
	d, now, _ := setup(t, DigestOff, good, bad)
	n := advice.FeedNotice("CISA KEV catalog", time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC), "connection refused")
	res, err := d.Notice(ctx, "kev-stale", n, 24*time.Hour)
	if err == nil || res[0].Sent != 1 || res[1].Err == nil {
		t.Fatalf("first: %+v, %v", res, err)
	}
	bad.fail = false
	*now = now.Add(2 * time.Hour)
	res, err = d.Notice(ctx, "kev-stale", n, 24*time.Hour)
	if err != nil || res[0].Held != 1 || res[1].Sent != 1 {
		t.Fatalf("2 h later: %+v, %v", res, err)
	}
	*now = now.Add(23 * time.Hour)
	if res, _ = d.Notice(ctx, "kev-stale", n, 24*time.Hour); res[0].Sent != 1 {
		t.Errorf("next day: %+v", res)
	}
	// The webhook first got through at +2 h; +25 h is a day later for it too
	// (the hour of drift allowance).
	if len(good.notices) != 2 || len(bad.notices) != 2 {
		t.Errorf("email %d notices (want 2), webhook %d (want 2)", len(good.notices), len(bad.notices))
	}
}

// A notice recorded while the clock was far ahead must not silence the next.
func TestNoticeIgnoresFutureTimes(t *testing.T) {
	ctx := context.Background()
	ch := &fakeChannel{name: "email"}
	d, now, ms := setup(t, DigestOff, ch)
	ms.notices["email|kev-stale"] = now.AddDate(1, 0, 0)
	if res, err := d.Notice(ctx, "kev-stale", advice.FeedNotice("CISA KEV catalog", time.Time{}, ""), 24*time.Hour); err != nil || res[0].Sent != 1 {
		t.Errorf("future-dated notice suppressed the next: %+v, %v", res, err)
	}
}

func TestDeadline(t *testing.T) {
	today := time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)
	for _, tt := range []struct {
		due          string
		soon, passed bool
	}{
		{"", false, false},
		{"2026-10-02", false, true},
		{"2026-10-03", true, false},
		{"2026-10-06", true, false},
		{"2026-10-07", false, false},
	} {
		var due time.Time
		if tt.due != "" {
			due, _ = time.Parse(time.DateOnly, tt.due)
		}
		if soon, passed := deadline(due, today); soon != tt.soon || passed != tt.passed {
			t.Errorf("deadline(%q) = %v, %v; want %v, %v", tt.due, soon, passed, tt.soon, tt.passed)
		}
	}
}
