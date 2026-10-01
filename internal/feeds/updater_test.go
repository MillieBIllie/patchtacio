package feeds

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/milliebillie/patchtacio/internal/httpcache"
	"github.com/milliebillie/patchtacio/internal/store"
)

// fakeSource serves canned responses. Its body format is
// {"count": n, "published": "RFC3339"}.
type fakeSource struct {
	mu        sync.Mutex
	responses []fakeResp
	calls     int
	gotPrev   []httpcache.Validators
}

type fakeResp struct {
	body        string
	notModified bool
	err         error
	via         string
}

func (f *fakeSource) Name() string              { return "fake" }
func (f *fakeSource) Title() string             { return "Fake feed" }
func (f *fakeSource) StaleAfter() time.Duration { return 48 * time.Hour }

func (f *fakeSource) Fetch(_ context.Context, _ *httpcache.Client, prev httpcache.Validators) (*Fetched, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gotPrev = append(f.gotPrev, prev)
	r := f.responses[min(f.calls, len(f.responses)-1)]
	f.calls++
	if r.err != nil {
		return nil, r.err
	}
	via := r.via
	if via == "" {
		via = ViaPrimary
	}
	resp := &httpcache.Response{NotModified: r.notModified, ETag: `"etag-` + r.body + `"`, URL: "https://example.com/fake.json?token=x"}
	if !r.notModified {
		resp.Body = []byte(r.body)
	}
	return &Fetched{Response: resp, Via: via}, nil
}

func (f *fakeSource) Parse(raw []byte) (Summary, error) {
	var v struct {
		Count     *int      `json:"count"`
		Published time.Time `json:"published"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		return Summary{}, err
	}
	if v.Count == nil {
		return Summary{}, errors.New("missing count")
	}
	return Summary{Count: *v.Count, PublishedAt: v.Published}, nil
}

func body(count int, published string) string {
	return `{"count":` + itoa(count) + `,"published":"` + published + `"}`
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

type harness struct {
	u     *Updater
	src   *fakeSource
	clock time.Time
}

func newHarness(t *testing.T, responses ...fakeResp) *harness {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(context.Background(), filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	h := &harness{src: &fakeSource{responses: responses}, clock: time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)}
	h.u = &Updater{
		Store:     st,
		CacheDir:  dir,
		Sources:   []Source{h.src},
		Now:       func() time.Time { return h.clock },
		LockWait:  200 * time.Millisecond,
		PollEvery: 10 * time.Millisecond,
	}
	return h
}

func (h *harness) update(t *testing.T, offline bool) Result {
	t.Helper()
	rs, err := h.u.Update(context.Background(), offline)
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if len(rs) != 1 {
		t.Fatalf("got %d results", len(rs))
	}
	return rs[0]
}

func (h *harness) cached(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(h.u.CacheDir, "fake.json"))
	if err != nil {
		t.Fatalf("read cache: %v", err)
	}
	return string(b)
}

const (
	day1 = "2026-09-30T16:59:23Z"
	day2 = "2026-10-01T08:00:00Z"
	day0 = "2026-09-01T00:00:00Z"
)

func TestFirstUpdateThenNotModified(t *testing.T) {
	h := newHarness(t, fakeResp{body: body(100, day1)}, fakeResp{notModified: true})

	r := h.update(t, false)
	if r.Outcome != Updated || r.Status.State != Fresh || r.Status.Count != 100 {
		t.Fatalf("first update: %+v", r)
	}
	if r.Status.URL != "https://example.com/fake.json?[REDACTED]" {
		t.Errorf("stored URL not redacted: %q", r.Status.URL)
	}
	if h.cached(t) != body(100, day1) {
		t.Errorf("cache file has %q", h.cached(t))
	}

	h.clock = h.clock.Add(3 * time.Hour)
	r = h.update(t, false)
	if r.Outcome != Unchanged || r.Status.State != Fresh || !r.Status.CheckedAt.Equal(h.clock) {
		t.Fatalf("second update: %+v", r)
	}
	if got := h.src.gotPrev[1].ETag; got != `"etag-`+body(100, day1)+`"` {
		t.Errorf("second fetch sent ETag %q", got)
	}
}

func TestFailureKeepsCacheAndGoesStale(t *testing.T) {
	h := newHarness(t, fakeResp{body: body(100, day1)}, fakeResp{err: errors.New(`Get "https://example.com/x?key=s3cret": timeout`)})
	h.update(t, false)

	h.clock = h.clock.Add(time.Hour)
	r := h.update(t, false)
	if r.Outcome != Failed || r.Err == nil || r.Status.State != Fresh || r.Status.Count != 100 {
		t.Fatalf("failed update within threshold: %+v", r)
	}
	if strings.Contains(r.Status.LastError, "s3cret") {
		t.Errorf("stored error leaks a secret: %q", r.Status.LastError)
	}

	h.clock = h.clock.Add(48 * time.Hour)
	r = h.update(t, false)
	if r.Outcome != Failed || r.Status.State != Stale || r.Status.Count != 100 {
		t.Fatalf("failed update past threshold: %+v", r)
	}
	if h.cached(t) != body(100, day1) {
		t.Errorf("cache was changed by a failed update")
	}
}

func TestRejectedDataKeepsCache(t *testing.T) {
	tests := []struct {
		name string
		next fakeResp
	}{
		{"html error page", fakeResp{body: "<html>Service Unavailable</html>"}},
		{"truncated", fakeResp{body: `{"count": 1`}},
		{"missing field", fakeResp{body: `{"published":"` + day2 + `"}`}},
		{"empty", fakeResp{body: body(0, day2)}},
		{"shrunk more than 10%", fakeResp{body: body(89, day2)}},
		{"older than cached", fakeResp{body: body(100, day0)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t, fakeResp{body: body(100, day1)}, tt.next)
			h.update(t, false)
			r := h.update(t, false)
			if r.Outcome != Failed || !errors.Is(r.Err, ErrRejected) {
				t.Fatalf("want rejection, got %+v", r)
			}
			if h.cached(t) != body(100, day1) || r.Status.Count != 100 {
				t.Errorf("cache replaced by rejected data")
			}
		})
	}
}

func TestSmallShrinkAccepted(t *testing.T) {
	h := newHarness(t, fakeResp{body: body(100, day1)}, fakeResp{body: body(90, day2)})
	h.update(t, false)
	if r := h.update(t, false); r.Outcome != Updated || r.Status.Count != 90 {
		t.Fatalf("10%% shrink should be accepted: %+v", r)
	}
}

func TestFirstFetchRejectsEmpty(t *testing.T) {
	h := newHarness(t, fakeResp{body: body(0, day1)})
	r := h.update(t, false)
	if r.Outcome != Failed || r.Status.State != Missing {
		t.Fatalf("got %+v", r)
	}
}

func TestTamperedCacheIsMissingAndRefetchedInFull(t *testing.T) {
	h := newHarness(t, fakeResp{body: body(100, day1)}, fakeResp{body: body(100, day2)})
	h.update(t, false)
	if err := os.WriteFile(filepath.Join(h.u.CacheDir, "fake.json"), []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	sts, err := h.u.Statuses(context.Background())
	if err != nil || sts[0].State != Missing {
		t.Fatalf("Statuses = %+v, %v; want Missing", sts, err)
	}
	r := h.update(t, false)
	if r.Outcome != Updated || h.src.gotPrev[1] != (httpcache.Validators{}) {
		t.Fatalf("want a full refetch without validators: %+v, sent %+v", r, h.src.gotPrev[1])
	}
}

func TestNotModifiedWithoutCacheFails(t *testing.T) {
	h := newHarness(t, fakeResp{notModified: true})
	if r := h.update(t, false); r.Outcome != Failed || r.Status.State != Missing {
		t.Fatalf("got %+v", r)
	}
}

func TestOfflineNeverFetches(t *testing.T) {
	h := newHarness(t, fakeResp{body: body(100, day1)})
	if r := h.update(t, true); r.Outcome != Offline || r.Status.State != Missing {
		t.Fatalf("offline with no cache: %+v", r)
	}
	if h.src.calls != 0 {
		t.Fatalf("offline fetched %d times", h.src.calls)
	}
	h.update(t, false)
	h.clock = h.clock.Add(time.Hour)
	if r := h.update(t, true); r.Outcome != Offline || r.Status.State != Fresh {
		t.Fatalf("offline with fresh cache: %+v", r)
	}
	h.clock = h.clock.Add(72 * time.Hour)
	if r := h.update(t, true); r.Status.State != Stale {
		t.Fatalf("offline with old cache: %+v", r)
	}
	if h.src.calls != 1 {
		t.Errorf("offline runs fetched: %d calls", h.src.calls)
	}
}

func TestMirrorRecorded(t *testing.T) {
	h := newHarness(t, fakeResp{body: body(100, day1), via: ViaMirror})
	if r := h.update(t, false); r.Status.Via != ViaMirror {
		t.Fatalf("via = %q", r.Status.Via)
	}
}

func TestBusyLockFailsWithoutFetching(t *testing.T) {
	h := newHarness(t, fakeResp{body: body(100, day1)})
	h.u.Now = time.Now // the wait deadline needs a moving clock
	if ok, err := h.u.Store.AcquireLock(context.Background(), lockName, "someone-else", time.Hour); err != nil || !ok {
		t.Fatal(err)
	}
	r := h.update(t, false)
	if r.Outcome != Failed || !errors.Is(r.Err, ErrBusy) || h.src.calls != 0 {
		t.Fatalf("got %+v after %d fetches", r, h.src.calls)
	}
}

func TestWaitsForConcurrentRunAndReusesItsResult(t *testing.T) {
	h := newHarness(t, fakeResp{body: body(100, day1)})
	h.u.Now = time.Now
	h.u.LockWait = 5 * time.Second
	ctx := context.Background()
	if ok, err := h.u.Store.AcquireLock(ctx, lockName, "other", time.Hour); err != nil || !ok {
		t.Fatal(err)
	}
	// The "other process" refreshes the feed, then releases the lock.
	other := &Updater{Store: h.u.Store, CacheDir: h.u.CacheDir, Sources: h.u.Sources, Now: time.Now}
	go func() {
		time.Sleep(50 * time.Millisecond)
		if _, err := other.updateOne(ctx, h.src); err != nil {
			t.Error(err)
		}
		_ = h.u.Store.ReleaseLock(ctx, lockName, "other")
	}()

	r := h.update(t, false)
	if r.Outcome != ByOther || r.Status.State != Fresh {
		t.Fatalf("got %+v", r)
	}
	if h.src.calls != 1 {
		t.Errorf("feed fetched %d times, want once (by the other run)", h.src.calls)
	}
}

func TestReadCache(t *testing.T) {
	h := newHarness(t, fakeResp{body: body(100, day1)})
	ctx := context.Background()
	if _, _, err := h.u.ReadCache(ctx, "fake"); err == nil {
		t.Fatal("want error before first update")
	}
	h.update(t, false)
	data, st, err := h.u.ReadCache(ctx, "fake")
	if err != nil || string(data) != body(100, day1) || st.State != Fresh {
		t.Fatalf("ReadCache = %q, %+v, %v", data, st, err)
	}
	if _, _, err := h.u.ReadCache(ctx, "nope"); err == nil {
		t.Fatal("want error for unknown source")
	}
}

func TestValidateRejectsBadSourceNames(t *testing.T) {
	h := newHarness(t)
	h.u.Sources = []Source{badName{h.src}}
	if _, err := h.u.Update(context.Background(), true); err == nil {
		t.Fatal("want error for a source name that could escape the cache dir")
	}
}

type badName struct{ *fakeSource }

func (badName) Name() string { return "../evil" }
