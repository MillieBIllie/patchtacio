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
	"unicode/utf8"

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
	onFetch   func() // runs during Fetch, e.g. to simulate another process
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
	if f.onFetch != nil {
		f.onFetch()
	}
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
	if !r.Status.LastUpdateFailed {
		t.Errorf("a failed attempt must be flagged even while the copy is fresh")
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
			// The source has newer data we refused: the saved copy is known to be behind.
			if r.Status.State != Stale || !strings.Contains(r.Status.StaleReason, "rejected") {
				t.Errorf("rejected update must make the copy stale: %+v", r.Status)
			}
		})
	}
}

func TestRejectionClearedBySuccess(t *testing.T) {
	h := newHarness(t, fakeResp{body: body(100, day1)}, fakeResp{body: body(50, day2)}, fakeResp{body: body(101, day2)})
	h.update(t, false)
	if r := h.update(t, false); r.Status.State != Stale {
		t.Fatalf("after rejection: %+v", r.Status)
	}
	if r := h.update(t, false); r.Outcome != Updated || r.Status.State != Fresh || r.Status.LastUpdateFailed {
		t.Fatalf("after a good update: %+v", r)
	}
}

func TestOldMirrorCopyIsStale(t *testing.T) {
	h := newHarness(t, fakeResp{body: body(100, day1), via: ViaMirror}, fakeResp{notModified: true, via: ViaMirror})
	if r := h.update(t, false); r.Status.State != Fresh {
		t.Fatalf("recent mirror copy: %+v", r.Status)
	}
	// The mirror keeps answering, but its copy is now 8 days old by its own date.
	h.clock = h.clock.Add(8 * 24 * time.Hour)
	r := h.update(t, false)
	if r.Status.State != Stale || !strings.Contains(r.Status.StaleReason, "mirror") {
		t.Fatalf("old mirror copy must be stale: %+v", r.Status)
	}
	if h.src.gotPrev[1] != (httpcache.Validators{}) {
		t.Errorf("mirror validators were reused: %+v", h.src.gotPrev[1])
	}
}

func TestWipedCacheStillBlocksOlderData(t *testing.T) {
	h := newHarness(t, fakeResp{body: body(100, day1)}, fakeResp{body: body(100, day0)})
	h.update(t, false)
	if err := os.Remove(filepath.Join(h.u.CacheDir, "fake.json")); err != nil {
		t.Fatal(err)
	}
	r := h.update(t, false)
	if r.Outcome != Failed || !errors.Is(r.Err, ErrRejected) {
		t.Fatalf("older data accepted after the cache was wiped: %+v", r)
	}
	if h.src.gotPrev[1] != (httpcache.Validators{}) {
		t.Errorf("validators sent without a cached copy: %+v", h.src.gotPrev[1])
	}
}

func TestFutureCheckTimeIsStale(t *testing.T) {
	h := newHarness(t, fakeResp{body: body(100, day1)})
	h.update(t, false)
	h.clock = h.clock.Add(-24 * time.Hour) // the clock was ahead and has been corrected
	sts, err := h.u.Statuses(context.Background())
	if err != nil || sts[0].State != Stale || !strings.Contains(sts[0].StaleReason, "clock") {
		t.Fatalf("Statuses = %+v, %v", sts, err)
	}
}

func TestStoredErrorIsBounded(t *testing.T) {
	h := newHarness(t, fakeResp{body: body(100, day1)}, fakeResp{err: errors.New(strings.Repeat("é", 10_000))})
	h.update(t, false)
	r := h.update(t, false)
	if len(r.Status.LastError) > maxErrorLen+len("…") || !utf8.ValidString(r.Status.LastError) {
		t.Errorf("stored error is %d bytes (valid UTF-8: %v)", len(r.Status.LastError), utf8.ValidString(r.Status.LastError))
	}
}

func TestJoinFirst(t *testing.T) {
	errs := make([]error, 25)
	for i := range errs {
		errs[i] = errors.New("e")
	}
	if got := JoinFirst(errs, 10).Error(); strings.Count(got, "e\n") != 10 || !strings.HasSuffix(got, "and 15 more") {
		t.Errorf("JoinFirst = %q", got)
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
		if _, err := other.updateOne(ctx, h.src, "other"); err != nil {
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

func TestLostLockWritesNothing(t *testing.T) {
	for name, next := range map[string]fakeResp{
		"new data":     {body: body(120, day2)},
		"fetch failed": {err: errors.New("connection reset")},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, fakeResp{body: body(100, day1)}, next)
			h.update(t, false)
			ctx := context.Background()
			// Mid-download, this run stalls past the lock TTL (a laptop sleeps);
			// another run takes the lock over and records its own result.
			h.src.onFetch = func() {
				if ok, err := h.u.Store.AcquireLock(ctx, lockName, "new-owner", 0); err != nil || !ok {
					t.Errorf("take over lock: %v, %v", ok, err)
				}
				if err := h.u.Store.PutFeedLocked(ctx, lockName, "new-owner", store.Feed{Name: "fake", Version: "new-owner"}); err != nil {
					t.Error(err)
				}
			}
			r := h.update(t, false)
			if r.Outcome != Failed || !errors.Is(r.Err, errLockLost) {
				t.Fatalf("got %+v", r)
			}
			if got, _, _ := h.u.Store.GetFeed(ctx, "fake"); got.Version != "new-owner" {
				t.Errorf("the run that lost the lock overwrote the new owner's record: %+v", got)
			}
			if h.cached(t) != body(100, day1) {
				t.Errorf("the run that lost the lock replaced the cache file")
			}
		})
	}
}

func TestAcceptShrink(t *testing.T) {
	h := newHarness(t, fakeResp{body: body(100, day1)}, fakeResp{body: body(50, day2)}, fakeResp{body: body(50, day2)})
	h.update(t, false)

	r := h.update(t, false)
	if !errors.Is(r.Err, ErrShrunk) || !errors.Is(r.Err, ErrRejected) {
		t.Fatalf("without the flag: want ErrShrunk+ErrRejected, got %+v", r)
	}
	if got, _, _ := h.u.Store.GetFeed(context.Background(), "fake"); got.ShrunkCount != 50 {
		t.Errorf("rejected count not recorded: ShrunkCount = %d", got.ShrunkCount)
	}
	h.u.AcceptShrink = []string{"fake"}
	r = h.update(t, false)
	if r.Outcome != Updated || r.Status.Count != 50 || r.Status.State != Fresh || r.ShrankFrom != 100 {
		t.Fatalf("with --accept-shrink: %+v", r)
	}
	if got, _, _ := h.u.Store.GetFeed(context.Background(), "fake"); got.ShrunkCount != 0 {
		t.Errorf("approval must be used up: ShrunkCount = %d", got.ShrunkCount)
	}
}

func TestAcceptShrinkOnlyApprovesTheShownReduction(t *testing.T) {
	h := newHarness(t, fakeResp{body: body(1400, day1)}, fakeResp{body: body(1000, day2)}, fakeResp{body: body(3, day2)})
	h.update(t, false)
	h.update(t, false) // rejected: the user is shown 1,000 records

	h.u.AcceptShrink = []string{"fake"}
	r := h.update(t, false) // but the server now returns 3
	if r.Outcome != Failed || !errors.Is(r.Err, ErrShrunk) || !strings.Contains(r.Err.Error(), "approved the download with 1000 records") {
		t.Fatalf("a different reduction must not be accepted: %+v", r)
	}
	if got, _, _ := h.u.Store.GetFeed(context.Background(), "fake"); got.RecordCount != 1400 {
		t.Errorf("saved copy replaced: %+v", got)
	}
}

func TestAcceptShrinkWithoutEarlierRejectionDoesNothing(t *testing.T) {
	h := newHarness(t, fakeResp{body: body(100, day1)}, fakeResp{body: body(50, day2)})
	h.update(t, false)
	h.u.AcceptShrink = []string{"fake"}
	r := h.update(t, false)
	if r.Outcome != Failed || !strings.Contains(r.Err.Error(), "there was none") {
		t.Fatalf("got %+v", r)
	}
}

func TestAcceptShrinkKeepsOtherChecks(t *testing.T) {
	h := newHarness(t, fakeResp{body: body(100, day1)}, fakeResp{body: body(50, day2)},
		fakeResp{body: body(50, day0)}, fakeResp{body: body(0, day2)})
	h.update(t, false)
	h.update(t, false) // shown: 50 records
	h.u.AcceptShrink = []string{"fake"}
	if r := h.update(t, false); !errors.Is(r.Err, ErrRejected) || errors.Is(r.Err, ErrShrunk) {
		t.Errorf("older data must still be rejected: %+v", r)
	}
	if r := h.update(t, false); !errors.Is(r.Err, ErrRejected) {
		t.Errorf("an empty feed must still be rejected: %+v", r)
	}
}

func TestLeftoverTempFilesCleaned(t *testing.T) {
	h := newHarness(t, fakeResp{body: body(100, day1)})
	old := filepath.Join(h.u.CacheDir, "fake.json.tmp-1234567")
	recent := filepath.Join(h.u.CacheDir, "fake.json.tmp-7654321")
	for _, f := range []string{old, recent} {
		if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	past := time.Now().Add(-time.Hour)
	if err := os.Chtimes(old, past, past); err != nil {
		t.Fatal(err)
	}
	h.update(t, false)
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Errorf("leftover temp file not removed: %v", err)
	}
	if _, err := os.Stat(recent); err != nil {
		t.Errorf("a recent temp file (maybe another run's) was removed: %v", err)
	}
}

func TestCheckAcceptShrink(t *testing.T) {
	h := newHarness(t)
	h.u.AcceptShrink = []string{"fake"}
	if err := h.u.CheckAcceptShrink(); err != nil {
		t.Errorf("known source: %v", err)
	}
	h.u.AcceptShrink = []string{"kve"}
	if err := h.u.CheckAcceptShrink(); err == nil || !strings.Contains(err.Error(), "fake") {
		t.Errorf("a typo must be refused and list the valid names: %v", err)
	}
}

func TestLostLockAfterCacheWriteFailsSafe(t *testing.T) {
	h := newHarness(t, fakeResp{body: body(100, day1)}, fakeResp{body: body(120, day2)})
	h.update(t, false)
	ctx := context.Background()
	// The lock is lost in the one-rename window between replacing the file
	// and saving its metadata.
	h.u.afterCommit = func() {
		if ok, err := h.u.Store.AcquireLock(ctx, lockName, "new-owner", 0); err != nil || !ok {
			t.Errorf("take over lock: %v, %v", ok, err)
		}
	}
	r := h.update(t, false)
	if r.Outcome != Failed || !errors.Is(r.Err, errLockLost) {
		t.Fatalf("got %+v", r)
	}
	got, _, _ := h.u.Store.GetFeed(ctx, "fake")
	if got.RecordCount != 100 {
		t.Errorf("metadata was written without the lock: %+v", got)
	}
	// File and metadata now disagree, which must read as Missing (so the
	// next run downloads again), never as a fresh copy.
	if r.Status.State != Missing {
		t.Errorf("state = %s, want missing", r.Status.State)
	}
}

func TestFailAfterLockLostWritesNothing(t *testing.T) {
	h := newHarness(t, fakeResp{body: body(100, day1)})
	h.update(t, false)
	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(errLockLost)

	meta, _, _ := h.u.Store.GetFeed(context.Background(), "fake")
	before := meta
	meta.LastError = "should not be stored"
	r, err := h.u.fail(ctx, h.src, meta, "us", errors.New("download interrupted"))
	if err != nil || r.Outcome != Failed || !errors.Is(r.Err, errLockLost) {
		t.Fatalf("fail = %+v, %v", r, err)
	}
	if after, _, _ := h.u.Store.GetFeed(context.Background(), "fake"); after != before {
		t.Errorf("fail wrote after the lock was lost:\nbefore %+v\nafter  %+v", before, after)
	}
}

// secondSource is a fakeSource with a different name.
type secondSource struct{ *fakeSource }

func (secondSource) Name() string { return "second" }

func TestLostLockSkipsRemainingSources(t *testing.T) {
	h := newHarness(t, fakeResp{body: body(100, day1)})
	second := secondSource{&fakeSource{responses: []fakeResp{{body: body(5, day1)}}}}
	h.u.Sources = []Source{h.src, second}
	ctx := context.Background()
	h.src.onFetch = func() {
		if ok, err := h.u.Store.AcquireLock(ctx, lockName, "new-owner", 0); err != nil || !ok {
			t.Errorf("take over lock: %v, %v", ok, err)
		}
	}
	rs, err := h.u.Update(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	for i, r := range rs {
		if r.Outcome != Failed || !errors.Is(r.Err, errLockLost) {
			t.Errorf("result %d: %+v", i, r)
		}
	}
	if second.calls != 0 {
		t.Errorf("second source was downloaded %d times after the lock was lost", second.calls)
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
