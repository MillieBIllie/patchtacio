package feeds

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/milliebillie/patchtacio/internal/httpcache"
	"github.com/milliebillie/patchtacio/internal/logging"
	"github.com/milliebillie/patchtacio/internal/store"
)

const (
	lockName         = "feeds-update"
	defaultLockWait  = 60 * time.Second
	defaultLockTTL   = 5 * time.Minute
	defaultPollEvery = time.Second
)

// ErrBusy means another Patchtacio process kept the update lock for longer
// than the Updater was willing to wait.
var ErrBusy = errors.New("another patchtacio update is still running")

// Outcome is what an update did for one source.
type Outcome string

// Outcomes of Updater.Update.
const (
	Updated   Outcome = "updated"   // new data replaced the cached copy
	Unchanged Outcome = "unchanged" // the server said nothing changed
	ByOther   Outcome = "by-other"  // a concurrent run refreshed it while we waited
	Failed    Outcome = "failed"    // not refreshed; the cached copy (if any) was kept
	Offline   Outcome = "offline"   // no network use was attempted
)

// Refreshed reports whether the source was successfully brought up to date.
func (o Outcome) Refreshed() bool { return o == Updated || o == Unchanged || o == ByOther }

// Result is the outcome of updating one source.
type Result struct {
	Outcome Outcome
	Err     error // set when Outcome is Failed
	Status  Status
	// ShrankFrom is the previous record count when an --accept-shrink update
	// replaced a larger saved copy (0 otherwise), so the CLI can say so.
	ShrankFrom int
}

// Updater refreshes sources and reports their status.
type Updater struct {
	Store    *store.Store
	Client   *httpcache.Client
	CacheDir string
	Sources  []Source
	Logger   *slog.Logger
	Now      func() time.Time

	LockWait  time.Duration // how long to wait for a concurrent update (default 60s)
	LockTTL   time.Duration // when a lock with no heartbeat counts as abandoned (default 5m)
	PollEvery time.Duration // how often to retry the lock while waiting (default 1s)

	// AcceptShrink names sources whose next download may have more than
	// MaxShrink fewer records than the saved copy. It is for a reduction the
	// user has confirmed is real; every other check still applies.
	AcceptShrink []string

	afterCommit func() // test hook: runs between the cache rename and the metadata save
}

func (u *Updater) acceptsShrink(src Source) bool { return slices.Contains(u.AcceptShrink, src.Name()) }

// CheckAcceptShrink reports an AcceptShrink entry that names no source, so
// a typo cannot silently do nothing.
func (u *Updater) CheckAcceptShrink() error {
	for _, name := range u.AcceptShrink {
		if !slices.ContainsFunc(u.Sources, func(s Source) bool { return s.Name() == name }) {
			names := make([]string, len(u.Sources))
			for i, s := range u.Sources {
				names[i] = s.Name()
			}
			return fmt.Errorf("unknown source %q for --accept-shrink (choose from: %s)", name, strings.Join(names, ", "))
		}
	}
	return nil
}

func (u *Updater) now() time.Time {
	if u.Now != nil {
		return u.Now()
	}
	return time.Now()
}

func (u *Updater) logger() *slog.Logger {
	if u.Logger != nil {
		return u.Logger
	}
	return slog.New(slog.DiscardHandler)
}

// Update refreshes every source. With offline set it touches no network and
// reports the cached state. The returned error is for local failures (the
// database, the cache directory); per-source problems are in each Result.
func (u *Updater) Update(ctx context.Context, offline bool) ([]Result, error) {
	if err := checkSources(u.Sources); err != nil {
		return nil, err
	}
	if offline {
		return u.resultsWithoutFetching(ctx, Offline, nil)
	}

	owner, err := newOwner()
	if err != nil {
		return nil, err
	}
	waitStart := u.now()
	waited, err := u.acquire(ctx, owner)
	if errors.Is(err, ErrBusy) {
		return u.resultsWithoutFetching(ctx, Failed, err)
	}
	if err != nil {
		return nil, err
	}
	defer func() {
		// Release even if ctx was cancelled (Ctrl-C), so the next run need not wait.
		if err := u.Store.ReleaseLock(context.WithoutCancel(ctx), lockName, owner); err != nil {
			u.logger().Warn("could not release update lock", "err", err)
		}
	}()
	// If the lock is taken over (we stalled past its TTL), stop: another run
	// is now updating and two writers must not interleave.
	ctx, cancelUpdate := context.WithCancelCause(ctx)
	defer cancelUpdate(nil)
	stopBeat := u.heartbeat(ctx, owner, cancelUpdate)
	defer stopBeat()
	u.cleanTempFiles()

	results := make([]Result, 0, len(u.Sources))
	for _, src := range u.Sources {
		if c := context.Cause(ctx); errors.Is(c, errLockLost) {
			// Another run owns the update now; report, but touch nothing.
			meta, _, err := u.Store.GetFeed(context.WithoutCancel(ctx), src.Name())
			if err != nil {
				return nil, fmt.Errorf("read %s metadata: %w", src.Name(), err)
			}
			meta.Name = src.Name()
			results = append(results, Result{Outcome: Failed, Err: c, Status: u.status(src, meta)})
			continue
		}
		if waited {
			meta, ok, err := u.Store.GetFeed(ctx, src.Name())
			if err != nil {
				return nil, fmt.Errorf("read %s metadata: %w", src.Name(), err)
			}
			if ok && meta.CheckedAt.After(waitStart) {
				results = append(results, Result{Outcome: ByOther, Status: u.status(src, meta)})
				continue
			}
		}
		r, err := u.updateOne(ctx, src, owner)
		if err != nil {
			return nil, err
		}
		if errors.Is(r.Err, errLockLost) {
			cancelUpdate(errLockLost) // don't download the remaining sources for nothing
		}
		results = append(results, r)
	}
	return results, nil
}

// acquire takes the update lock, waiting up to LockWait. waited reports
// whether another process held it first.
func (u *Updater) acquire(ctx context.Context, owner string) (waited bool, err error) {
	ttl := orDefault(u.LockTTL, defaultLockTTL)
	deadline := u.now().Add(orDefault(u.LockWait, defaultLockWait))
	for {
		ok, err := u.Store.AcquireLock(ctx, lockName, owner, ttl)
		if err != nil {
			return waited, fmt.Errorf("take update lock: %w", err)
		}
		if ok {
			return waited, nil
		}
		if !waited {
			u.logger().Info("waiting for another patchtacio update to finish")
		}
		waited = true
		if u.now().After(deadline) {
			return waited, ErrBusy
		}
		t := time.NewTimer(orDefault(u.PollEvery, defaultPollEvery))
		select {
		case <-ctx.Done():
			t.Stop()
			return waited, fmt.Errorf("waiting for update lock: %w", ctx.Err())
		case <-t.C:
		}
	}
}

// errLockLost cancels an update whose lock another process took over.
var errLockLost = errors.New("the update lock was taken over by another patchtacio run")

// heartbeat keeps the lock alive during long downloads, and calls lost if the
// lock has been taken over.
func (u *Updater) heartbeat(ctx context.Context, owner string, lost context.CancelCauseFunc) (stop func()) {
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		t := time.NewTicker(orDefault(u.LockTTL, defaultLockTTL) / 5)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				ok, err := u.Store.HeartbeatLock(ctx, lockName, owner)
				switch {
				case err != nil:
					u.logger().Warn("update lock heartbeat failed", "err", err)
				case !ok:
					u.logger().Warn("update lock was taken over; stopping this update")
					lost(errLockLost)
					return
				}
			}
		}
	}()
	return func() { cancel(); <-done }
}

func (u *Updater) resultsWithoutFetching(ctx context.Context, o Outcome, cause error) ([]Result, error) {
	sts, err := u.Statuses(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Result, len(sts))
	for i, st := range sts {
		out[i] = Result{Outcome: o, Err: cause, Status: st}
	}
	return out, nil
}

// updateOne refreshes src. owner is this run's lock owner: every write checks
// the lock is still ours, so a run that stalled past the lock TTL cannot
// overwrite the result of the run that took over.
func (u *Updater) updateOne(ctx context.Context, src Source, owner string) (Result, error) {
	meta, _, err := u.Store.GetFeed(ctx, src.Name())
	if err != nil {
		return Result{}, fmt.Errorf("read %s metadata: %w", src.Name(), err)
	}
	meta.Name = src.Name()
	cacheOK := u.cacheValid(src, meta)

	// Compare against what we last accepted even if the cache file has since
	// been deleted: a wiped cache must not let an older or shrunken copy in.
	var prev *Summary
	if meta.RecordCount > 0 {
		prev = &Summary{Count: meta.RecordCount, Version: meta.Version, PublishedAt: meta.PublishedAt}
	}
	// Validators are only meaningful to the server that issued them, and a
	// 304 is only useful if we still have the bytes. Mirror validators are
	// never sent to the primary.
	var validators httpcache.Validators
	if cacheOK && meta.Via != ViaMirror {
		validators = httpcache.Validators{ETag: meta.ETag, LastModified: meta.LastModified}
	}

	now := u.now()
	meta.AttemptedAt = now
	log := u.logger().With("source", src.Name())
	log.Info("checking for updates")

	f, err := src.Fetch(ctx, u.Client, validators)
	if err != nil {
		return u.fail(ctx, src, meta, owner, err)
	}
	if f.NotModified {
		if !cacheOK {
			return u.fail(ctx, src, meta, owner, errors.New("server reported no change, but there is no valid cached copy"))
		}
		meta.CheckedAt, meta.Via = now, f.Via
		meta.ETag, meta.LastModified = f.ETag, f.LastModified
		meta.LastError, meta.Rejected, meta.ShrunkCount = "", false, 0
		if err := u.save(ctx, owner, meta); err != nil {
			return u.lockLostOr(ctx, src, err)
		}
		log.Info("not modified")
		return Result{Outcome: Unchanged, Status: u.status(src, meta)}, nil
	}

	sum, err := src.Parse(f.Body)
	if err != nil {
		return u.fail(ctx, src, meta, owner, fmt.Errorf("%w: %w", ErrRejected, err))
	}
	// --accept-shrink approves the reduction the user was shown (recorded in
	// ShrunkCount when it was rejected), not whatever the server says now.
	approved := u.acceptsShrink(src) && approvedShrink(meta.ShrunkCount, sum.Count)
	if err := validateFor(prev, sum, approved); err != nil {
		if errors.Is(err, ErrShrunk) {
			if u.acceptsShrink(src) {
				err = shrinkNotApproved(err, meta.ShrunkCount, sum.Count)
			}
			meta.ShrunkCount = sum.Count // the reduction now shown to the user
		}
		return u.fail(ctx, src, meta, owner, err)
	}
	shrankFrom := 0
	if approved && prev != nil && sum.Count < prev.Count {
		shrankFrom = prev.Count
		log.Warn("accepting a smaller feed as requested", "from", prev.Count, "to", sum.Count)
	}

	// Do the slow part (write + sync) first, then check the lock immediately
	// before the atomic rename. The remaining window is one rename; if the
	// lock is lost inside it, the mismatched file reads as Missing and the
	// next update downloads it again (fails safe).
	name := cacheFileName(src)
	pending, err := prepareFile(u.CacheDir, name, f.Body)
	if err != nil {
		return Result{}, fmt.Errorf("write %s cache: %w", src.Name(), err)
	}
	if held, err := u.Store.HeartbeatLock(context.WithoutCancel(ctx), lockName, owner); err != nil || !held {
		pending.Abort()
		if err == nil {
			err = errLockLost
		}
		return u.lockLostOr(ctx, src, err)
	}
	if err := pending.Commit(); err != nil {
		return Result{}, fmt.Errorf("write %s cache: %w", src.Name(), err)
	}
	if u.afterCommit != nil {
		u.afterCommit()
	}
	digest := sha256.Sum256(f.Body)
	meta.URL, meta.Via = logging.RedactString(f.URL), f.Via
	meta.ETag, meta.LastModified = f.ETag, f.LastModified
	meta.CacheFile, meta.SHA256 = name, hex.EncodeToString(digest[:])
	meta.RecordCount, meta.Version, meta.PublishedAt = sum.Count, sum.Version, sum.PublishedAt
	meta.FetchedAt, meta.CheckedAt, meta.LastError, meta.Rejected = now, now, "", false
	meta.ShrunkCount = 0
	if err := u.save(ctx, owner, meta); err != nil {
		return u.lockLostOr(ctx, src, err)
	}
	log.Info("updated", "records", sum.Count, "version", sum.Version, "via", f.Via)
	return Result{Outcome: Updated, Status: u.status(src, meta), ShrankFrom: shrankFrom}, nil
}

// approvedShrink reports whether a download of got records matches, within
// MaxShrink, the shrunken download of shown records the user approved.
func approvedShrink(shown, got int) bool {
	if shown <= 0 {
		return false
	}
	diff := got - shown
	if diff < 0 {
		diff = -diff
	}
	return float64(diff) <= MaxShrink*float64(shown)
}

func shrinkNotApproved(err error, shown, got int) error {
	if shown <= 0 {
		return fmt.Errorf("%w (--accept-shrink only accepts a reduction you were already warned about; "+
			"there was none, so run `feeds update` without it first)", err)
	}
	return fmt.Errorf("%w (--accept-shrink approved the download with %d records, but this one has %d, "+
		"so it was not accepted; check the source again)", err, shown, got)
}

// cleanTempFiles removes temp files left by a run that was killed between
// writing and renaming. Only files older than the lock TTL are touched, so
// a concurrent run's in-progress file is never removed.
func (u *Updater) cleanTempFiles() {
	matches, err := filepath.Glob(filepath.Join(u.CacheDir, "*.json.tmp-*"))
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-orDefault(u.LockTTL, defaultLockTTL))
	for _, m := range matches {
		if fi, err := os.Stat(m); err == nil && fi.Mode().IsRegular() && fi.ModTime().Before(cutoff) {
			if err := os.Remove(m); err == nil {
				u.logger().Debug("removed leftover temp file", "file", filepath.Base(m))
			}
		}
	}
}

// fail records why src could not be refreshed and keeps the cached copy.
func (u *Updater) fail(ctx context.Context, src Source, meta Feed, owner string, cause error) (Result, error) {
	if c := context.Cause(ctx); errors.Is(c, errLockLost) {
		return u.lockLostOr(ctx, src, c) // the new owner's record wins; write nothing
	}
	meta.LastError = truncate(logging.RedactString(cause.Error()), maxErrorLen)
	if errors.Is(cause, ErrRejected) {
		// The source offered data that failed validation (newer data in a
		// form we cannot accept, or a block page): treat our copy as behind.
		// A plain network failure leaves this unchanged.
		meta.Rejected = true
	}
	if err := u.save(ctx, owner, meta); err != nil {
		return u.lockLostOr(ctx, src, err)
	}
	// Info, not Warn: the CLI prints its own plain-language warning for this.
	u.logger().Info("could not refresh", "source", src.Name(), "err", cause)
	return Result{Outcome: Failed, Err: cause, Status: u.status(src, meta)}, nil
}

// save stores meta only if this run still holds the update lock. Writes are
// not cancelled by ctx, so Ctrl-C cannot leave a cache file without metadata.
func (u *Updater) save(ctx context.Context, owner string, meta Feed) error {
	err := u.Store.PutFeedLocked(context.WithoutCancel(ctx), lockName, owner, meta)
	if errors.Is(err, store.ErrLockNotHeld) {
		return errLockLost
	}
	if err != nil {
		return fmt.Errorf("save %s metadata: %w", meta.Name, err)
	}
	return nil
}

// lockLostOr turns a lost lock into a Failed result reported from the stored
// (new owner's) state; any other error is a local failure.
func (u *Updater) lockLostOr(ctx context.Context, src Source, err error) (Result, error) {
	if !errors.Is(err, errLockLost) {
		return Result{}, err
	}
	meta, _, gerr := u.Store.GetFeed(context.WithoutCancel(ctx), src.Name())
	if gerr != nil {
		return Result{}, fmt.Errorf("read %s metadata: %w", src.Name(), gerr)
	}
	meta.Name = src.Name()
	u.logger().Warn("stopped: another patchtacio run took over the update", "source", src.Name())
	return Result{Outcome: Failed, Err: errLockLost, Status: u.status(src, meta)}, nil
}

// Feed is the stored metadata row for a source.
type Feed = store.Feed

func cacheFileName(src Source) string { return src.Name() + ".json" }

// cacheValid reports whether the cached file exists and matches its recorded
// digest. A missing or altered file means there is no usable cache.
func (u *Updater) cacheValid(src Source, meta Feed) bool {
	_, err := u.readCache(src, meta)
	return err == nil
}

func (u *Updater) readCache(src Source, meta Feed) ([]byte, error) {
	if meta.SHA256 == "" || meta.CacheFile == "" {
		return nil, errors.New("no cached copy")
	}
	// Always derive the file name from the source, never trust the stored one.
	data, err := os.ReadFile(filepath.Join(u.CacheDir, cacheFileName(src)))
	if err != nil {
		return nil, fmt.Errorf("read cached copy: %w", err)
	}
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != meta.SHA256 {
		return nil, errors.New("cached copy does not match its recorded checksum")
	}
	return data, nil
}

// ReadCache returns the cached raw bytes for the named source and its status.
// It fails if there is no valid cached copy.
func (u *Updater) ReadCache(ctx context.Context, name string) ([]byte, Status, error) {
	for _, src := range u.Sources {
		if src.Name() != name {
			continue
		}
		meta, _, err := u.Store.GetFeed(ctx, name)
		if err != nil {
			return nil, Status{}, fmt.Errorf("read %s metadata: %w", name, err)
		}
		meta.Name = name
		data, err := u.readCache(src, meta)
		if err != nil {
			return nil, u.status(src, meta), fmt.Errorf("%s: %w", src.Title(), err)
		}
		return data, u.status(src, meta), nil
	}
	return nil, Status{}, fmt.Errorf("unknown source %q", name)
}

func newOwner() (string, error) {
	host, err := os.Hostname()
	if err != nil {
		host = "unknown-host"
	}
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate lock owner id: %w", err)
	}
	return fmt.Sprintf("%s:%d:%x", host, os.Getpid(), b), nil
}

// maxErrorLen bounds a stored error: a body with thousands of malformed
// records must not produce a multi-megabyte database row or terminal line.
const maxErrorLen = 2048

// truncate cuts s to at most n bytes on a rune boundary.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

func orDefault(d, def time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return def
}
