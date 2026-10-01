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
	"time"

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
	stopBeat := u.heartbeat(ctx, owner)
	defer stopBeat()

	results := make([]Result, 0, len(u.Sources))
	for _, src := range u.Sources {
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
		r, err := u.updateOne(ctx, src)
		if err != nil {
			return nil, err
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

// heartbeat keeps the lock alive during long downloads.
func (u *Updater) heartbeat(ctx context.Context, owner string) (stop func()) {
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
				if ok, err := u.Store.HeartbeatLock(ctx, lockName, owner); err != nil || !ok {
					u.logger().Warn("update lock heartbeat failed", "held", ok, "err", err)
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

func (u *Updater) updateOne(ctx context.Context, src Source) (Result, error) {
	meta, _, err := u.Store.GetFeed(ctx, src.Name())
	if err != nil {
		return Result{}, fmt.Errorf("read %s metadata: %w", src.Name(), err)
	}
	meta.Name = src.Name()
	cacheOK := u.cacheValid(src, meta)

	var prev *Summary
	var validators httpcache.Validators
	if cacheOK {
		prev = &Summary{Count: meta.RecordCount, Version: meta.Version, PublishedAt: meta.PublishedAt}
		validators = httpcache.Validators{ETag: meta.ETag, LastModified: meta.LastModified}
	}

	now := u.now()
	meta.AttemptedAt = now
	log := u.logger().With("source", src.Name())
	log.Info("checking for updates")

	f, err := src.Fetch(ctx, u.Client, validators)
	if err != nil {
		return u.fail(ctx, src, meta, err)
	}
	if f.NotModified {
		if !cacheOK {
			return u.fail(ctx, src, meta, errors.New("server reported no change, but there is no valid cached copy"))
		}
		meta.CheckedAt = now
		meta.ETag, meta.LastModified = f.ETag, f.LastModified
		meta.LastError = ""
		if err := u.Store.PutFeed(ctx, meta); err != nil {
			return Result{}, fmt.Errorf("save %s metadata: %w", src.Name(), err)
		}
		log.Info("not modified")
		return Result{Outcome: Unchanged, Status: u.status(src, meta)}, nil
	}

	sum, err := src.Parse(f.Body)
	if err != nil {
		return u.fail(ctx, src, meta, fmt.Errorf("%w: %w", ErrRejected, err))
	}
	if err := Validate(prev, sum); err != nil {
		return u.fail(ctx, src, meta, err)
	}
	name := cacheFileName(src)
	if err := writeFileAtomic(u.CacheDir, name, f.Body); err != nil {
		return Result{}, fmt.Errorf("write %s cache: %w", src.Name(), err)
	}
	digest := sha256.Sum256(f.Body)
	meta.URL, meta.Via = logging.RedactString(f.URL), f.Via
	meta.ETag, meta.LastModified = f.ETag, f.LastModified
	meta.CacheFile, meta.SHA256 = name, hex.EncodeToString(digest[:])
	meta.RecordCount, meta.Version, meta.PublishedAt = sum.Count, sum.Version, sum.PublishedAt
	meta.FetchedAt, meta.CheckedAt, meta.LastError = now, now, ""
	if err := u.Store.PutFeed(ctx, meta); err != nil {
		return Result{}, fmt.Errorf("save %s metadata: %w", src.Name(), err)
	}
	log.Info("updated", "records", sum.Count, "version", sum.Version, "via", f.Via)
	return Result{Outcome: Updated, Status: u.status(src, meta)}, nil
}

// fail records why src could not be refreshed and keeps the cached copy.
func (u *Updater) fail(ctx context.Context, src Source, meta Feed, cause error) (Result, error) {
	meta.LastError = logging.RedactString(cause.Error())
	if err := u.Store.PutFeed(context.WithoutCancel(ctx), meta); err != nil {
		return Result{}, fmt.Errorf("save %s metadata: %w", src.Name(), err)
	}
	u.logger().Warn("could not refresh", "source", src.Name(), "err", cause)
	return Result{Outcome: Failed, Err: cause, Status: u.status(src, meta)}, nil
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

func orDefault(d, def time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return def
}
