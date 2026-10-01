package store

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// openTemp opens a store in a directory whose name has a space, as many
// Windows profile paths do.
func openTemp(t *testing.T) (*Store, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "my data")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "patchtacio.db")
	s, err := Open(context.Background(), file)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, file
}

func TestOpenMigratesOnceAndUsesWAL(t *testing.T) {
	ctx := context.Background()
	s, file := openTemp(t)
	ms, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	if v, err := s.userVersion(ctx); err != nil || v != len(ms) {
		t.Fatalf("user_version = %d, %v; want %d", v, err, len(ms))
	}
	var mode string
	if err := s.db.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&mode); err != nil || mode != "wal" {
		t.Errorf("journal_mode = %q, %v; want wal", mode, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// Re-opening must not re-run migrations (CREATE TABLE would fail).
	s2, err := Open(ctx, file)
	if err != nil {
		t.Fatalf("re-Open: %v", err)
	}
	_ = s2.Close()
}

func TestOpenRefusesNewerSchema(t *testing.T) {
	ctx := context.Background()
	s, file := openTemp(t)
	if _, err := s.db.ExecContext(ctx, "PRAGMA user_version = 999"); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()

	_, err := Open(ctx, file)
	if err == nil || !strings.Contains(err.Error(), "newer") {
		t.Fatalf("want a 'newer schema' error, got %v", err)
	}
}

func TestOpenRejectsURIMetacharacters(t *testing.T) {
	if _, err := Open(context.Background(), filepath.Join(t.TempDir(), "x?mode=ro")); err == nil {
		t.Fatal("want error for path containing '?'")
	}
}

func TestDatabaseFileIsPrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions only")
	}
	_, file := openTemp(t)
	fi, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("database permissions = %o, want no group/other access", perm)
	}
}

func TestFeedRoundTrip(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)

	if _, ok, err := s.GetFeed(ctx, "kev"); err != nil || ok {
		t.Fatalf("GetFeed on empty store = ok %v, err %v", ok, err)
	}

	ts := time.Date(2026, 9, 30, 16, 59, 23, 68_800_000, time.UTC)
	want := Feed{
		Name: "kev", URL: "https://example.com/kev.json", Via: "mirror",
		ETag: `"e-ssl"`, LastModified: "Wed, 30 Sep 2026 16:59:23 GMT",
		CacheFile: "kev.json", SHA256: "abc", RecordCount: 1730, Version: "2026.09.30",
		PublishedAt: ts, FetchedAt: ts.Add(time.Hour), CheckedAt: ts.Add(2 * time.Hour),
		AttemptedAt: ts.Add(3 * time.Hour), LastError: "",
	}
	if err := s.PutFeed(ctx, want); err != nil {
		t.Fatalf("PutFeed: %v", err)
	}
	got, ok, err := s.GetFeed(ctx, "kev")
	if err != nil || !ok {
		t.Fatalf("GetFeed = ok %v, err %v", ok, err)
	}
	if !got.PublishedAt.Equal(want.PublishedAt) || !got.CheckedAt.Equal(want.CheckedAt) {
		t.Errorf("times differ: got %+v", got)
	}
	got.PublishedAt, got.FetchedAt, got.CheckedAt, got.AttemptedAt = want.PublishedAt, want.FetchedAt, want.CheckedAt, want.AttemptedAt
	if got != want {
		t.Errorf("GetFeed = %+v\nwant %+v", got, want)
	}

	// Update in place; zero times round-trip as zero.
	upd := Feed{Name: "kev", AttemptedAt: ts, LastError: "timeout"}
	if err := s.PutFeed(ctx, upd); err != nil {
		t.Fatal(err)
	}
	got, _, _ = s.GetFeed(ctx, "kev")
	if !got.CheckedAt.IsZero() || got.LastError != "timeout" {
		t.Errorf("update not applied: %+v", got)
	}

	if err := s.PutFeed(ctx, Feed{Name: "eol"}); err != nil {
		t.Fatal(err)
	}
	all, err := s.ListFeeds(ctx)
	if err != nil || len(all) != 2 || all[0].Name != "eol" || all[1].Name != "kev" {
		t.Errorf("ListFeeds = %+v, %v", all, err)
	}
}

func TestLocks(t *testing.T) {
	ctx := context.Background()
	s, file := openTemp(t)
	// A second Store on the same file stands in for a second process.
	other, err := Open(ctx, file)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = other.Close() }()

	clock := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return clock }
	other.now = func() time.Time { return clock }
	const ttl = 5 * time.Minute

	mustAcquire := func(st *Store, owner string, want bool) {
		t.Helper()
		got, err := st.AcquireLock(ctx, "feeds-update", owner, ttl)
		if err != nil || got != want {
			t.Fatalf("AcquireLock(%s) = %v, %v; want %v", owner, got, err, want)
		}
	}

	mustAcquire(s, "A", true)
	mustAcquire(other, "B", false)
	mustAcquire(s, "A", true) // re-entrant refresh

	if ok, err := other.HeartbeatLock(ctx, "feeds-update", "B"); err != nil || ok {
		t.Errorf("non-owner heartbeat = %v, %v", ok, err)
	}
	if err := other.ReleaseLock(ctx, "feeds-update", "B"); err != nil {
		t.Fatal(err)
	}
	mustAcquire(other, "B", false) // B's release did not free A's lock

	if err := s.ReleaseLock(ctx, "feeds-update", "A"); err != nil {
		t.Fatal(err)
	}
	mustAcquire(other, "B", true)

	// B stalls past the TTL; A may take the lock over, and B learns of it.
	clock = clock.Add(ttl + time.Second)
	mustAcquire(s, "A", true)
	if ok, err := other.HeartbeatLock(ctx, "feeds-update", "B"); err != nil || ok {
		t.Errorf("stale owner heartbeat = %v, %v; want false", ok, err)
	}
}
