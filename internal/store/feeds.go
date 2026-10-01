package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Feed is the metadata for one cached feed. Zero times mean "never".
type Feed struct {
	Name         string
	URL          string
	Via          string // "primary" or "mirror"
	ETag         string
	LastModified string
	CacheFile    string
	SHA256       string
	RecordCount  int
	Version      string
	PublishedAt  time.Time
	FetchedAt    time.Time
	CheckedAt    time.Time
	AttemptedAt  time.Time
	LastError    string
	// Rejected means the source's latest answer failed validation (newer
	// data in a form we cannot accept, or a block page instead of data), so
	// the cached copy is treated as behind what the source now publishes.
	Rejected bool
}

const feedColumns = `name, url, via, etag, last_modified, cache_file, sha256, record_count,
	version, published_at, fetched_at, checked_at, attempted_at, last_error, rejected`

// GetFeed returns the metadata for name; ok is false if there is none.
func (s *Store) GetFeed(ctx context.Context, name string) (f Feed, ok bool, err error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+feedColumns+` FROM feeds WHERE name = ?`, name)
	f, err = scanFeed(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Feed{}, false, nil
	}
	if err != nil {
		return Feed{}, false, fmt.Errorf("get feed %s: %w", name, err)
	}
	return f, true, nil
}

// ListFeeds returns metadata for every feed that has ever been attempted.
func (s *Store) ListFeeds(ctx context.Context) ([]Feed, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+feedColumns+` FROM feeds ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list feeds: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Feed
	for rows.Next() {
		f, err := scanFeed(rows)
		if err != nil {
			return nil, fmt.Errorf("list feeds: %w", err)
		}
		out = append(out, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list feeds: %w", err)
	}
	return out, nil
}

// ErrLockNotHeld is returned by PutFeedLocked when the caller no longer holds
// the lock (another process took it over).
var ErrLockNotHeld = errors.New("lock not held")

// PutFeed inserts or replaces the metadata row for f.Name.
func (s *Store) PutFeed(ctx context.Context, f Feed) error {
	return putFeed(ctx, s.db, f)
}

// PutFeedLocked is PutFeed, but only if owner still holds lockName, checked
// in the same transaction. A process that lost its lock (for example after a
// laptop slept mid-update) can then never overwrite the new owner's result.
func (s *Store) PutFeedLocked(ctx context.Context, lockName, owner string, f Feed) error {
	tx, err := s.db.BeginTx(ctx, nil) // BEGIN IMMEDIATE via _txlock
	if err != nil {
		return fmt.Errorf("save feed %s: %w", f.Name, err)
	}
	defer func() { _ = tx.Rollback() }()
	var one int
	err = tx.QueryRowContext(ctx, `SELECT 1 FROM locks WHERE name = ? AND owner = ?`, lockName, owner).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("save feed %s: %w", f.Name, ErrLockNotHeld)
	}
	if err != nil {
		return fmt.Errorf("save feed %s: %w", f.Name, err)
	}
	if err := putFeed(ctx, tx, f); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("save feed %s: %w", f.Name, err)
	}
	return nil
}

type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func putFeed(ctx context.Context, db execer, f Feed) error {
	_, err := db.ExecContext(ctx, `INSERT INTO feeds (`+feedColumns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(name) DO UPDATE SET
			url = excluded.url, via = excluded.via, etag = excluded.etag,
			last_modified = excluded.last_modified, cache_file = excluded.cache_file,
			sha256 = excluded.sha256, record_count = excluded.record_count,
			version = excluded.version, published_at = excluded.published_at,
			fetched_at = excluded.fetched_at, checked_at = excluded.checked_at,
			attempted_at = excluded.attempted_at, last_error = excluded.last_error,
			rejected = excluded.rejected`,
		f.Name, f.URL, f.Via, f.ETag, f.LastModified, f.CacheFile, f.SHA256, f.RecordCount,
		f.Version, timeArg(f.PublishedAt), timeArg(f.FetchedAt), timeArg(f.CheckedAt),
		timeArg(f.AttemptedAt), f.LastError, f.Rejected)
	if err != nil {
		return fmt.Errorf("save feed %s: %w", f.Name, err)
	}
	return nil
}

type scanner interface{ Scan(dest ...any) error }

func scanFeed(sc scanner) (Feed, error) {
	var f Feed
	var published, fetched, checked, attempted sql.NullString
	if err := sc.Scan(&f.Name, &f.URL, &f.Via, &f.ETag, &f.LastModified, &f.CacheFile, &f.SHA256,
		&f.RecordCount, &f.Version, &published, &fetched, &checked, &attempted, &f.LastError, &f.Rejected); err != nil {
		return Feed{}, err // callers wrap with context
	}
	var err error
	for _, p := range []struct {
		dst *time.Time
		src sql.NullString
	}{{&f.PublishedAt, published}, {&f.FetchedAt, fetched}, {&f.CheckedAt, checked}, {&f.AttemptedAt, attempted}} {
		if *p.dst, err = parseTime(p.src); err != nil {
			return Feed{}, err
		}
	}
	return f, nil
}
