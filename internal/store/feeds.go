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
	// Rejected means the source offered newer data that failed validation, so
	// the cached copy is known to be behind what the source now publishes.
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

// PutFeed inserts or replaces the metadata row for f.Name.
func (s *Store) PutFeed(ctx context.Context, f Feed) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO feeds (`+feedColumns+`)
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
