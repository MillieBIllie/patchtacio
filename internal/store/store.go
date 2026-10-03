// Package store is Patchtacio's SQLite database: feed cache metadata and
// cross-process locks (M1); findings, acknowledgements and alert deliveries (M3).
//
// It uses the pure-Go modernc.org/sqlite driver (CGO_ENABLED=0), WAL mode and
// a busy timeout so a scheduled check and a manual run can share the file.
// Schema changes are embedded SQL files applied in order and tracked with
// PRAGMA user_version.
package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"modernc.org/sqlite" // also registers the "sqlite" driver
	sqlite3 "modernc.org/sqlite/lib"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// setupDeadline bounds how long Open keeps retrying while another process
// is creating the database.
const setupDeadline = 15 * time.Second

// Store wraps the database. It is safe for concurrent use.
type Store struct {
	db  *sql.DB
	now func() time.Time
	dir string // the database's directory (install.key lives beside it)
}

// Open opens (creating if needed) the database at file and applies pending
// migrations. The directory must already exist.
func Open(ctx context.Context, file string) (*Store, error) {
	if strings.ContainsAny(file, "?#") {
		return nil, fmt.Errorf("database path %q must not contain '?' or '#'", file)
	}
	// Create the file ourselves so it is private to the user; SQLite would
	// otherwise create it with umask-dependent permissions.
	file = filepath.Clean(file) // from internal/paths, not user-supplied content
	f, err := os.OpenFile(file, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open database file: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("close database file: %w", err)
	}
	// O_CREATE's mode only applies to new files; tighten an existing one too.
	if err := os.Chmod(file, 0o600); err != nil {
		return nil, fmt.Errorf("set database file permissions: %w", err)
	}

	dsn := file + "?_txlock=immediate&_busy_timeout=10000&_journal_mode=WAL&_synchronous=NORMAL&_foreign_keys=1"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	// One connection per process: SQLite serialises writers anyway, and a
	// single connection avoids SQLITE_BUSY between our own goroutines.
	db.SetMaxOpenConns(1)

	s := &Store{db: db, now: time.Now, dir: filepath.Dir(file)}
	// While another process is creating the database and switching it to WAL,
	// SQLite can answer SQLITE_BUSY without honoring busy_timeout, so retry
	// setup until a fixed deadline (not an attempt count: each attempt may
	// itself wait out busy_timeout).
	deadline := time.Now().Add(setupDeadline)
	for attempt := 0; ; attempt++ {
		err = s.migrate(ctx)
		if err == nil || !isBusy(err) || time.Now().After(deadline) {
			break
		}
		t := time.NewTimer(time.Duration(min(20+attempt*10, 500)) * time.Millisecond)
		select {
		case <-ctx.Done():
			t.Stop()
			err = ctx.Err()
		case <-t.C:
			continue
		}
		break
	}
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func isBusy(err error) bool {
	if se, ok := errors.AsType[*sqlite.Error](err); ok {
		code := se.Code() & 0xff // primary result code
		return code == sqlite3.SQLITE_BUSY || code == sqlite3.SQLITE_LOCKED
	}
	return false
}

// Close closes the database.
func (s *Store) Close() error {
	if err := s.db.Close(); err != nil {
		return fmt.Errorf("close database: %w", err)
	}
	return nil
}

type migration struct {
	version int
	name    string
	sql     string
}

func loadMigrations() ([]migration, error) {
	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return nil, fmt.Errorf("read migrations: %w", err)
	}
	var ms []migration
	for _, e := range entries {
		var v int
		if _, err := fmt.Sscanf(e.Name(), "%04d_", &v); err != nil {
			return nil, fmt.Errorf("migration %s: name must start with a 4-digit version: %w", e.Name(), err)
		}
		b, err := migrationFS.ReadFile(path.Join("migrations", e.Name()))
		if err != nil {
			return nil, fmt.Errorf("read migration %s: %w", e.Name(), err)
		}
		ms = append(ms, migration{version: v, name: e.Name(), sql: string(b)})
	}
	sort.Slice(ms, func(i, j int) bool { return ms[i].version < ms[j].version })
	for i, m := range ms {
		if m.version != i+1 {
			return nil, fmt.Errorf("migrations must be numbered 1..n without gaps; found %s at position %d", m.name, i+1)
		}
	}
	return ms, nil
}

func (s *Store) migrate(ctx context.Context) error {
	ms, err := loadMigrations()
	if err != nil {
		return err
	}
	current, err := s.userVersion(ctx)
	if err != nil {
		return err
	}
	if current > len(ms) {
		return fmt.Errorf("database schema version %d is newer than this patchtacio supports (%d); upgrade patchtacio", current, len(ms))
	}
	for _, m := range ms[current:] {
		tx, err := s.db.BeginTx(ctx, nil) // BEGIN IMMEDIATE: one migrator at a time
		if err != nil {
			return fmt.Errorf("begin migration %s: %w", m.name, err)
		}
		// Another process may have applied it while we waited for the lock.
		var v int
		if err := tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&v); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("read schema version: %w", err)
		}
		if v >= m.version {
			_ = tx.Rollback()
			continue
		}
		if _, err := tx.ExecContext(ctx, m.sql); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("apply migration %s: %w", m.name, err)
		}
		// PRAGMA does not accept bound parameters; m.version is an int we parsed.
		if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", m.version)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("record migration %s: %w", m.name, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %s: %w", m.name, err)
		}
	}
	return nil
}

func (s *Store) userVersion(ctx context.Context) (int, error) {
	var v int
	if err := s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&v); err != nil {
		return 0, fmt.Errorf("read schema version: %w", err)
	}
	return v, nil
}

// Times are stored as RFC 3339 UTC text; the zero time is stored as NULL.

func timeArg(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func parseTime(ns sql.NullString) (time.Time, error) {
	if !ns.Valid || ns.String == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339Nano, ns.String)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse stored time %q: %w", ns.String, err)
	}
	return t, nil
}
