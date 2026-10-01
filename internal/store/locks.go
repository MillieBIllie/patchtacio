package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// AcquireLock takes the named lock for owner unless another owner holds it
// with a heartbeat newer than ttl. It never blocks; callers poll.
// Re-acquiring a lock you already hold refreshes its heartbeat.
func (s *Store) AcquireLock(ctx context.Context, name, owner string, ttl time.Duration) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil) // BEGIN IMMEDIATE via _txlock
	if err != nil {
		return false, fmt.Errorf("acquire lock %s: %w", name, err)
	}
	defer func() { _ = tx.Rollback() }()

	now := s.now()
	var holder string
	var beat sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT owner, heartbeat_at FROM locks WHERE name = ?`, name).Scan(&holder, &beat)
	switch {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return false, fmt.Errorf("acquire lock %s: %w", name, err)
	default:
		t, err := parseTime(beat)
		if err != nil {
			return false, fmt.Errorf("acquire lock %s: %w", name, err)
		}
		if holder != owner && now.Sub(t) < ttl {
			return false, nil
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO locks (name, owner, heartbeat_at) VALUES (?, ?, ?)
		ON CONFLICT(name) DO UPDATE SET owner = excluded.owner, heartbeat_at = excluded.heartbeat_at`,
		name, owner, timeArg(now)); err != nil {
		return false, fmt.Errorf("acquire lock %s: %w", name, err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("acquire lock %s: %w", name, err)
	}
	return true, nil
}

// HeartbeatLock refreshes a lock owner holds. It reports false if the lock
// was taken over (e.g. after this process stalled past the TTL).
func (s *Store) HeartbeatLock(ctx context.Context, name, owner string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE locks SET heartbeat_at = ? WHERE name = ? AND owner = ?`,
		timeArg(s.now()), name, owner)
	if err != nil {
		return false, fmt.Errorf("heartbeat lock %s: %w", name, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("heartbeat lock %s: %w", name, err)
	}
	return n == 1, nil
}

// ReleaseLock releases a lock owner holds. Releasing a lock you do not hold
// is a no-op.
func (s *Store) ReleaseLock(ctx context.Context, name, owner string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM locks WHERE name = ? AND owner = ?`, name, owner); err != nil {
		return fmt.Errorf("release lock %s: %w", name, err)
	}
	return nil
}
