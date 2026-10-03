package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// Finding is one stored finding. FirstSeen and LastSeen are set by
// RecordFindings; DueDate is "" when the feed gives none.
type Finding struct {
	ID        string
	Source    string
	ProductID string
	VulnID    string
	DueDate   string // YYYY-MM-DD
	FirstSeen time.Time
	LastSeen  time.Time
}

// FindingID is the stable identity of a finding: "kev/<product-id>/<CVE>".
func FindingID(source, productID, vulnID string) string {
	return source + "/" + productID + "/" + vulnID
}

// Alert kinds recorded in deliveries.
const (
	KindNew     = "new"
	KindDueSoon = "due-soon"
	KindOverdue = "overdue"
)

// State is what the store knows about a finding beyond the feed data.
type State struct {
	Finding
	AckedAt   time.Time // zero = not acknowledged
	AckNote   string
	Delivered map[string]map[string]time.Time // channel -> kind -> sent_at
}

// Acked reports whether the finding has been acknowledged.
func (s State) Acked() bool { return !s.AckedAt.IsZero() }

// Sent reports whether an alert of kind was delivered on channel.
func (s State) Sent(channel, kind string) bool {
	_, ok := s.Delivered[channel][kind]
	return ok
}

// RecordFindings inserts new findings and refreshes known ones: last_seen and
// due_date change, first_seen never does. It runs in one transaction.
func (s *Store) RecordFindings(ctx context.Context, fs []Finding) error {
	if len(fs) == 0 {
		return nil
	}
	now := timeArg(s.now())
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("record findings: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO findings (id, source, product_id, vuln_id, due_date, first_seen, last_seen)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET due_date = excluded.due_date, last_seen = excluded.last_seen`)
	if err != nil {
		return fmt.Errorf("record findings: %w", err)
	}
	defer func() { _ = stmt.Close() }()
	for _, f := range fs {
		if f.ID == "" {
			f.ID = FindingID(f.Source, f.ProductID, f.VulnID)
		}
		if _, err := stmt.ExecContext(ctx, f.ID, f.Source, f.ProductID, f.VulnID, nullString(f.DueDate), now, now); err != nil {
			return fmt.Errorf("record finding %s: %w", f.ID, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("record findings: %w", err)
	}
	return nil
}

// States returns the stored state of each given finding ID that exists.
func (s *Store) States(ctx context.Context, ids []string) (map[string]State, error) {
	out := make(map[string]State, len(ids))
	// Batches keep well under SQLite's bound-parameter limit.
	for start := 0; start < len(ids); start += 500 {
		batch := ids[start:min(start+500, len(ids))]
		in := "?" + strings.Repeat(",?", len(batch)-1)
		args := make([]any, len(batch))
		for i, id := range batch {
			args[i] = id
		}
		if err := s.loadFindings(ctx, `WHERE f.id IN (`+in+`)`, args, out); err != nil {
			return nil, err
		}
		if err := s.loadDeliveries(ctx, `WHERE finding_id IN (`+in+`)`, args, out); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// FindingsForVuln returns every stored finding for a vulnerability ID (any
// product), sorted by product ID. Matching ignores case.
func (s *Store) FindingsForVuln(ctx context.Context, vulnID string) ([]State, error) {
	m := map[string]State{}
	if err := s.loadFindings(ctx, `WHERE f.vuln_id = ? COLLATE NOCASE`, []any{vulnID}, m); err != nil {
		return nil, err
	}
	out := make([]State, 0, len(m))
	for _, st := range m {
		out = append(out, st)
	}
	slices.SortFunc(out, func(a, b State) int { return strings.Compare(a.ProductID, b.ProductID) })
	return out, nil
}

// GetFinding returns one finding by ID; ok is false if there is none.
func (s *Store) GetFinding(ctx context.Context, id string) (st State, ok bool, err error) {
	m, err := s.States(ctx, []string{id})
	if err != nil {
		return State{}, false, err
	}
	st, ok = m[id]
	return st, ok, nil
}

// loadFindings and loadDeliveries take a WHERE clause built only from
// constants and "?" placeholders; values always go in args.
func (s *Store) loadFindings(ctx context.Context, where string, args []any, out map[string]State) error {
	const sel = `SELECT f.id, f.source, f.product_id, f.vuln_id, f.due_date, f.first_seen, f.last_seen,
		a.acked_at, a.note
		FROM findings f LEFT JOIN acknowledgements a ON a.finding_id = f.id `
	rows, err := s.db.QueryContext(ctx, sel+where, args...) //nolint:gosec // where: constants and placeholders only
	if err != nil {
		return fmt.Errorf("load findings: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var st State
		var due, first, last, acked, note sql.NullString
		if err := rows.Scan(&st.ID, &st.Source, &st.ProductID, &st.VulnID, &due, &first, &last, &acked, &note); err != nil {
			return fmt.Errorf("load findings: %w", err)
		}
		st.DueDate = due.String
		st.AckNote = note.String
		for _, p := range []struct {
			dst *time.Time
			src sql.NullString
		}{{&st.FirstSeen, first}, {&st.LastSeen, last}, {&st.AckedAt, acked}} {
			if *p.dst, err = parseTime(p.src); err != nil {
				return fmt.Errorf("load finding %s: %w", st.ID, err)
			}
		}
		st.Delivered = map[string]map[string]time.Time{}
		out[st.ID] = st
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("load findings: %w", err)
	}
	return nil
}

func (s *Store) loadDeliveries(ctx context.Context, where string, args []any, out map[string]State) error {
	const sel = `SELECT finding_id, channel, kind, sent_at FROM deliveries `
	rows, err := s.db.QueryContext(ctx, sel+where, args...) //nolint:gosec // where: constants and placeholders only
	if err != nil {
		return fmt.Errorf("load deliveries: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var id, channel, kind string
		var sent sql.NullString
		if err := rows.Scan(&id, &channel, &kind, &sent); err != nil {
			return fmt.Errorf("load deliveries: %w", err)
		}
		st, ok := out[id]
		if !ok {
			continue
		}
		t, err := parseTime(sent)
		if err != nil {
			return fmt.Errorf("load delivery for %s: %w", id, err)
		}
		if st.Delivered[channel] == nil {
			st.Delivered[channel] = map[string]time.Time{}
		}
		st.Delivered[channel][kind] = t
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("load deliveries: %w", err)
	}
	return nil
}

// Delivery is one alert sent for a finding on a channel.
type Delivery struct {
	FindingID string
	Channel   string
	Kind      string
}

// RecordDeliveries marks alerts as sent now. Recording one twice keeps the
// first time.
func (s *Store) RecordDeliveries(ctx context.Context, ds []Delivery) error {
	if len(ds) == 0 {
		return nil
	}
	now := timeArg(s.now())
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("record deliveries: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, d := range ds {
		if _, err := tx.ExecContext(ctx, `INSERT INTO deliveries (finding_id, channel, kind, sent_at) VALUES (?, ?, ?, ?)
			ON CONFLICT DO NOTHING`, d.FindingID, d.Channel, d.Kind, now); err != nil {
			return fmt.Errorf("record delivery for %s: %w", d.FindingID, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("record deliveries: %w", err)
	}
	return nil
}

// LastDelivery returns when channel last delivered anything (zero = never).
func (s *Store) LastDelivery(ctx context.Context, channel string) (time.Time, error) {
	var last sql.NullString
	if err := s.db.QueryRowContext(ctx, `SELECT MAX(sent_at) FROM deliveries WHERE channel = ?`, channel).Scan(&last); err != nil {
		return time.Time{}, fmt.Errorf("last delivery on %s: %w", channel, err)
	}
	return parseTime(last)
}

// ErrNoFinding is returned when acknowledging a finding the store has never
// recorded.
var ErrNoFinding = errors.New("no such finding")

// Acknowledge marks findings as acknowledged now, with an optional note. An
// already acknowledged finding keeps its original time; its note is replaced
// only if note is not empty.
func (s *Store) Acknowledge(ctx context.Context, ids []string, note string) error {
	now := timeArg(s.now())
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("acknowledge: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, id := range ids {
		var exists int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM findings WHERE id = ?`, id).Scan(&exists); err != nil {
			return fmt.Errorf("acknowledge %s: %w", id, err)
		}
		if exists == 0 {
			return fmt.Errorf("acknowledge %s: %w", id, ErrNoFinding)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO acknowledgements (finding_id, acked_at, note) VALUES (?, ?, ?)
			ON CONFLICT (finding_id) DO UPDATE SET note = CASE WHEN excluded.note = '' THEN note ELSE excluded.note END`,
			id, now, note); err != nil {
			return fmt.Errorf("acknowledge %s: %w", id, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("acknowledge: %w", err)
	}
	return nil
}

// Unacknowledge removes acknowledgements; alerts and reminders resume for
// kinds not yet delivered.
func (s *Store) Unacknowledge(ctx context.Context, ids []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("unacknowledge: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, id := range ids {
		if _, err := tx.ExecContext(ctx, `DELETE FROM acknowledgements WHERE finding_id = ?`, id); err != nil {
			return fmt.Errorf("unacknowledge %s: %w", id, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("unacknowledge: %w", err)
	}
	return nil
}

func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}
