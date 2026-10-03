package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

// clock returns a store whose clock the test moves.
func clock(t *testing.T) (*Store, *time.Time) {
	t.Helper()
	s, _ := openTemp(t)
	now := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	return s, &now
}

func TestRecordFindingsKeepsFirstSeen(t *testing.T) {
	ctx := context.Background()
	s, now := clock(t)
	f := Finding{Source: "kev", ProductID: "fortinet-fortios", VulnID: "CVE-2024-21762", DueDate: "2024-02-16"}
	if err := s.RecordFindings(ctx, []Finding{f}); err != nil {
		t.Fatal(err)
	}
	first := *now
	*now = now.Add(24 * time.Hour)
	f.DueDate = "2024-02-20" // CISA moved it
	if err := s.RecordFindings(ctx, []Finding{f}); err != nil {
		t.Fatal(err)
	}
	id := FindingID("kev", "fortinet-fortios", "CVE-2024-21762")
	if id != "kev/fortinet-fortios/CVE-2024-21762" {
		t.Errorf("FindingID = %q", id)
	}
	st, ok, err := s.GetFinding(ctx, id)
	if err != nil || !ok {
		t.Fatalf("GetFinding = %v, %v", ok, err)
	}
	if !st.FirstSeen.Equal(first) || !st.LastSeen.Equal(*now) || st.DueDate != "2024-02-20" {
		t.Errorf("got first %v last %v due %q", st.FirstSeen, st.LastSeen, st.DueDate)
	}
	if st.Acked() || len(st.Delivered) != 0 {
		t.Errorf("new finding has state: %+v", st)
	}
}

func TestDeliveriesAndAcknowledgements(t *testing.T) {
	ctx := context.Background()
	s, now := clock(t)
	fs := []Finding{
		{Source: "kev", ProductID: "microsoft-windows", VulnID: "CVE-2026-1"},
		{Source: "kev", ProductID: "microsoft-windows-server", VulnID: "CVE-2026-1"},
		{Source: "kev", ProductID: "fortinet-fortios", VulnID: "CVE-2026-2"},
	}
	if err := s.RecordFindings(ctx, fs); err != nil {
		t.Fatal(err)
	}
	win := FindingID("kev", "microsoft-windows", "CVE-2026-1")
	fos := FindingID("kev", "fortinet-fortios", "CVE-2026-2")

	if last, err := s.LastDelivery(ctx, "webhook"); err != nil || !last.IsZero() {
		t.Errorf("LastDelivery before any = %v, %v", last, err)
	}
	sent := *now
	if err := s.RecordDeliveries(ctx, []Delivery{{win, "webhook", KindNew}, {fos, "email", KindNew}}); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(time.Hour)
	// Recording again keeps the first time.
	if err := s.RecordDeliveries(ctx, []Delivery{{win, "webhook", KindNew}}); err != nil {
		t.Fatal(err)
	}
	if last, err := s.LastDelivery(ctx, "webhook"); err != nil || !last.Equal(sent) {
		t.Errorf("LastDelivery = %v, %v; want %v", last, err, sent)
	}
	sts, err := s.States(ctx, []string{win, fos, "kev/none/CVE-0"})
	if err != nil {
		t.Fatal(err)
	}
	if len(sts) != 2 {
		t.Fatalf("States returned %d, want 2 (unknown IDs skipped)", len(sts))
	}
	if !sts[win].Sent("webhook", KindNew) || sts[win].Sent("email", KindNew) || !sts[fos].Sent("email", KindNew) {
		t.Errorf("deliveries wrong: %+v", sts)
	}

	// Acknowledge by ID; an unknown ID fails and changes nothing.
	if err := s.Acknowledge(ctx, []string{fos, "kev/none/CVE-0"}, "patched"); !errors.Is(err, ErrNoFinding) {
		t.Errorf("Acknowledge unknown = %v, want ErrNoFinding", err)
	}
	if st, _, _ := s.GetFinding(ctx, fos); st.Acked() {
		t.Error("a failed Acknowledge must not acknowledge anything")
	}
	if err := s.Acknowledge(ctx, []string{fos}, "patched to 7.4.3"); err != nil {
		t.Fatal(err)
	}
	ackedAt := *now
	*now = now.Add(time.Hour)
	if err := s.Acknowledge(ctx, []string{fos}, ""); err != nil { // again, no note
		t.Fatal(err)
	}
	st, _, _ := s.GetFinding(ctx, fos)
	if !st.AckedAt.Equal(ackedAt) || st.AckNote != "patched to 7.4.3" {
		t.Errorf("re-acknowledge changed time or dropped note: %v %q", st.AckedAt, st.AckNote)
	}
	if err := s.Unacknowledge(ctx, []string{fos}); err != nil {
		t.Fatal(err)
	}
	if st, _, _ := s.GetFinding(ctx, fos); st.Acked() {
		t.Error("still acknowledged after Unacknowledge")
	}

	// By CVE, any product, case-insensitive, sorted.
	got, err := s.FindingsForVuln(ctx, "cve-2026-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].ProductID != "microsoft-windows" || got[1].ProductID != "microsoft-windows-server" {
		t.Errorf("FindingsForVuln = %+v", got)
	}
}

func TestStatesManyIDs(t *testing.T) {
	ctx := context.Background()
	s, _ := clock(t)
	var fs []Finding
	var ids []string
	for i := range 1200 { // more than one batch
		f := Finding{Source: "kev", ProductID: "p", VulnID: "CVE-2026-" + string(rune('a'+i%26)) + time.Duration(i).String()}
		fs = append(fs, f)
		ids = append(ids, FindingID(f.Source, f.ProductID, f.VulnID))
	}
	if err := s.RecordFindings(ctx, fs); err != nil {
		t.Fatal(err)
	}
	sts, err := s.States(ctx, ids)
	if err != nil {
		t.Fatal(err)
	}
	if len(sts) != len(ids) {
		t.Errorf("States returned %d of %d", len(sts), len(ids))
	}
}
