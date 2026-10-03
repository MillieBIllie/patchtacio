package atomicfile

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A rename that cannot succeed by waiting must fail at once, not after
// about 2.5 seconds of retries.
func TestRenameMissingDirectoryFailsFast(t *testing.T) {
	dir := t.TempDir()
	from := filepath.Join(dir, "x")
	if err := os.WriteFile(from, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := rename(from, filepath.Join(dir, "missing", "x")); err == nil {
		t.Fatal("want an error")
	}
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Errorf("took %v; a missing directory should not be retried", d)
	}
}

// os.Open does not grant FILE_SHARE_DELETE, so replacing the file fails with
// access denied until the holder closes it; rename must wait it out.
func TestRenameWaitsForOpenDestination(t *testing.T) {
	dir := t.TempDir()
	from, to := filepath.Join(dir, "new"), filepath.Join(dir, "dest")
	for _, p := range []string{from, to} {
		if err := os.WriteFile(p, []byte(p), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	f, err := os.Open(to)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(150 * time.Millisecond)
		_ = f.Close()
	}()
	if err := rename(from, to); err != nil {
		t.Fatalf("rename while briefly open: %v", err)
	}
	got, _ := os.ReadFile(to)
	if string(got) != from {
		t.Errorf("destination holds %q", got)
	}
}
