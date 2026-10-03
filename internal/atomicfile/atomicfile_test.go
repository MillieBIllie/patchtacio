package atomicfile

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
	"time"
)

func TestWriteCreatesAndReplaces(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	for _, body := range []string{"first\n", "second\n"} {
		if err := Write(path, []byte(body)); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != body {
			t.Errorf("got %q, want %q", got, body)
		}
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("temp files left behind: %v", entries)
	}
	if runtime.GOOS != "windows" {
		st, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0o600 {
			t.Errorf("mode %v, want 0600", st.Mode().Perm())
		}
	}
}

func TestAbortLeavesDestinationAlone(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kev.json")
	if err := Write(path, []byte("old")); err != nil {
		t.Fatal(err)
	}
	p, err := Prepare(dir, "kev.json", []byte("new"))
	if err != nil {
		t.Fatal(err)
	}
	p.Abort()
	got, _ := os.ReadFile(path)
	if string(got) != "old" {
		t.Errorf("destination changed to %q", got)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("temp file not removed: %v", entries)
	}
}

func TestWriteMissingDirectoryFails(t *testing.T) {
	if err := Write(filepath.Join(t.TempDir(), "nope", "x"), []byte("x")); err == nil {
		t.Error("want an error for a missing directory")
	}
}

func TestPrepareRejectsNonPlainNames(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"", ".", "..", "a/b", filepath.Join("a", "b")} {
		if p, err := Prepare(dir, name, []byte("x")); err == nil {
			p.Abort()
			t.Errorf("Prepare(%q) succeeded, want an error", name)
		}
	}
}

func TestRemoveStale(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, age time.Duration) {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		mt := time.Now().Add(-age)
		if err := os.Chtimes(path, mt, mt); err != nil {
			t.Fatal(err)
		}
	}
	write("config.yaml", 48*time.Hour)        // the real file: never touched
	write("config.yaml.tmp-123", 2*time.Hour) // stale: removed
	write("config.yaml.tmp-456", time.Minute) // a save in progress: kept
	write("config.yaml.tmp-old", 2*time.Hour) // not a CreateTemp name: kept
	write("other.yaml.tmp-789", 2*time.Hour)  // another destination: kept
	write("cfgA.yaml.tmp-1", 2*time.Hour)     // would match the glob cfg[A].yaml: kept
	if err := os.Mkdir(filepath.Join(dir, "config.yaml.tmp-9"), 0o700); err != nil {
		t.Fatal(err)
	}

	for _, base := range []string{"config.yaml", "cfg[A].yaml", "*"} {
		got, err := RemoveStale(dir, func(dest string) bool { return dest == base }, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		want := map[string][]string{"config.yaml": {"config.yaml.tmp-123"}}[base]
		if !slices.Equal(got, want) {
			t.Errorf("owner %q removed %v, want %v", base, got, want)
		}
	}
	var left []string
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		left = append(left, e.Name())
	}
	want := []string{"cfgA.yaml.tmp-1", "config.yaml", "config.yaml.tmp-456", "config.yaml.tmp-9",
		"config.yaml.tmp-old", "other.yaml.tmp-789"}
	if !slices.Equal(left, want) {
		t.Errorf("left %v, want %v", left, want)
	}
}

// Brackets are legal in Windows and POSIX directory names; with a glob they
// made cleanup fail silently.
func TestRemoveStaleBracketDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "IT [shared]")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.yaml.tmp-1")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	got, err := RemoveStale(dir, func(string) bool { return true }, time.Hour)
	if err != nil || len(got) != 1 {
		t.Errorf("RemoveStale = %v, %v; want the one temp file removed", got, err)
	}
}

func TestRemoveStaleMissingDirectory(t *testing.T) {
	if _, err := RemoveStale(filepath.Join(t.TempDir(), "nope"), func(string) bool { return true }, 0); err == nil {
		t.Error("want an error for a missing directory")
	}
}
