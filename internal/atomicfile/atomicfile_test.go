package atomicfile

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
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
