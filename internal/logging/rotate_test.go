package logging

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

func TestOpenLogFileCreatesAndAppends(t *testing.T) {
	path := filepath.Join(t.TempDir(), "logs", "patchtacio.log")
	for _, line := range []string{"one\n", "two\n"} {
		f, err := OpenLogFile(path, 100, 3)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.WriteString(line); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if got := readFile(t, path); got != "one\ntwo\n" {
		t.Errorf("log = %q, want both runs appended", got)
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if perm := fi.Mode().Perm(); perm != 0o600 {
			t.Errorf("log file mode %o, want 600", perm)
		}
	}
}

func TestOpenLogFileRotates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "patchtacio.log")
	writeFile(t, path, strings.Repeat("x", 11)) // over the limit
	writeFile(t, path+".1", "old1")
	writeFile(t, path+".2", "old2")
	writeFile(t, path+".3", "old3") // the oldest: dropped

	f, err := OpenLogFile(path, 10, 3)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("new")
	_ = f.Close()

	want := map[string]string{
		path:        "new",
		path + ".1": strings.Repeat("x", 11),
		path + ".2": "old1",
		path + ".3": "old2",
	}
	for p, w := range want {
		if got := readFile(t, p); got != w {
			t.Errorf("%s = %q, want %q", filepath.Base(p), got, w)
		}
	}
	if _, err := os.Stat(path + ".4"); !os.IsNotExist(err) {
		t.Errorf("more than 3 old logs kept")
	}
}

func TestOpenLogFileUnderLimitDoesNotRotate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "patchtacio.log")
	writeFile(t, path, "0123456789") // exactly the limit
	f, err := OpenLogFile(path, 10, 3)
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	if _, err := os.Stat(path + ".1"); !os.IsNotExist(err) {
		t.Errorf("rotated a log that was not over the limit")
	}
}

func TestNewFileKeepsTimeAndRedacts(t *testing.T) {
	var buf bytes.Buffer
	NewFile(&buf, slog.LevelInfo).Info("sending", "password", "hunter2", "url", "https://u:p@example.com/x?token=1")
	out := buf.String()
	if !strings.Contains(out, "time=") {
		t.Errorf("file log has no timestamp: %s", out)
	}
	for _, leak := range []string{"hunter2", "u:p@", "token=1"} {
		if strings.Contains(out, leak) {
			t.Errorf("file log leaks %q: %s", leak, out)
		}
	}
}

func TestOpenLogFileRefusesSymlinkAndTightensMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "patchtacio.log")
	if err := os.Symlink(filepath.Join(dir, "elsewhere"), path); err == nil {
		if f, err := OpenLogFile(path, 100, 3); err == nil {
			_ = f.Close()
			t.Error("followed a symlink")
		}
		_ = os.Remove(path)
	}
	if runtime.GOOS == "windows" {
		return
	}
	writeFile(t, path, "old\n")
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := OpenLogFile(path, 100, 3)
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	fi, _ := os.Stat(path)
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("existing log left at mode %o", perm)
	}
}

func TestRotateIfLarger(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "launchd.log")
	if err := RotateIfLarger(path, 10, 1); err != nil {
		t.Errorf("a missing file is not an error: %v", err)
	}
	writeFile(t, path, strings.Repeat("y", 11))
	writeFile(t, path+".1", "older")
	if err := RotateIfLarger(path, 10, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("the large file was not moved aside")
	}
	if got := readFile(t, path+".1"); got != strings.Repeat("y", 11) {
		t.Errorf(".1 = %q, want the rotated file (the older copy dropped)", got)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := RotateIfLarger(path, 10, 1); err == nil {
		t.Error("a directory at the log path was accepted")
	}
}
