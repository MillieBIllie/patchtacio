//go:build !windows && !darwin

package paths

import (
	"os"
	"path/filepath"
	"testing"
)

func TestXDGDataHome(t *testing.T) {
	xdg := t.TempDir()
	t.Setenv("XDG_DATA_HOME", xdg)
	got, err := defaultDataDir()
	if err != nil {
		t.Fatalf("defaultDataDir: %v", err)
	}
	if want := filepath.Join(xdg, appName); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestXDGDataHomeFallback(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", "relative/ignored")
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("no home dir: %v", err)
	}
	got, err := defaultDataDir()
	if err != nil {
		t.Fatalf("defaultDataDir: %v", err)
	}
	if want := filepath.Join(home, ".local", "share", appName); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
