package sysdir

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestSystem(t *testing.T) {
	d, err := System()
	if runtime.GOOS != "windows" {
		if err == nil {
			t.Errorf("got %q on %s", d, runtime.GOOS)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(d, "schtasks.exe")); err != nil {
		t.Errorf("%s has no schtasks.exe: %v", d, err)
	}
}
