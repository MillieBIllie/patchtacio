package paths

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestEnvOverrides(t *testing.T) {
	base := t.TempDir()
	cfg, cache, data := filepath.Join(base, "c"), filepath.Join(base, "k"), filepath.Join(base, "d")
	t.Setenv(EnvConfigDir, cfg)
	t.Setenv(EnvCacheDir, cache)
	t.Setenv(EnvDataDir, data)

	got, err := Resolve()
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	want := Dirs{Config: cfg, Cache: cache, Data: data}
	if got != want {
		t.Errorf("Resolve() = %+v, want %+v", got, want)
	}
}

func TestRelativeOverrideRejected(t *testing.T) {
	t.Setenv(EnvDataDir, filepath.Join("relative", "dir"))
	if _, err := Resolve(); err == nil || !strings.Contains(err.Error(), EnvDataDir) {
		t.Errorf("Resolve() error = %v, want one naming %s", err, EnvDataDir)
	}
}

func TestDefaultsAreSeparate(t *testing.T) {
	for _, env := range []string{EnvConfigDir, EnvCacheDir, EnvDataDir} {
		t.Setenv(env, "")
	}
	d, err := Resolve()
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	for name, dir := range map[string]string{"config": d.Config, "cache": d.Cache, "data": d.Data} {
		if !filepath.IsAbs(dir) || !strings.Contains(dir, appName) {
			t.Errorf("%s dir %q: want an absolute path containing %q", name, dir, appName)
		}
	}
	if within(d.Data, d.Cache) {
		t.Errorf("data dir %q must not be inside the cache dir %q", d.Data, d.Cache)
	}
	if runtime.GOOS == "windows" {
		roaming, err := os.UserConfigDir()
		if err != nil {
			t.Fatalf("UserConfigDir: %v", err)
		}
		if within(d.Data, roaming) {
			t.Errorf("data dir %q must not be under Roaming %q", d.Data, roaming)
		}
	}
}

func TestEnsureCreatesCacheAndData(t *testing.T) {
	base := t.TempDir()
	d := Dirs{Config: filepath.Join(base, "c"), Cache: filepath.Join(base, "k"), Data: filepath.Join(base, "d")}
	if err := d.Ensure(); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	for _, dir := range []string{d.Cache, d.Data} {
		if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
			t.Errorf("%s not created: %v", dir, err)
		}
	}
	if _, err := os.Stat(d.Config); !os.IsNotExist(err) {
		t.Errorf("config dir should not be created, stat err = %v", err)
	}
}

func within(path, dir string) bool {
	rel, err := filepath.Rel(dir, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
