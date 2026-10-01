// Package paths resolves the directories Patchtacio reads and writes.
//
// There are three, and they are deliberately separate (see
// docs/decisions/0001-m1-data-layer.md):
//
//   - Config: user-edited YAML. May roam between machines.
//   - Cache: raw feed responses. Safe to delete at any time.
//   - Data: the SQLite database. Durable, never roaming, never in the cache.
//
// Each can be overridden with PATCHTACIO_CONFIG_DIR, PATCHTACIO_CACHE_DIR or
// PATCHTACIO_DATA_DIR (Docker, tests, portable installs).
package paths

import (
	"fmt"
	"os"
	"path/filepath"
)

const appName = "patchtacio"

// Environment variables that override the default directories.
const (
	EnvConfigDir = "PATCHTACIO_CONFIG_DIR"
	EnvCacheDir  = "PATCHTACIO_CACHE_DIR"
	EnvDataDir   = "PATCHTACIO_DATA_DIR"
)

// Dirs holds the resolved, absolute directories.
type Dirs struct {
	Config string
	Cache  string
	Data   string
}

// Resolve returns the directories for the current user, applying env
// overrides. It does not create them; call Ensure before writing.
func Resolve() (Dirs, error) {
	var d Dirs
	var err error
	if d.Config, err = resolve(EnvConfigDir, defaultConfigDir); err != nil {
		return Dirs{}, err
	}
	if d.Cache, err = resolve(EnvCacheDir, defaultCacheDir); err != nil {
		return Dirs{}, err
	}
	if d.Data, err = resolve(EnvDataDir, defaultDataDir); err != nil {
		return Dirs{}, err
	}
	return d, nil
}

// Ensure creates the cache and data directories if they do not exist.
// The config directory is left alone until something writes config.
func (d Dirs) Ensure() error {
	for _, dir := range []string{d.Cache, d.Data} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
	}
	return nil
}

func resolve(env string, fallback func() (string, error)) (string, error) {
	if v := os.Getenv(env); v != "" {
		if !filepath.IsAbs(v) {
			return "", fmt.Errorf("%s must be an absolute path, got %q", env, v)
		}
		return filepath.Clean(v), nil
	}
	dir, err := fallback()
	if err != nil {
		return "", fmt.Errorf("find default directory (set %s to override): %w", env, err)
	}
	return dir, nil
}

func defaultConfigDir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("user config dir: %w", err)
	}
	return filepath.Join(base, appName), nil
}

func defaultCacheDir() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("user cache dir: %w", err)
	}
	return filepath.Join(base, appName, "cache"), nil
}
