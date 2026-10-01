//go:build !windows && !darwin

package paths

import (
	"fmt"
	"os"
	"path/filepath"
)

// defaultDataDir follows the XDG Base Directory spec: $XDG_DATA_HOME, or
// ~/.local/share when it is unset or not absolute.
func defaultDataDir() (string, error) {
	if v := os.Getenv("XDG_DATA_HOME"); v != "" && filepath.IsAbs(v) {
		return filepath.Join(v, appName), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("home dir: %w", err)
	}
	return filepath.Join(home, ".local", "share", appName), nil
}
