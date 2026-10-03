package secrets

import (
	"errors"
	"os"
	"path/filepath"
)

// keychainReachable needs a D-Bus session bus, found the way godbus finds
// it. Without one, godbus would run dbus-launch and leave a new daemon behind
// on every run, so the keychain is treated as absent instead.
func keychainReachable() error {
	if os.Getenv("DBUS_SESSION_BUS_ADDRESS") != "" {
		return nil
	}
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		if _, err := os.Stat(filepath.Join(filepath.Clean(dir), "bus")); err == nil { //nolint:gosec // the user's own runtime directory, only checked
			return nil
		}
	}
	return errors.New("no desktop session (D-Bus session bus) to reach the Secret Service")
}
