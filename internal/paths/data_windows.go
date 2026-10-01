package paths

import (
	"fmt"
	"os"
	"path/filepath"
)

// defaultDataDir is %LocalAppData%\patchtacio\data. It must never be under
// Roaming %AppData% (os.UserConfigDir): roaming profiles sync files at logoff
// and corrupt a live SQLite database.
func defaultDataDir() (string, error) {
	local, err := os.UserCacheDir() // %LocalAppData% on Windows
	if err != nil {
		return "", fmt.Errorf("local app data dir: %w", err)
	}
	return filepath.Join(local, appName, "data"), nil
}
