package paths

import (
	"fmt"
	"os"
	"path/filepath"
)

// defaultDataDir is ~/Library/Application Support/patchtacio, which Apple
// documents for app data that is not a cache.
func defaultDataDir() (string, error) {
	support, err := os.UserConfigDir() // ~/Library/Application Support on macOS
	if err != nil {
		return "", fmt.Errorf("application support dir: %w", err)
	}
	return filepath.Join(support, appName), nil
}
