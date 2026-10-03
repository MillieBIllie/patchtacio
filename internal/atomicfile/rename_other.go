//go:build !windows

package atomicfile

import (
	"fmt"
	"os"
	"path/filepath"
)

// rename is atomic on POSIX filesystems, even if the target is open. The
// directory is synced afterwards so the rename survives a power cut; that is
// best effort, because some filesystems cannot sync a directory and the new
// content is already in place.
func rename(from, to string) error {
	if err := os.Rename(from, to); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	if d, err := os.Open(filepath.Dir(to)); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
