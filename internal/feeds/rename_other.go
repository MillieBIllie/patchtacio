//go:build !windows

package feeds

import (
	"fmt"
	"os"
)

// rename is atomic on POSIX filesystems, even if the target is open.
func rename(from, to string) error {
	if err := os.Rename(from, to); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}
