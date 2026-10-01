package feeds

import (
	"fmt"
	"os"
	"path/filepath"
)

// writeFileAtomic replaces dir/name with data so that readers see either the
// old or the new content, never a partial file. The temp file is created in
// the same directory (so rename is atomic) with owner-only permissions.
func writeFileAtomic(dir, name string, data []byte) error {
	tmp, err := os.CreateTemp(dir, name+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("write %s: %w", tmpName, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("sync %s: %w", tmpName, err)
	}
	// Close before rename: Windows cannot rename an open file.
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close %s: %w", tmpName, err)
	}
	if err := rename(tmpName, filepath.Join(dir, name)); err != nil {
		cleanup()
		return fmt.Errorf("replace %s: %w", name, err)
	}
	return nil
}
