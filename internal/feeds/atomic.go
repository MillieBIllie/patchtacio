package feeds

import (
	"fmt"
	"os"
	"path/filepath"
)

// pendingFile is new content written and synced to a temp file next to its
// destination, waiting to replace it. Splitting the write this way lets the
// Updater check it still holds the update lock after the slow part (writing
// and syncing megabytes) and immediately before the fast, atomic rename.
type pendingFile struct {
	tmp, dest string
}

// prepareFile writes data to a temp file in dir (same filesystem, so the
// later rename is atomic) with owner-only permissions, synced and closed.
func prepareFile(dir, name string, data []byte) (*pendingFile, error) {
	tmp, err := os.CreateTemp(dir, name+".tmp-*")
	if err != nil {
		return nil, fmt.Errorf("create temp file: %w", err)
	}
	p := &pendingFile{tmp: tmp.Name(), dest: filepath.Join(dir, name)}

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		p.Abort()
		return nil, fmt.Errorf("write %s: %w", p.tmp, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		p.Abort()
		return nil, fmt.Errorf("sync %s: %w", p.tmp, err)
	}
	// Close before rename: Windows cannot rename an open file.
	if err := tmp.Close(); err != nil {
		p.Abort()
		return nil, fmt.Errorf("close %s: %w", p.tmp, err)
	}
	return p, nil
}

// Commit replaces the destination, so readers see either the old or the new
// content, never a partial file.
func (p *pendingFile) Commit() error {
	if err := rename(p.tmp, p.dest); err != nil {
		p.Abort()
		return fmt.Errorf("replace %s: %w", filepath.Base(p.dest), err)
	}
	return nil
}

// Abort discards the temp file. It is safe to call after Commit.
func (p *pendingFile) Abort() { _ = os.Remove(p.tmp) }
