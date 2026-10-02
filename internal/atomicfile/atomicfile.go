// Package atomicfile replaces files so readers see either the old or the new
// content, never a partial file: write a temp file in the same directory,
// sync and close it, then rename it over the destination. On Windows the
// rename is retried briefly, because it fails while another process (a
// concurrent reader, an antivirus scanner, the search indexer) has the
// destination open.
package atomicfile

import (
	"fmt"
	"os"
	"path/filepath"
)

// Pending is new content written and synced to a temp file next to its
// destination, waiting to replace it. Splitting the write this way lets a
// caller check it still holds a lock after the slow part (writing and
// syncing megabytes) and immediately before the fast, atomic rename.
type Pending struct {
	tmp, dest string
}

// Prepare writes data to a temp file in dir (same filesystem, so the later
// rename is atomic) with owner-only permissions, synced and closed.
func Prepare(dir, name string, data []byte) (*Pending, error) {
	tmp, err := os.CreateTemp(dir, name+".tmp-*")
	if err != nil {
		return nil, fmt.Errorf("create temp file: %w", err)
	}
	p := &Pending{tmp: tmp.Name(), dest: filepath.Join(dir, name)}

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

// Commit replaces the destination.
func (p *Pending) Commit() error {
	if err := rename(p.tmp, p.dest); err != nil {
		p.Abort()
		return fmt.Errorf("replace %s: %w", filepath.Base(p.dest), err)
	}
	return nil
}

// Abort discards the temp file. It is safe to call after Commit.
func (p *Pending) Abort() { _ = os.Remove(p.tmp) }

// Write atomically replaces path with data, with owner-only permissions.
func Write(path string, data []byte) error {
	p, err := Prepare(filepath.Dir(path), filepath.Base(path), data)
	if err != nil {
		return err
	}
	return p.Commit()
}
