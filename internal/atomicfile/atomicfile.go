// Package atomicfile replaces files so readers see either the old or the new
// content, never a partial file: write a temp file in the same directory,
// sync and close it, then rename it over the destination. On Windows the
// rename is retried briefly, because it fails while another process (a
// concurrent reader, an antivirus scanner, the search indexer) has the
// destination open.
package atomicfile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Pending is new content written and synced to a temp file next to its
// destination, waiting to replace it. Splitting the write this way lets a
// caller check it still holds a lock after the slow part (writing and
// syncing megabytes) and immediately before the fast, atomic rename.
type Pending struct {
	tmp, dest string
}

// Prepare writes data to a temp file in dir (same filesystem, so the later
// rename is atomic), synced and closed. name must be a plain file name.
//
// On POSIX the file is owner-only (0600). On Windows the mode only controls
// the read-only attribute: the file gets the directory's inherited ACL, so it
// is as private as the directory it lives in. Do not store secrets with it.
func Prepare(dir, name string, data []byte) (*Pending, error) {
	if name == "" || name == "." || name == ".." || name != filepath.Base(name) {
		return nil, fmt.Errorf("atomicfile: %q is not a plain file name", name)
	}
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

// Write atomically replaces path with data. Permissions are as for Prepare.
func Write(path string, data []byte) error {
	p, err := Prepare(filepath.Dir(path), filepath.Base(path), data)
	if err != nil {
		return err
	}
	return p.Commit()
}

// RemoveStale deletes temp files left in dir by a process killed between
// Prepare and Commit: files matching name+".tmp-*" (name may be a glob, such
// as "*.json") last modified more than olderThan ago. Keep olderThan longer
// than any write can take, so a concurrent writer's file is never removed. It
// returns the names it removed.
func RemoveStale(dir, name string, olderThan time.Duration) []string {
	matches, err := filepath.Glob(filepath.Join(dir, name+".tmp-*"))
	if err != nil {
		return nil
	}
	cutoff := time.Now().Add(-olderThan)
	var removed []string
	for _, m := range matches {
		fi, err := os.Lstat(m)
		if err != nil || !fi.Mode().IsRegular() || !fi.ModTime().Before(cutoff) {
			continue
		}
		if err := os.Remove(m); err == nil || errors.Is(err, os.ErrNotExist) {
			removed = append(removed, filepath.Base(m))
		}
	}
	return removed
}
