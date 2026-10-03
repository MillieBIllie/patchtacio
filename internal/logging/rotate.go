package logging

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
)

// Log file rotation limits for the scheduled run's log (docs/decisions/0004).
const (
	MaxLogBytes = 1 << 20 // rotate when the log is larger than this at open
	KeepLogs    = 3       // patchtacio.log.1 … .3
)

// OpenLogFile opens path for appending, readable only by the user, creating
// its directory. If the file is already larger than maxBytes it is first
// rotated: path becomes path.1, path.1 becomes path.2, and so on up to
// path.<keep>; the oldest is removed.
//
// Rotation happens only at open, which suits a short-lived scheduled run. It
// is best effort: on Windows a file another process has open cannot be
// renamed, and then the run simply appends.
func OpenLogFile(path string, maxBytes int64, keep int) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create log directory: %w", err)
	}
	if err := RotateIfLarger(path, maxBytes, keep); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Clean(path), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open log file: %w", err)
	}
	// An existing file keeps its mode on open; make it the user's alone.
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("restrict log file: %w", err)
	}
	return f, nil
}

// RotateIfLarger rotates path (as OpenLogFile does) when it is larger than
// maxBytes. A missing file is fine; anything but a regular file is refused,
// since a symlink could point the log at another file (the cache directory
// can be moved with PATCHTACIO_CACHE_DIR, even somewhere shared). It also
// serves logs another program writes, like launchd's output file.
func RotateIfLarger(path string, maxBytes int64, keep int) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil //nolint:nilerr // nothing to rotate; opening reports real problems
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("log file %s is not a regular file", path)
	}
	if fi.Size() > maxBytes && keep > 0 {
		rotate(path, keep)
	}
	return nil
}

func rotate(path string, keep int) {
	numbered := func(i int) string { return path + "." + strconv.Itoa(i) }
	_ = os.Remove(numbered(keep))
	for i := keep - 1; i >= 1; i-- {
		_ = os.Rename(numbered(i), numbered(i+1)) // a missing file is fine
	}
	_ = os.Rename(path, numbered(1))
}

// NewFile returns a logger for a log file: like New, but with timestamps,
// since a file is read long after the fact.
func NewFile(w io.Writer, level slog.Level) *slog.Logger {
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{
		Level: level,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 && a.Key == slog.TimeKey {
				return a
			}
			return Redact(a)
		},
	}))
}
