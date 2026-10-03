package atomicfile

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
)

const (
	errSharingViolation syscall.Errno = 32 // ERROR_SHARING_VIOLATION
	errLockViolation    syscall.Errno = 33 // ERROR_LOCK_VIOLATION
)

// rename retries briefly: on Windows, replacing a file fails while another
// process (a concurrent reader, an antivirus scanner, the search indexer)
// has it open. Other errors (missing directory, destination is a directory)
// cannot clear by waiting and are returned at once.
func rename(from, to string) error {
	const attempts = 10
	var err error
	for i := range attempts {
		if err = os.Rename(from, to); err == nil || !transient(err) {
			break
		}
		if i < attempts-1 {
			time.Sleep(time.Duration(i+1) * 50 * time.Millisecond)
		}
	}
	if err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

// transient reports whether err is a sharing error that clears once the other
// process closes the file. A destination that is a directory also reports
// access denied; it is retried in vain, which only costs time.
func transient(err error) bool {
	return errors.Is(err, syscall.ERROR_ACCESS_DENIED) ||
		errors.Is(err, errSharingViolation) ||
		errors.Is(err, errLockViolation)
}
