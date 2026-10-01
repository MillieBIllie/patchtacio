package main

import "errors"

// Exit codes are a public contract: scripts, scheduled checks, and the GitHub
// Action depend on them. See docs/decisions/0001-m1-data-layer.md.
const (
	exitOK        = 0 // finished, nothing at or above the threshold, all data fresh
	exitFindings  = 1 // findings at or above the --fail-on threshold
	exitToolError = 2 // tool error, or a feed has no usable data at all
	exitStale     = 3 // finished, but at least one feed was served stale from cache
)

const exitCodesHelp = `Exit codes:
  0  finished; nothing at or above the threshold and all data is fresh
  1  findings at or above the --fail-on threshold
  2  error, or a data source has no usable data
  3  finished, but some data came from an out-of-date cache (warning printed)`

// isOutcome reports whether err only carries an exit code; the command has
// already explained it, so main prints nothing more.
func isOutcome(err error) bool {
	_, ok := errors.AsType[*exitError](err)
	return ok
}

// exitError lets a command finish with a non-zero code after explaining the
// result itself: findings, stale data, or a feed with no usable data.
type exitError struct {
	code int
}

func (e *exitError) Error() string {
	switch e.code {
	case exitFindings:
		return "findings at or above threshold"
	case exitStale:
		return "some data is out of date"
	default:
		return "exit"
	}
}

// exitCodeFor maps a command error to the process exit code. Anything that is
// not an explicit outcome is a tool error.
func exitCodeFor(err error) int {
	if err == nil {
		return exitOK
	}
	if ee, ok := errors.AsType[*exitError](err); ok {
		return ee.code
	}
	return exitToolError
}
