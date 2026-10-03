// Package schedule installs, removes and inspects the daily scheduled check
// with the operating system's own scheduler (docs/decisions/0004):
//
//   - Linux: a systemd user timer, or a crontab line without a user manager;
//   - macOS: a launchd agent;
//   - Windows: a Task Scheduler task.
//
// Everything is per user. Commands run with argument lists through a Runner,
// never through a shell, so tests substitute a fake and never touch the real
// scheduler. The generated files (unit, crontab line, plist, task XML) are
// pure functions of a Job, tested with golden files on every OS.
package schedule

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"
)

// Names of the scheduled job on each system.
const (
	SystemdService = "patchtacio-check.service"
	SystemdTimer   = "patchtacio-check.timer"
	CronMarker     = "# patchtacio-check"
	LaunchdLabel   = "io.github.milliebillie.patchtacio.check"
	TaskName       = "Patchtacio check"
)

// Methods, as Status and Result report them.
const (
	MethodSystemd = "systemd user timer"
	MethodCron    = "crontab"
	MethodLaunchd = "launchd agent"
	MethodTask    = "Task Scheduler"
)

// Job is what the scheduler runs, and when.
type Job struct {
	Program string   // absolute path
	Args    []string // e.g. watch run --config /path/config.yaml
	// Env is copied into the job where the scheduler supports it (not on
	// Windows). Never secrets: only PATCHTACIO_*_DIR overrides.
	Env    []EnvVar
	Hour   int // local time
	Minute int
}

// EnvVar is one environment variable for the job.
type EnvVar struct {
	Name, Value string
}

var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// Validate rejects a job no scheduler file could express safely: a relative
// program, a time that is not a clock time, or control characters anywhere.
// Control characters are refused rather than escaped, because each format
// (unit file, crontab, XML) treats line breaks differently.
func (j Job) Validate() error {
	if !isAbs(j.Program) {
		return fmt.Errorf("program %q is not an absolute path", j.Program)
	}
	if j.Hour < 0 || j.Hour > 23 || j.Minute < 0 || j.Minute > 59 {
		return fmt.Errorf("time %02d:%02d is not a time of day", j.Hour, j.Minute)
	}
	values := append([]string{j.Program}, j.Args...)
	for _, e := range j.Env {
		if !envName.MatchString(e.Name) {
			return fmt.Errorf("environment variable name %q is not valid", e.Name)
		}
		values = append(values, e.Value)
	}
	for _, v := range values {
		if strings.ContainsFunc(v, unicode.IsControl) {
			return fmt.Errorf("%q contains a control character, which a scheduled job cannot carry safely", v)
		}
	}
	return nil
}

var windowsAbs = regexp.MustCompile(`^[A-Za-z]:\\`)

// isAbs accepts absolute paths in both forms, so every generator can be
// tested on every OS (a task XML test runs on Linux too).
func isAbs(p string) bool {
	return filepath.IsAbs(p) || strings.HasPrefix(p, "/") || windowsAbs.MatchString(p)
}

// At formats the job's time as HH:MM.
func (j Job) At() string { return fmt.Sprintf("%02d:%02d", j.Hour, j.Minute) }

// NextRun is the next time the job is due after now, in now's location.
func (j Job) NextRun(now time.Time) time.Time {
	next := time.Date(now.Year(), now.Month(), now.Day(), j.Hour, j.Minute, 0, 0, now.Location())
	if !next.After(now) {
		next = next.AddDate(0, 0, 1)
	}
	return next
}

// Result says how a job was installed.
type Result struct {
	Method string
	Files  []string // files written, for the user's information
	Notes  []string // things the user should know or do (linger, console window)
}

// Status says whether a job is installed.
type Status struct {
	Installed bool
	Method    string
	Notes     []string // problems worth showing (linger off, cron does not catch up)
}

// Scheduler installs and inspects the scheduled job.
type Scheduler interface {
	Install(ctx context.Context, j Job) (Result, error)
	// Uninstall removes every kind of job it finds and returns what it
	// removed; nothing found is not an error.
	Uninstall(ctx context.Context) ([]string, error)
	Status(ctx context.Context) (Status, error)
	// RunNow asks the scheduler to start the installed job now.
	RunNow(ctx context.Context) error
}

// ErrNotInstalled is returned by RunNow when there is no job.
var ErrNotInstalled = errors.New("the scheduled check is not installed: run `patchtacio watch --install`")

// ErrUnsupported is returned on systems without a supported scheduler.
var ErrUnsupported = errors.New("scheduled checks are not supported on this operating system; run `patchtacio check --notify` from your own scheduler")

// Runner runs a program with arguments (never through a shell), feeding it
// stdin, and returns its standard output. A failure's error includes the
// program's output, cleaned of control characters.
type Runner func(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error)

// ExecRunner runs real programs.
func ExecRunner(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // fixed scheduler programs, arguments as a list, never a shell
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	hideWindow(cmd)
	if err := cmd.Run(); err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		return out.Bytes(), &RunError{Name: name, Err: err, Output: tidy(errOut.String() + " " + out.String())}
	}
	return out.Bytes(), nil
}

// RunError is a program that ran and failed.
type RunError struct {
	Name   string
	Err    error
	Output string
}

func (e *RunError) Error() string {
	if e.Output == "" {
		return fmt.Sprintf("%s failed: %v", e.Name, e.Err)
	}
	return fmt.Sprintf("%s failed: %v: %s", e.Name, e.Err, e.Output)
}

func (e *RunError) Unwrap() error { return e.Err }

// tidy folds output to one line without control characters, at most 300 bytes.
func tidy(s string) string {
	s = strings.Join(strings.FieldsFunc(s, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }), " ")
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}

// plainWord reports whether s needs no quoting in a unit file, crontab or
// command line.
func plainWord(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune("/._-+:,=@", r):
		default:
			return false
		}
	}
	return true
}
