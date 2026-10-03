package schedule

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"time"

	"github.com/milliebillie/patchtacio/internal/atomicfile"
	"github.com/milliebillie/patchtacio/internal/sysdir"
)

// Options are what a Scheduler needs from its surroundings. Tests fill them
// with temp directories and a fake Runner.
type Options struct {
	Run      Runner
	LookPath func(string) (string, error)
	Now      func() time.Time

	Home       string // the user's home directory (macOS LaunchAgents)
	ConfigHome string // the user's config directory (Linux: ~/.config, for systemd units)
	LogDir     string // where launchd writes its own output
	TempDir    string // where the Windows task definition is written before registering
	SystemDir  string // Windows: the system directory (C:\Windows\System32), for conhost.exe
	// Programs maps a scheduler program's name to the full path it is run
	// by; a name not listed is found on PATH.
	Programs map[string]string
	UID      int    // POSIX user ID (launchd domain, loginctl)
	UserSID  string // Windows: the user to register the task for
	UserName string // Windows: names the task, which is machine-wide
}

// DefaultOptions describes the current user on this computer. logDir is where
// launchd writes its own output; tempDir "" means the user's temp directory.
func DefaultOptions(logDir, tempDir string) (Options, error) {
	o := Options{
		Run: ExecRunner, LookPath: exec.LookPath, Now: time.Now,
		LogDir: logDir, TempDir: tempDir,
		UID: os.Getuid(),
	}
	if o.TempDir == "" {
		o.TempDir = os.TempDir()
	}
	var err error
	if o.Home, err = os.UserHomeDir(); err != nil {
		return Options{}, fmt.Errorf("find home directory: %w", err)
	}
	if o.ConfigHome, err = os.UserConfigDir(); err != nil {
		return Options{}, fmt.Errorf("find config directory: %w", err)
	}
	switch runtime.GOOS {
	case "windows":
		u, err := user.Current()
		if err != nil {
			return Options{}, fmt.Errorf("find current user: %w", err)
		}
		o.UserSID = u.Uid // the SID on Windows
		o.UserName = u.Username
		// From Windows itself, not %SystemRoot%, which a parent process sets.
		if o.SystemDir, err = sysdir.System(); err != nil {
			return Options{}, err
		}
		o.Programs = map[string]string{"schtasks": filepath.Join(o.SystemDir, "schtasks.exe")}
	case "darwin":
		o.Programs = map[string]string{"launchctl": "/bin/launchctl"}
	}
	return o, nil
}

// program is the path a scheduler program is run by.
func (o Options) program(name string) string {
	if p, ok := o.Programs[name]; ok {
		return p
	}
	return name
}

// writeFile atomically writes a scheduler file, creating its directory.
func writeFile(path, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create %s: %w", filepath.Dir(path), err)
	}
	if err := atomicfile.Write(path, []byte(content)); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// removeFile removes path, reporting whether it existed.
func removeFile(path string) (bool, error) {
	err := os.Remove(path)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, os.ErrNotExist):
		return false, nil
	default:
		return false, fmt.Errorf("remove %s: %w", path, err)
	}
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// ran reports whether err is a program that ran and failed (as opposed to
// one that could not be started at all).
func ran(err error) bool {
	_, ok := errors.AsType[*RunError](err)
	return ok
}
