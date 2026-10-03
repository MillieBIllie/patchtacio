package schedule

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Windows uses a Task Scheduler task, registered from a generated definition
// with schtasks.
type Windows struct {
	O    Options
	Name string // task name; "" means TaskNameFor the user (tests use their own)
}

func (w *Windows) name() string {
	if w.Name != "" {
		return w.Name
	}
	return TaskNameFor(w.O.UserName)
}

func (w *Windows) schtasks(ctx context.Context, args ...string) error {
	_, err := w.O.Run(ctx, nil, w.O.program("schtasks"), args...)
	return err
}

// Launch picks how the task starts j.Program without a console window, and
// returns the job to register with how it launches (Launch* constants).
func (w *Windows) Launch(j Job) (Job, string) {
	var gui, conhost string
	if p := filepath.Join(filepath.Dir(j.Program), WindowlessName); exists(p) {
		gui = p
	}
	if w.O.SystemDir != "" {
		if p := filepath.Join(w.O.SystemDir, "conhost.exe"); exists(p) {
			conhost = p
		}
	}
	return WindowsLaunch(j, gui, conhost)
}

// Install implements Scheduler.
func (w *Windows) Install(ctx context.Context, j Job) (Result, error) {
	run, how := w.Launch(j)
	def, err := TaskXML(run, w.name(), w.O.UserSID, w.O.Now())
	if err != nil {
		return Result{}, err
	}
	// The definition goes in a fresh private directory: whoever could swap
	// the file before schtasks reads it would choose what the task runs.
	dir, err := os.MkdirTemp(w.O.TempDir, "patchtacio-task-")
	if err != nil {
		return Result{}, fmt.Errorf("write the task definition: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	path := filepath.Join(dir, "task.xml")
	if err := os.WriteFile(path, UTF16(def), 0o600); err != nil {
		return Result{}, fmt.Errorf("write the task definition: %w", err)
	}
	if err := w.schtasks(ctx, "/Create", "/TN", w.name(), "/XML", path, "/F"); err != nil {
		return Result{}, fmt.Errorf("create the scheduled task %q: %w", w.name(), err)
	}
	r := Result{Method: MethodTask, Launch: how, Job: run}
	if how == LaunchConsole {
		r.Notes = append(r.Notes, ConsoleNote)
	}
	if len(j.Env) > 0 {
		names := make([]string, len(j.Env))
		for i, e := range j.Env {
			names[i] = e.Name
		}
		r.Notes = append(r.Notes, fmt.Sprintf("A scheduled task cannot be given %s; set it for your user with `setx`, or the check will use the default folders.",
			strings.Join(names, ", ")))
	}
	return r, nil
}

// ConsoleNote explains a task that will flash a console window.
const ConsoleNote = "A console window will flash briefly each time the check runs, because neither " + WindowlessName +
	" (next to patchtacio.exe) nor conhost.exe was found. Install from a release, which includes " + WindowlessName + ", then run `patchtacio watch --install` again."

// installed reports whether the task exists. Only the exit status is used:
// schtasks' messages are translated.
func (w *Windows) installed(ctx context.Context) (bool, error) {
	err := w.schtasks(ctx, "/Query", "/TN", w.name())
	switch {
	case err == nil:
		return true, nil
	case ran(err):
		return false, nil
	default:
		return false, err
	}
}

// Uninstall implements Scheduler.
func (w *Windows) Uninstall(ctx context.Context) ([]string, error) {
	ok, err := w.installed(ctx)
	if err != nil || !ok {
		return nil, err
	}
	if err := w.schtasks(ctx, "/Delete", "/TN", w.name(), "/F"); err != nil {
		return nil, fmt.Errorf("delete the scheduled task: %w", err)
	}
	return []string{"scheduled task " + w.name()}, nil
}

// Status implements Scheduler.
func (w *Windows) Status(ctx context.Context) (Status, error) {
	ok, err := w.installed(ctx)
	if err != nil || !ok {
		return Status{}, err
	}
	return Status{Installed: true, Method: MethodTask}, nil
}

// RunNow implements Scheduler.
func (w *Windows) RunNow(ctx context.Context) error {
	ok, err := w.installed(ctx)
	if err != nil {
		return err
	}
	if !ok {
		return ErrNotInstalled
	}
	if err := w.schtasks(ctx, "/Run", "/TN", w.name()); err != nil {
		return fmt.Errorf("start the check: %w", err)
	}
	return nil
}
