package schedule

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

// Darwin uses a launchd agent in ~/Library/LaunchAgents.
type Darwin struct{ O Options }

func (d *Darwin) plistPath() string {
	return filepath.Join(d.O.Home, "Library", "LaunchAgents", LaunchdLabel+".plist")
}

func (d *Darwin) domain() string  { return "gui/" + strconv.Itoa(d.O.UID) }
func (d *Darwin) service() string { return d.domain() + "/" + LaunchdLabel }

func (d *Darwin) launchctl(ctx context.Context, args ...string) error {
	_, err := d.O.Run(ctx, nil, d.O.program("launchctl"), args...)
	return err
}

// LaunchdOutputName is the file, in the log directory, launchd writes the
// job's own output to (only written when a run cannot open its log).
const LaunchdOutputName = "launchd.log"

// LaunchdOutput is the file launchd writes the job's own output to.
func (d *Darwin) LaunchdOutput() string { return filepath.Join(d.O.LogDir, LaunchdOutputName) }

// Install implements Scheduler.
func (d *Darwin) Install(ctx context.Context, j Job) (Result, error) {
	plist, err := LaunchdPlist(j, d.LaunchdOutput())
	if err != nil {
		return Result{}, err
	}
	if err := os.MkdirAll(d.O.LogDir, 0o700); err != nil { // launchd does not create it
		return Result{}, fmt.Errorf("create %s: %w", d.O.LogDir, err)
	}
	path := d.plistPath()
	if err := writeFile(path, plist); err != nil {
		return Result{}, err
	}
	// Unload an earlier copy so the new time applies; not loaded is fine.
	_ = d.launchctl(ctx, "bootout", d.service())
	if err := d.launchctl(ctx, "bootstrap", d.domain(), path); err != nil {
		// Older macOS, or no GUI session (ssh): the legacy subcommand.
		if err2 := d.launchctl(ctx, "load", "-w", path); err2 != nil {
			return Result{}, fmt.Errorf("load the launchd agent: %w", err)
		}
	}
	return Result{Method: MethodLaunchd, Job: j, Files: []string{path}, Notes: []string{
		"If the Mac is asleep at the scheduled time the check runs when it wakes; if it is shut down, that day's check is skipped.",
	}}, nil
}

// Uninstall implements Scheduler.
func (d *Darwin) Uninstall(ctx context.Context) ([]string, error) {
	path := d.plistPath()
	if !exists(path) {
		return nil, nil
	}
	if err := d.launchctl(ctx, "bootout", d.service()); err != nil {
		_ = d.launchctl(ctx, "unload", "-w", path)
	}
	ok, err := removeFile(path)
	if err != nil || !ok {
		return nil, err
	}
	return []string{path}, nil
}

// Status implements Scheduler.
func (d *Darwin) Status(ctx context.Context) (Status, error) {
	if !exists(d.plistPath()) {
		return Status{}, nil
	}
	if err := d.launchctl(ctx, "print", d.service()); err != nil {
		if !ran(err) {
			return Status{}, err
		}
		return Status{Method: MethodLaunchd, Notes: []string{
			"The launchd agent file exists but is not loaded (it loads at your next login); run `patchtacio watch --install` again to load it now.",
		}}, nil
	}
	return Status{Installed: true, Method: MethodLaunchd}, nil
}

// RunNow implements Scheduler.
func (d *Darwin) RunNow(ctx context.Context) error {
	st, err := d.Status(ctx)
	if err != nil {
		return err
	}
	if !st.Installed {
		return ErrNotInstalled
	}
	if err := d.launchctl(ctx, "kickstart", d.service()); err != nil {
		return fmt.Errorf("start the check: %w", err)
	}
	return nil
}
