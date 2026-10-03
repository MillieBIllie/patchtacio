package schedule

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
)

// Linux uses a systemd user timer, or a crontab line when there is no
// systemd user manager (WSL, containers, minimal servers).
type Linux struct{ O Options }

func (l *Linux) unitDir() string { return filepath.Join(l.O.ConfigHome, "systemd", "user") }

func (l *Linux) systemctl(ctx context.Context, args ...string) ([]byte, error) {
	return l.O.Run(ctx, nil, "systemctl", append([]string{"--user"}, args...)...)
}

// hasSystemd reports whether a systemd user manager answers.
func (l *Linux) hasSystemd(ctx context.Context) bool {
	_, err := l.systemctl(ctx, "show-environment")
	return err == nil
}

// Install implements Scheduler.
func (l *Linux) Install(ctx context.Context, j Job) (Result, error) {
	if l.hasSystemd(ctx) {
		return l.installSystemd(ctx, j)
	}
	return l.installCron(ctx, j)
}

func (l *Linux) installSystemd(ctx context.Context, j Job) (Result, error) {
	svc, err := SystemdServiceUnit(j)
	if err != nil {
		return Result{}, err
	}
	timer, err := SystemdTimerUnit(j)
	if err != nil {
		return Result{}, err
	}
	svcPath, timerPath := filepath.Join(l.unitDir(), SystemdService), filepath.Join(l.unitDir(), SystemdTimer)
	if err := writeFile(svcPath, svc); err != nil {
		return Result{}, err
	}
	if err := writeFile(timerPath, timer); err != nil {
		return Result{}, err
	}
	for _, args := range [][]string{
		{"daemon-reload"},
		{"enable", SystemdTimer},
		{"restart", SystemdTimer}, // picks up a changed time on reinstall
	} {
		if _, err := l.systemctl(ctx, args...); err != nil {
			return Result{}, fmt.Errorf("enable the timer: %w", err)
		}
	}
	// One kind of job at a time: drop a crontab line from an earlier install.
	if _, err := l.removeCron(ctx); err != nil {
		return Result{}, err
	}
	r := Result{Method: MethodSystemd, Files: []string{svcPath, timerPath}}
	r.Notes = append(r.Notes, l.lingerNotes(ctx)...)
	return r, nil
}

func (l *Linux) installCron(ctx context.Context, j Job) (Result, error) {
	if _, err := l.O.LookPath("crontab"); err != nil {
		return Result{}, errors.New("neither a systemd user manager nor crontab is available, so the check cannot be scheduled here; " +
			"run `patchtacio check --notify` from your own scheduler")
	}
	line, err := CronLine(j)
	if err != nil {
		return Result{}, err
	}
	tab, err := l.readCrontab(ctx)
	if err != nil {
		return Result{}, err
	}
	if _, err := l.O.Run(ctx, []byte(CronMerge(tab, line)), "crontab", "-"); err != nil {
		return Result{}, fmt.Errorf("save the crontab: %w", err)
	}
	return Result{Method: MethodCron, Notes: []string{cronNote}}, nil
}

const cronNote = "Cron does not catch up: if the computer is off at the scheduled time, that day's check is skipped."

// readCrontab returns the user's crontab; none at all is "".
func (l *Linux) readCrontab(ctx context.Context) (string, error) {
	out, err := l.O.Run(ctx, nil, "crontab", "-l")
	if err != nil {
		if re, ok := errors.AsType[*RunError](err); ok && strings.Contains(strings.ToLower(re.Output), "no crontab") {
			return "", nil
		}
		return "", fmt.Errorf("read the crontab: %w", err)
	}
	return string(out), nil
}

// removeCron removes Patchtacio's crontab line, if there is one.
func (l *Linux) removeCron(ctx context.Context) (bool, error) {
	if _, err := l.O.LookPath("crontab"); err != nil {
		return false, nil // no cron, so no line
	}
	tab, err := l.readCrontab(ctx)
	if err != nil || !CronHas(tab) {
		return false, err
	}
	if _, err := l.O.Run(ctx, []byte(CronMerge(tab, "")), "crontab", "-"); err != nil {
		return false, fmt.Errorf("save the crontab: %w", err)
	}
	return true, nil
}

// lingerNotes explains linger when it is off: without it, user timers run
// only while the user is logged in.
func (l *Linux) lingerNotes(ctx context.Context) []string {
	out, err := l.O.Run(ctx, nil, "loginctl", "show-user", strconv.Itoa(l.O.UID), "--property=Linger", "--value")
	switch {
	case err != nil:
		return []string{"Could not check whether the check runs while you are logged out (loginctl: " + tidy(err.Error()) + ")."}
	case strings.TrimSpace(string(out)) != "yes":
		return []string{"The check runs only while you are logged in. To run it when you are logged out (on a server, say), run: loginctl enable-linger"}
	}
	return nil
}

// Uninstall implements Scheduler.
func (l *Linux) Uninstall(ctx context.Context) ([]string, error) {
	var removed []string
	svcPath, timerPath := filepath.Join(l.unitDir(), SystemdService), filepath.Join(l.unitDir(), SystemdTimer)
	if exists(timerPath) || exists(svcPath) {
		systemd := l.hasSystemd(ctx)
		if systemd {
			_, _ = l.systemctl(ctx, "disable", "--now", SystemdTimer) // not loaded is fine
		}
		for _, p := range []string{timerPath, svcPath} {
			ok, err := removeFile(p)
			if err != nil {
				return removed, err
			}
			if ok {
				removed = append(removed, p)
			}
		}
		if systemd {
			_, _ = l.systemctl(ctx, "daemon-reload")
		}
	}
	ok, err := l.removeCron(ctx)
	if err != nil {
		return removed, err
	}
	if ok {
		removed = append(removed, "crontab line")
	}
	return removed, nil
}

// Status implements Scheduler.
func (l *Linux) Status(ctx context.Context) (Status, error) {
	if exists(filepath.Join(l.unitDir(), SystemdTimer)) {
		st := Status{Method: MethodSystemd}
		out, err := l.systemctl(ctx, "is-enabled", SystemdTimer)
		if strings.TrimSpace(string(out)) == "enabled" && err == nil {
			st.Installed = true
			st.Notes = l.lingerNotes(ctx)
		} else {
			st.Notes = []string{"The timer file exists but systemd does not have it enabled; run `patchtacio watch --install` again."}
		}
		return st, nil
	}
	if _, err := l.O.LookPath("crontab"); err == nil {
		tab, err := l.readCrontab(ctx)
		if err != nil {
			return Status{}, err
		}
		if CronHas(tab) {
			return Status{Installed: true, Method: MethodCron, Notes: []string{cronNote}}, nil
		}
	}
	return Status{}, nil
}

// RunNow implements Scheduler.
func (l *Linux) RunNow(ctx context.Context) error {
	st, err := l.Status(ctx)
	if err != nil {
		return err
	}
	switch {
	case !st.Installed:
		return ErrNotInstalled
	case st.Method == MethodCron:
		return errors.New("cron cannot start a job on demand; run `patchtacio watch run` to run the same check now")
	}
	if _, err := l.systemctl(ctx, "start", "--no-block", SystemdService); err != nil {
		return fmt.Errorf("start the check: %w", err)
	}
	return nil
}
