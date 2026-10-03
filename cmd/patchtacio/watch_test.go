package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/milliebillie/patchtacio/internal/config"
	"github.com/milliebillie/patchtacio/internal/paths"
	"github.com/milliebillie/patchtacio/internal/schedule"
	"github.com/milliebillie/patchtacio/internal/secrets"
)

// fakeScheduler stands in for the OS scheduler.
type fakeScheduler struct {
	installed  bool
	method     string
	job        schedule.Job
	launch     string
	notes      []string
	installErr error
	runs       int
}

func (f *fakeScheduler) Install(_ context.Context, j schedule.Job) (schedule.Result, error) {
	if f.installErr != nil {
		return schedule.Result{}, f.installErr
	}
	if err := j.Validate(); err != nil {
		return schedule.Result{}, err
	}
	f.installed, f.job = true, j
	return schedule.Result{Method: f.method, Launch: f.launch, Notes: f.notes}, nil
}

func (f *fakeScheduler) Uninstall(context.Context) ([]string, error) {
	if !f.installed {
		return nil, nil
	}
	f.installed = false
	return []string{"the fake job"}, nil
}

func (f *fakeScheduler) Status(context.Context) (schedule.Status, error) {
	return schedule.Status{Installed: f.installed, Method: f.method}, nil
}

func (f *fakeScheduler) RunNow(context.Context) error {
	if !f.installed {
		return schedule.ErrNotInstalled
	}
	f.runs++
	return nil
}

// useFakeScheduler wires a fake scheduler and an installed-looking program.
func (e *testEnv) useFakeScheduler(t *testing.T) (*fakeScheduler, string) {
	t.Helper()
	f := &fakeScheduler{method: schedule.MethodSystemd}
	prog := filepath.Join(t.TempDir(), "bin", "patchtacio")
	if err := os.MkdirAll(filepath.Dir(prog), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(prog, []byte("binary"), 0o600); err != nil {
		t.Fatal(err)
	}
	e.app.scheduler = func(string, string) (schedule.Scheduler, error) { return f, nil }
	e.app.executable = func() (string, error) { return prog, nil }
	e.app.lookPath = func(string) (string, error) { return "", exec.ErrNotFound }
	e.app.randIntN = func(int) int { return 17 }
	e.useFakeChannels()
	e.app.secrets = secrets.Mock(os.Getenv(paths.EnvConfigDir), func(string) string { return "" })
	return f, prog
}

func dataFile(name string) string { return filepath.Join(os.Getenv(paths.EnvDataDir), name) }

func TestWatchInstallNeedsConfigAndChannels(t *testing.T) {
	e := newTestEnv(t)
	f, _ := e.useFakeScheduler(t)

	_, errOut, code := e.exec(t, "watch", "--install")
	requireCode(t, code, exitToolError, "", errOut)
	requireContains(t, errOut, "patchtacio init")

	e.exec(t, "init", "--products", "citrix-netscaler")
	_, errOut, code = e.exec(t, "watch", "--install")
	requireCode(t, code, exitToolError, "", errOut)
	requireContains(t, errOut, "nothing to schedule yet", "notify:")
	if f.installed {
		t.Error("installed a check that would alert no one")
	}
}

func TestWatchInstall(t *testing.T) {
	e := newTestEnv(t)
	f, prog := e.useFakeScheduler(t)
	f.notes = []string{"The check runs only while you are logged in."}
	e.exec(t, "init", "--products", "citrix-netscaler")
	addNotify(t, "notify:\n  desktop: true\n")

	out, errOut, code := e.exec(t, "watch", "--install")
	requireCode(t, code, exitOK, out, errOut)
	requireContains(t, out,
		"Set up the daily check (systemd user timer): `patchtacio check --notify` every day at 08:17.",
		"Runs:      "+commandLine(prog, []string{"watch", "run"}),
		"Next run:  Fri 2 Oct 2026 08:17", // clock: 1 Oct 09:00
		filepath.Join("logs", "patchtacio.log"),
		"Note: The check runs only while you are logged in.",
		"watch --run-now")
	if errOut != "" {
		t.Errorf("no warnings expected for a desktop channel:\n%s", errOut)
	}
	if f.job.Program != prog || !slices.Equal(f.job.Args, []string{"watch", "run"}) || f.job.At() != "08:17" {
		t.Errorf("job %+v", f.job)
	}
	// The test's PATCHTACIO_*_DIR overrides travel with the job.
	var names []string
	for _, v := range f.job.Env {
		names = append(names, v.Name)
		if v.Value != os.Getenv(v.Name) {
			t.Errorf("%s = %q, want %q", v.Name, v.Value, os.Getenv(v.Name))
		}
	}
	if !slices.Equal(names, []string{paths.EnvConfigDir, paths.EnvCacheDir, paths.EnvDataDir}) {
		t.Errorf("job env %q", names)
	}
	rec, err := readJSON[watchInstall](dataFile(watchInstallFile))
	if err != nil || rec == nil || rec.At != "08:17" || rec.Program != prog {
		t.Errorf("install record %+v, %v", rec, err)
	}
}

func TestWatchInstallAtAndConfig(t *testing.T) {
	e := newTestEnv(t)
	f, _ := e.useFakeScheduler(t)
	cfgPath := filepath.Join(t.TempDir(), "my config.yaml")
	e.exec(t, "--config", cfgPath, "init", "--products", "citrix-netscaler")
	if err := os.WriteFile(cfgPath, append(readFile(t, cfgPath), "notify:\n  desktop: true\n"...), 0o600); err != nil {
		t.Fatal(err)
	}
	out, errOut, code := e.exec(t, "--config", cfgPath, "watch", "--install", "--at", "7:30")
	requireCode(t, code, exitOK, out, errOut)
	if f.job.At() != "07:30" || !slices.Equal(f.job.Args, []string{"watch", "run", "--config", cfgPath}) {
		t.Errorf("job %+v", f.job)
	}

	for _, bad := range []string{"7.30", "24:00", "08:60", "8"} {
		_, errOut, code := e.exec(t, "--config", cfgPath, "watch", "--install", "--at", bad)
		requireCode(t, code, exitToolError, "", errOut)
		requireContains(t, errOut, "HH:MM")
	}
	_, errOut, code = e.exec(t, "watch", "--status", "--at", "07:30")
	requireCode(t, code, exitToolError, "", errOut)
	_, errOut, code = e.exec(t, "watch", "--install", "--uninstall")
	requireCode(t, code, exitToolError, "", errOut)
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestWatchInstallSecretWarnings(t *testing.T) {
	e := newTestEnv(t)
	e.useFakeScheduler(t)
	e.exec(t, "init", "--products", "citrix-netscaler")
	addNotify(t, "notify:\n  webhook:\n    kind: slack\n  ntfy: {}\n")
	e.app.secrets = secrets.Mock(os.Getenv(paths.EnvConfigDir), func(name string) string {
		if name == config.EnvWebhookURL {
			return "https://hooks.slack.com/services/T/B/secret"
		}
		return ""
	})
	out, errOut, code := e.exec(t, "watch", "--install")
	requireCode(t, code, exitOK, out, errOut)
	requireContains(t, errOut,
		"PATCHTACIO_WEBHOOK_URL comes from an environment variable",
		"patchtacio secret set webhook-url",
		"PATCHTACIO_NTFY_URL is not set, so ntfy alerts will fail")
	if strings.Contains(errOut, "NTFY_TOKEN") {
		t.Errorf("the optional ntfy token was reported missing:\n%s", errOut)
	}
	if strings.Contains(out+errOut, "hooks.slack.com") {
		t.Error("a secret value was printed")
	}
}

func TestResolveProgram(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "Cellar", "patchtacio")
	onPath := filepath.Join(dir, "bin", "patchtacio")
	for _, p := range []string{real, onPath} {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(real, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(real, onPath); err != nil {
		t.Skipf("hard links not supported here: %v", err)
	}
	found := func(string) (string, error) { return onPath, nil }
	if got, err := resolveProgram(real, found); err != nil || got != onPath {
		t.Errorf("same file on PATH: got %q, %v; want the PATH name", got, err)
	}
	other := filepath.Join(dir, "other")
	if err := os.WriteFile(other, []byte("y"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, _ := resolveProgram(other, found); got != other {
		t.Errorf("different file on PATH: got %q, want the running program", got)
	}
	tmp := filepath.Join(dir, "go-build123", "b001", "exe", "patchtacio")
	if _, err := resolveProgram(tmp, found); err == nil || !strings.Contains(err.Error(), "go run") {
		t.Errorf("go run build accepted: %v", err)
	}
}

func TestWatchStatus(t *testing.T) {
	e := newTestEnv(t)
	f, prog := e.useFakeScheduler(t)

	out, errOut, code := e.exec(t, "watch")
	requireCode(t, code, exitToolError, out, errOut)
	requireContains(t, out, "The daily check is not set up", "watch --install")

	e.exec(t, "init", "--products", "citrix-netscaler")
	addNotify(t, "notify:\n  desktop: true\n")
	e.exec(t, "watch", "--install")

	out, errOut, code = e.exec(t, "watch", "--status")
	requireCode(t, code, exitOK, out, errOut)
	requireContains(t, out, "The daily check is set up (systemd user timer)", "every day at 08:17", "Last run:  not yet")

	// A day and a bit without a run: overdue.
	e.clock = e.clock.Add(27 * time.Hour)
	out, errOut, code = e.exec(t, "watch", "--status")
	requireCode(t, code, exitToolError, out, errOut)
	requireContains(t, out, "Problem: it has not run since it was set up on 1 Oct 2026", "linger")

	// A recent run with findings is healthy.
	rec := watchRun{StartedAt: e.clock.Add(-time.Hour), FinishedAt: e.clock.Add(-time.Hour), ExitCode: exitFindings}
	if err := writeJSON(dataFile(watchRunFile), rec); err != nil {
		t.Fatal(err)
	}
	out, errOut, code = e.exec(t, "watch", "--status")
	requireCode(t, code, exitOK, out, errOut)
	requireContains(t, out, "Last run:  2 Oct 2026 11:00 UTC (1 hour ago), finished: findings reported")

	// A failed run is a problem.
	rec.ExitCode, rec.Error = exitToolError, "update feeds: no network"
	if err := writeJSON(dataFile(watchRunFile), rec); err != nil {
		t.Fatal(err)
	}
	out, errOut, code = e.exec(t, "watch", "--status")
	requireCode(t, code, exitToolError, out, errOut)
	requireContains(t, out, "failed: update feeds: no network", "Problem: the last run failed")

	// So is a program that is gone.
	rec.ExitCode, rec.Error = exitOK, ""
	if err := writeJSON(dataFile(watchRunFile), rec); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(prog); err != nil {
		t.Fatal(err)
	}
	out, errOut, code = e.exec(t, "watch", "--status")
	requireCode(t, code, exitToolError, out, errOut)
	requireContains(t, out, "nothing in the KEV or end-of-life data matched", "is missing")
	for _, banned := range []string{"safe", "all clear", "no vulnerabilities"} {
		if strings.Contains(strings.ToLower(out), banned) {
			t.Errorf("status must not say %q:\n%s", banned, out)
		}
	}

	// The scheduler lost the job: not set up, whatever the records say.
	f.installed = false
	out, _, code = e.exec(t, "watch", "--status")
	requireCode(t, code, exitToolError, out, "")
	requireContains(t, out, "not set up")
}

func TestWatchStatusConsoleWindowNote(t *testing.T) {
	e := newTestEnv(t)
	f, _ := e.useFakeScheduler(t)
	f.method, f.launch = schedule.MethodTask, schedule.LaunchConsole
	e.exec(t, "init", "--products", "citrix-netscaler")
	addNotify(t, "notify:\n  desktop: true\n")
	out, errOut, code := e.exec(t, "watch", "--install")
	requireCode(t, code, exitOK, out, errOut)
	requireContains(t, out, "Started:   patchtacio.exe (a console window flashes)")
	out, _, _ = e.exec(t, "watch", "--status")
	requireContains(t, out, schedule.WindowlessName+" (next to patchtacio.exe)")
}

func TestWatchRunNowAndUninstall(t *testing.T) {
	e := newTestEnv(t)
	f, _ := e.useFakeScheduler(t)
	_, errOut, code := e.exec(t, "watch", "--run-now")
	requireCode(t, code, exitToolError, "", errOut)
	requireContains(t, errOut, "not installed")

	e.exec(t, "init", "--products", "citrix-netscaler")
	addNotify(t, "notify:\n  desktop: true\n")
	e.exec(t, "watch", "--install")
	out, errOut, code := e.exec(t, "watch", "--run-now")
	requireCode(t, code, exitOK, out, errOut)
	if f.runs != 1 {
		t.Errorf("runs = %d", f.runs)
	}
	requireContains(t, out, "watch --status")

	if err := writeJSON(dataFile(watchRunFile), watchRun{ExitCode: 0}); err != nil {
		t.Fatal(err)
	}
	out, errOut, code = e.exec(t, "watch", "--uninstall")
	requireCode(t, code, exitOK, out, errOut)
	requireContains(t, out, "Removed the fake job", "is removed")
	for _, name := range []string{watchInstallFile, watchRunFile} {
		if _, err := os.Stat(dataFile(name)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s left after uninstall", name)
		}
	}
	out, _, code = e.exec(t, "watch", "--uninstall")
	requireCode(t, code, exitOK, out, "")
	requireContains(t, out, "nothing to remove")
}

func TestWatchRunLogsAndRecords(t *testing.T) {
	e := newTestEnv(t)
	fc := e.useFakeChannels()
	e.exec(t, "init", "--products", "citrix-netscaler")
	addNotify(t, "notify:\n  desktop: true\n")

	out, errOut, code := e.exec(t, "watch", "run")
	requireCode(t, code, exitFindings, out, errOut)
	if out != "" || errOut != "" {
		t.Errorf("a scheduled run writes to its log, not the terminal:\nstdout: %s\nstderr: %s", out, errOut)
	}
	if len(fc.sent["desktop"]) != 1 {
		t.Errorf("alerts sent: %d", len(fc.sent["desktop"]))
	}
	log := string(readFile(t, filepath.Join(os.Getenv(paths.EnvCacheDir), "logs", logFileName)))
	requireContains(t, log,
		"=== 2026-10-01T09:00:00Z scheduled check started (patchtacio",
		"KEV entries match your products",
		"=== 2026-10-01T09:00:00Z finished, exit code 1 ===")
	for _, noise := range []string{"Usage:", "Error:"} {
		if strings.Contains(log, noise) {
			t.Errorf("log of a run with findings contains %q:\n%s", noise, log)
		}
	}
	rec, err := readJSON[watchRun](dataFile(watchRunFile))
	if err != nil || rec == nil || rec.ExitCode != exitFindings || rec.Error != "" {
		t.Errorf("run record %+v, %v", rec, err)
	}

	// A run that cannot even start the check records why.
	if err := os.Remove(filepath.Join(os.Getenv(paths.EnvConfigDir), config.FileName)); err != nil {
		t.Fatal(err)
	}
	_, _, code = e.exec(t, "watch", "run")
	requireCode(t, code, exitToolError, "", "")
	rec, _ = readJSON[watchRun](dataFile(watchRunFile))
	if rec == nil || rec.ExitCode != exitToolError || !strings.Contains(rec.Error, "patchtacio init") {
		t.Errorf("failed run record %+v", rec)
	}
	log = string(readFile(t, filepath.Join(os.Getenv(paths.EnvCacheDir), "logs", logFileName)))
	requireContains(t, log, "Error: no products chosen yet", "finished, exit code 2")
}
