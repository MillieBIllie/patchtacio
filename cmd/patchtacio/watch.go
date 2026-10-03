package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/milliebillie/patchtacio/internal/advice"
	"github.com/milliebillie/patchtacio/internal/atomicfile"
	"github.com/milliebillie/patchtacio/internal/catalog"
	"github.com/milliebillie/patchtacio/internal/config"
	"github.com/milliebillie/patchtacio/internal/logging"
	"github.com/milliebillie/patchtacio/internal/paths"
	"github.com/milliebillie/patchtacio/internal/schedule"
	"github.com/milliebillie/patchtacio/internal/secrets"
	"github.com/milliebillie/patchtacio/internal/version"
)

// Files the scheduled check keeps (docs/decisions/0004-m4-scheduling.md).
const (
	watchInstallFile = "watch-install.json"  // data directory: what install set up
	watchRunFile     = "watch-last-run.json" // data directory: the last scheduled run
	logFileName      = "patchtacio.log"      // <cache>/logs
	// overdueAfter is how long without a run before --status calls the
	// daily check overdue: a day plus slack for a late start.
	overdueAfter = 26 * time.Hour
)

// watchInstall records what `watch --install` set up.
type watchInstall struct {
	Method      string    `json:"method"`
	At          string    `json:"at"` // HH:MM, local time
	Program     string    `json:"program"`
	Args        []string  `json:"args"`
	Launch      string    `json:"launch,omitempty"` // Windows: windowless, headless or console
	Starts      string    `json:"starts,omitempty"` // the program the scheduler starts, when not Program (patchtaciow.exe, conhost.exe)
	InstalledAt time.Time `json:"installedAt"`
}

// watchRun records the last scheduled run.
type watchRun struct {
	StartedAt  time.Time `json:"startedAt"`
	FinishedAt time.Time `json:"finishedAt"`
	ExitCode   int       `json:"exitCode"`
	Error      string    `json:"error,omitempty"` // first line, redacted
}

func newWatchCmd(a *app) *cobra.Command {
	var install, uninstall, status, runNow bool
	var at string
	cmd := &cobra.Command{
		Use:   "watch",
		Short: "Run `check --notify` every day with your computer's scheduler",
		Long: "Sets up, removes or shows a daily `patchtacio check --notify`, run by your computer's own\n" +
			"scheduler: a systemd user timer (or cron) on Linux, a launchd agent on macOS, Task Scheduler on\n" +
			"Windows. It runs as you, needs no administrator rights, and catches up on a run missed while the\n" +
			"computer was off where the scheduler can.\n\n" +
			"Without --at, install picks a time between 08:00 and 08:59. Each run writes to a log file in the\n" +
			"cache folder; --status shows the last run and the log's location.\n\n" +
			"Exit codes: --status exits 0 when the check is installed and has run recently, and 2 when it is\n" +
			"not installed, its last run failed, or it is overdue (no run for 26 hours). The other actions\n" +
			"exit 0 on success and 2 on error.",
		Example: "  patchtacio watch --install\n" +
			"  patchtacio watch --install --at 07:30\n" +
			"  patchtacio watch --run-now\n" +
			"  patchtacio watch --status",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if at != "" && !install {
				return errors.New("--at is used with --install")
			}
			switch {
			case install:
				return a.watchInstall(cmd, at)
			case uninstall:
				return a.watchUninstall(cmd)
			case runNow:
				return a.watchRunNow(cmd)
			default:
				return a.watchStatus(cmd)
			}
		},
	}
	cmd.Flags().BoolVar(&install, "install", false, "set up the daily check (again, to change it)")
	cmd.Flags().BoolVar(&uninstall, "uninstall", false, "remove the daily check")
	cmd.Flags().BoolVar(&status, "status", false, "show whether the daily check is set up and how its last run went (the default)")
	cmd.Flags().BoolVar(&runNow, "run-now", false, "ask the scheduler to start the check now, to test the setup")
	cmd.Flags().StringVar(&at, "at", "", "time of day to run, HH:MM in local time (default: a time between 08:00 and 08:59)")
	cmd.MarkFlagsMutuallyExclusive("install", "uninstall", "status", "run-now")
	cmd.AddCommand(newWatchRunCmd(a))
	return cmd
}

// newWatchRunCmd is what the scheduler runs.
func newWatchRunCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:    "run",
		Short:  "Run the scheduled check now, writing to the log file (the scheduler runs this)",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE:   func(cmd *cobra.Command, _ []string) error { return a.watchRun(cmd) },
	}
}

// watchDirs are the directories the scheduled check uses.
type watchDirs struct {
	paths.Dirs
	Logs string
}

func resolveWatchDirs() (watchDirs, error) {
	d, err := paths.Resolve()
	if err != nil {
		return watchDirs{}, fmt.Errorf("find data directories: %w", err)
	}
	return watchDirs{Dirs: d, Logs: filepath.Join(d.Cache, "logs")}, nil
}

func (a *app) openScheduler() (schedule.Scheduler, watchDirs, error) {
	d, err := resolveWatchDirs()
	if err != nil {
		return nil, watchDirs{}, err
	}
	s, err := a.scheduler(d.Logs, "") // "": the user's own temp directory
	if err != nil {
		return nil, watchDirs{}, err
	}
	return s, d, nil
}

var clockTime = regexp.MustCompile(`^([01]?[0-9]|2[0-3]):([0-5][0-9])$`)

// parseAt reads --at, or picks a minute from 08:00 to 08:59 so installs do
// not all fetch the feeds at the same second.
func (a *app) parseAt(at string) (hour, minute int, err error) {
	if at == "" {
		return 8, a.randIntN(60), nil
	}
	m := clockTime.FindStringSubmatch(at)
	if m == nil {
		return 0, 0, fmt.Errorf("--at %q: want a time of day as HH:MM, like 07:30", at)
	}
	hour, _ = strconv.Atoi(m[1])
	minute, _ = strconv.Atoi(m[2])
	return hour, minute, nil
}

// resolveProgram is the program the scheduler should start: the running
// one, but by its PATH name when that is the same file, so a Homebrew
// upgrade or Scoop's `current` link keeps working. A `go run` build is
// refused: it is deleted when go run exits.
func resolveProgram(exe string, lookPath func(string) (string, error)) (string, error) {
	exe, err := filepath.Abs(exe)
	if err != nil {
		return "", fmt.Errorf("find this program: %w", err)
	}
	if strings.Contains(exe, string(filepath.Separator)+"go-build") {
		return "", errors.New("this is a temporary `go run` build; install Patchtacio first (a release, or `go install`), then run `patchtacio watch --install`")
	}
	if p, err := lookPath("patchtacio"); err == nil {
		if p, err = filepath.Abs(p); err == nil {
			a, errA := os.Stat(p)
			b, errB := os.Stat(exe)
			if errA == nil && errB == nil && os.SameFile(a, b) {
				return p, nil
			}
		}
	}
	return exe, nil
}

// dirOverrides are the PATCHTACIO_*_DIR variables set now, which the job
// needs too. Never secrets.
func dirOverrides() []schedule.EnvVar {
	var env []schedule.EnvVar
	for _, name := range []string{paths.EnvConfigDir, paths.EnvCacheDir, paths.EnvDataDir} {
		if v := os.Getenv(name); v != "" {
			env = append(env, schedule.EnvVar{Name: name, Value: v})
		}
	}
	return env
}

func (a *app) watchInstall(cmd *cobra.Command, at string) error {
	out, warn := cmd.OutOrStdout(), cmd.ErrOrStderr()
	if os.Geteuid() == 0 {
		// Through sudo, root-owned units, logs and records would land in the
		// user's folders, and the user's own runs could not write them.
		return errors.New("run `patchtacio watch --install` as the user who should get the alerts, not as root or with sudo")
	}
	hour, minute, err := a.parseAt(at)
	if err != nil {
		return err
	}
	// A job that would tell no one is worse than none: the user would
	// believe they were being watched.
	cat, err := catalog.Embedded()
	if err != nil {
		return err
	}
	cfg, err := a.loadConfig(cat, warn)
	if err != nil {
		return err
	}
	if _, err := a.configuredChannels(cfg); err != nil {
		return fmt.Errorf("nothing to schedule yet: %w", err)
	}

	exe, err := a.executable()
	if err != nil {
		return fmt.Errorf("find this program: %w", err)
	}
	prog, err := resolveProgram(exe, a.lookPath)
	if err != nil {
		return err
	}
	// Always name the configuration install checked: the job may not see the
	// same PATCHTACIO_CONFIG_DIR (a Windows task cannot be given it).
	cfgPath, err := a.configPath()
	if err != nil {
		return err
	}
	if cfgPath, err = filepath.Abs(cfgPath); err != nil {
		return fmt.Errorf("find the configuration: %w", err)
	}
	args := []string{"watch", "run", "--config", cfgPath}
	job := schedule.Job{Program: prog, Args: args, Env: dirOverrides(), Hour: hour, Minute: minute}

	s, dirs, err := a.openScheduler()
	if err != nil {
		return err
	}
	res, err := s.Install(cmd.Context(), job)
	if err != nil {
		return fmt.Errorf("set up the daily check: %w", err)
	}
	rec := watchInstall{Method: res.Method, At: job.At(), Program: prog, Args: args, Launch: res.Launch, InstalledAt: a.now().UTC()}
	if res.Job.Program != "" && res.Job.Program != prog {
		rec.Starts = res.Job.Program
	}
	if err := writeJSON(filepath.Join(dirs.Data, watchInstallFile), rec); err != nil {
		_, _ = fmt.Fprintf(warn, "Warning: the check is set up, but `watch --status` will know less about it: %s\n", firstLine(err.Error()))
	}

	_, _ = fmt.Fprintf(out, "Set up the daily check (%s): `patchtacio check --notify` every day at %s.\n", res.Method, job.At())
	_, _ = fmt.Fprintf(out, "  Runs:      %s\n", commandLine(prog, args))
	if res.Launch != "" {
		_, _ = fmt.Fprintf(out, "  Started:   %s\n", launchText(res.Launch))
	}
	_, _ = fmt.Fprintf(out, "  Next run:  %s\n", job.NextRun(a.now().In(a.loc)).Format("Mon 2 Jan 2006 15:04"))
	_, _ = fmt.Fprintf(out, "  Log file:  %s\n", filepath.Join(dirs.Logs, logFileName))
	for _, f := range res.Files {
		_, _ = fmt.Fprintf(out, "  Wrote:     %s\n", f)
	}
	for _, n := range res.Notes {
		_, _ = fmt.Fprintf(out, "Note: %s\n", n)
	}
	for _, w := range a.secretWarnings(cfg.Notify, runtime.GOOS) {
		_, _ = fmt.Fprintf(warn, "Warning: %s\n", w)
	}
	_, _ = fmt.Fprintln(out, "Try it now with `patchtacio watch --run-now`, then check `patchtacio watch --status` a minute later.")
	return nil
}

// secretWarnings names secrets the scheduled check may not be able to read:
// ones found only in an environment variable (the job does not inherit this
// terminal's environment), ones in a Linux keychain (locked while the user is
// logged out), and required ones not set at all.
func (a *app) secretWarnings(n *config.Notify, goos string) []string {
	type need struct {
		env      string
		channel  string
		optional bool
	}
	var needs []need
	if n.Email != nil && n.Email.Username != "" {
		needs = append(needs, need{config.EnvSMTPPassword, config.ChannelEmail, false})
	}
	if n.Webhook != nil {
		needs = append(needs, need{config.EnvWebhookURL, config.ChannelWebhook, false})
	}
	if n.Ntfy != nil {
		needs = append(needs, need{config.EnvNtfyURL, config.ChannelNtfy, false}, need{config.EnvNtfyToken, config.ChannelNtfy, true})
	}
	var out []string
	for _, nd := range needs {
		sec, _ := secrets.ByName(nd.env)
		_, src, _ := a.secretStore().Lookup(nd.env)
		switch {
		case src == secrets.FromEnv:
			out = append(out, fmt.Sprintf("%s comes from an environment variable, which the scheduled check does not see. "+
				"Save it with `patchtacio secret set %s` (a server without a keychain: see docs/SCHEDULING.md).", nd.env, sec.Name))
		case src == secrets.FromKeychain && goos == "linux":
			out = append(out, fmt.Sprintf("%s is in the keychain, which a scheduled run can read only while you are logged in and it is unlocked. "+
				"If the check runs while you are logged out (linger), give it the secret in a file only you can read instead (docs/SCHEDULING.md).", nd.env))
		case src == secrets.NotSet && !nd.optional:
			out = append(out, fmt.Sprintf("%s is not set, so %s alerts will fail: save it with `patchtacio secret set %s`.", nd.env, nd.channel, sec.Name))
		}
	}
	return out
}

func (a *app) watchUninstall(cmd *cobra.Command) error {
	s, dirs, err := a.openScheduler()
	if err != nil {
		return err
	}
	removed, err := s.Uninstall(cmd.Context())
	for _, r := range removed {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Removed %s\n", r)
	}
	if err != nil {
		return fmt.Errorf("remove the daily check: %w", err)
	}
	for _, f := range []string{watchInstallFile, watchRunFile} {
		if err := os.Remove(filepath.Join(dirs.Data, f)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("remove %s: %w", f, err)
		}
	}
	if len(removed) == 0 {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "The daily check was not set up; nothing to remove.")
		return nil
	}
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "The daily check is removed. Alerts are sent only when you run `patchtacio check --notify` yourself.")
	return nil
}

func (a *app) watchRunNow(cmd *cobra.Command) error {
	s, dirs, err := a.openScheduler()
	if err != nil {
		return err
	}
	if err := s.RunNow(cmd.Context()); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Asked the scheduler to start the check. It runs in the background: see how it went with\n"+
		"`patchtacio watch --status` in a minute, or in the log file %s\n", filepath.Join(dirs.Logs, logFileName))
	return nil
}

func (a *app) watchStatus(cmd *cobra.Command) error {
	out := cmd.OutOrStdout()
	s, dirs, err := a.openScheduler()
	if err != nil {
		return err
	}
	st, err := s.Status(cmd.Context())
	if err != nil {
		return fmt.Errorf("ask the scheduler: %w", err)
	}
	inst, err := readJSON[watchInstall](filepath.Join(dirs.Data, watchInstallFile))
	if err != nil {
		return err
	}
	last, err := readJSON[watchRun](filepath.Join(dirs.Data, watchRunFile))
	if err != nil {
		return err
	}
	if !st.Installed {
		_, _ = fmt.Fprintln(out, "The daily check is not set up, so alerts are sent only when you run `patchtacio check --notify`.")
		for _, n := range st.Notes {
			_, _ = fmt.Fprintf(out, "Note: %s\n", n)
		}
		_, _ = fmt.Fprintln(out, "Set it up with `patchtacio watch --install`.")
		return outcome(exitToolError)
	}

	var problems []string
	now := a.now()
	if inst != nil {
		_, _ = fmt.Fprintf(out, "The daily check is set up (%s): `patchtacio check --notify` every day at %s.\n", st.Method, inst.At)
		_, _ = fmt.Fprintf(out, "  Runs:      %s\n", clean(commandLine(inst.Program, inst.Args)))
		if inst.Launch != "" {
			_, _ = fmt.Fprintf(out, "  Started:   %s\n", launchText(inst.Launch))
		}
		if h, m, err := a.parseAt(inst.At); err == nil {
			next := schedule.Job{Hour: h, Minute: m}.NextRun(now.In(a.loc))
			_, _ = fmt.Fprintf(out, "  Next run:  %s\n", next.Format("Mon 2 Jan 2006 15:04"))
		}
		for _, p := range []string{inst.Program, inst.Starts} {
			if _, err := os.Stat(p); p != "" && err != nil {
				problems = append(problems, fmt.Sprintf("the program it runs, %s, is missing. Run `patchtacio watch --install` again from the copy you use now.", clean(p)))
			}
		}
	} else {
		_, _ = fmt.Fprintf(out, "The daily check is set up (%s).\n", st.Method)
		if last == nil {
			// Without either record nothing shows whether it has ever run,
			// and "not yet" must not stay healthy for ever.
			problems = append(problems, "Patchtacio cannot tell when it was set up or whether it has ever run; run `patchtacio watch --install` again.")
		}
	}

	if last == nil {
		_, _ = fmt.Fprintln(out, "  Last run:  not yet")
		if inst != nil && now.Sub(inst.InstalledAt) > overdueAfter {
			problems = append(problems, fmt.Sprintf("it has not run since it was set up on %s. %s", a.date(inst.InstalledAt), overdueHelp(st.Method)))
		}
	} else {
		_, _ = fmt.Fprintf(out, "  Last run:  %s, %s\n", a.when(last.FinishedAt), runResult(last))
		if last.ExitCode == exitToolError {
			problems = append(problems, "the last run failed; the log file says why. Alerts may not have been sent.")
		}
		if now.Sub(last.FinishedAt) > overdueAfter {
			problems = append(problems, fmt.Sprintf("it has not run since %s. %s", a.date(last.FinishedAt), overdueHelp(st.Method)))
		}
	}
	_, _ = fmt.Fprintf(out, "  Log file:  %s\n", filepath.Join(dirs.Logs, logFileName))
	if inst != nil && inst.Launch == schedule.LaunchConsole {
		_, _ = fmt.Fprintf(out, "Note: %s\n", schedule.ConsoleNote)
	}
	for _, n := range st.Notes {
		_, _ = fmt.Fprintf(out, "Note: %s\n", n)
	}
	for _, p := range problems {
		_, _ = fmt.Fprintf(out, "Problem: %s\n", p)
	}
	if len(problems) > 0 {
		return outcome(exitToolError)
	}
	return nil
}

func overdueHelp(method string) string {
	switch method {
	case schedule.MethodSystemd:
		return "Was the computer off, or were you logged out without linger? `systemctl --user status patchtacio-check.timer` shows more."
	case schedule.MethodTask:
		return "Was the computer off, or were you logged out? The History tab of the \"" + schedule.TaskName + " (your user name)\" task in Task Scheduler shows more."
	default:
		return "Was the computer off or asleep at the scheduled time?"
	}
}

// runResult explains a run's exit code. Never "all clear": exit 0 only
// means nothing matched in the data the run had.
func runResult(r *watchRun) string {
	switch r.ExitCode {
	case exitOK:
		return "finished: nothing in the KEV or end-of-life data matched your products"
	case exitFindings:
		return "finished: findings reported, alerts sent as configured"
	case exitStale:
		return "finished, but some data was out of date (see the log)"
	default:
		if r.Error != "" {
			return "failed: " + clean(r.Error)
		}
		return "failed (exit code " + strconv.Itoa(r.ExitCode) + "); see the log"
	}
}

func launchText(how string) string {
	switch how {
	case schedule.LaunchWindowless:
		return schedule.WindowlessName + " (no console window)"
	case schedule.LaunchHeadless:
		return "conhost.exe --headless (no console window)"
	default:
		return "patchtacio.exe (a console window flashes)"
	}
}

// commandLine shows a program and its arguments, quoting any with spaces.
func commandLine(prog string, args []string) string {
	words := make([]string, 0, 1+len(args))
	for _, w := range append([]string{prog}, args...) {
		if strings.ContainsAny(w, " \t\"'") {
			w = strconv.Quote(w)
		}
		words = append(words, w)
	}
	return strings.Join(words, " ")
}

// watchRun is the scheduled check: `check --notify`, writing to the log file
// instead of a terminal, and recording the run for --status.
func (a *app) watchRun(cmd *cobra.Command) error {
	started := a.now()
	d, err := resolveWatchDirs()
	if err != nil {
		return err
	}
	w := cmd.ErrOrStderr()
	if f, err := logging.OpenLogFile(filepath.Join(d.Logs, logFileName), logging.MaxLogBytes, logging.KeepLogs); err != nil {
		_, _ = fmt.Fprintf(w, "Warning: cannot open the log file, writing here instead: %s\n", firstLine(err.Error()))
	} else {
		defer func() { _ = f.Close() }()
		w = f
	}
	level := slog.LevelInfo
	if a.verbosity >= 2 {
		level = slog.LevelDebug
	}
	a.log = logging.NewFile(w, level)
	_, _ = fmt.Fprintf(w, "\n=== %s scheduled check started (patchtacio %s) ===\n", started.Format(time.RFC3339), version.Get().Version)

	check := newCheckCmd(a)
	// Run on its own, check does not inherit the root's settings: without
	// these cobra would log "Error: findings at or above threshold" and usage.
	check.SilenceErrors, check.SilenceUsage = true, true
	check.SetArgs([]string{"--notify"})
	check.SetIn(strings.NewReader(""))
	check.SetOut(w)
	check.SetErr(w)
	err = check.ExecuteContext(cmd.Context())

	rec := watchRun{StartedAt: started.UTC(), FinishedAt: a.now().UTC(), ExitCode: exitCodeFor(err)}
	if err != nil && !isOutcome(err) {
		msg := clean(logging.RedactString(err.Error()))
		_, _ = fmt.Fprintf(w, "Error: %s\n", msg)
		rec.Error = firstLine(msg)
	}
	_, _ = fmt.Fprintf(w, "=== %s finished, exit code %d ===\n", rec.FinishedAt.In(started.Location()).Format(time.RFC3339), rec.ExitCode)
	if werr := writeJSON(filepath.Join(d.Data, watchRunFile), rec); werr != nil {
		_, _ = fmt.Fprintf(w, "Warning: cannot record this run for `watch --status`: %s\n", firstLine(werr.Error()))
	}
	if rec.ExitCode == exitToolError {
		// A failed run may not have reached any channel (no configuration, a
		// keychain it cannot read), and the log is read only when someone
		// looks. A desktop notification needs no secrets; on a computer
		// without a desktop it simply fails.
		if nerr := a.desktopNotice(cmd.Context(), advice.RunFailedNotice(started.In(a.loc))); nerr != nil {
			_, _ = fmt.Fprintf(w, "Could not show a desktop notification about this failure: %s\n", firstLine(logging.RedactString(nerr.Error())))
		} else {
			_, _ = fmt.Fprintln(w, "Showed a desktop notification about this failure.")
		}
	}
	return err
}

// writeJSON atomically writes v as JSON, creating the directory.
func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("encode %s: %w", filepath.Base(path), err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create %s: %w", filepath.Dir(path), err)
	}
	return atomicfile.Write(path, append(b, '\n'))
}

// readJSON reads a JSON record; a missing file is nil, not an error.
func readJSON[T any](path string) (*T, error) {
	b, err := os.ReadFile(filepath.Clean(path))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", filepath.Base(path), err)
	}
	var v T
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, fmt.Errorf("%s is damaged (%w); run `patchtacio watch --install` again", path, err)
	}
	return &v, nil
}
