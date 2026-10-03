package schedule

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

// fakeRunner records commands and answers from a script keyed by the command
// line ("systemctl --user show-environment"). Unscripted commands succeed
// with no output.
type fakeRunner struct {
	calls  []string
	stdins map[string]string
	answer map[string]func() ([]byte, error)
}

func newFake() *fakeRunner {
	return &fakeRunner{stdins: map[string]string{}, answer: map[string]func() ([]byte, error){}}
}

func (f *fakeRunner) run(_ context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	line := strings.Join(append([]string{name}, args...), " ")
	f.calls = append(f.calls, line)
	if stdin != nil {
		f.stdins[line] = string(stdin)
	}
	if a, ok := f.answer[line]; ok {
		return a()
	}
	return nil, nil
}

func (f *fakeRunner) say(line, out string) {
	f.answer[line] = func() ([]byte, error) { return []byte(out), nil }
}

func (f *fakeRunner) fail(line, output string) {
	f.answer[line] = func() ([]byte, error) {
		return nil, &RunError{Name: strings.Fields(line)[0], Code: 1, Err: errors.New("exit status 1"), Output: output}
	}
}

func (f *fakeRunner) missing(line string) {
	f.answer[line] = func() ([]byte, error) { return nil, exec.ErrNotFound }
}

func (f *fakeRunner) requireCalls(t *testing.T, want ...string) {
	t.Helper()
	if !slices.Equal(f.calls, want) {
		t.Errorf("commands:\ngot  %q\nwant %q", f.calls, want)
	}
}

func testOptions(t *testing.T, f *fakeRunner, hasCrontab bool) Options {
	base := t.TempDir()
	return Options{
		Run: f.run,
		LookPath: func(name string) (string, error) {
			if name == "crontab" && hasCrontab {
				return "/usr/bin/crontab", nil
			}
			return "", exec.ErrNotFound
		},
		Now:        func() time.Time { return time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC) },
		Home:       filepath.Join(base, "home"),
		ConfigHome: filepath.Join(base, "home", ".config"),
		LogDir:     filepath.Join(base, "cache", "logs"),
		TempDir:    base,
		UID:        1000,
		UserSID:    "S-1-5-21-1-2-3-1001",
	}
}

func readText(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

const (
	showEnv = "systemctl --user show --property=Version --value"
	linger  = "loginctl show-user 1000 --property=Linger --value"
)

func TestSystemdInstall(t *testing.T) {
	f := newFake()
	f.say(linger, "no\n")
	f.say("crontab -l", "0 1 * * * /usr/bin/backup\n17 8 * * * /old/patchtacio watch run # patchtacio-check\n")
	l := &Linux{O: testOptions(t, f, true)}
	r, err := l.Install(context.Background(), plainJob)
	if err != nil {
		t.Fatal(err)
	}
	f.requireCalls(t,
		showEnv,
		"systemctl --user daemon-reload",
		"systemctl --user enable patchtacio-check.timer",
		"systemctl --user restart patchtacio-check.timer",
		"crontab -l", "crontab -", // the old crontab line goes
		linger,
	)
	if got := f.stdins["crontab -"]; got != "0 1 * * * /usr/bin/backup\n" {
		t.Errorf("crontab after removing the old line: %q", got)
	}
	if r.Method != MethodSystemd || len(r.Files) != 2 {
		t.Errorf("result %+v", r)
	}
	want, _ := SystemdTimerUnit(plainJob)
	if got := readText(t, filepath.Join(l.unitDir(), SystemdTimer)); got != want {
		t.Errorf("timer file differs from the generated unit")
	}
	if len(r.Notes) != 1 || !strings.Contains(r.Notes[0], "loginctl enable-linger") {
		t.Errorf("linger off must be explained: %q", r.Notes)
	}
}

func TestSystemdInstallLingerOn(t *testing.T) {
	f := newFake()
	f.say(linger, "yes\n")
	r, err := (&Linux{O: testOptions(t, f, false)}).Install(context.Background(), plainJob)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Notes) != 0 {
		t.Errorf("no notes expected with linger on and no crontab: %q", r.Notes)
	}
}

func TestCronFallback(t *testing.T) {
	f := newFake()
	f.fail(showEnv, "Failed to connect to bus: No medium found")
	f.fail("crontab -l", "no crontab for jo")
	l := &Linux{O: testOptions(t, f, true)}
	r, err := l.Install(context.Background(), plainJob)
	if err != nil {
		t.Fatal(err)
	}
	f.requireCalls(t, showEnv, "crontab -l", "crontab -")
	line, _ := CronLine(plainJob)
	if got := f.stdins["crontab -"]; got != line+"\n" {
		t.Errorf("crontab written: %q", got)
	}
	if r.Method != MethodCron || len(r.Notes) != 1 {
		t.Errorf("result %+v", r)
	}
	if exists(filepath.Join(l.unitDir(), SystemdTimer)) {
		t.Error("cron install wrote systemd units")
	}
}

func TestCronCannotReadCrontab(t *testing.T) {
	f := newFake()
	f.fail(showEnv, "")
	f.fail("crontab -l", "permission denied")
	_, err := (&Linux{O: testOptions(t, f, true)}).Install(context.Background(), plainJob)
	if err == nil || !strings.Contains(err.Error(), "read the crontab") {
		t.Fatalf("an unreadable crontab must not be overwritten: %v", err)
	}
	if slices.Contains(f.calls, "crontab -") {
		t.Error("crontab was written after a failed read")
	}
}

func TestNoSchedulerAtAll(t *testing.T) {
	f := newFake()
	f.missing(showEnv)
	_, err := (&Linux{O: testOptions(t, f, false)}).Install(context.Background(), plainJob)
	if err == nil || !strings.Contains(err.Error(), "check --notify") {
		t.Fatalf("want an explanation, got %v", err)
	}
}

func TestSystemdUninstallAndStatus(t *testing.T) {
	f := newFake()
	f.say(linger, "yes")
	f.say("systemctl --user is-enabled patchtacio-check.timer", "enabled\n")
	l := &Linux{O: testOptions(t, f, false)}
	if _, err := l.Install(context.Background(), plainJob); err != nil {
		t.Fatal(err)
	}
	st, err := l.Status(context.Background())
	if err != nil || !st.Installed || st.Method != MethodSystemd {
		t.Fatalf("status %+v, %v", st, err)
	}
	f.calls = nil
	if err := l.RunNow(context.Background()); err != nil {
		t.Fatal(err)
	}
	if last := f.calls[len(f.calls)-1]; last != "systemctl --user start --no-block patchtacio-check.service" {
		t.Errorf("run now: %s", last)
	}

	f.calls = nil
	removed, err := l.Uninstall(context.Background())
	if err != nil || len(removed) != 2 {
		t.Fatalf("removed %q, %v", removed, err)
	}
	f.requireCalls(t, showEnv, "systemctl --user disable --now patchtacio-check.timer", "systemctl --user daemon-reload")
	st, err = l.Status(context.Background())
	if err != nil || st.Installed {
		t.Errorf("after uninstall: %+v, %v", st, err)
	}
	if err := l.RunNow(context.Background()); !errors.Is(err, ErrNotInstalled) {
		t.Errorf("run now without a job: %v", err)
	}
}

func TestSystemdStatusNotEnabled(t *testing.T) {
	f := newFake()
	f.say(linger, "yes")
	l := &Linux{O: testOptions(t, f, false)}
	if _, err := l.Install(context.Background(), plainJob); err != nil {
		t.Fatal(err)
	}
	f.fail("systemctl --user is-enabled patchtacio-check.timer", "disabled")
	st, err := l.Status(context.Background())
	if err != nil || st.Installed || len(st.Notes) != 1 {
		t.Errorf("a disabled timer is not installed: %+v, %v", st, err)
	}
}

func TestCronStatusAndUninstall(t *testing.T) {
	f := newFake()
	f.fail(showEnv, "")
	line, _ := CronLine(plainJob)
	f.say("crontab -l", "MAILTO=x\n"+line+"\n")
	l := &Linux{O: testOptions(t, f, true)}
	st, err := l.Status(context.Background())
	if err != nil || !st.Installed || st.Method != MethodCron {
		t.Fatalf("status %+v, %v", st, err)
	}
	if err := l.RunNow(context.Background()); err == nil || !strings.Contains(err.Error(), "watch run") {
		t.Errorf("cron run now should explain: %v", err)
	}
	removed, err := l.Uninstall(context.Background())
	if err != nil || len(removed) != 1 {
		t.Fatalf("removed %q, %v", removed, err)
	}
	if got := f.stdins["crontab -"]; got != "MAILTO=x\n" {
		t.Errorf("crontab after uninstall: %q", got)
	}
}

func TestLaunchdInstall(t *testing.T) {
	f := newFake()
	d := &Darwin{O: testOptions(t, f, false)}
	r, err := d.Install(context.Background(), plainJob)
	if err != nil {
		t.Fatal(err)
	}
	path := d.plistPath()
	f.requireCalls(t,
		"launchctl bootout gui/1000/io.github.milliebillie.patchtacio.check",
		"launchctl bootstrap gui/1000 "+path,
	)
	want, _ := LaunchdPlist(plainJob, d.LaunchdOutput())
	if got := readText(t, path); got != want {
		t.Error("plist differs from the generated one")
	}
	if !exists(d.O.LogDir) {
		t.Error("log directory for launchd output not created")
	}
	if r.Method != MethodLaunchd || len(r.Notes) != 1 {
		t.Errorf("result %+v", r)
	}
}

func TestLaunchdLegacyLoad(t *testing.T) {
	f := newFake()
	d := &Darwin{O: testOptions(t, f, false)}
	f.fail("launchctl bootstrap gui/1000 "+d.plistPath(), "Bootstrap failed: 125: Domain does not support specified action")
	if _, err := d.Install(context.Background(), plainJob); err != nil {
		t.Fatal(err)
	}
	if last := f.calls[len(f.calls)-1]; last != "launchctl load -w "+d.plistPath() {
		t.Errorf("no legacy fallback: %q", f.calls)
	}
	f.fail("launchctl load -w "+d.plistPath(), "nope")
	if _, err := d.Install(context.Background(), plainJob); err == nil {
		t.Error("both loads failed but install succeeded")
	}
}

func TestLaunchdStatusRunNowUninstall(t *testing.T) {
	f := newFake()
	d := &Darwin{O: testOptions(t, f, false)}
	if st, _ := d.Status(context.Background()); st.Installed {
		t.Fatal("installed before install")
	}
	if _, err := d.Install(context.Background(), plainJob); err != nil {
		t.Fatal(err)
	}
	f.fail("launchctl print gui/1000/io.github.milliebillie.patchtacio.check", "Could not find service")
	st, err := d.Status(context.Background())
	if err != nil || st.Installed || len(st.Notes) != 1 {
		t.Errorf("unloaded agent: %+v, %v", st, err)
	}
	delete(f.answer, "launchctl print gui/1000/io.github.milliebillie.patchtacio.check")
	f.calls = nil
	if err := d.RunNow(context.Background()); err != nil {
		t.Fatal(err)
	}
	if last := f.calls[len(f.calls)-1]; last != "launchctl kickstart gui/1000/io.github.milliebillie.patchtacio.check" {
		t.Errorf("run now: %s", last)
	}
	removed, err := d.Uninstall(context.Background())
	if err != nil || len(removed) != 1 || exists(d.plistPath()) {
		t.Errorf("uninstall: %q, %v", removed, err)
	}
}

func TestTaskInstall(t *testing.T) {
	f := newFake()
	o := testOptions(t, f, false)
	bin := filepath.Join(t.TempDir(), "Program Files", "patchtacio")
	if err := os.MkdirAll(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(bin, "patchtacio.exe")
	j := Job{Program: exe, Args: []string{"watch", "run"}, Hour: 8, Minute: 5,
		Env: []EnvVar{{Name: "PATCHTACIO_DATA_DIR", Value: `D:\data`}}}

	var registered string
	w := &Windows{O: o}
	o.Run = func(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
		if name == "schtasks" && args[0] == "/Create" {
			b := readText(t, args[4])
			registered = decodeUTF16(t, []byte(b))
		}
		return f.run(ctx, stdin, name, args...)
	}
	w.O = o

	// No patchtaciow.exe, no conhost.exe: the console flashes, and says so.
	r, err := w.Install(context.Background(), j)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.calls) != 1 || !strings.HasPrefix(f.calls[0], "schtasks /Create /TN Patchtacio check /XML ") || !strings.HasSuffix(f.calls[0], " /F") {
		t.Errorf("commands %q", f.calls)
	}
	if !strings.Contains(registered, "<Command>"+xmlText(windowsArg(exe))+"</Command>") {
		t.Errorf("task does not run patchtacio.exe:\n%s", registered)
	}
	if len(r.Notes) != 2 || r.Notes[0] != ConsoleNote || !strings.Contains(r.Notes[1], "PATCHTACIO_DATA_DIR") {
		t.Errorf("notes %q", r.Notes)
	}
	if left, _ := filepath.Glob(filepath.Join(o.TempDir, "patchtacio-task-*")); len(left) != 0 {
		t.Errorf("task definition left behind: %q", left)
	}

	// conhost.exe present: headless.
	o.SystemDir = filepath.Join(t.TempDir(), "Windows", "System32")
	touch(t, filepath.Join(o.SystemDir, "conhost.exe"))
	w.O = o
	if _, how := w.Launch(j); how != LaunchHeadless {
		t.Errorf("with conhost: %s", how)
	}
	// patchtaciow.exe next to patchtacio.exe wins.
	touch(t, filepath.Join(bin, WindowlessName))
	run, how := w.Launch(j)
	if how != LaunchWindowless || run.Program != filepath.Join(bin, WindowlessName) {
		t.Errorf("with patchtaciow.exe: %s %s", how, run.Program)
	}
	r, err = w.Install(context.Background(), Job{Program: exe, Args: []string{"watch", "run"}, Hour: 8})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Notes) != 0 {
		t.Errorf("windowless install should need no notes: %q", r.Notes)
	}
}

func TestTaskStatusRunNowUninstall(t *testing.T) {
	f := newFake()
	w := &Windows{O: testOptions(t, f, false)}
	f.fail("schtasks /Query /TN Patchtacio check", "ERROR: The system cannot find the file specified.")
	if st, err := w.Status(context.Background()); err != nil || st.Installed {
		t.Errorf("missing task: %+v %v", st, err)
	}
	if removed, err := w.Uninstall(context.Background()); err != nil || len(removed) != 0 {
		t.Errorf("uninstall without a task: %q %v", removed, err)
	}
	if err := w.RunNow(context.Background()); !errors.Is(err, ErrNotInstalled) {
		t.Errorf("run now without a task: %v", err)
	}

	delete(f.answer, "schtasks /Query /TN Patchtacio check")
	f.calls = nil
	if st, err := w.Status(context.Background()); err != nil || !st.Installed {
		t.Errorf("task present: %+v %v", st, err)
	}
	if err := w.RunNow(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Uninstall(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.requireCalls(t,
		"schtasks /Query /TN Patchtacio check",
		"schtasks /Query /TN Patchtacio check", "schtasks /Run /TN Patchtacio check",
		"schtasks /Query /TN Patchtacio check", "schtasks /Delete /TN Patchtacio check /F",
	)

	f.missing("schtasks /Query /TN Patchtacio check")
	if _, err := w.Status(context.Background()); err == nil {
		t.Error("schtasks missing must be an error, not 'not installed'")
	}
}

func touch(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
}

func decodeUTF16(t *testing.T, b []byte) string {
	t.Helper()
	if len(b) < 2 || b[0] != 0xFF || b[1] != 0xFE {
		t.Fatalf("not UTF-16LE with a byte-order mark")
	}
	u := make([]uint16, (len(b)-2)/2)
	for i := range u {
		u[i] = uint16(b[2+2*i]) | uint16(b[3+2*i])<<8
	}
	return string(utf16.Decode(u))
}

func TestCrontabOnlyEmptyWhenCronSaysSo(t *testing.T) {
	f := newFake()
	f.fail(showEnv, "")
	// "no crontab" with another exit code is not "none": never overwrite.
	f.answer["crontab -l"] = func() ([]byte, error) {
		return nil, &RunError{Name: "crontab", Code: 2, Err: errors.New("exit status 2"), Output: "no crontab for jo; also something else"}
	}
	if _, err := (&Linux{O: testOptions(t, f, true)}).Install(context.Background(), plainJob); err == nil {
		t.Fatal("an unclear crontab answer was taken as empty")
	}
	if slices.Contains(f.calls, "crontab -") {
		t.Error("crontab was overwritten")
	}
}

func TestSystemdUninstallRemovesDropIn(t *testing.T) {
	f := newFake()
	f.say(linger, "yes")
	l := &Linux{O: testOptions(t, f, false)}
	if _, err := l.Install(context.Background(), plainJob); err != nil {
		t.Fatal(err)
	}
	override := filepath.Join(l.unitDir(), SystemdService+".d", "override.conf")
	touch(t, override)
	removed, err := l.Uninstall(context.Background())
	if err != nil || len(removed) != 3 || exists(filepath.Dir(override)) {
		t.Errorf("drop-in (which may hold secrets) left behind: %q %v", removed, err)
	}
}

func TestTaskNamedPerUser(t *testing.T) {
	f := newFake()
	o := testOptions(t, f, false)
	o.UserName = `SCHOOL\jsmith`
	w := &Windows{O: o}
	if _, err := w.Status(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.requireCalls(t, "schtasks /Query /TN Patchtacio check (jsmith)")
}

func TestProgramsByFullPath(t *testing.T) {
	f := newFake()
	o := testOptions(t, f, false)
	o.Programs = map[string]string{"schtasks": `C:\Windows\System32\schtasks.exe`, "launchctl": "/bin/launchctl"}
	if _, err := (&Windows{O: o}).Status(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := (&Darwin{O: o}).Uninstall(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.requireCalls(t, `C:\Windows\System32\schtasks.exe /Query /TN Patchtacio check`)
	o.Programs = nil
	if got := o.program("systemctl"); got != "systemctl" {
		t.Errorf("unlisted program: %q", got)
	}
}

func TestDefaultOptionsPrograms(t *testing.T) {
	o, err := DefaultOptions(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	if o.TempDir == "" {
		t.Error("no temp directory")
	}
	switch runtime.GOOS {
	case "windows":
		if p := o.program("schtasks"); !filepath.IsAbs(p) || !exists(p) {
			t.Errorf("schtasks at %q", p)
		}
	case "darwin":
		if p := o.program("launchctl"); p != "/bin/launchctl" {
			t.Errorf("launchctl at %q", p)
		}
	}
}

func TestCronUninstallLastLineRemovesCrontab(t *testing.T) {
	f := newFake()
	f.fail(showEnv, "")
	line, _ := CronLine(plainJob)
	f.say("crontab -l", line+"\n")
	if _, err := (&Linux{O: testOptions(t, f, true)}).Uninstall(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(f.calls, "crontab -r") || slices.Contains(f.calls, "crontab -") {
		t.Errorf("ours was the only line, so the crontab should be removed: %q", f.calls)
	}
}

func TestCronUninstallKeepsLineAddedMeanwhile(t *testing.T) {
	f := newFake()
	f.fail(showEnv, "")
	line, _ := CronLine(plainJob)
	reads := 0
	f.answer["crontab -l"] = func() ([]byte, error) {
		reads++
		if reads == 1 {
			return []byte(line + "\n"), nil
		}
		return []byte(line + "\n0 3 * * * /usr/bin/backup\n"), nil // the user added a job meanwhile
	}
	if _, err := (&Linux{O: testOptions(t, f, true)}).Uninstall(context.Background()); err == nil {
		t.Fatal("removed the crontab although it changed")
	}
	if slices.Contains(f.calls, "crontab -r") {
		t.Error("crontab -r would have deleted the user's new line")
	}
}
