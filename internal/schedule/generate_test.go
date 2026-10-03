package schedule

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/milliebillie/patchtacio/internal/testutil"
)

// plainJob is a typical install.
var plainJob = Job{
	Program: "/usr/local/bin/patchtacio",
	Args:    []string{"watch", "run"},
	Hour:    8, Minute: 17,
}

// awkwardJob has everything each format must escape: spaces, both quotes,
// %, $, backslashes and a trailing backslash.
var awkwardJob = Job{
	Program: "/home/o'brien/my tools/patch$tacio",
	Args:    []string{"watch", "run", "--config", `/home/o'brien/100% "real"/config.yaml`},
	Env: []EnvVar{
		{Name: "PATCHTACIO_DATA_DIR", Value: `/srv/data $HOME %h\`},
	},
	Hour: 23, Minute: 5,
}

var windowsJob = Job{
	Program: `C:\Users\Jo Smith\AppData\Local\Programs\patchtacio\patchtacio.exe`,
	Args:    []string{"watch", "run", "--config", `C:\Users\Jo Smith\cfg "x"\config.yaml`, `C:\trailing\`},
	Hour:    8, Minute: 5,
}

func golden(name string) string { return filepath.Join("testdata", name) }

func TestSystemdGolden(t *testing.T) {
	for name, j := range map[string]Job{"plain": plainJob, "awkward": awkwardJob} {
		svc, err := SystemdServiceUnit(j)
		if err != nil {
			t.Fatal(err)
		}
		testutil.GoldenText(t, golden("systemd-"+name+".service"), svc)
		timer, err := SystemdTimerUnit(j)
		if err != nil {
			t.Fatal(err)
		}
		testutil.GoldenText(t, golden("systemd-"+name+".timer"), timer)
	}
}

func TestSystemdQuoting(t *testing.T) {
	svc, err := SystemdServiceUnit(awkwardJob)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`ExecStart="/home/o'brien/my tools/patch$$tacio" watch run --config "/home/o'brien/100%% \"real\"/config.yaml"`,
		`Environment="PATCHTACIO_DATA_DIR=/srv/data $HOME %%h\\"`, // $ is literal in Environment=
	} {
		if !strings.Contains(svc, want) {
			t.Errorf("unit lacks %s:\n%s", want, svc)
		}
	}
}

func TestCronLine(t *testing.T) {
	line, err := CronLine(plainJob)
	if err != nil {
		t.Fatal(err)
	}
	if want := "17 8 * * * /usr/local/bin/patchtacio watch run # patchtacio-check"; line != want {
		t.Errorf("got  %s\nwant %s", line, want)
	}
	line, err = CronLine(cronAwkwardJob)
	if err != nil {
		t.Fatal(err)
	}
	want := `5 23 * * * PATCHTACIO_DATA_DIR='/srv/data $HOME\' '/home/o'\''brien/my tools/patch$tacio' watch run --config '/home/o'\''brien/real "one"/config.yaml' # patchtacio-check`
	if line != want {
		t.Errorf("got  %s\nwant %s", line, want)
	}
	// % cannot be passed to every cron reliably, so it is refused.
	if _, err := CronLine(awkwardJob); err == nil || !strings.Contains(err.Error(), "%") {
		t.Errorf("a %% in the job must be refused for cron: %v", err)
	}
}

// cronAwkwardJob is awkwardJob without %, which cron refuses.
var cronAwkwardJob = Job{
	Program: "/home/o'brien/my tools/patch$tacio",
	Args:    []string{"watch", "run", "--config", `/home/o'brien/real "one"/config.yaml`},
	Env:     []EnvVar{{Name: "PATCHTACIO_DATA_DIR", Value: `/srv/data $HOME\`}},
	Hour:    23, Minute: 5,
}

func TestTaskXMLRefusesPercent(t *testing.T) {
	j := windowsJob
	j.Args = []string{"watch", "run", "--config", `C:\100%\config.yaml`}
	if _, err := TaskXML(j, TaskName, "S-1-5-21-1", time.Now()); err == nil || !strings.Contains(err.Error(), "%") {
		t.Errorf("Task Scheduler would expand %%: %v", err)
	}
}

func TestTaskNameFor(t *testing.T) {
	cases := map[string]string{
		`DESKTOP-1\Jo Smith`: "Patchtacio check (Jo Smith)",
		"jo":                 "Patchtacio check (jo)",
		`AD\o:dd*name`:       "Patchtacio check (o-dd-name)",
		"":                   "Patchtacio check",
	}
	for in, want := range cases {
		if got := TaskNameFor(in); got != want {
			t.Errorf("TaskNameFor(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCronMerge(t *testing.T) {
	line, _ := CronLine(plainJob)
	other := "MAILTO=it@example.org\n0 1 * * * /usr/bin/backup # nightly\n"
	cases := []struct {
		name, crontab, line, want string
	}{
		{"empty, add", "", line, line + "\n"},
		{"keep others, add", other, line, other + line + "\n"},
		{"replace old line", other + "1 2 * * * /old/patchtacio watch run # patchtacio-check\n", line, other + line + "\n"},
		{"no final newline", strings.TrimSuffix(other, "\n"), line, other + line + "\n"},
		{"remove, keep others", other + line + "\n", "", other},
		{"remove last line", line + "\n", "", ""},
		{"remove when absent", other, "", other},
	}
	for _, c := range cases {
		if got := CronMerge(c.crontab, c.line); got != c.want {
			t.Errorf("%s:\ngot  %q\nwant %q", c.name, got, c.want)
		}
	}
	if !CronHas(other+line+"\n") || CronHas(other) {
		t.Error("CronHas is wrong")
	}
}

func TestLaunchdGolden(t *testing.T) {
	for name, j := range map[string]Job{"plain": plainJob, "awkward": awkwardJob} {
		p, err := LaunchdPlist(j, "/Users/jo/Library/Caches/patchtacio/cache/logs/launchd.log")
		if err != nil {
			t.Fatal(err)
		}
		testutil.GoldenText(t, golden("launchd-"+name+".plist"), p)
	}
}

func TestTaskXMLGolden(t *testing.T) {
	start := time.Date(2026, 10, 3, 15, 4, 0, 0, time.UTC)
	const sid = "S-1-5-21-1111111111-2222222222-3333333333-1001"
	launches := map[string][2]string{
		"windowless": {`C:\Users\Jo Smith\AppData\Local\Programs\patchtacio\patchtaciow.exe`, ""},
		"headless":   {"", `C:\Windows\System32\conhost.exe`},
		"console":    {"", ""},
	}
	for name, l := range launches {
		j, how := WindowsLaunch(windowsJob, l[0], l[1])
		if how != name {
			t.Errorf("launch %s: got %s", name, how)
		}
		x, err := TaskXML(j, TaskNameFor(`DESKTOP-1\Jo Smith`), sid, start)
		if err != nil {
			t.Fatal(err)
		}
		testutil.GoldenText(t, golden("task-"+name+".xml"), x)
	}
}

func TestWindowsArg(t *testing.T) {
	cases := map[string]string{
		"run":             "run",
		"":                `""`,
		`C:\a b\c`:        `"C:\a b\c"`,
		`C:\dir\`:         `C:\dir\`,
		`C:\a b\`:         `"C:\a b\\"`,
		`say "hi"`:        `"say \"hi\""`,
		`back\"slash`:     `"back\\\"slash"`,
		`C:\no\spaces.do`: `C:\no\spaces.do`,
	}
	for in, want := range cases {
		if got := windowsArg(in); got != want {
			t.Errorf("windowsArg(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestUTF16(t *testing.T) {
	b := UTF16("<a>é\n</a>")
	if b[0] != 0xFF || b[1] != 0xFE {
		t.Fatalf("no UTF-16LE byte-order mark: % x", b[:2])
	}
	u := make([]uint16, (len(b)-2)/2)
	for i := range u {
		u[i] = uint16(b[2+2*i]) | uint16(b[3+2*i])<<8
	}
	if got := string(utf16.Decode(u)); got != "<a>é\r\n</a>" {
		t.Errorf("decoded %q", got)
	}
}

func TestValidateRefuses(t *testing.T) {
	bad := []Job{
		{Program: "patchtacio", Hour: 8},
		{Program: "/bin/patchtacio", Hour: 24},
		{Program: "/bin/patchtacio", Minute: 60},
		{Program: "/bin/patchtacio", Args: []string{"run\nrm -rf ~"}},
		{Program: "/bin/patch\rtacio"},
		{Program: "/bin/patchtacio", Env: []EnvVar{{Name: "A=B", Value: "x"}}},
		{Program: "/bin/patchtacio", Env: []EnvVar{{Name: "A", Value: "x\ny"}}},
	}
	for _, j := range bad {
		if err := j.Validate(); err == nil {
			t.Errorf("Validate accepted %+v", j)
		}
		if _, err := CronLine(j); err == nil {
			t.Errorf("CronLine accepted %+v", j)
		}
	}
	if err := windowsJob.Validate(); err != nil {
		t.Errorf("Windows path refused on this OS: %v", err)
	}
}

func TestNextRun(t *testing.T) {
	loc := time.FixedZone("X", 3600)
	j := Job{Program: "/p", Hour: 8, Minute: 15}
	if got := j.NextRun(time.Date(2026, 10, 3, 7, 0, 0, 0, loc)); !got.Equal(time.Date(2026, 10, 3, 8, 15, 0, 0, loc)) {
		t.Errorf("before today's run: %v", got)
	}
	if got := j.NextRun(time.Date(2026, 10, 3, 8, 15, 0, 0, loc)); !got.Equal(time.Date(2026, 10, 4, 8, 15, 0, 0, loc)) {
		t.Errorf("at today's run: %v", got)
	}
}
