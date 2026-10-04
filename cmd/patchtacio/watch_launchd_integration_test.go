//go:build integration && darwin

package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/milliebillie/patchtacio/internal/paths"
	"github.com/milliebillie/patchtacio/internal/schedule"
)

// TestLaunchdEndToEnd installs the scheduled check as a real launchd agent and
// checks that it runs, both started on demand (launchctl kickstart) and by
// itself at the scheduled minute. It builds patchtacio, keeps every Patchtacio
// directory in a temp folder (the plist carries PATCHTACIO_*_DIR), and sends
// alerts by email to an SMTP receiver inside the test, so no secret is needed.
// It fetches the live CISA KEV catalog, hence the integration tag. It runs in
// .github/workflows/scheduling-e2e.yml, and on a Mac with:
//
//	go test -tags integration -run LaunchdEndToEnd -v ./cmd/patchtacio/
func TestLaunchdEndToEnd(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(home, "Library", "LaunchAgents", schedule.LaunchdLabel+".plist")); err == nil {
		t.Skip("a real Patchtacio launchd agent is installed; this test would replace it")
	}

	base, err := filepath.EvalSymlinks(t.TempDir()) // /var/folders is a symlink to /private/var
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(base, "bin", "patchtacio")
	ctx := context.Background() // not t.Context(): the cleanup uninstall runs after it ends
	build := exec.CommandContext(ctx, "go", "build", "-o", bin, ".")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	dirs := map[string]string{
		paths.EnvConfigDir: filepath.Join(base, "config"),
		paths.EnvCacheDir:  filepath.Join(base, "cache"),
		paths.EnvDataDir:   filepath.Join(base, "data"),
	}
	env := os.Environ()
	for k, v := range dirs {
		env = append(env, k+"="+v)
	}
	run := func(args ...string) (string, int) {
		t.Helper()
		cmd := exec.CommandContext(ctx, bin, args...)
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		if ee, ok := errors.AsType[*exec.ExitError](err); ok {
			return string(out), ee.ExitCode()
		}
		if err != nil {
			t.Fatalf("patchtacio %s: %v", strings.Join(args, " "), err)
		}
		return string(out), 0
	}
	must := func(want int, args ...string) string {
		t.Helper()
		out, code := run(args...)
		if code != want {
			t.Fatalf("patchtacio %s: exit %d, want %d\n%s", strings.Join(args, " "), code, want, out)
		}
		return out
	}
	logFile := filepath.Join(dirs[paths.EnvCacheDir], "logs", logFileName)
	t.Cleanup(func() {
		if t.Failed() {
			for _, f := range []string{logFile, filepath.Join(filepath.Dir(logFile), schedule.LaunchdOutputName)} {
				if b, err := os.ReadFile(f); err == nil {
					t.Logf("--- %s:\n%s", f, b)
				}
			}
		}
		out, _ := run("watch", "--uninstall") // never leave an agent behind
		t.Logf("cleanup: %s", strings.TrimSpace(out))
	})

	sink := startSMTPSink(t)
	must(0, "init", "--products", "citrix-netscaler")
	appendFile(t, filepath.Join(dirs[paths.EnvConfigDir], "config.yaml"), fmt.Sprintf(
		"notify:\n  email:\n    host: 127.0.0.1\n    port: %d\n    security: none\n    from: patchtacio@example.org\n    to: [it@example.org]\n",
		sink.port()))
	must(0, "test-alert")
	sink.require(t, 1, "[Test]")

	// At least a minute away, so the on-demand run below is over before it.
	at := time.Now().Add(2 * time.Minute).Truncate(time.Minute)
	out := must(0, "watch", "--install", "--at", at.Format("15:04"))
	t.Logf("install:\n%s", out)
	if !strings.Contains(out, schedule.MethodLaunchd) {
		t.Fatalf("not installed as a launchd agent:\n%s", out)
	}
	plist := filepath.Join(home, "Library", "LaunchAgents", schedule.LaunchdLabel+".plist")
	if fi, err := os.Stat(plist); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("plist %s: %v (mode %v)", plist, err, fi.Mode())
	}

	// 1. Started on demand through launchd.
	asked := time.Now()
	must(0, "watch", "--run-now")
	rec := waitForRun(t, dirs[paths.EnvDataDir], asked, 2*time.Minute)
	if rec.ExitCode != exitFindings {
		t.Fatalf("on-demand run: exit %d, want %d (findings); error %q", rec.ExitCode, exitFindings, rec.Error)
	}
	sink.require(t, 2, "actively exploited")
	must(0, "watch", "--status")

	// 2. Started by launchd itself at the scheduled minute.
	rec = waitForRun(t, dirs[paths.EnvDataDir], at.Add(-time.Second), time.Until(at)+2*time.Minute)
	if late := rec.StartedAt.Sub(at); late < 0 || late > time.Minute {
		t.Errorf("scheduled run started at %s, want within a minute after %s", rec.StartedAt.Local().Format(time.TimeOnly), at.Format(time.TimeOnly))
	}
	if rec.ExitCode != exitFindings {
		t.Errorf("scheduled run: exit %d, want %d; error %q", rec.ExitCode, exitFindings, rec.Error)
	}
	sink.require(t, 2, "") // nothing new to send: no second alert
	status := must(0, "watch", "--status")
	t.Logf("status:\n%s", status)

	b, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(b), "scheduled check started"); n != 2 {
		t.Errorf("log has %d runs, want 2", n)
	}
	if strings.Contains(string(b), "Usage:") {
		t.Error("log contains cobra usage text")
	}

	// 3. Uninstall removes the agent from disk and from launchd.
	must(0, "watch", "--uninstall")
	if _, err := os.Stat(plist); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("plist left after uninstall: %v", err)
	}
	if err := exec.CommandContext(ctx, "/bin/launchctl", "print", fmt.Sprintf("gui/%d/%s", os.Getuid(), schedule.LaunchdLabel)).Run(); err == nil {
		t.Error("launchd still has the agent after uninstall")
	}
	must(2, "watch", "--status")
}

// waitForRun waits for a scheduled run that started after after.
func waitForRun(t *testing.T, dataDir string, after time.Time, limit time.Duration) watchRun {
	t.Helper()
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if r, err := readJSON[watchRun](filepath.Join(dataDir, watchRunFile)); err == nil && r != nil && r.StartedAt.After(after) {
			return *r
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("no run started after %s within %s", after.Format(time.TimeOnly), limit)
	return watchRun{}
}

func appendFile(t *testing.T, path, text string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteString(text); err != nil {
		t.Fatal(err)
	}
}

// smtpSink is just enough of an SMTP server to receive Patchtacio's mail.
type smtpSink struct {
	ln   net.Listener
	mu   sync.Mutex
	msgs []string
}

func startSMTPSink(t *testing.T) *smtpSink {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &smtpSink{ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(c)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

func (s *smtpSink) port() int { return s.ln.Addr().(*net.TCPAddr).Port }

func (s *smtpSink) serve(c net.Conn) {
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(time.Minute))
	r := bufio.NewReader(c)
	say := func(line string) { _, _ = fmt.Fprintf(c, "%s\r\n", line) }
	say("220 sink ESMTP")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		switch cmd := strings.ToUpper(strings.TrimSpace(line)); {
		case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
			say("250-sink")
			say("250 8BITMIME")
		case cmd == "DATA":
			say("354 end with <CRLF>.<CRLF>")
			var b strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				b.WriteString(l)
			}
			s.mu.Lock()
			s.msgs = append(s.msgs, b.String())
			s.mu.Unlock()
			say("250 queued")
		case cmd == "QUIT":
			say("221 bye")
			return
		default: // MAIL, RCPT, RSET, NOOP
			say("250 OK")
		}
	}
}

// require checks the sink has n messages, the last containing want.
func (s *smtpSink) require(t *testing.T, n int, want string) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.msgs) != n {
		t.Fatalf("mail received: %d messages, want %d", len(s.msgs), n)
	}
	if want != "" && !strings.Contains(s.msgs[n-1], want) {
		t.Fatalf("last message lacks %q:\n%.1500s", want, s.msgs[n-1])
	}
}
