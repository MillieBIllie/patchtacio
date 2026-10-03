package notify

import (
	"context"
	"encoding/base64"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/milliebillie/patchtacio/internal/testutil"
)

func fakeLookPath(name string) (string, error) { return "/usr/bin/" + name, nil }

func fakeSysDir() (string, error) { return `C:\WINDOWS\System32`, nil }

func decodePowerShell(t *testing.T, s string) string {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = uint16(b[2*i]) | uint16(b[2*i+1])<<8
	}
	return string(utf16.Decode(u))
}

// Every OS's command is checked on every OS (cross-platform skill).
func TestDesktopCommandGolden(t *testing.T) {
	// Text that would be dangerous if it reached a shell or a script.
	title := `[Action needed by 12 Oct 2026] Acme "Widget"; $(rm -rf ~) & '`
	body := `-n Patchtacio: Acme exploited flaw CVE-2026-1. ` + "`whoami`" + ` <toast/>`
	for _, goos := range []string{"linux", "darwin", "windows"} {
		t.Run(goos, func(t *testing.T) {
			c, err := desktopCommand(goos, title, body, fakeLookPath, fakeSysDir)
			if err != nil {
				t.Fatal(err)
			}
			var b strings.Builder
			b.WriteString("path: " + c.Path + "\n")
			for i, a := range c.Args {
				if i > 0 && c.Args[i-1] == "-EncodedCommand" {
					b.WriteString("arg: <EncodedCommand>\n--- decoded script ---\n" + decodePowerShell(t, a) + "--- end ---\n")
					continue
				}
				b.WriteString("arg: " + a + "\n")
			}
			for _, e := range c.Env {
				b.WriteString("env: " + e + "\n")
			}
			testutil.GoldenText(t, filepath.Join("testdata", "desktop_"+goos+".golden"), b.String())

			if goos == "windows" {
				// The text reaches PowerShell only through the environment.
				for _, a := range c.Args {
					if strings.Contains(a, "Widget") || strings.Contains(decodeIfEncoded(t, c.Args, a), "Widget") {
						t.Errorf("alert text in a PowerShell argument: %q", a)
					}
				}
			}
		})
	}
}

func decodeIfEncoded(t *testing.T, args []string, a string) string {
	i := slices.Index(args, a)
	if i > 0 && args[i-1] == "-EncodedCommand" {
		return decodePowerShell(t, a)
	}
	return ""
}

func TestDesktopTextNeverAnOption(t *testing.T) {
	c, err := desktopCommand("darwin", "-e do shell script", "-x", fakeLookPath, fakeSysDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range c.Args[6:] {
		if strings.HasPrefix(a, "-") {
			t.Errorf("osascript argument %q starts with -", a)
		}
	}
	c, _ = desktopCommand("linux", "t", `<a href="x">&</a>`, fakeLookPath, fakeSysDir)
	if got := c.Args[len(c.Args)-1]; got != "&lt;a href=\"x\"&gt;&amp;&lt;/a&gt;" {
		t.Errorf("notify-send body not escaped: %q", got)
	}
}

func TestChildEnvDropsSecrets(t *testing.T) {
	got := childEnv([]string{"PATH=/bin", "PATCHTACIO_WEBHOOK_URL=https://x/secret", "patchtacio_smtp_password=p",
		"PATCHTACIO_NTFY_TOKEN=t", "PATCHTACIO_NTFY_URL=u", "NVD_API_KEY=k", "HOME=/h"}, []string{"PATCHTACIO_TOAST_TITLE=x"})
	want := []string{"PATH=/bin", "HOME=/h", "PATCHTACIO_TOAST_TITLE=x"}
	if !slices.Equal(got, want) {
		t.Errorf("childEnv = %v, want %v", got, want)
	}
}

func TestDesktopLinuxWithoutNotifySend(t *testing.T) {
	_, err := desktopCommand("linux", "t", "b", func(string) (string, error) { return "", errors.New("not found") }, fakeSysDir)
	if err == nil || !strings.Contains(err.Error(), "notify-send") {
		t.Errorf("want an install hint, got %v", err)
	}
	if _, err := desktopCommand("plan9", "t", "b", fakeLookPath, fakeSysDir); err == nil {
		t.Error("want an error on an unsupported OS")
	}
}

func TestDesktopSendUsesShortText(t *testing.T) {
	var got desktopCmd
	d := &Desktop{goos: "linux", lookPath: fakeLookPath, sysDir: fakeSysDir,
		run: func(_ context.Context, c desktopCmd) error { got = c; return nil }}
	if err := d.Send(context.Background(), sample()); err != nil {
		t.Fatal(err)
	}
	n := len(got.Args)
	if n < 2 || !strings.HasPrefix(got.Args[n-2], "[Action needed by 12 Oct 2026]") || !strings.HasPrefix(got.Args[n-1], "Patchtacio: Acme Widget exploited flaw CVE-2026-1") {
		t.Errorf("args: %q", got.Args)
	}
	if strings.ContainsAny(got.Args[n-1], "\n\r") {
		t.Error("notification body spans lines")
	}
}

func TestDesktopWindowsNeedsSystemDirectory(t *testing.T) {
	noDir := func() (string, error) { return "", errors.New("no system directory") }
	if _, err := desktopCommand("windows", "t", "b", fakeLookPath, noDir); err == nil {
		t.Error("PowerShell was run without knowing where Windows keeps it")
	}
}
