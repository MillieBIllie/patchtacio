package notify

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/milliebillie/patchtacio/internal/advice"
	"github.com/milliebillie/patchtacio/internal/config"
	"github.com/milliebillie/patchtacio/internal/logging"
)

// Desktop shows a notification on this computer. The alert text never passes
// through a shell or into a script: Linux and macOS get it as program
// arguments, and Windows' fixed PowerShell script reads it from environment
// variables.
type Desktop struct {
	goos     string
	lookPath func(string) (string, error)
	getenv   func(string) string
	run      func(ctx context.Context, c desktopCmd) error
}

// NewDesktop returns a desktop channel for this computer.
func NewDesktop() *Desktop {
	return &Desktop{goos: runtime.GOOS, lookPath: exec.LookPath, getenv: os.Getenv, run: runDesktop}
}

// Name implements Channel.
func (d *Desktop) Name() string { return config.ChannelDesktop }

// Send implements Channel.
func (d *Desktop) Send(ctx context.Context, m advice.Message) error {
	c, err := advice.ChatMessage(m)
	if err != nil {
		return err
	}
	return d.show(ctx, c.Title, advice.Short(m))
}

// SendTest implements Channel.
func (d *Desktop) SendTest(ctx context.Context) error {
	return d.show(ctx, advice.TestSubject, advice.TestShort)
}

func (d *Desktop) show(ctx context.Context, title, body string) error {
	c, err := desktopCommand(d.goos, oneLineText(title), oneLineText(body), d.lookPath, d.getenv)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return d.run(ctx, c)
}

// desktopCmd is a program to run, with extra environment variables.
type desktopCmd struct {
	Path string
	Args []string
	Env  []string
}

// Environment variables that carry the text to the Windows script.
const (
	envToastTitle = "PATCHTACIO_TOAST_TITLE"
	envToastBody  = "PATCHTACIO_TOAST_BODY"
)

// toastScript shows a Windows toast through the WinRT API, which Windows
// PowerShell 5.1 can reach (PowerShell 7 cannot). It is fixed: the text
// arrives in environment variables and CreateTextNode escapes it, so nothing
// in an alert can become code or XML. Notifications are shown under Windows
// PowerShell's own app ID, which every Windows 10 and 11 has registered.
const toastScript = `$ErrorActionPreference = 'Stop'
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom, ContentType = WindowsRuntime] | Out-Null
$xml = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
$text = $xml.GetElementsByTagName('text')
$text.Item(0).AppendChild($xml.CreateTextNode($env:PATCHTACIO_TOAST_TITLE)) | Out-Null
$text.Item(1).AppendChild($xml.CreateTextNode($env:PATCHTACIO_TOAST_BODY)) | Out-Null
$toast = [Windows.UI.Notifications.ToastNotification]::new($xml)
$app = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($app).Show($toast)
`

// desktopCommand builds the command for goos. It is pure (given lookPath and
// getenv), so tests check every OS's command on every OS.
func desktopCommand(goos, title, body string, lookPath func(string) (string, error), getenv func(string) string) (desktopCmd, error) {
	switch goos {
	case "linux", "freebsd", "openbsd", "netbsd":
		p, err := lookPath("notify-send")
		if err != nil {
			return desktopCmd{}, errors.New("desktop notifications need notify-send: install libnotify-bin (Debian, Ubuntu) or libnotify (Fedora, Arch)")
		}
		// "--" ends options, so text starting with "-" is never one.
		return desktopCmd{Path: p, Args: []string{"--app-name=Patchtacio", "--urgency=critical", "--", title, body}}, nil
	case "darwin":
		// The text arrives as argv, never inside the AppleScript source.
		return desktopCmd{Path: "/usr/bin/osascript", Args: []string{
			"-e", "on run argv",
			"-e", "display notification (item 2 of argv) with title (item 1 of argv)",
			"-e", "end run",
			title, body,
		}}, nil
	case "windows":
		root := getenv("SystemRoot")
		if root == "" {
			root = `C:\Windows`
		}
		// A full path, so a powershell.exe earlier in PATH is never run.
		ps := root + `\System32\WindowsPowerShell\v1.0\powershell.exe`
		return desktopCmd{
			Path: ps,
			Args: []string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encodePowerShell(toastScript)},
			Env:  []string{envToastTitle + "=" + title, envToastBody + "=" + body},
		}, nil
	default:
		return desktopCmd{}, fmt.Errorf("desktop notifications are not supported on %s", goos)
	}
}

// encodePowerShell is what -EncodedCommand expects: UTF-16LE, base64.
func encodePowerShell(script string) string {
	u := utf16.Encode([]rune(script))
	b := make([]byte, 2*len(u))
	for i, r := range u {
		binary.LittleEndian.PutUint16(b[2*i:], r)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func runDesktop(ctx context.Context, c desktopCmd) error {
	cmd := exec.CommandContext(ctx, filepath.Clean(c.Path), c.Args...) //nolint:gosec // fixed program; text passed as arguments, never through a shell
	cmd.Env = append(os.Environ(), c.Env...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		msg := strings.Join(strings.Fields(logging.Clean(out.String())), " ")
		if len(msg) > 300 {
			msg = msg[:300] + "…"
		}
		if msg != "" {
			return fmt.Errorf("desktop notification failed: %w: %s", err, msg)
		}
		return fmt.Errorf("desktop notification failed: %w", err)
	}
	return nil
}

// oneLineText folds whitespace so a notification is one tidy line.
func oneLineText(s string) string {
	return strings.Join(strings.Fields(logging.Clean(strings.NewReplacer("\n", " ", "\r", " ", "\t", " ").Replace(s))), " ")
}
