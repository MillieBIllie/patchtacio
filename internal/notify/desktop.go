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
	"slices"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/milliebillie/patchtacio/internal/advice"
	"github.com/milliebillie/patchtacio/internal/config"
	"github.com/milliebillie/patchtacio/internal/logging"
	"github.com/milliebillie/patchtacio/internal/sysdir"
)

// Desktop shows a notification on this computer. The alert text never passes
// through a shell or into a script: Linux and macOS get it as program
// arguments, and Windows' fixed PowerShell script reads it from environment
// variables.
type Desktop struct {
	goos     string
	lookPath func(string) (string, error)
	sysDir   func() (string, error) // the Windows system directory
	run      func(ctx context.Context, c desktopCmd) error
}

// NewDesktop returns a desktop channel for this computer.
func NewDesktop() *Desktop {
	return &Desktop{goos: runtime.GOOS, lookPath: exec.LookPath, sysDir: sysdir.System, run: runDesktop}
}

// Name implements Channel.
func (d *Desktop) Name() string { return config.ChannelDesktop }

// Destination implements Channel: this computer.
func (d *Desktop) Destination() []string { return nil }

// Send implements Channel.
func (d *Desktop) Send(ctx context.Context, m advice.Message) error {
	c, err := advice.ChatMessage(m)
	if err != nil {
		return err
	}
	return d.show(ctx, c.Title, advice.Short(m))
}

// SendNotice implements Channel.
func (d *Desktop) SendNotice(ctx context.Context, n advice.Notice) error {
	return d.show(ctx, n.Subject, n.Short)
}

func (d *Desktop) show(ctx context.Context, title, body string) error {
	c, err := desktopCommand(d.goos, oneLineText(title), oneLineText(body), d.lookPath, d.sysDir)
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
// sysDir), so tests check every OS's command on every OS.
func desktopCommand(goos, title, body string, lookPath func(string) (string, error), sysDir func() (string, error)) (desktopCmd, error) {
	switch goos {
	case "linux", "freebsd", "openbsd", "netbsd":
		p, err := lookPath("notify-send")
		if err != nil {
			return desktopCmd{}, errors.New("desktop notifications need notify-send: install libnotify-bin (Debian, Ubuntu) or libnotify (Fedora, Arch)")
		}
		// "--" ends options, so text starting with "-" is never one. The
		// body is markup on GNOME and KDE, so & < > are escaped.
		return desktopCmd{Path: p, Args: []string{"--app-name=Patchtacio", "--urgency=critical", "--", title, markupEscape(body)}}, nil
	case "darwin":
		// The text arrives as argv, never inside the AppleScript source.
		// osascript has no "--", so text must not start with "-".
		return desktopCmd{Path: "/usr/bin/osascript", Args: []string{
			"-e", "on run argv",
			"-e", "display notification (item 2 of argv) with title (item 1 of argv)",
			"-e", "end run",
			notOption(title), notOption(body),
		}}, nil
	case "windows":
		// A full path from Windows itself (not %SystemRoot%, which a parent
		// process sets), so a powershell.exe earlier in PATH is never run.
		sys, err := sysDir()
		if err != nil {
			return desktopCmd{}, fmt.Errorf("find Windows PowerShell: %w", err)
		}
		ps := sys + `\WindowsPowerShell\v1.0\powershell.exe`
		return desktopCmd{
			Path: ps,
			Args: []string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encodePowerShell(toastScript)},
			Env:  []string{envToastTitle + "=" + title, envToastBody + "=" + body},
		}, nil
	default:
		return desktopCmd{}, fmt.Errorf("desktop notifications are not supported on %s", goos)
	}
}

// markupEscape escapes the characters notify-send bodies treat as markup.
func markupEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

// notOption keeps text from being read as a command-line option.
func notOption(s string) string {
	if strings.HasPrefix(s, "-") {
		return " " + s
	}
	return s
}

// secretEnv lists environment variables a notification program never needs.
var secretEnv = []string{
	config.EnvSMTPPassword, config.EnvWebhookURL, config.EnvNtfyURL, config.EnvNtfyToken, "NVD_API_KEY",
}

// childEnv is env without the secrets, plus extra.
func childEnv(env, extra []string) []string {
	out := make([]string, 0, len(env)+len(extra))
	for _, kv := range env {
		name, _, _ := strings.Cut(kv, "=")
		if !slices.ContainsFunc(secretEnv, func(s string) bool { return strings.EqualFold(s, name) }) {
			out = append(out, kv)
		}
	}
	return append(out, extra...)
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
	cmd.Env = childEnv(os.Environ(), c.Env)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	hideWindow(cmd)
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
