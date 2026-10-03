package schedule

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"
)

// Launchers: how the Windows task starts Patchtacio without a console window
// (docs/decisions/0004).
const (
	LaunchWindowless = "windowless" // patchtaciow.exe, a GUI-subsystem build
	LaunchHeadless   = "headless"   // conhost.exe --headless patchtacio.exe
	LaunchConsole    = "console"    // patchtacio.exe itself: a console window flashes
)

// WindowlessName is the GUI-subsystem build shipped next to patchtacio.exe.
const WindowlessName = "patchtaciow.exe"

// WindowsLaunch returns the job the task actually runs:
//   - with gui (the path of patchtaciow.exe, if it exists), that program;
//   - otherwise with conhost (the path of conhost.exe, if it exists),
//     conhost.exe --headless running the console program;
//   - otherwise j unchanged, which flashes a console window.
func WindowsLaunch(j Job, gui, conhost string) (Job, string) {
	switch {
	case gui != "":
		j.Program = gui
		return j, LaunchWindowless
	case conhost != "":
		j.Args = append([]string{"--headless", j.Program}, j.Args...)
		j.Program = conhost
		return j, LaunchHeadless
	default:
		return j, LaunchConsole
	}
}

// TaskXML is the Task Scheduler definition for j, registered for the user
// with the given SID. start is the first day the trigger applies (its date
// only is used; the time comes from j).
//
// The task runs only while the user is logged on (no stored password, and
// Credential Manager and notifications still work), also on battery, catches
// up on a missed run, stops after 30 minutes, and never runs twice at once.
func TaskXML(j Job, userSID string, start time.Time) (string, error) {
	return taskXML(j, TaskName, userSID, start)
}

func taskXML(j Job, name, userSID string, start time.Time) (string, error) {
	if err := j.Validate(); err != nil {
		return "", err
	}
	if userSID == "" {
		return "", fmt.Errorf("no user to register the task for")
	}
	boundary := time.Date(start.Year(), start.Month(), start.Day(), j.Hour, j.Minute, 0, 0, time.UTC)
	args := make([]string, len(j.Args))
	for i, a := range j.Args {
		args[i] = windowsArg(a)
	}
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-16"?>` + "\n")
	b.WriteString(`<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">` + "\n")
	b.WriteString("  <RegistrationInfo>\n")
	b.WriteString("    <Author>patchtacio</Author>\n")
	b.WriteString("    <Description>Daily Patchtacio check: alerts for exploited vulnerabilities and end-of-life products. " +
		"Written by `patchtacio watch --install`; remove with `patchtacio watch --uninstall`.</Description>\n")
	fmt.Fprintf(&b, "    <URI>\\%s</URI>\n", xmlText(name))
	b.WriteString("  </RegistrationInfo>\n")
	b.WriteString("  <Triggers>\n    <CalendarTrigger>\n")
	// No time zone offset: local time, so the check follows daylight saving.
	fmt.Fprintf(&b, "      <StartBoundary>%s</StartBoundary>\n", boundary.Format("2006-01-02T15:04:05"))
	b.WriteString("      <Enabled>true</Enabled>\n")
	b.WriteString("      <ScheduleByDay>\n        <DaysInterval>1</DaysInterval>\n      </ScheduleByDay>\n")
	b.WriteString("    </CalendarTrigger>\n  </Triggers>\n")
	b.WriteString("  <Principals>\n    <Principal id=\"Author\">\n")
	fmt.Fprintf(&b, "      <UserId>%s</UserId>\n", xmlText(userSID))
	b.WriteString("      <LogonType>InteractiveToken</LogonType>\n")
	b.WriteString("      <RunLevel>LeastPrivilege</RunLevel>\n")
	b.WriteString("    </Principal>\n  </Principals>\n")
	b.WriteString("  <Settings>\n")
	b.WriteString("    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\n")
	b.WriteString("    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\n")
	b.WriteString("    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\n")
	b.WriteString("    <AllowHardTerminate>true</AllowHardTerminate>\n")
	b.WriteString("    <StartWhenAvailable>true</StartWhenAvailable>\n")
	b.WriteString("    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>\n")
	b.WriteString("    <IdleSettings>\n      <StopOnIdleEnd>false</StopOnIdleEnd>\n      <RestartOnIdle>false</RestartOnIdle>\n    </IdleSettings>\n")
	b.WriteString("    <AllowStartOnDemand>true</AllowStartOnDemand>\n")
	b.WriteString("    <Enabled>true</Enabled>\n")
	b.WriteString("    <Hidden>false</Hidden>\n")
	b.WriteString("    <RunOnlyIfIdle>false</RunOnlyIfIdle>\n")
	b.WriteString("    <WakeToRun>false</WakeToRun>\n")
	b.WriteString("    <ExecutionTimeLimit>PT30M</ExecutionTimeLimit>\n")
	b.WriteString("    <Priority>7</Priority>\n")
	b.WriteString("  </Settings>\n")
	b.WriteString("  <Actions Context=\"Author\">\n    <Exec>\n")
	fmt.Fprintf(&b, "      <Command>%s</Command>\n", xmlText(windowsArg(j.Program)))
	if len(args) > 0 {
		fmt.Fprintf(&b, "      <Arguments>%s</Arguments>\n", xmlText(strings.Join(args, " ")))
	}
	b.WriteString("    </Exec>\n  </Actions>\n")
	b.WriteString("</Task>\n")
	return b.String(), nil
}

// windowsArg quotes one argument the way Windows programs (the Microsoft C
// runtime, and Go) split a command line: quotes around anything with a space,
// tab or quote; backslashes doubled only before a quote.
func windowsArg(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t\"") {
		return s
	}
	var b strings.Builder
	b.WriteByte('"')
	slashes := 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '\\':
			slashes++
			continue
		case '"':
			b.WriteString(strings.Repeat(`\`, 2*slashes+1))
		default:
			b.WriteString(strings.Repeat(`\`, slashes))
		}
		b.WriteByte(s[i])
		slashes = 0
	}
	b.WriteString(strings.Repeat(`\`, 2*slashes))
	b.WriteByte('"')
	return b.String()
}

// UTF16 encodes a task definition as UTF-16LE with a byte-order mark, which
// is what `schtasks /Create /XML` reliably accepts.
func UTF16(s string) []byte {
	u := utf16.Encode([]rune(strings.ReplaceAll(s, "\n", "\r\n")))
	var buf bytes.Buffer
	buf.Write([]byte{0xFF, 0xFE})
	_ = binary.Write(&buf, binary.LittleEndian, u) // writing to a bytes.Buffer cannot fail
	return buf.Bytes()
}
