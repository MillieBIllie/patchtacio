package schedule

import (
	"fmt"
	"strings"
)

// SystemdServiceUnit is the service the timer starts.
func SystemdServiceUnit(j Job) (string, error) {
	if err := j.Validate(); err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("# Written by `patchtacio watch --install`; remove with `patchtacio watch --uninstall`.\n")
	b.WriteString("[Unit]\n")
	b.WriteString("Description=Patchtacio daily check (exploited vulnerabilities and end-of-life alerts)\n")
	b.WriteString("Documentation=https://github.com/milliebillie/patchtacio\n")
	b.WriteString("\n[Service]\n")
	b.WriteString("Type=oneshot\n")
	words := []string{systemdExecWord(j.Program)}
	for _, a := range j.Args {
		words = append(words, systemdExecWord(a))
	}
	fmt.Fprintf(&b, "ExecStart=%s\n", strings.Join(words, " "))
	for _, e := range j.Env {
		fmt.Fprintf(&b, "Environment=%s\n", systemdQuote(e.Name+"="+e.Value, false))
	}
	b.WriteString("# 1 = findings, 3 = some data out of date: both reported, not failures. 2 is.\n")
	b.WriteString("SuccessExitStatus=1 3\n")
	b.WriteString("TimeoutStartSec=30min\n")
	b.WriteString("Nice=10\n")
	return b.String(), nil
}

// SystemdTimerUnit runs the service daily; Persistent catches up on a run
// missed while the computer was off.
func SystemdTimerUnit(j Job) (string, error) {
	if err := j.Validate(); err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("# Written by `patchtacio watch --install`; remove with `patchtacio watch --uninstall`.\n")
	b.WriteString("[Unit]\n")
	b.WriteString("Description=Run the Patchtacio check daily\n")
	b.WriteString("\n[Timer]\n")
	fmt.Fprintf(&b, "OnCalendar=*-*-* %02d:%02d:00\n", j.Hour, j.Minute)
	b.WriteString("Persistent=true\n")
	b.WriteString("AccuracySec=1min\n")
	b.WriteString("\n[Install]\n")
	b.WriteString("WantedBy=timers.target\n")
	return b.String(), nil
}

// systemdExecWord quotes one ExecStart word. In ExecStart, $ starts a
// variable and % a specifier, so both are doubled.
func systemdExecWord(s string) string {
	if plainWord(s) {
		return s
	}
	return systemdQuote(s, true)
}

// systemdQuote double-quotes s for a unit file, escaping backslashes and
// quotes, doubling % (specifiers) and, in ExecStart, $ (variables).
func systemdQuote(s string, exec bool) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '\\', '"':
			b.WriteByte('\\')
			b.WriteRune(r)
		case '%':
			b.WriteString("%%")
		case '$':
			if exec {
				b.WriteString("$$")
			} else {
				b.WriteRune(r)
			}
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}
