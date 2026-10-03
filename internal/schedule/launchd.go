package schedule

import (
	"encoding/xml"
	"fmt"
	"strings"
)

// LaunchdPlist is the launchd agent for j. launchd's own output (only written
// if the run cannot open its log file) goes to outPath.
func LaunchdPlist(j Job, outPath string) (string, error) {
	if err := j.Validate(); err != nil {
		return "", err
	}
	if !isAbs(outPath) {
		return "", fmt.Errorf("launchd output path %q is not absolute", outPath)
	}
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` + "\n")
	b.WriteString("<!-- Written by `patchtacio watch --install`; remove with `patchtacio watch --uninstall`. -->\n")
	b.WriteString(`<plist version="1.0">` + "\n<dict>\n")
	key := func(k string) { fmt.Fprintf(&b, "\t<key>%s</key>\n", k) }
	str := func(indent, s string) { fmt.Fprintf(&b, "%s<string>%s</string>\n", indent, xmlText(s)) }

	key("Label")
	str("\t", LaunchdLabel)
	key("ProgramArguments")
	b.WriteString("\t<array>\n")
	str("\t\t", j.Program)
	for _, a := range j.Args {
		str("\t\t", a)
	}
	b.WriteString("\t</array>\n")
	if len(j.Env) > 0 {
		key("EnvironmentVariables")
		b.WriteString("\t<dict>\n")
		for _, e := range j.Env {
			fmt.Fprintf(&b, "\t\t<key>%s</key>\n", xmlText(e.Name))
			str("\t\t", e.Value)
		}
		b.WriteString("\t</dict>\n")
	}
	key("StartCalendarInterval")
	fmt.Fprintf(&b, "\t<dict>\n\t\t<key>Hour</key>\n\t\t<integer>%d</integer>\n\t\t<key>Minute</key>\n\t\t<integer>%d</integer>\n\t</dict>\n", j.Hour, j.Minute)
	key("Umask") // files it creates are readable only by the user (077)
	b.WriteString("\t<integer>63</integer>\n")
	key("ProcessType")
	str("\t", "Background")
	key("StandardOutPath")
	str("\t", outPath)
	key("StandardErrorPath")
	str("\t", outPath)
	b.WriteString("</dict>\n</plist>\n")
	return b.String(), nil
}

func xmlText(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s)) // writing to a strings.Builder cannot fail
	return b.String()
}
