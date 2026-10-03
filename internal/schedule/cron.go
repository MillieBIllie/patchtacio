package schedule

import (
	"fmt"
	"strings"
)

// CronLine is the crontab line for j, ending in CronMarker. Cron hands the
// command to /bin/sh, so every value that is not a plain word is single-quoted,
// and % (which cron turns into a newline) is escaped.
func CronLine(j Job) (string, error) {
	if err := j.Validate(); err != nil {
		return "", err
	}
	words := make([]string, 0, len(j.Env)+1+len(j.Args))
	for _, e := range j.Env {
		words = append(words, e.Name+"="+cronQuote(e.Value))
	}
	words = append(words, cronQuote(j.Program))
	for _, a := range j.Args {
		words = append(words, cronQuote(a))
	}
	return fmt.Sprintf("%d %d * * * %s %s", j.Minute, j.Hour, strings.Join(words, " "), CronMarker), nil
}

func cronQuote(s string) string {
	if plainWord(s) {
		return s
	}
	s = strings.ReplaceAll(s, "'", `'\''`)
	s = strings.ReplaceAll(s, "%", `\%`)
	return "'" + s + "'"
}

// isCronJob reports whether a crontab line is Patchtacio's.
func isCronJob(line string) bool {
	return strings.HasSuffix(strings.TrimRight(line, " \t\r"), CronMarker)
}

// CronHas reports whether a crontab holds Patchtacio's line.
func CronHas(crontab string) bool {
	for line := range strings.SplitSeq(crontab, "\n") {
		if isCronJob(line) {
			return true
		}
	}
	return false
}

// CronMerge returns crontab with Patchtacio's line replaced by line, or
// removed when line is "". Every other line is kept as it was.
func CronMerge(crontab, line string) string {
	var kept []string
	for l := range strings.SplitSeq(strings.TrimRight(crontab, "\n"), "\n") {
		if !isCronJob(l) {
			kept = append(kept, l)
		}
	}
	if len(kept) == 1 && kept[0] == "" {
		kept = nil
	}
	if line != "" {
		kept = append(kept, line)
	}
	if len(kept) == 0 {
		return ""
	}
	return strings.Join(kept, "\n") + "\n" // cron ignores a last line without a newline
}
