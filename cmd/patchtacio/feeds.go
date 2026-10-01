package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/spf13/cobra"

	"github.com/milliebillie/patchtacio/internal/feeds"
	"github.com/milliebillie/patchtacio/internal/logging"
)

func newFeedsCmd(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "feeds",
		Short: "Download and inspect the vulnerability and end-of-life data",
	}
	cmd.AddCommand(newFeedsUpdateCmd(a), newFeedsStatusCmd(a))
	return cmd
}

func newFeedsUpdateCmd(a *app) *cobra.Command {
	var offline bool
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Download the latest data (falls back to the saved copy if a source is down)",
		Long: "Downloads the CISA KEV catalog and endoflife.date data, keeping a saved copy.\n" +
			"If a source cannot be reached, the saved copy is used and a warning explains how old it is.\n\n" +
			"Exit codes: 0 all data updated; 3 some data could not be updated (saved copy used);\n" +
			"2 some data is not available at all.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			u, closeFn, err := a.openUpdater(cmd.Context())
			if err != nil {
				return err
			}
			defer closeFn()
			results, err := u.Update(cmd.Context(), offline)
			if err != nil {
				return fmt.Errorf("update feeds: %w", err)
			}
			out, warn := cmd.OutOrStdout(), cmd.ErrOrStderr()
			code := exitOK
			for _, r := range results {
				c := a.reportResult(out, warn, r, offline)
				code = worse(code, c)
			}
			return outcome(code)
		},
	}
	cmd.Flags().BoolVar(&offline, "offline", false, "do not use the network; report on the saved copies only")
	return cmd
}

func newFeedsStatusCmd(a *app) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show how up to date the saved data is (no network use)",
		Long: "Shows each data source's saved copy and when it was last checked.\n\n" +
			"Exit codes: 0 all data is up to date; 3 some data is out of date; 2 some data is missing.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			u, closeFn, err := a.openUpdater(cmd.Context())
			if err != nil {
				return err
			}
			defer closeFn()
			sts, err := u.Statuses(cmd.Context())
			if err != nil {
				return fmt.Errorf("read feed status: %w", err)
			}
			code := exitOK
			for _, st := range sts {
				code = worse(code, stateCode(st.State))
			}
			if asJSON {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				if err := enc.Encode(sts); err != nil {
					return fmt.Errorf("encode status: %w", err)
				}
				return outcome(code)
			}
			a.printStatusTable(cmd.OutOrStdout(), sts)
			for _, st := range sts {
				a.warnState(cmd.ErrOrStderr(), st)
			}
			return outcome(code)
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print machine-readable JSON")
	return cmd
}

// reportResult prints one source's update outcome and returns its exit code.
// Success goes to stdout (hidden by --quiet); anything that changes what the
// data can be trusted for goes to stderr, always.
func (a *app) reportResult(out, warn io.Writer, r feeds.Result, offline bool) int {
	st := r.Status
	if r.Outcome.Refreshed() {
		if !a.quiet {
			_, _ = fmt.Fprintf(out, "%s: %s. %s.\n", st.Title, refreshedVerb(r.Outcome), a.describe(st))
		}
		if st.Via == feeds.ViaMirror && r.Outcome == feeds.Updated {
			_, _ = fmt.Fprintf(warn, "Note: %s was downloaded from its official GitHub mirror because the main site did not answer.\n", st.Title)
		}
		a.warnState(warn, st) // e.g. an old copy from a mirror
		return stateCode(st.State)
	}

	if offline {
		if st.State == feeds.Fresh && !a.quiet {
			_, _ = fmt.Fprintf(out, "%s: not checked (offline). Saved copy: %s.\n", st.Title, a.describe(st))
		}
		a.warnState(warn, st)
		return stateCode(st.State)
	}

	// Not refreshed: say why, then what the user is left with.
	reason := ""
	switch {
	case r.Err != nil: // this run's error, not an older stored one
		reason = " Reason: " + firstLine(logging.RedactString(r.Err.Error()))
	case st.LastError != "":
		reason = " Reason: " + firstLine(st.LastError)
	}
	if st.State == feeds.Missing {
		_, _ = fmt.Fprintf(warn, "Warning: %s could not be downloaded and there is no saved copy, so this data is not available.%s\n"+
			"  Check your internet connection or proxy settings (HTTPS_PROXY), then run `patchtacio feeds update` again.\n", st.Title, reason)
		return exitToolError
	}
	_, _ = fmt.Fprintf(warn, "Warning: %s could not be updated, so Patchtacio is using the saved copy last checked %s.%s\n",
		st.Title, a.when(st.CheckedAt), reason)
	if st.State == feeds.Stale {
		a.warnState(warn, st)
	}
	return exitStale
}

// warnState explains stale or missing data. Fresh data needs no warning.
func (a *app) warnState(w io.Writer, st feeds.Status) {
	switch st.State {
	case feeds.Stale:
		reason := st.StaleReason
		if reason == "" {
			reason = "it has not been checked recently"
		}
		_, _ = fmt.Fprintf(w, "Warning: %s data is out of date because %s. Last checked %s. "+
			"Anything published since then is not included.\n", st.Title, reason, a.when(st.CheckedAt))
		if st.LastError != "" {
			_, _ = fmt.Fprintf(w, "  Last problem: %s\n", firstLine(st.LastError))
		}
		_, _ = fmt.Fprintln(w, "  Run `patchtacio feeds update` when you are online.")
	case feeds.Fresh:
		if st.LastUpdateFailed {
			_, _ = fmt.Fprintf(w, "Note: the last update attempt for %s (%s) failed: %s\n"+
				"  The saved copy is still recent enough to use.\n", st.Title, a.when(st.AttemptedAt), firstLine(st.LastError))
		}
	case feeds.Missing:
		_, _ = fmt.Fprintf(w, "Warning: there is no saved copy of %s, so this data is not available.\n"+
			"  Run `patchtacio feeds update` when you are online.\n", st.Title)
	}
}

func (a *app) printStatusTable(w io.Writer, sts []feeds.Status) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "SOURCE\tSTATE\tSAVED COPY\tLAST CHECKED")
	for _, st := range sts {
		saved, checked := "none", "never"
		if st.State != feeds.Missing {
			saved = a.describe(st)
		}
		if !st.CheckedAt.IsZero() {
			checked = a.when(st.CheckedAt)
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", st.Title, stateLabel(st.State), saved, checked)
	}
	_ = tw.Flush()
}

// describe summarises a saved copy: "1,730 entries, catalog 2026.09.30, published 30 Sep 2026".
func (a *app) describe(st feeds.Status) string {
	parts := []string{fmt.Sprintf("%s %s", thousands(st.Count), unitFor(st.Name))}
	if st.Name == "kev" && st.Version != "" {
		parts = append(parts, "catalog "+clean(st.Version))
	}
	if !st.PublishedAt.IsZero() {
		parts = append(parts, "published "+a.date(st.PublishedAt))
	}
	if st.Via == feeds.ViaMirror {
		parts = append(parts, "via GitHub mirror")
	}
	return strings.Join(parts, ", ")
}

func refreshedVerb(o feeds.Outcome) string {
	switch o {
	case feeds.Updated:
		return "updated"
	case feeds.Unchanged:
		return "up to date (no changes since the last check)"
	default:
		return "up to date (just updated by another Patchtacio run)"
	}
}

func stateLabel(s feeds.State) string {
	switch s {
	case feeds.Fresh:
		return "up to date"
	case feeds.Stale:
		return "out of date"
	default:
		return "missing"
	}
}

func stateCode(s feeds.State) int {
	switch s {
	case feeds.Fresh:
		return exitOK
	case feeds.Stale:
		return exitStale
	default:
		return exitToolError
	}
}

// worse combines exit codes for this command: missing data (2) beats stale
// data (3), which beats success (0).
func worse(a, b int) int {
	rank := func(c int) int {
		switch c {
		case exitToolError:
			return 2
		case exitStale:
			return 1
		default:
			return 0
		}
	}
	if rank(b) > rank(a) {
		return b
	}
	return a
}

func outcome(code int) error {
	if code == exitOK {
		return nil
	}
	return &exitError{code: code}
}

func unitFor(name string) string {
	switch name {
	case "kev":
		return "entries"
	case "eol":
		return "products"
	default:
		return "records"
	}
}

// date formats a calendar date in the user's time zone: "30 Sep 2026".
func (a *app) date(t time.Time) string { return t.In(a.loc).Format("2 Jan 2006") }

// when formats a moment with its age: "30 Sep 2026 14:05 UTC (3 hours ago)".
func (a *app) when(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return fmt.Sprintf("%s (%s)", t.In(a.loc).Format("2 Jan 2006 15:04 MST"), age(a.now().Sub(t)))
}

func age(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return plural(int(d/time.Minute), "minute") + " ago"
	case d < 48*time.Hour:
		return plural(int(d/time.Hour), "hour") + " ago"
	default:
		return plural(int(d/(24*time.Hour)), "day") + " ago"
	}
}

func plural(n int, unit string) string {
	if n == 1 {
		return "1 " + unit
	}
	return strconv.Itoa(n) + " " + unit + "s"
}

func thousands(n int) string {
	s := strconv.Itoa(n)
	if n < 0 {
		return s
	}
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

// firstLine returns the first line of s, cleaned and cut to a readable length
// on a character boundary.
func firstLine(s string) string {
	s, _, _ = strings.Cut(s, "\n")
	s = clean(s)
	const limit = 300
	if utf8.RuneCountInString(s) > limit {
		s = string([]rune(s)[:limit]) + "…"
	}
	return s
}

// clean drops control characters from text that came from a feed or a
// server, so it cannot move the cursor, recolor or retitle the terminal.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
}
