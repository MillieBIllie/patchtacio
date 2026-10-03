package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"slices"
	"strings"
	"text/tabwriter"
	"time"
	"unicode/utf8"

	"github.com/spf13/cobra"

	"github.com/milliebillie/patchtacio/internal/advice"
	"github.com/milliebillie/patchtacio/internal/catalog"
	"github.com/milliebillie/patchtacio/internal/config"
	"github.com/milliebillie/patchtacio/internal/feeds"
	"github.com/milliebillie/patchtacio/internal/logging"
	"github.com/milliebillie/patchtacio/internal/match"
	"github.com/milliebillie/patchtacio/internal/store"
)

func newCheckCmd(a *app) *cobra.Command {
	var offline, asJSON, sendAlerts bool
	var since string
	cmd := &cobra.Command{
		Use:   "check",
		Short: "Show known exploited vulnerabilities (CISA KEV) for the products you run",
		Long: "Updates the CISA KEV catalog (using the saved copy if CISA cannot be reached), then lists every\n" +
			"KEV entry that matches a product in your configuration, newest first.\n\n" +
			"Matching is by product name: versions are not compared yet, so check each entry against the\n" +
			"version you run.\n\n" +
			"Exit codes: 1 at least one match; 0 no match and the data is up to date;\n" +
			"3 no match, but the KEV data is out of date (warning printed); 2 error or no KEV data.\n\n" +
			"With --notify, new findings and reminders are also sent on the channels in the notify: section\n" +
			"of your configuration: at most one message per channel per run, each finding alerted once.\n" +
			"If a channel fails, check exits 2 and that channel retries next run. If the KEV data cannot be\n" +
			"updated, each channel also gets a notice (at most once a day) that alerts may be missing.\n" +
			"--since narrows what is shown, never what is alerted.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var sinceDate feeds.Date
			if since != "" {
				d, err := feeds.ParseDate(since)
				if err != nil {
					return fmt.Errorf("--since: %w", err)
				}
				sinceDate = d
				if now := a.now().In(a.loc); d.After(time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)) {
					return fmt.Errorf("--since %s is in the future", since)
				}
			}
			cat, err := catalog.Embedded()
			if err != nil {
				return err
			}
			cfg, err := a.loadConfig(cat, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			if sendAlerts {
				// Fail before any network work if alerts cannot be sent.
				if _, err := a.configuredChannels(cfg); err != nil {
					return err
				}
			}

			u, closeFn, err := a.openUpdater(cmd.Context())
			if err != nil {
				return err
			}
			defer closeFn()
			// KEV always; endoflife.date only when a product has a version to
			// look up, so KEV-only users fetch nothing more.
			needEOL := wantsEOL(cat, cfg)
			u.Sources = slices.DeleteFunc(u.Sources, func(s feeds.Source) bool {
				return s.Name() != "kev" && (s.Name() != "eol" || !needEOL)
			})
			results, err := u.Update(cmd.Context(), offline)
			if err != nil {
				return fmt.Errorf("update feeds: %w", err)
			}
			warn := cmd.ErrOrStderr()
			kevCode, eolCode := exitOK, exitOK
			for _, r := range results {
				// Success lines are for `feeds update`; check prints only what
				// changes how far the result can be trusted.
				c := a.reportResult(io.Discard, warn, r, offline)
				if r.Status.Name == "eol" {
					eolCode = worse(eolCode, c)
				} else {
					kevCode = worse(kevCode, c)
				}
			}
			kc, st, err := a.loadKEV(cmd.Context(), u)
			if err != nil {
				_, _ = fmt.Fprintf(warn, "Cannot check your products: %s\n", firstLine(logging.RedactString(err.Error())))
				if sendAlerts {
					// No data means no alerts: say so on the alert channels,
					// or silence would read as an all clear.
					reps, alertErr := a.sendAlerts(cmd.Context(), u.Store, cfg, nil, nil, false, []feedProblem{{
						kind: noticeKEVStale, feed: advice.KEVFeed, lastGood: st.CheckedAt, why: logging.RedactString(err.Error()),
					}})
					out := cmd.OutOrStdout()
					if asJSON {
						out = io.Discard // stdout stays JSON (or empty)
					}
					a.reportAlerts(out, warn, reps, alertErr)
				}
				return outcome(exitToolError)
			}
			kevCode = worse(kevCode, stateCode(st.State)) // in case a source reported no result
			stale := kevCode != exitOK
			var problems []feedProblem
			if st.State != feeds.Fresh {
				// Only when the copy is actually out of date: one failed fetch
				// while it is still fresh is not worth an alert.
				problems = append(problems, feedProblem{kind: noticeKEVStale, feed: advice.KEVFeed, lastGood: st.CheckedAt, why: logging.RedactString(staleWhy(st))})
			}

			findings := match.New(cat).KEV(kc.Vulnerabilities, cfg.IDs())
			var eols []match.EOLStatus
			var eolFeed *feeds.Status
			if needEOL {
				ec, est, err := a.loadEOL(cmd.Context(), u)
				eolFeed = &est
				switch {
				case err != nil:
					// Whatever the feed's state: unreadable data must never
					// quietly stop end-of-life alerts.
					why := logging.RedactString(err.Error())
					_, _ = fmt.Fprintf(warn, "Cannot check end of life: %s\n", firstLine(why))
					eolCode = worse(eolCode, exitToolError)
					problems = append(problems, feedProblem{kind: noticeEOLStale, feed: advice.EOLFeed, lastGood: est.CheckedAt, why: why})
				case est.State != feeds.Fresh:
					eolCode = worse(eolCode, stateCode(est.State))
					problems = append(problems, feedProblem{kind: noticeEOLStale, feed: advice.EOLFeed, lastGood: est.CheckedAt, why: logging.RedactString(staleWhy(est))})
				}
				eols = match.EOL(cat, ec, ticked(cfg), a.today())
				if gone := notListed(eols); len(gone) > 0 {
					_, _ = fmt.Fprintf(warn, "Warning: endoflife.date no longer lists %s, so end of life cannot be checked for it; check the vendor's lifecycle page.\n",
						strings.Join(gone, ", "))
					eolCode = worse(eolCode, exitStale)
					problems = append(problems, feedProblem{kind: noticeEOLNotListed, notice: advice.NotListedNotice(gone)})
				}
			}
			// Every run records what matched, so `patchtacio ack` works after
			// a plain check; only --notify sends anything.
			if err := u.Store.RecordFindings(cmd.Context(), append(storedFindings(findings), storedEOLFindings(eols)...)); err != nil {
				return fmt.Errorf("save findings: %w", err)
			}
			allFindings := slices.Clone(findings) // --since narrows the report, never the alerts (DeleteFunc works in place)
			if !sinceDate.IsZero() {
				findings = slices.DeleteFunc(findings, func(f match.Finding) bool { return f.Vuln.DateAdded.Before(sinceDate.Time) })
			}
			rep := a.newCheckReport(cat, cfg, kc.Version, kc.Released, st, stale, sinceDate, findings)
			rep.EndOfLife = a.eolReport(cat, cfg, eols, needEOL)
			rep.EOLFeed = eolFeed
			rep.EOLStale = needEOL && eolCode != exitOK
			for _, e := range rep.EndOfLife {
				if e.State.IsFinding() {
					rep.eolFindings++
				}
			}
			if err := markAcknowledged(cmd.Context(), u.Store, &rep); err != nil {
				return err
			}
			var alertErr error
			if sendAlerts {
				rep.Alerts, alertErr = a.sendAlerts(cmd.Context(), u.Store, cfg, allFindings, eols, true, problems)
			}
			if asJSON {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				if err := enc.Encode(rep); err != nil {
					return fmt.Errorf("encode findings: %w", err)
				}
			} else {
				a.printCheck(cmd.OutOrStdout(), rep)
				a.printEOL(cmd.OutOrStdout(), rep)
			}
			if sendAlerts {
				out := cmd.OutOrStdout()
				if asJSON {
					out = io.Discard // the reports are in the JSON
				}
				a.reportAlerts(out, warn, rep.Alerts, alertErr)
			}
			if alertErr != nil {
				return outcome(exitToolError) // a scheduled run must not fail silently
			}
			if len(findings) > 0 || rep.eolFindings > 0 {
				return outcome(exitFindings) // stale warnings, if any, are already printed
			}
			return outcome(worse(kevCode, eolCode))
		},
	}
	cmd.Flags().BoolVar(&offline, "offline", false, "do not use the network; check against the saved copy")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print machine-readable JSON, with CISA's required action and links")
	cmd.Flags().BoolVar(&sendAlerts, "notify", false, "also send alerts for new findings and reminders (see the notify: section of the configuration)")
	cmd.Flags().StringVar(&since, "since", "", "only show entries added to KEV on or after this date (YYYY-MM-DD)")
	return cmd
}

// loadConfig reads and validates the configuration for commands that need
// products. Warnings (deprecated IDs) go to warn.
func (a *app) loadConfig(cat *catalog.Catalog, warn io.Writer) (*config.Config, error) {
	path, err := a.configPath()
	if err != nil {
		return nil, err
	}
	cfg, err := config.Load(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("no products chosen yet (no configuration at %s): run `patchtacio init` first", path)
	}
	if err != nil {
		return nil, err
	}
	warnings, err := cfg.Validate(cat)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	for _, w := range warnings {
		_, _ = fmt.Fprintf(warn, "Note: %s\n", clean(w))
	}
	if len(cfg.Products) == 0 {
		return nil, fmt.Errorf("%s lists no products: run `patchtacio init` to choose them", path)
	}
	return cfg.Resolve(cat), nil
}

// checkReport is check's output; its JSON form is a public format.
type checkReport struct {
	CheckedAt        time.Time      `json:"checkedAt"`
	KEVVersion       string         `json:"kevVersion"`
	KEVReleased      time.Time      `json:"kevReleased"`
	KEVEntries       int            `json:"-"`
	Feed             feeds.Status   `json:"feed"`
	Stale            bool           `json:"stale"`            // the KEV data (feed) could not be refreshed or is out of date
	VersionsCompared bool           `json:"versionsCompared"` // always false until version matching exists
	Since            feeds.Date     `json:"since,omitzero"`
	Products         []checkProduct `json:"products"`
	Findings         []checkFinding `json:"findings"`
	EndOfLife        []eolEntry     `json:"endOfLife"`         // products endoflife.date tracks
	EOLFeed          *feeds.Status  `json:"eolFeed,omitempty"` // endoflife.date data, when it was looked up
	EOLStale         bool           `json:"eolStale"`          // endoflife.date data out of date, unreadable, or missing a product
	Alerts           []alertReport  `json:"alerts,omitempty"`  // with --notify
	eolFindings      int
	today            time.Time      // for "passed" due dates
	byProduct        map[string]int // finding count per product
	newest           map[string]feeds.Date
}

type checkProduct struct {
	ID       string `json:"id"`
	Display  string `json:"display"`
	Version  string `json:"version,omitempty"`
	Findings int    `json:"findings"`
}

type checkFinding struct {
	ID                string     `json:"id"` // finding ID: kev/<product>/<CVE>
	ProductID         string     `json:"productId"`
	Product           string     `json:"product"`
	CVEID             string     `json:"cveID"`
	VulnerabilityName string     `json:"vulnerabilityName"`
	KEVVendor         string     `json:"kevVendorProject"`
	KEVProduct        string     `json:"kevProduct"`
	DateAdded         feeds.Date `json:"dateAdded"`
	DueDate           feeds.Date `json:"dueDate"`
	DuePassed         bool       `json:"duePassed"`
	RansomwareUse     string     `json:"ransomwareUse"` // "known" or "unknown", as CISA states it; never "no"
	ShortDescription  string     `json:"shortDescription"`
	RequiredAction    string     `json:"requiredAction"`
	Notes             []string   `json:"notes"` // KEV notes: usually the vendor advisory link first
	CWEs              []string   `json:"cwes"`
	NVDURL            string     `json:"nvdURL"`
	Acknowledged      bool       `json:"acknowledged"` // patchtacio ack: no more alerts or reminders
}

func (a *app) newCheckReport(cat *catalog.Catalog, cfg *config.Config, kevVersion string, released time.Time,
	st feeds.Status, stale bool, since feeds.Date, findings []match.Finding) checkReport {
	now := a.now().In(a.loc)
	rep := checkReport{
		CheckedAt:   a.now().UTC(),
		KEVVersion:  kevVersion,
		KEVReleased: released,
		KEVEntries:  st.Count,
		Feed:        st,
		Stale:       stale,
		Since:       since,
		Products:    []checkProduct{},
		Findings:    []checkFinding{},
		today:       time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC),
		byProduct:   map[string]int{},
		newest:      map[string]feeds.Date{},
	}
	for _, f := range findings {
		rep.byProduct[f.Product.ID]++
		if f.Vuln.DateAdded.After(rep.newest[f.Product.ID].Time) {
			rep.newest[f.Product.ID] = f.Vuln.DateAdded
		}
		v := f.Vuln
		rep.Findings = append(rep.Findings, checkFinding{
			ID:                store.FindingID("kev", f.Product.ID, v.CVEID),
			ProductID:         f.Product.ID,
			Product:           f.Product.Display,
			CVEID:             v.CVEID,
			VulnerabilityName: v.Name,
			KEVVendor:         v.VendorProject,
			KEVProduct:        v.Product,
			DateAdded:         v.DateAdded,
			DueDate:           v.DueDate,
			DuePassed:         !v.DueDate.IsZero() && v.DueDate.Before(rep.today),
			RansomwareUse:     ransomwareUse(v.KnownRansomware),
			ShortDescription:  v.ShortDescription,
			RequiredAction:    v.RequiredAction,
			Notes:             v.Notes,
			CWEs:              v.CWEs,
			NVDURL:            "https://nvd.nist.gov/vuln/detail/" + url.PathEscape(v.CVEID),
		})
	}
	for _, p := range cfg.Products {
		cp, _ := cat.Get(p.ID)
		rep.Products = append(rep.Products, checkProduct{ID: p.ID, Display: cp.Display, Version: p.Version, Findings: rep.byProduct[p.ID]})
	}
	return rep
}

func (a *app) printCheck(w io.Writer, rep checkReport) {
	_, _ = fmt.Fprintf(w, "Checked %s against the CISA KEV catalog (%s entries, catalog %s, published %s).\n",
		plural(len(rep.Products), "product"), thousands(rep.KEVEntries), clean(rep.KEVVersion), a.date(rep.KEVReleased))
	scope := ""
	if !rep.Since.IsZero() {
		scope = " added since " + calDate(rep.Since)
	}

	if len(rep.Findings) == 0 {
		_, _ = fmt.Fprintf(w, "\nNone of your products matched a KEV entry%s.\n", scope)
		_, _ = fmt.Fprintln(w, "This is not an all clear: KEV lists only vulnerabilities known to be exploited, and Patchtacio\n"+
			"matches by product name. Keep installing your vendors' security updates.")
		if rep.Stale {
			_, _ = fmt.Fprintln(w, "The KEV data is out of date (see the warning above), so recent entries may be missing.")
		}
		return
	}

	verb := "match"
	if len(rep.Findings) == 1 {
		verb = "matches"
	}
	_, _ = fmt.Fprintf(w, "\n%s%s %s your products. Attackers are already using these vulnerabilities.\n",
		kevEntryCount(len(rep.Findings)), scope, verb)
	_, _ = fmt.Fprintln(w, "Patchtacio matched them by product name and did not compare versions, so check each one\n"+
		"against the version you run and follow the vendor's advice to update or mitigate.")

	_, _ = fmt.Fprintln(w)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, p := range rep.Products {
		n := rep.byProduct[p.ID]
		summary := "no matching KEV entries"
		if n > 0 {
			summary = fmt.Sprintf("%s, newest added %s", kevEntryCount(n), calDate(rep.newest[p.ID]))
		}
		_, _ = fmt.Fprintf(tw, "  %s\t%s\n", clean(p.Display), summary)
	}
	_ = tw.Flush()

	_, _ = fmt.Fprintln(w)
	tw = tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "PRODUCT\tCVE\tADDED TO KEV\tCISA DUE DATE\tRANSOMWARE\tACK\tVULNERABILITY")
	for _, f := range rep.Findings {
		due := calDate(f.DueDate)
		if f.DuePassed {
			due += " (passed)"
		}
		ransomware := f.RansomwareUse
		if ransomware == "known" {
			ransomware = "known use"
		}
		ack := "-"
		if f.Acknowledged {
			ack = "yes"
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			clean(shortName(f.Product)), clean(f.CVEID), calDate(f.DateAdded), due, ransomware, ack, clean(truncate(f.VulnerabilityName, 70)))
	}
	_ = tw.Flush()
	_, _ = fmt.Fprintln(w, "\nCISA due dates are deadlines for US federal agencies; use them as a guide to urgency.")
	_, _ = fmt.Fprintln(w, "For CISA's required action and the vendor advisory link for each entry, run: patchtacio check --json")
	_, _ = fmt.Fprintln(w, "When you have dealt with an entry, run: patchtacio ack <CVE ID> (ACK yes: no more alerts or reminders).")
}

// reportAlerts prints what --notify did and, on failure, a warning that says
// why when no channel could even be tried.
func (a *app) reportAlerts(out, warn io.Writer, reps []alertReport, err error) {
	if len(reps) > 0 {
		a.printAlerts(out, reps)
	}
	switch {
	case err == nil:
	case len(reps) == 0:
		_, _ = fmt.Fprintf(warn, "Warning: no alerts were sent: %s\n", firstLine(logging.RedactString(err.Error())))
	default:
		_, _ = fmt.Fprintln(warn, "Warning: some alerts could not be sent; they will be retried on the next run.")
	}
	a.explainKeychain(warn)
}

// explainKeychain says when a secret saved in the keychain could not be read
// in this run, which otherwise looks like an unset environment variable.
func (a *app) explainKeychain(warn io.Writer) {
	if a.secrets == nil {
		return
	}
	for _, p := range a.secrets.Problems() {
		_, _ = fmt.Fprintf(warn, "Note: %s was saved with `patchtacio secret set`, but this run could not read it (%s). "+
			"Scheduled runs often cannot reach the keychain; set %s for them instead.\n", p.Secret.Name, firstLine(p.Err.Error()), p.Secret.Env)
	}
}

// markAcknowledged sets Acknowledged on the report's findings.
func markAcknowledged(ctx context.Context, st *store.Store, rep *checkReport) error {
	ids := make([]string, 0, len(rep.Findings)+len(rep.EndOfLife))
	for _, f := range rep.Findings {
		ids = append(ids, f.ID)
	}
	for _, e := range rep.EndOfLife {
		if e.ID != "" {
			ids = append(ids, e.ID)
		}
	}
	states, err := st.States(ctx, ids)
	if err != nil {
		return fmt.Errorf("read acknowledgements: %w", err)
	}
	for i := range rep.Findings {
		rep.Findings[i].Acknowledged = states[rep.Findings[i].ID].Acked()
	}
	for i := range rep.EndOfLife {
		if id := rep.EndOfLife[i].ID; id != "" {
			rep.EndOfLife[i].Acknowledged = states[id].Acked()
		}
	}
	return nil
}

// ransomwareUse renders KEV's knownRansomwareCampaignUse. CISA says "Known" or
// "Unknown"; "Unknown" does not mean ransomware gangs are not using it.
func ransomwareUse(known bool) string {
	if known {
		return "known"
	}
	return "unknown"
}

// kevEntryCount is "1 KEV entry" or "12 KEV entries".
func kevEntryCount(n int) string {
	if n == 1 {
		return "1 KEV entry"
	}
	return thousands(n) + " KEV entries"
}

// shortName drops a display name's parenthetical: "Fortinet FortiOS (FortiGate
// firewalls)" becomes "Fortinet FortiOS".
func shortName(display string) string {
	if i := strings.Index(display, " ("); i > 0 {
		return display[:i]
	}
	return display
}

// truncate cuts s to n characters on a character boundary.
func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n-1]) + "…"
}
