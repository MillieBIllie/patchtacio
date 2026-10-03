package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/milliebillie/patchtacio/internal/advice"
	"github.com/milliebillie/patchtacio/internal/catalog"
	"github.com/milliebillie/patchtacio/internal/config"
	"github.com/milliebillie/patchtacio/internal/logging"
	"github.com/milliebillie/patchtacio/internal/match"
	"github.com/milliebillie/patchtacio/internal/notify"
	"github.com/milliebillie/patchtacio/internal/store"
)

// realChannels builds the configured channels. Secrets are read from the
// environment when a channel sends, not here.
func realChannels(n *config.Notify) ([]notify.Channel, error) {
	var out []notify.Channel
	for _, name := range n.Channels() {
		switch name {
		case config.ChannelEmail:
			out = append(out, notify.NewEmail(*n.Email, os.Getenv))
		case config.ChannelWebhook:
			out = append(out, notify.NewWebhook(n.Webhook.Kind, os.Getenv))
		case config.ChannelNtfy:
			out = append(out, notify.NewNtfy(n.Ntfy.Priority, os.Getenv))
		case config.ChannelDesktop:
			out = append(out, notify.NewDesktop())
		}
	}
	return out, nil
}

// errNoChannels means alerts were asked for but none are configured.
var errNoChannels = errors.New("no alert channels are configured: add a notify: section to your configuration " +
	"(see docs/ALERTS.md), then try it with `patchtacio test-alert`")

// configuredChannels returns the channels in cfg, or errNoChannels.
func (a *app) configuredChannels(cfg *config.Config) ([]notify.Channel, error) {
	if cfg.Notify == nil || len(cfg.Notify.Channels()) == 0 {
		return nil, errNoChannels
	}
	return a.channels(cfg.Notify)
}

// storedFindings turns matches into store rows.
func storedFindings(findings []match.Finding) []store.Finding {
	out := make([]store.Finding, 0, len(findings))
	for _, f := range findings {
		sf := store.Finding{Source: "kev", ProductID: f.Product.ID, VulnID: f.Vuln.CVEID}
		if !f.Vuln.DueDate.IsZero() {
			sf.DueDate = f.Vuln.DueDate.Format("2006-01-02")
		}
		sf.ID = store.FindingID(sf.Source, sf.ProductID, sf.VulnID)
		out = append(out, sf)
	}
	return out
}

// candidates turns matches into alert candidates, with the user's version
// and notes for each product.
func candidates(cfg *config.Config, findings []match.Finding) []notify.Candidate {
	byID := map[string]config.Product{}
	for _, p := range cfg.Products {
		byID[p.ID] = p
	}
	out := make([]notify.Candidate, 0, len(findings))
	for _, f := range findings {
		v, up := f.Vuln, byID[f.Product.ID]
		out = append(out, notify.Candidate{
			ID: store.FindingID("kev", f.Product.ID, v.CVEID),
			Item: advice.Item{
				CVE:            v.CVEID,
				Name:           v.Name,
				Description:    v.ShortDescription,
				RequiredAction: v.RequiredAction,
				Products:       []advice.Product{{Display: f.Product.Display, Version: up.Version, Notes: up.Notes}},
				DateAdded:      v.DateAdded.Time,
				DueDate:        v.DueDate.Time,
				Ransomware:     v.KnownRansomware,
				Links:          v.Notes,
			},
		})
	}
	return out
}

// alertReport is what --notify did on one channel; its JSON form is public.
type alertReport struct {
	Channel   string `json:"channel"`
	Notice    string `json:"notice,omitempty"`    // set for a notice, e.g. "kev-out-of-date"; else findings
	Sent      int    `json:"sent"`                // findings covered by the one message sent (1 for a notice)
	Vulns     int    `json:"vulnerabilities"`     // distinct CVEs in it (one CVE can match two products)
	Held      int    `json:"held,omitempty"`      // waiting for the next digest (or a notice already sent today)
	NextAfter string `json:"nextAfter,omitempty"` // RFC 3339: when a held message may go
	Error     string `json:"error,omitempty"`
}

// feedProblem says why the KEV data could not be refreshed, for the notice
// --notify sends so that silence is never mistaken for an all clear.
type feedProblem struct {
	title    string
	lastGood time.Time // last successful contact; zero = never
	why      string
}

// Kind and interval of the "KEV could not be updated" notice.
const (
	noticeKEVStale = "kev-out-of-date"
	noticeEvery    = 24 * time.Hour
	notifyLockName = "notify"
	// Two passes (notice, then alerts) over four slow channels take about 12
	// minutes at worst. A laptop that sleeps mid-send can outlast it; the
	// cost is a possible duplicate alert, never a missed one.
	notifyLockTTL = 30 * time.Minute
)

// notifyLockWait is how long a run waits for another to finish sending; a
// variable so tests need not wait.
var notifyLockWait = time.Minute

// sendAlerts sends, under a cross-process lock so two runs never send the
// same alert, a notice if the feed could not be updated (problem != nil) and
// the alerts due for findings (if haveData). The error is non-nil if anything
// failed; the reports say which channel. If nothing could be attempted the
// reports are empty and the error says why.
func (a *app) sendAlerts(ctx context.Context, st *store.Store, cfg *config.Config,
	findings []match.Finding, haveData bool, problem *feedProblem) ([]alertReport, error) {
	chans, err := a.configuredChannels(cfg)
	if err != nil {
		return nil, err
	}
	release, err := a.notifyLock(ctx, st)
	if err != nil {
		return nil, err
	}
	defer release()

	secret, err := st.InstallSecret(ctx)
	if err != nil {
		return nil, err
	}
	d := &notify.Dispatcher{Store: st, Channels: chans, Digest: cfg.Notify.Digest, Now: a.now, Location: a.loc, Secret: secret}
	var reps []alertReport
	var errs []error
	if problem != nil {
		n := advice.FeedNotice(problem.title, problem.lastGood, problem.why)
		results, err := d.Notice(ctx, noticeKEVStale, n, noticeEvery)
		reps = append(reps, toReports(results, noticeKEVStale)...)
		errs = append(errs, err)
	}
	if haveData {
		results, err := d.Run(ctx, candidates(cfg, findings))
		reps = append(reps, toReports(results, "")...)
		if results == nil && err != nil {
			// Nothing was tried (e.g. alert state unreadable): report why.
			reps = append(reps, alertReport{Channel: "all channels", Error: firstLine(logging.RedactString(err.Error()))})
		}
		errs = append(errs, err)
	}
	return reps, errors.Join(errs...)
}

func toReports(results []notify.Result, notice string) []alertReport {
	reps := make([]alertReport, 0, len(results))
	for _, r := range results {
		rep := alertReport{Channel: r.Channel, Notice: notice, Sent: r.Sent, Vulns: r.Vulns, Held: r.Held}
		if !r.NextAfter.IsZero() {
			rep.NextAfter = r.NextAfter.UTC().Format("2006-01-02T15:04:05Z")
		}
		if r.Err != nil {
			rep.Error = firstLine(r.Err.Error())
		}
		reps = append(reps, rep)
	}
	return reps
}

// notifyLock takes the store's "notify" lock, waiting up to notifyLockWait
// for another run (a scheduled check overlapping a manual one) to finish.
func (a *app) notifyLock(ctx context.Context, st *store.Store) (func(), error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("make lock owner: %w", err)
	}
	owner := "check-notify-" + hex.EncodeToString(b)
	deadline := time.Now().Add(notifyLockWait)
	for {
		ok, err := st.AcquireLock(ctx, notifyLockName, owner, notifyLockTTL)
		if err != nil {
			return nil, err
		}
		if ok {
			return func() { _ = st.ReleaseLock(context.WithoutCancel(ctx), notifyLockName, owner) }, nil
		}
		if time.Now().After(deadline) {
			return nil, errors.New("another `patchtacio check --notify` is sending alerts right now; " +
				"this run sent nothing, and the next one will catch up")
		}
		t := time.NewTimer(500 * time.Millisecond)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil, ctx.Err()
		case <-t.C:
		}
	}
}

// printAlerts summarises --notify for people.
func (a *app) printAlerts(w io.Writer, reps []alertReport) {
	_, _ = fmt.Fprintln(w)
	for _, r := range reps {
		var what string
		switch {
		case r.Error != "":
			what = "failed: " + r.Error + " (it will be retried next run)"
		case r.Sent > 0:
			what = fmt.Sprintf("sent one alert about %d vulnerabilities", r.Vulns)
			if r.Vulns == 1 {
				what = "sent one alert about 1 vulnerability"
			}
		case r.Held > 0:
			what = fmt.Sprintf("%s waiting for the next digest", plural(r.Held, "finding"))
			if r.NextAfter != "" {
				what += " (after " + r.NextAfter + ")"
			}
		default:
			what = "nothing new to send"
		}
		if r.Notice != "" {
			switch {
			case r.Error != "":
			case r.Sent > 0:
				what = "sent a notice that the KEV data could not be updated"
			case r.Held > 0:
				what = "the notice that the KEV data could not be updated was already sent today"
			}
			_, _ = fmt.Fprintf(w, "Notice by %s: %s.\n", r.Channel, what)
			continue
		}
		_, _ = fmt.Fprintf(w, "Alerts by %s: %s.\n", r.Channel, what)
	}
}

// productName is the catalog display name of id, or id itself.
func productName(cat *catalog.Catalog, id string) string {
	if p, ok := cat.Get(id); ok {
		return p.Display
	}
	return id
}

// isFindingID reports whether s looks like "kev/<product>/<CVE>".
func isFindingID(s string) bool { return strings.Count(s, "/") == 2 }
