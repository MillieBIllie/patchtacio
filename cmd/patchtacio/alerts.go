package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/milliebillie/patchtacio/internal/advice"
	"github.com/milliebillie/patchtacio/internal/catalog"
	"github.com/milliebillie/patchtacio/internal/config"
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
	Sent      int    `json:"sent"`                // findings covered by the one message sent
	Held      int    `json:"held,omitempty"`      // waiting for the next digest
	NextAfter string `json:"nextAfter,omitempty"` // RFC 3339: when a held digest may go
	Error     string `json:"error,omitempty"`
}

// sendAlerts runs the dispatcher. The error is non-nil if any channel failed;
// the reports say which.
func (a *app) sendAlerts(ctx context.Context, st *store.Store, cfg *config.Config, findings []match.Finding) ([]alertReport, error) {
	chans, err := a.configuredChannels(cfg)
	if err != nil {
		return nil, err
	}
	d := &notify.Dispatcher{Store: st, Channels: chans, Digest: cfg.Notify.Digest, Now: a.now, Location: a.loc}
	results, runErr := d.Run(ctx, candidates(cfg, findings))
	reps := make([]alertReport, 0, len(results))
	for _, r := range results {
		rep := alertReport{Channel: r.Channel, Sent: r.Sent, Held: r.Held}
		if !r.NextAfter.IsZero() {
			rep.NextAfter = r.NextAfter.UTC().Format("2006-01-02T15:04:05Z")
		}
		if r.Err != nil {
			rep.Error = firstLine(r.Err.Error())
		}
		reps = append(reps, rep)
	}
	return reps, runErr
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
			what = "sent one alert covering " + plural(r.Sent, "finding")
		case r.Held > 0:
			what = fmt.Sprintf("%s waiting for the next digest", plural(r.Held, "finding"))
			if r.NextAfter != "" {
				what += " (after " + r.NextAfter + ")"
			}
		default:
			what = "nothing new to send"
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
