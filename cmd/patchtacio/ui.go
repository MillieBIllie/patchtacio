package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/milliebillie/patchtacio/internal/advice"
	"github.com/milliebillie/patchtacio/internal/catalog"
	"github.com/milliebillie/patchtacio/internal/config"
	"github.com/milliebillie/patchtacio/internal/match"
	"github.com/milliebillie/patchtacio/internal/notify"
	"github.com/milliebillie/patchtacio/internal/secrets"
	"github.com/milliebillie/patchtacio/internal/store"
	"github.com/milliebillie/patchtacio/internal/ui"
	"github.com/milliebillie/patchtacio/internal/version"
)

func newUICmd(a *app) *cobra.Command {
	var noBrowser bool
	cmd := &cobra.Command{
		Use:   "ui",
		Short: "Set up and use Patchtacio in your web browser",
		Long: "Opens Patchtacio in your web browser: choose your products, set up alerts and send a test,\n" +
			"see and acknowledge findings, and set up the daily check, without the command line.\n\n" +
			"The page is served only to this computer (127.0.0.1) and only to the browser that opened the\n" +
			"one-time link Patchtacio prints, so other users of this computer cannot use it. Patchtacio runs\n" +
			"until you click Stop Patchtacio on the page or press Ctrl+C.\n\n" +
			"On Windows, double-clicking patchtacio.exe does the same.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return a.runUI(cmd.Context(), cmd.OutOrStdout(), cmd.ErrOrStderr(), noBrowser)
		},
	}
	cmd.Flags().BoolVar(&noBrowser, "no-browser", false, "only print the link; do not open a browser")
	return cmd
}

func (a *app) runUI(ctx context.Context, out, warn io.Writer, noBrowser bool) error {
	srv, err := ui.New(&uiBackend{a: a}, ui.Options{Version: version.Get().Version, Now: a.now, Logger: a.log})
	if err != nil {
		return err
	}
	ln, err := srv.Listen(ctx)
	if err != nil {
		return err
	}
	link := srv.LaunchURL()
	_, _ = fmt.Fprintf(out, "Patchtacio is running at %s\n", srv.URL())
	opened := false
	if !noBrowser {
		if err := a.openBrowser(link); err != nil {
			_, _ = fmt.Fprintf(warn, "Could not open your browser: %s\n", firstLine(err.Error()))
		} else {
			opened = true
			_, _ = fmt.Fprintln(out, "It should now be open in your web browser.")
		}
	}
	if opened {
		_, _ = fmt.Fprintf(out, "If it did not open, go to this address in your browser (it works once, for 2 minutes):\n  %s\n", link)
	} else {
		_, _ = fmt.Fprintf(out, "Go to this address in your web browser (it works once, for 2 minutes):\n  %s\n", link)
	}
	_, _ = fmt.Fprintln(out, "Keep this window open while you use Patchtacio. To stop, click Stop Patchtacio on the page, or press Ctrl+C here.")
	err = srv.Serve(ctx, ln)
	_, _ = fmt.Fprintln(out, "Patchtacio has stopped.")
	return err
}

// uiBackend does the web UI's work with the same code as the commands.
type uiBackend struct{ a *app }

var _ ui.Backend = (*uiBackend)(nil)

// fileHash identifies a version of the configuration file, so a save never
// overwrites changes made after the page was loaded.
func fileHash(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// currentHash is the configuration file's hash, or "" when there is none.
func currentHash(path string) (string, error) {
	b, err := os.ReadFile(filepath.Clean(path)) //nolint:gosec // the user's own config path (--config or the config directory)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "", nil
	case err != nil:
		return "", fmt.Errorf("read configuration: %w", err)
	}
	return fileHash(b), nil
}

func (b *uiBackend) Config(context.Context) (*ui.Config, error) {
	cat, err := catalog.Embedded()
	if err != nil {
		return nil, err
	}
	path, err := b.a.configPath()
	if err != nil {
		return nil, err
	}
	c := &ui.Config{Path: path, Products: pickerProducts(cat), File: &config.Config{Version: config.SchemaVersion}}
	if c.Hash, err = currentHash(path); err != nil {
		c.Problem = err.Error()
		return c, nil
	}
	if c.Hash == "" {
		return c, nil
	}
	cfg, err := config.Load(path)
	if err != nil {
		c.Problem = err.Error()
		return c, nil
	}
	if _, err := cfg.Validate(cat); err != nil {
		c.Problem = fmt.Sprintf("%s: %s", path, err)
		return c, nil
	}
	// Renamed catalog entries show (and are saved) as their successors.
	c.File = cfg.Resolve(cat)
	return c, nil
}

func (b *uiBackend) SaveConfig(_ context.Context, hash string, c *config.Config) error {
	cat, err := catalog.Embedded()
	if err != nil {
		return err
	}
	if _, err := c.Validate(cat); err != nil {
		return err
	}
	path, err := b.a.configPath()
	if err != nil {
		return err
	}
	now, err := currentHash(path)
	if err != nil {
		return err
	}
	if now != hash {
		return ui.ErrConflict
	}
	return config.Save(path, c)
}

func (b *uiBackend) Secrets(context.Context) []ui.Secret {
	out := make([]ui.Secret, 0, len(secrets.All))
	for _, sec := range secrets.All {
		_, src, err := b.a.secretStore().Lookup(sec.Env)
		s := ui.Secret{Env: sec.Env, Name: sec.Name, What: sec.What, Source: string(src)}
		if err != nil && src == secrets.NotSet {
			s.Problem = firstLine(err.Error())
		}
		out = append(out, s)
	}
	return out
}

func (b *uiBackend) SetSecret(_ context.Context, env, value string) error {
	sec, ok := secrets.ByName(env)
	if !ok {
		return fmt.Errorf("unknown secret %s", env)
	}
	if env == config.EnvWebhookURL || env == config.EnvNtfyURL {
		if err := notify.CheckURL(value, sec.What); err != nil {
			return err
		}
	}
	return b.a.secretStore().Set(sec, value)
}

func (b *uiBackend) DeleteSecret(_ context.Context, env string) error {
	sec, ok := secrets.ByName(env)
	if !ok {
		return fmt.Errorf("unknown secret %s", env)
	}
	return b.a.secretStore().Delete(sec)
}

func (b *uiBackend) Test(ctx context.Context, channel string) error {
	path, err := b.a.configPath()
	if err != nil {
		return err
	}
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	if problems := cfg.Notify.Validate(); len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	chans, err := b.a.configuredChannels(cfg)
	if err != nil {
		return err
	}
	for _, c := range chans {
		if c.Name() != channel {
			continue
		}
		if err := c.SendNotice(ctx, advice.TestNotice()); err != nil {
			msg := firstLine(err.Error())
			for _, p := range b.a.secretStore().Problems() {
				msg += fmt.Sprintf(" (the %s is saved in the keychain, but Patchtacio could not read it: %s)", p.Secret.What, firstLine(p.Err.Error()))
			}
			return errors.New(msg)
		}
		return nil
	}
	return fmt.Errorf("%s is not set up", channel)
}

func (b *uiBackend) Report(ctx context.Context, update bool) (*ui.Report, error) {
	cat, err := catalog.Embedded()
	if err != nil {
		return nil, err
	}
	var warn bytes.Buffer
	cfg, err := b.a.loadConfig(cat, &warn)
	if err != nil {
		return nil, err
	}
	res, err := b.a.runCheck(ctx, cat, cfg, &warn, checkOpts{offline: !update})
	if err != nil {
		return nil, err
	}
	r := &ui.Report{NoData: res.noData, Warnings: warningLines(warn.String())}
	if res.noData {
		return r, nil
	}
	rep := res.rep
	r.Feed = "Known exploited vulnerabilities: CISA KEV catalog, " + b.a.describe(rep.Feed) + ", last checked " + b.a.when(rep.Feed.CheckedAt) + "."
	if rep.EOLFeed != nil {
		r.EOLFeed = "End of life: endoflife.date, " + b.a.describe(*rep.EOLFeed) + ", last checked " + b.a.when(rep.EOLFeed.CheckedAt) + "."
	}
	byID := map[string]config.Product{}
	for _, p := range cfg.Products {
		byID[p.ID] = p
	}
	for _, p := range rep.Products {
		r.Products = append(r.Products, ui.ReportProduct{Display: p.Display, Version: p.Version, Findings: p.Findings})
	}
	today := b.a.today()
	for _, f := range rep.Findings {
		up := byID[f.ProductID]
		card, err := advice.KEVCard(advice.Item{
			Kind: advice.KindNew, CVE: f.CVEID, Name: f.VulnerabilityName, Description: f.ShortDescription,
			RequiredAction: f.RequiredAction,
			Products:       []advice.Product{{Display: f.Product, Version: up.Version, Notes: up.Notes}},
			DateAdded:      f.DateAdded.Time, DueDate: f.DueDate.Time, Ransomware: f.RansomwareUse == "known",
			Links: f.Notes,
		}, today)
		if err != nil {
			return nil, err
		}
		r.Findings = append(r.Findings, ui.Finding{ID: f.ID, CVE: f.CVEID, Acked: f.Acknowledged, Card: card})
	}
	for _, e := range rep.EndOfLife {
		entry := ui.EOLEntry{ID: e.ID, Product: e.Product, Version: e.Version, Release: e.Release, What: eolWhat(e, rep.today), Acked: e.Acknowledged}
		if e.State == match.EOLNoVersion {
			r.NoVersion++
		}
		if e.State.IsFinding() && e.ID != "" {
			up := byID[e.ProductID]
			it := advice.EOLItem{
				Kind:    advice.KindNew,
				Product: advice.Product{Display: e.Product, Version: up.Version, Notes: up.Notes},
				Release: e.Release, EOLDate: e.EOLDate.Time, Ended: e.State == match.EOLEnded,
				ExtendedUntil: e.ExtendedUntil.Time, Successor: e.SuccessorLabel, SuccessorAt: e.SuccessorLatest,
				Page: e.Page, Policy: e.Policy, AckID: e.ID,
			}
			card, err := advice.EOLCard(it, today)
			if err != nil {
				return nil, err
			}
			entry.Card = &card
		}
		r.EOL = append(r.EOL, entry)
	}
	return r, nil
}

// warningLines turns check's warnings into one entry per warning (indented
// lines continue the one before) and points the CLI hints at the UI.
func warningLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		line = strings.ReplaceAll(line, "Run `patchtacio feeds update` when you are online.",
			"Use \"Download the latest data\" when you are online.")
		line = strings.ReplaceAll(line, "run patchtacio feeds update", "use \"Download the latest data\"")
		if strings.HasPrefix(line, " ") && len(out) > 0 {
			out[len(out)-1] += " " + strings.TrimSpace(line)
			continue
		}
		out = append(out, strings.TrimSpace(line))
	}
	return out
}

func (b *uiBackend) Ack(ctx context.Context, id, note string) error {
	return b.withStore(ctx, func(st *store.Store) error {
		err := st.Acknowledge(ctx, []string{id}, note)
		if errors.Is(err, store.ErrNoFinding) {
			return errors.New("this finding is not in Patchtacio's records yet; download the latest data and try again")
		}
		return err
	})
}

func (b *uiBackend) Unack(ctx context.Context, id string) error {
	return b.withStore(ctx, func(st *store.Store) error { return st.Unacknowledge(ctx, []string{id}) })
}

func (b *uiBackend) withStore(ctx context.Context, f func(*store.Store) error) error {
	u, closeFn, err := b.a.openUpdater(ctx)
	if err != nil {
		return err
	}
	defer closeFn()
	return f(u.Store)
}

func (b *uiBackend) Schedule(ctx context.Context) (*ui.Schedule, error) {
	ws, err := b.a.watchState(ctx)
	if err != nil {
		return nil, err
	}
	s := &ui.Schedule{
		Installed: ws.Installed, Method: ws.Method, At: ws.At, Command: ws.Command, LastRun: ws.LastRun,
		LogFile: ws.LogFile, Notes: ws.Notes, Problems: ws.Problems,
	}
	if !ws.NextRun.IsZero() {
		s.NextRun = ws.NextRun.Format("Mon 2 Jan 2006 15:04")
	}
	if ws.Launch != "" {
		s.Notes = append([]string{"Started as " + ws.Launch + "."}, s.Notes...)
	}
	return s, nil
}

func (b *uiBackend) InstallSchedule(ctx context.Context, at string) (*ui.ScheduleSetup, error) {
	var warn bytes.Buffer
	ws, err := b.a.installWatch(ctx, &warn, at, true)
	if err != nil {
		return nil, err
	}
	return &ui.ScheduleSetup{
		Method: ws.Method, At: ws.At, NextRun: ws.NextRun.Format("Mon 2 Jan 2006 15:04"), LogFile: ws.LogFile,
		Notes: ws.Notes, Warnings: append(warningLines(warn.String()), ws.Warnings...),
	}, nil
}

func (b *uiBackend) UninstallSchedule(ctx context.Context) ([]string, error) {
	return b.a.uninstallWatch(ctx)
}

func (b *uiBackend) RunScheduleNow(ctx context.Context) (string, error) {
	return b.a.runWatchNow(ctx)
}
