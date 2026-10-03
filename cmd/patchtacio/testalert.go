package main

import (
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/milliebillie/patchtacio/internal/advice"
	"github.com/milliebillie/patchtacio/internal/config"
	"github.com/milliebillie/patchtacio/internal/notify"
)

func newTestAlertCmd(a *app) *cobra.Command {
	var only []string
	cmd := &cobra.Command{
		Use:   "test-alert",
		Short: "Send a test message on each configured alert channel",
		Long: "Sends a message clearly marked as a test on every channel in the notify: section of your\n" +
			"configuration (or only those named with --channel) and reports which worked. Nothing is\n" +
			"recorded, so real alerts are unaffected.\n\n" +
			"Exit codes: 0 every channel worked; 2 at least one failed, or none is configured.",
		Example: "  patchtacio test-alert\n  patchtacio test-alert --channel email",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			path, err := a.configPath()
			if err != nil {
				return err
			}
			cfg, err := config.Load(path)
			if errors.Is(err, fs.ErrNotExist) {
				return fmt.Errorf("no configuration at %s yet: run `patchtacio init`, then add a notify: section", path)
			}
			if err != nil {
				return err
			}
			if problems := cfg.Notify.Validate(); len(problems) > 0 {
				return fmt.Errorf("%s: %s", path, strings.Join(problems, "; "))
			}
			chans, err := a.configuredChannels(cfg)
			if err != nil {
				return err
			}
			for _, name := range only {
				if !slices.ContainsFunc(chans, func(c notify.Channel) bool { return c.Name() == name }) {
					return fmt.Errorf("--channel %s is not configured; configured: %s", name, strings.Join(cfg.Notify.Channels(), ", "))
				}
			}

			w := cmd.OutOrStdout()
			failed := 0
			for _, c := range chans {
				if len(only) > 0 && !slices.Contains(only, c.Name()) {
					continue
				}
				if err := c.SendNotice(cmd.Context(), advice.TestNotice()); err != nil {
					failed++
					_, _ = fmt.Fprintf(w, "%s: failed: %s\n", c.Name(), firstLine(err.Error()))
					continue
				}
				_, _ = fmt.Fprintf(w, "%s: sent. %s\n", c.Name(), testHint(c.Name(), cfg.Notify))
			}
			if failed > 0 {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "%s failed; fix it, then run `patchtacio test-alert` again.\n", plural(failed, "channel"))
				return outcome(exitToolError)
			}
			return nil
		},
	}
	cmd.Flags().StringSliceVar(&only, "channel", nil, "test only these channels: email, webhook, ntfy, desktop")
	return cmd
}

func testHint(channel string, n *config.Notify) string {
	switch channel {
	case config.ChannelEmail:
		return "Check the inbox of " + strings.Join(n.Email.To, ", ") + " (and the spam folder)."
	case config.ChannelWebhook:
		return "Check the " + n.Webhook.Kind + " channel."
	case config.ChannelNtfy:
		return "Check the ntfy app subscribed to your topic."
	case config.ChannelDesktop:
		return "A notification should have appeared on this computer."
	}
	return ""
}
