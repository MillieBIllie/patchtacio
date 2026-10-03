package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/charmbracelet/x/term"
	"github.com/spf13/cobra"

	"github.com/milliebillie/patchtacio/internal/secrets"
)

func newSecretCmd(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "secret",
		Short: "Keep alert passwords and URLs in the OS keychain instead of environment variables",
		Long: "Alert secrets (the SMTP password, the webhook URL, the ntfy topic URL and token) are read from\n" +
			"their environment variable first, then from the OS keychain: Credential Manager on Windows,\n" +
			"Keychain on macOS, the Secret Service (GNOME Keyring, KWallet) on Linux desktops.\n" +
			"They never go in the configuration file, and Patchtacio never prints them.\n\n" +
			"Names: " + secretNames() + ".",
		Args: cobra.NoArgs,
	}
	cmd.AddCommand(newSecretSetCmd(a), newSecretDeleteCmd(a), newSecretStatusCmd(a))
	return cmd
}

func secretNames() string {
	names := make([]string, len(secrets.All))
	for i, s := range secrets.All {
		names[i] = s.Name
	}
	return strings.Join(names, ", ")
}

func lookupSecret(name string) (secrets.Secret, error) {
	s, ok := secrets.ByName(name)
	if !ok {
		return s, fmt.Errorf("unknown secret %q; names: %s", name, secretNames())
	}
	return s, nil
}

func newSecretSetCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "set <name>",
		Short: "Save a secret in the OS keychain (asks for it; never pass it as an argument)",
		Long: "Asks for the value without showing it. Without a terminal, reads one line from standard input,\n" +
			"so it never appears in your shell history or the process list:\n" +
			"  patchtacio secret set webhook-url < url.txt",
		Example: "  patchtacio secret set webhook-url\n  patchtacio secret set smtp-password",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			sec, err := lookupSecret(args[0])
			if err != nil {
				return err
			}
			var value string
			if a.isTerminal() {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "%s (%s), input hidden: ", sec.Name, sec.What)
				b, err := term.ReadPassword(os.Stdin.Fd())
				_, _ = fmt.Fprintln(cmd.ErrOrStderr())
				if err != nil {
					return fmt.Errorf("read %s: %w", sec.Name, err)
				}
				value = string(b)
			} else {
				const limit = 8192
				line, err := bufio.NewReader(io.LimitReader(cmd.InOrStdin(), limit+1)).ReadString('\n')
				if err != nil && !errors.Is(err, io.EOF) {
					return fmt.Errorf("read %s from standard input: %w", sec.Name, err)
				}
				if len(strings.TrimRight(line, "\r\n")) >= limit {
					return fmt.Errorf("%s is longer than %d bytes; nothing saved", sec.Name, limit)
				}
				value = line
			}
			value = strings.TrimSpace(value)
			if value == "" {
				return fmt.Errorf("no value given for %s; nothing saved", sec.Name)
			}
			if strings.ContainsAny(value, "\r\n") {
				return fmt.Errorf("%s must be one line; nothing saved", sec.Name)
			}
			if err := a.secretStore().Set(sec, value); err != nil {
				return err
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Saved %s in the keychain.", sec.Name)
			if _, src, _ := a.secretStore().Lookup(sec.Env); src == secrets.FromEnv {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), " Note: %s is also set in the environment, and that value is used first.", sec.Env)
			}
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "\nTry it with: patchtacio test-alert")
			return nil
		},
	}
}

func newSecretDeleteCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "delete <name>",
		Short: "Remove a secret from the OS keychain",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			sec, err := lookupSecret(args[0])
			if err != nil {
				return err
			}
			if err := a.secretStore().Delete(sec); err != nil {
				return err
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Removed %s from the keychain (if it was there).\n", sec.Name)
			return nil
		},
	}
}

func newSecretStatusCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show where each secret comes from (never its value)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			_, _ = fmt.Fprintln(tw, "SECRET\tFROM\tUSED FOR")
			for _, sec := range secrets.All {
				_, src, err := a.secretStore().Lookup(sec.Env)
				where := string(src)
				switch {
				case src == secrets.FromEnv:
					where = "environment (" + sec.Env + ")"
				case err != nil:
					where = "not set (keychain unavailable: " + firstLine(err.Error()) + ")"
				case src == secrets.NotSet:
					where = "not set"
				}
				_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\n", sec.Name, where, sec.What)
			}
			return tw.Flush()
		},
	}
}
