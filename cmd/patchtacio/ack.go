package main

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/milliebillie/patchtacio/internal/catalog"
	"github.com/milliebillie/patchtacio/internal/store"
)

func newAckCmd(a *app) *cobra.Command {
	var product, note string
	var undo bool
	cmd := &cobra.Command{
		Use:   "ack <CVE ID>...",
		Short: "Acknowledge a finding you have dealt with, so alerts and reminders about it stop",
		Long: "Marks KEV findings as dealt with (patched, mitigated, or the product is not exposed), so\n" +
			"`check --notify` sends no more alerts or reminders about them. `patchtacio check` still lists\n" +
			"them, with ACK yes.\n\n" +
			"A CVE ID acknowledges it for every product it matched; --product narrows that to one.\n" +
			"A finding ID from `check --json` (kev/<product>/<CVE>) names exactly one.\n" +
			"Run `patchtacio check` first: only findings it has seen can be acknowledged.",
		Example: "  patchtacio ack CVE-2024-21762\n" +
			"  patchtacio ack CVE-2024-21762 --note \"upgraded to 7.4.3 on 14 Oct\"\n" +
			"  patchtacio ack CVE-2026-81963 --product microsoft-windows-server\n" +
			"  patchtacio ack CVE-2024-21762 --undo",
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cat, err := catalog.Embedded()
			if err != nil {
				return err
			}
			if product != "" {
				if _, ok := cat.Get(product); !ok {
					return fmt.Errorf("--product %q is not a product in the catalog (see `patchtacio catalog list`)", product)
				}
			}
			u, closeFn, err := a.openUpdater(cmd.Context())
			if err != nil {
				return err
			}
			defer closeFn()
			st := u.Store

			var targets []store.State
			for _, arg := range args {
				arg = strings.TrimSpace(arg)
				var found []store.State
				if isFindingID(arg) {
					s, ok, err := st.GetFinding(cmd.Context(), arg)
					if err != nil {
						return err
					}
					if ok {
						found = []store.State{s}
					}
				} else {
					if found, err = st.FindingsForVuln(cmd.Context(), arg); err != nil {
						return err
					}
				}
				if product != "" {
					found = slices.DeleteFunc(found, func(s store.State) bool { return s.ProductID != product })
				}
				if len(found) == 0 {
					return fmt.Errorf("no finding for %s%s: run `patchtacio check` first, and check the ID",
						clean(arg), map[bool]string{true: " on " + product, false: ""}[product != ""])
				}
				targets = append(targets, found...)
			}
			ids := make([]string, len(targets))
			for i, t := range targets {
				ids[i] = t.ID
			}

			w := cmd.OutOrStdout()
			if undo {
				if err := st.Unacknowledge(cmd.Context(), ids); err != nil {
					return err
				}
				for _, t := range targets {
					_, _ = fmt.Fprintf(w, "Removed the acknowledgement of %s for %s.\n", t.VulnID, productName(cat, t.ProductID))
				}
				_, _ = fmt.Fprintln(w, "Reminders about it resume with the next `patchtacio check --notify`.")
				return nil
			}
			if err := st.Acknowledge(cmd.Context(), ids, strings.TrimSpace(note)); err != nil {
				if errors.Is(err, store.ErrNoFinding) {
					return fmt.Errorf("%w: run `patchtacio check` first", err)
				}
				return err
			}
			for _, t := range targets {
				_, _ = fmt.Fprintf(w, "Acknowledged %s for %s.\n", t.VulnID, productName(cat, t.ProductID))
			}
			_, _ = fmt.Fprintln(w, "Patchtacio will not alert or remind you about it again; `patchtacio check` still lists it (ACK yes).")
			if len(targets) > 1 && product == "" {
				_, _ = fmt.Fprintln(w, "It matched more than one of your products; use --product to acknowledge just one.")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&product, "product", "", "acknowledge only for this product ID")
	cmd.Flags().StringVar(&note, "note", "", "what you did, kept with the acknowledgement")
	cmd.Flags().BoolVar(&undo, "undo", false, "remove the acknowledgement, so reminders resume")
	return cmd
}
