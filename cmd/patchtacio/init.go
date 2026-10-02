package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"charm.land/huh/v2"
	"github.com/charmbracelet/x/term"
	"github.com/spf13/cobra"

	"github.com/milliebillie/patchtacio/internal/catalog"
	"github.com/milliebillie/patchtacio/internal/config"
	"github.com/milliebillie/patchtacio/internal/paths"
)

// pickFunc asks the user which products they run. preselected holds the IDs
// already configured.
type pickFunc func(ctx context.Context, products []catalog.Product, preselected []string) ([]string, error)

func newInitCmd(a *app) *cobra.Command {
	var products []string
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Choose the products you run (interactive picker)",
		Long: "Shows a searchable list of products. Tick the ones you run and Patchtacio saves them to its\n" +
			"configuration file. Run it again to add or remove products; your choices are kept.\n\n" +
			"Without a terminal (scripts, Docker), list the products instead:\n" +
			"  patchtacio init --products fortinet-fortios,microsoft-exchange-server\n" +
			"Product IDs come from `patchtacio catalog list`.\n" +
			"Set ACCESSIBLE=1 for a screen-reader friendly picker.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cat, err := catalog.Embedded()
			if err != nil {
				return err
			}
			path, err := a.configPath()
			if err != nil {
				return err
			}
			existing, err := config.Load(path)
			switch {
			case errors.Is(err, fs.ErrNotExist):
				existing = &config.Config{Version: config.SchemaVersion}
			case err != nil:
				// Never overwrite a file the user may have edited by hand.
				return fmt.Errorf("%w\nFix the file or move it away, then run `patchtacio init` again", err)
			}

			var ids []string
			if cmd.Flags().Changed("products") {
				ids, err = parseProductIDs(cat, products)
				if err != nil {
					return err
				}
			} else {
				if !a.isTerminal() {
					return errors.New("the product picker needs an interactive terminal; " +
						"pass the products instead, e.g. `patchtacio init --products fortinet-fortios` (IDs from `patchtacio catalog list`)")
				}
				ids, err = a.pick(cmd.Context(), pickerProducts(cat), existing.IDs())
				if errors.Is(err, huh.ErrUserAborted) {
					_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "Cancelled; nothing was saved.")
					return outcome(exitToolError)
				}
				if err != nil {
					return fmt.Errorf("product picker: %w", err)
				}
			}
			if len(ids) == 0 {
				return errors.New("no products selected, so nothing was saved")
			}

			next := existing.WithProducts(ids)
			if err := config.Save(path, next); err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			_, _ = fmt.Fprintf(out, "Saved %s to %s:\n", plural(len(ids), "product"), clean(path))
			for _, id := range ids {
				p, _ := cat.Get(id)
				_, _ = fmt.Fprintf(out, "  - %s\n", clean(p.Display))
			}
			// Say what is no longer watched, so a scripted --products run
			// cannot quietly reduce coverage. Comments in the file are not kept.
			var dropped []string
			for _, id := range existing.IDs() {
				if !slices.Contains(ids, id) {
					dropped = append(dropped, clean(id))
				}
			}
			if len(dropped) > 0 {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Note: no longer watching %s.\n", strings.Join(dropped, ", "))
			}
			_, _ = fmt.Fprintln(out, "\nNext: run `patchtacio check` to see known exploited vulnerabilities for these products.")
			return nil
		},
	}
	cmd.Flags().StringSliceVar(&products, "products", nil, "product IDs to save, comma-separated (skips the picker)")
	return cmd
}

// parseProductIDs checks IDs from the command line against the catalog.
func parseProductIDs(cat *catalog.Catalog, raw []string) ([]string, error) {
	var ids, unknown []string
	for _, id := range raw {
		id = strings.TrimSpace(id)
		if id == "" || slices.Contains(ids, id) {
			continue
		}
		p, ok := cat.Get(id)
		switch {
		case !ok:
			unknown = append(unknown, clean(id))
			continue
		case p.Deprecated != "":
			return nil, fmt.Errorf("%q has been replaced by %q; use that instead", id, p.Deprecated)
		}
		ids = append(ids, id)
	}
	if len(unknown) > 0 {
		return nil, fmt.Errorf("not in the catalog: %s (see `patchtacio catalog list`)", strings.Join(unknown, ", "))
	}
	return ids, nil
}

// pickerProducts lists the active products in the order the picker shows them.
func pickerProducts(cat *catalog.Catalog) []catalog.Product {
	ps := cat.Active()
	slices.SortFunc(ps, func(a, b catalog.Product) int {
		return strings.Compare(strings.ToLower(a.Display), strings.ToLower(b.Display))
	})
	return ps
}

// huhPicker returns the interactive picker reading in and writing out.
// accessible switches to huh's plain numbered prompts for screen readers.
// The option label carries the search words too, because huh filters on it.
func huhPicker(in io.Reader, out io.Writer, accessible bool) pickFunc {
	return func(ctx context.Context, products []catalog.Product, preselected []string) ([]string, error) {
		return runPicker(ctx, in, out, accessible, products, preselected)
	}
}

func runPicker(ctx context.Context, in io.Reader, out io.Writer, accessible bool, products []catalog.Product, preselected []string) ([]string, error) {
	opts := make([]huh.Option[string], len(products))
	for i, p := range products {
		label := p.Display
		if len(p.AliasesSearch) > 0 {
			label += "  · " + strings.Join(p.AliasesSearch, ", ")
		}
		opts[i] = huh.NewOption(label, p.ID).Selected(slices.Contains(preselected, p.ID))
	}
	var ids []string
	field := huh.NewMultiSelect[string]().
		Title("Which products do you run?").
		Description("Type / to search, space or x to tick, enter when done.").
		Options(opts...).
		Filterable(true).
		Height(18).
		Validate(func(v []string) error {
			if len(v) == 0 {
				return errors.New("tick at least one product")
			}
			return nil
		}).
		Value(&ids)
	form := huh.NewForm(huh.NewGroup(field)).WithAccessible(accessible).WithInput(in).WithOutput(out)
	if err := form.RunWithContext(ctx); err != nil {
		return nil, err
	}
	// Keep the picker's order stable: catalog order, not tick order.
	slices.SortFunc(ids, func(a, b string) int {
		return slices.IndexFunc(products, func(p catalog.Product) bool { return p.ID == a }) -
			slices.IndexFunc(products, func(p catalog.Product) bool { return p.ID == b })
	})
	return ids, nil
}

func stdinIsTerminal() bool { return term.IsTerminal(os.Stdin.Fd()) && term.IsTerminal(os.Stdout.Fd()) }

// configPath is --config, or config.yaml in the config directory.
func (a *app) configPath() (string, error) {
	if a.configFile != "" {
		return a.configFile, nil
	}
	dirs, err := paths.Resolve()
	if err != nil {
		return "", fmt.Errorf("find config directory: %w", err)
	}
	return filepath.Join(dirs.Config, config.FileName), nil
}
