package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/milliebillie/patchtacio/internal/catalog"
	"github.com/milliebillie/patchtacio/internal/feeds"
	"github.com/milliebillie/patchtacio/internal/feeds/eol"
	"github.com/milliebillie/patchtacio/internal/feeds/kev"
	"github.com/milliebillie/patchtacio/internal/logging"
	"github.com/milliebillie/patchtacio/internal/match"
)

func newCatalogCmd(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "catalog",
		Short: "Check the product catalog that maps products to KEV and endoflife.date",
	}
	cmd.AddCommand(newCatalogListCmd(), newCatalogLintCmd(a), newCatalogCoverageCmd(a))
	return cmd
}

func newCatalogListCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List the products Patchtacio knows, with the IDs `init --products` takes",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cat, err := catalog.Embedded()
			if err != nil {
				return err
			}
			ps := pickerProducts(cat)
			if asJSON {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				if err := enc.Encode(ps); err != nil {
					return fmt.Errorf("encode catalog: %w", err)
				}
				return nil
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			_, _ = fmt.Fprintln(tw, "ID\tPRODUCT\tCATEGORY")
			for _, p := range ps {
				_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\n", clean(p.ID), clean(p.Display), clean(p.Category))
			}
			return tw.Flush()
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print machine-readable JSON, including every KEV alias")
	return cmd
}

func newCatalogLintCmd(a *app) *cobra.Command {
	var dir string
	cmd := &cobra.Command{
		Use:   "lint",
		Short: "Check product files for mistakes (no network use)",
		Long: "Checks every product file for schema mistakes. If saved feed data is available, it also checks\n" +
			"that each endoflife.date slug exists and that each KEV alias matches at least one KEV entry.\n\n" +
			"Exit codes: 0 no errors (warnings may be printed); 1 errors found; 2 the check could not run.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			fsys, where := catalog.EmbeddedFS(), "the built-in catalog"
			if dir != "" {
				fsys, where = os.DirFS(dir), dir
			}
			refs, err := a.catalogReferences(cmd.Context(), cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			cat, problems := catalog.Lint(fsys, refs)
			out := cmd.OutOrStdout()
			errs, warns := 0, 0
			for _, p := range problems {
				_, _ = fmt.Fprintln(out, clean(p.String()))
				if p.Severity == catalog.Error {
					errs++
				} else {
					warns++
				}
			}
			_, _ = fmt.Fprintf(out, "Checked %s in %s: %s, %s.\n",
				plural(len(cat.Products()), "product"), clean(where), plural(errs, "error"), plural(warns, "warning"))
			if errs > 0 {
				return outcome(exitFindings)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&dir, "dir", "", "check product files in this directory instead of the built-in catalog\n(for example catalog/products)")
	return cmd
}

func newCatalogCoverageCmd(a *app) *cobra.Command {
	var days, top int
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "coverage",
		Short: "Show how much of the saved KEV catalog maps to a catalog product (no network use)",
		Long: "Counts the KEV entries added in the chosen window that map to at least one catalog product,\n" +
			"and lists the most common vendor/product pairs no product covers yet. The window ends at the\n" +
			"KEV catalog's own release date, so the same saved copy always gives the same numbers.\n\n" +
			"Exit codes: 0 done; 3 the saved KEV copy is out of date (warning printed); 2 no saved copy.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if days < 1 {
				return errors.New("--days must be at least 1")
			}
			cat, err := catalog.Embedded()
			if err != nil {
				return err
			}
			u, closeFn, err := a.openUpdater(cmd.Context())
			if err != nil {
				return err
			}
			defer closeFn()
			kc, st, err := a.loadKEV(cmd.Context(), u)
			if err != nil {
				a.warnState(cmd.ErrOrStderr(), st)
				return fmt.Errorf("read KEV: %w", err)
			}
			end := time.Date(kc.Released.Year(), kc.Released.Month(), kc.Released.Day(), 0, 0, 0, 0, time.UTC)
			since := feeds.Date{Time: end.AddDate(0, 0, -days)}
			c := match.New(cat).Coverage(kc.Vulnerabilities, since)
			if asJSON {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				if err := enc.Encode(struct {
					KEVVersion string `json:"kevVersion"`
					match.Coverage
				}{kc.Version, c}); err != nil {
					return fmt.Errorf("encode coverage: %w", err)
				}
			} else {
				a.printCoverage(cmd.OutOrStdout(), kc, c, top)
			}
			a.warnState(cmd.ErrOrStderr(), st)
			return outcome(stateCode(st.State))
		},
	}
	cmd.Flags().IntVar(&days, "days", 730, "count KEV entries added in this many days before the catalog's release")
	cmd.Flags().IntVar(&top, "top", 20, "how many unmapped vendor/product pairs to list (0 for all)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print machine-readable JSON")
	return cmd
}

func (a *app) printCoverage(w io.Writer, kc *kev.Catalog, c match.Coverage, top int) {
	_, _ = fmt.Fprintf(w, "%s of %s KEV entries added since %s map to a catalog product (%.1f%%).\n",
		thousands(c.Mapped), thousands(c.Total), calDate(c.Since), c.Percent)
	_, _ = fmt.Fprintf(w, "KEV catalog %s, published %s.\n", clean(kc.Version), a.date(kc.Released))
	if len(c.Unmapped) == 0 {
		return
	}
	rows := c.Unmapped
	if top > 0 && len(rows) > top {
		rows = rows[:top]
	}
	_, _ = fmt.Fprintf(w, "\nMost common unmapped vendor/product pairs (%d of %d):\n", len(rows), len(c.Unmapped))
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "ENTRIES\tLATEST\tVENDOR\tPRODUCT")
	for _, p := range rows {
		_, _ = fmt.Fprintf(tw, "%d\t%s\t%s\t%s\n", p.Count, calDate(p.Latest), clean(p.Vendor), clean(p.Product))
	}
	_ = tw.Flush()
}

// catalogReferences loads the saved KEV and endoflife.date data for the
// catalog cross-checks. A missing feed only skips its checks, with a note.
func (a *app) catalogReferences(ctx context.Context, warn io.Writer) (*catalog.References, error) {
	u, closeFn, err := a.openUpdater(ctx)
	if err != nil {
		return nil, err
	}
	defer closeFn()
	refs := &catalog.References{}
	if kc, _, err := a.loadKEV(ctx, u); err != nil {
		_, _ = fmt.Fprintf(warn, "Note: skipping the checks against KEV: %s. Run `patchtacio feeds update` to enable them.\n", firstLine(logging.RedactString(err.Error())))
	} else {
		refs.KEV = kevEntries(kc)
	}
	if raw, _, err := u.ReadCache(ctx, "eol"); err != nil {
		_, _ = fmt.Fprintf(warn, "Note: skipping the checks against endoflife.date: %s. Run `patchtacio feeds update` to enable them.\n", firstLine(logging.RedactString(err.Error())))
	} else if ec, err := eol.ParseCatalog(raw); err != nil {
		_, _ = fmt.Fprintf(warn, "Note: skipping the checks against endoflife.date: the saved copy could not be read: %s\n", firstLine(logging.RedactString(err.Error())))
	} else {
		refs.EOLSlugs = map[string]bool{}
		for _, p := range ec.Products {
			refs.EOLSlugs[p.Name] = true
		}
	}
	return refs, nil
}

// loadKEV reads and parses the saved KEV catalog.
func (a *app) loadKEV(ctx context.Context, u *feeds.Updater) (*kev.Catalog, feeds.Status, error) {
	raw, st, err := u.ReadCache(ctx, "kev")
	if err != nil {
		return nil, st, err
	}
	kc, err := kev.ParseCatalog(raw)
	if err != nil {
		return nil, st, fmt.Errorf("the saved copy of %s could not be read: %w", st.Title, err)
	}
	return kc, st, nil
}

func kevEntries(kc *kev.Catalog) []catalog.KEVEntry {
	out := make([]catalog.KEVEntry, len(kc.Vulnerabilities))
	for i, v := range kc.Vulnerabilities {
		out[i] = catalog.KEVEntry{Vendor: v.VendorProject, Product: v.Product, Text: []string{v.Name, v.ShortDescription}}
	}
	return out
}
