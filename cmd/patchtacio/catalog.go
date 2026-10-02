package main

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/milliebillie/patchtacio/internal/catalog"
	"github.com/milliebillie/patchtacio/internal/feeds"
	"github.com/milliebillie/patchtacio/internal/feeds/eol"
	"github.com/milliebillie/patchtacio/internal/feeds/kev"
)

func newCatalogCmd(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "catalog",
		Short: "Check the product catalog that maps products to KEV and endoflife.date",
	}
	cmd.AddCommand(newCatalogLintCmd(a))
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
		_, _ = fmt.Fprintf(warn, "Note: skipping the checks against KEV: %s. Run `patchtacio feeds update` to enable them.\n", firstLine(err.Error()))
	} else {
		refs.KEV = kevEntries(kc)
	}
	if raw, _, err := u.ReadCache(ctx, "eol"); err != nil {
		_, _ = fmt.Fprintf(warn, "Note: skipping the checks against endoflife.date: %s. Run `patchtacio feeds update` to enable them.\n", firstLine(err.Error()))
	} else if ec, err := eol.ParseCatalog(raw); err != nil {
		_, _ = fmt.Fprintf(warn, "Note: skipping the checks against endoflife.date: the saved copy could not be read: %s\n", firstLine(err.Error()))
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
