package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCatalogLintBuiltIn(t *testing.T) {
	e := newTestEnv(t)
	out, errOut, code := e.exec(t, "catalog", "lint")
	requireCode(t, code, exitOK, out, errOut)
	requireContains(t, out, "in the built-in catalog: 0 errors")
	// No saved feeds yet: the cross-checks are skipped, and the user is told.
	requireContains(t, errOut, "Note: skipping the checks against KEV", "Note: skipping the checks against endoflife.date")
}

func TestCatalogLintDirWithErrors(t *testing.T) {
	e := newTestEnv(t)
	e.exec(t, "feeds", "update")
	dir := t.TempDir()
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("acme-widget.yaml", `id: acme-widget
display: "Acme Widget"
vendor: "Acme"
category: firewall-vpn
kev_aliases:
  - { vendor: "Acme", product: "Widget" }
  - { vendor: "Citrix", product: "NetScaler" }
cpe_prefixes: []
eol_slug: not-a-real-slug
verified: 2026-10-02
`)
	write("wrong-name.yaml", "id: acme-gadget\n")

	out, errOut, code := e.exec(t, "catalog", "lint", "--dir", dir)
	requireCode(t, code, exitFindings, out, errOut)
	requireContains(t, out,
		`acme-widget.yaml: error: eol_slug "not-a-real-slug" is not an endoflife.date product`,
		"acme-widget.yaml: warning: kev_aliases[0] (Acme / Widget) matches no entry in the saved KEV catalog",
		"wrong-name.yaml: error: display is required",
		"wrong-name.yaml: error: file name must match the id: rename it to acme-gadget.yaml",
		"Checked 2 products in "+dir)
	// The NetScaler alias matches a fixture entry, so it is not reported.
	if strings.Contains(out, "kev_aliases[1]") {
		t.Errorf("real alias reported:\n%s", out)
	}
	if errOut != "" {
		t.Errorf("feeds are saved, so no skip notes expected:\n%s", errOut)
	}
}
