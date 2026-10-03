package match

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/milliebillie/patchtacio/internal/catalog"
	"github.com/milliebillie/patchtacio/internal/feeds"
	"github.com/milliebillie/patchtacio/internal/feeds/kev"
	"github.com/milliebillie/patchtacio/internal/testutil"
)

func load(t *testing.T) (*catalog.Catalog, *Matcher, *kev.Catalog) {
	t.Helper()
	cat, err := catalog.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join("testdata", "kev_sample.json"))
	if err != nil {
		t.Fatal(err)
	}
	kc, err := kev.ParseCatalog(raw)
	if err != nil {
		t.Fatal(err)
	}
	return cat, New(cat), kc
}

// Every alias in the shipped catalog must match at least one real KEV entry,
// so a misspelled alias (which would silently never alert) fails CI.
func TestEveryAliasMatchesARealEntry(t *testing.T) {
	cat, m, kc := load(t)
	for _, p := range cat.Products() {
		for i, a := range p.KEVAliases {
			found := false
			for _, v := range kc.Vulnerabilities {
				for _, h := range m.Products(v) {
					if h.ProductID == p.ID && h.Alias.Matches(v.VendorProject, v.Product, v.Name, v.ShortDescription) &&
						catalog.Key(h.Alias.Vendor, h.Alias.Product) == catalog.Key(a.Vendor, a.Product) {
						found = true
					}
				}
			}
			if !found {
				t.Errorf("%s kev_aliases[%d] (%s / %s) matches no entry in testdata/kev_sample.json; add a real one",
					p.ID, i, a.Vendor, a.Product)
			}
		}
	}
}

// Edge is built on Chromium: every Chromium component pair Chrome matches must
// also match Edge, unfiltered, or an Edge-only user silently misses that flaw.
func TestEdgeCoversEveryChromiumPair(t *testing.T) {
	cat, _, _ := load(t)
	chrome, ok := cat.Get("google-chrome")
	if !ok {
		t.Fatal("google-chrome is not in the catalog")
	}
	edge, ok := cat.Get("microsoft-edge")
	if !ok {
		t.Fatal("microsoft-edge is not in the catalog")
	}
	for _, a := range chrome.KEVAliases {
		if a.Vendor != "Google" || !strings.HasPrefix(a.Product, "Chromium") {
			continue
		}
		if !slices.ContainsFunc(edge.KEVAliases, func(e catalog.KEVAlias) bool {
			return catalog.Key(e.Vendor, e.Product) == catalog.Key(a.Vendor, a.Product) && len(e.Mentions) == 0
		}) {
			t.Errorf("microsoft-edge has no unfiltered alias for %s / %s", a.Vendor, a.Product)
		}
	}
}

func TestProducts(t *testing.T) {
	_, m, kc := load(t)
	byCVE := map[string]kev.Vulnerability{}
	for _, v := range kc.Vulnerabilities {
		byCVE[v.CVEID] = v
	}
	tests := []struct {
		cve  string
		want []string
	}{
		// "FortiOS and FortiProxy" names two products: both must alert.
		{"CVE-2025-24472", []string{"fortinet-fortios", "fortinet-fortiproxy"}},
		// "Multiple Products": only the products CISA's description names.
		{"CVE-2025-59718", []string{"fortinet-fortios", "fortinet-fortiproxy", "fortinet-fortiweb"}},
		{"CVE-2025-25249", []string{"fortinet-fortios"}},
		{"CVE-2025-32756", nil}, // FortiMail, FortiVoice, ...
		{"CVE-2026-93616", nil}, // Check Point management servers
		{"CVE-2026-85102", []string{"checkpoint-security-gateway"}},
		{"CVE-2019-12989", nil}, // Citrix SD-WAN
		{"CVE-2025-20393", nil}, // Cisco email gateways
		// KEV does not say which Windows edition: both get the alert.
		{"CVE-2026-81963", []string{"microsoft-windows", "microsoft-windows-server"}},
		// Chromium flaws reach Edge (built on Chromium) whether or not CISA's
		// description names it.
		{"CVE-2026-87491", []string{"google-chrome", "microsoft-edge"}},
		{"CVE-2023-4863", []string{"google-chrome", "microsoft-edge"}},
		// Legacy (pre-Chromium) Edge entries.
		{"CVE-2017-0037", []string{"microsoft-edge"}},
		// ASA and FTD named together.
		{"CVE-2024-20481", []string{"cisco-asa", "cisco-ftd"}},
	}
	for _, tt := range tests {
		v, ok := byCVE[tt.cve]
		if !ok {
			t.Errorf("%s is not in the fixture", tt.cve)
			continue
		}
		var got []string
		for _, h := range m.Products(v) {
			got = append(got, h.ProductID)
		}
		if !slices.Equal(got, tt.want) {
			t.Errorf("%s (%s / %s) -> %v, want %v", tt.cve, v.VendorProject, v.Product, got, tt.want)
		}
	}
}

func TestKEVFindings(t *testing.T) {
	_, m, kc := load(t)
	got := m.KEV(kc.Vulnerabilities, []string{"fortinet-fortios", "citrix-netscaler", "not-in-catalog"})
	if len(got) == 0 {
		t.Fatal("no findings")
	}
	type row struct{ Product, CVE, Added, Alias string }
	var rows []row
	for i, f := range got {
		if f.Product.ID != "fortinet-fortios" && f.Product.ID != "citrix-netscaler" {
			t.Errorf("finding for unticked product %s", f.Product.ID)
		}
		if i > 0 && got[i-1].Vuln.DateAdded.Before(f.Vuln.DateAdded.Time) {
			t.Errorf("findings not newest first at %d", i)
		}
		rows = append(rows, row{f.Product.ID, f.Vuln.CVEID, f.Vuln.DateAdded.String(), f.Alias.Vendor + " / " + f.Alias.Product})
	}
	testutil.Golden(t, filepath.Join("testdata", "findings.golden.json"), rows)
}

func TestKEVNoProducts(t *testing.T) {
	_, m, kc := load(t)
	if got := m.KEV(kc.Vulnerabilities, nil); len(got) != 0 {
		t.Errorf("got %d findings with no products ticked", len(got))
	}
}

func TestCoverage(t *testing.T) {
	_, m, kc := load(t)
	since, err := feeds.ParseDate("2024-10-02")
	if err != nil {
		t.Fatal(err)
	}
	c := m.Coverage(kc.Vulnerabilities, since)
	if c.Total == 0 || c.Mapped == 0 || c.Mapped > c.Total {
		t.Fatalf("implausible coverage: %+v", c)
	}
	unmapped := 0
	for _, p := range c.Unmapped {
		unmapped += p.Count
	}
	if c.Mapped+unmapped != c.Total {
		t.Errorf("mapped %d + unmapped %d != total %d", c.Mapped, unmapped, c.Total)
	}
	testutil.Golden(t, filepath.Join("testdata", "coverage.golden.json"), c)
}

func TestCoverageEmptyWindow(t *testing.T) {
	_, m, kc := load(t)
	since, _ := feeds.ParseDate("2099-01-01")
	c := m.Coverage(kc.Vulnerabilities, since)
	if c.Total != 0 || c.Percent != 0 || len(c.Unmapped) != 0 {
		t.Errorf("want an empty report, got %+v", c)
	}
}
