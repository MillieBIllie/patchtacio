package match

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/milliebillie/patchtacio/internal/catalog"
	"github.com/milliebillie/patchtacio/internal/feeds/eol"
	"github.com/milliebillie/patchtacio/internal/testutil"
)

func loadEOL(t *testing.T) (*catalog.Catalog, *eol.Catalog) {
	t.Helper()
	cat, err := catalog.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	ec, err := eol.ParseCatalog(testutil.ReadFile(t, filepath.Join("..", "..", "testdata", "feeds", "eol", "products_full.json")))
	if err != nil {
		t.Fatal(err)
	}
	return cat, ec
}

func TestEOL(t *testing.T) {
	cat, ec := loadEOL(t)
	today := time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		id, version string
		state       EOLState
		release     string
		successor   string
	}{
		{"fortinet-fortios", "7.2.8", EOLEnded, "7.2", "8.0"},    // isEol, 30 Sep 2026
		{"fortinet-fortios", "v7.2", EOLEnded, "7.2", "8.0"},     // exact, leading v
		{"fortinet-fortios", "7.4.2", EOLSupported, "7.4", ""},   // ends 2028
		{"fortinet-fortios", "7.20", EOLNoMatch, "", ""},         // never a prefix match without a dot
		{"fortinet-fortios", "", EOLNoVersion, "", ""},           // no version given
		{"atlassian-confluence", "7.20.1", EOLEnded, "7.20", ""}, // 7.20, not 7.2
		{"atlassian-confluence", "9.2.3", EOLEnding, "9.2", ""},  // ends 10 Dec 2026, within 90 days
		{"atlassian-confluence", "9.1", EOLEnding, "9.1", ""},    // ends today: not yet ended
		{"microsoft-windows-server", "2012 R2", EOLEnded, "2012-r2", ""},
		{"microsoft-windows-server", "2022", EOLSupported, "2022", ""},
		{"vmware-esxi", "8.0", EOLNoData, "", ""},           // slug not in the fixture
		{"citrix-netscaler", "14.1", EOLNotTracked, "", ""}, // no endoflife.date slug
	}
	for _, tt := range tests {
		got := EOL(cat, ec, []Ticked{{ID: tt.id, Version: tt.version}}, today)
		if len(got) != 1 {
			t.Fatalf("%s %q: %d results", tt.id, tt.version, len(got))
		}
		g := got[0]
		rel, succ := "", ""
		if g.Release != nil {
			rel = g.Release.Name
		}
		if g.Successor != nil {
			succ = g.Successor.Name
		}
		if g.State != tt.state || rel != tt.release || (tt.successor != "" && succ != tt.successor) {
			t.Errorf("%s %q: state %s release %q successor %q; want %s %q %q", tt.id, tt.version, g.State, rel, succ, tt.state, tt.release, tt.successor)
		}
		if g.State == EOLNoMatch && len(g.Releases) == 0 {
			t.Errorf("%s %q: no release names for the hint", tt.id, tt.version)
		}
	}
	// Supported releases suggest nothing; an ended one only something newer.
	for _, g := range EOL(cat, ec, []Ticked{{ID: "atlassian-confluence", Version: "7.20"}}, today) {
		if g.Successor == nil || g.Successor.Name != "10.2" {
			t.Errorf("confluence 7.20 successor %+v, want 10.2 (newest supported)", g.Successor)
		}
	}
	if got := EOL(cat, nil, []Ticked{{ID: "fortinet-fortios", Version: "7.2"}}, today); got[0].State != EOLNoData {
		t.Errorf("no data at all: %s", got[0].State)
	}
}
