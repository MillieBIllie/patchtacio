package catalog

import (
	"strings"
	"testing"
	"testing/fstest"
)

const goodYAML = `id: acme-widget
display: "Acme Widget"
vendor: "Acme"
category: firewall-vpn
kev_aliases:
  - { vendor: "Acme", product: "Widget" }
  - { vendor: "Acme", product: "Multiple Products", mentions: ["Widget"] }
cpe_prefixes: ["cpe:2.3:o:acme:widget"]
eol_slug: acme-widget
aliases_search: [gadget]
notes: ""
verified: 2026-10-02
`

func fsWith(files map[string]string) fstest.MapFS {
	m := fstest.MapFS{}
	for name, body := range files {
		m[name] = &fstest.MapFile{Data: []byte(body)}
	}
	return m
}

func TestLoadGood(t *testing.T) {
	cat, err := Load(fsWith(map[string]string{"acme-widget.yaml": goodYAML, "README.md": "ignored"}))
	if err != nil {
		t.Fatal(err)
	}
	p, ok := cat.Get("acme-widget")
	if !ok {
		t.Fatal("product not found")
	}
	if p.Verified != "2026-10-02" || p.EOLSlug != "acme-widget" || len(p.KEVAliases) != 2 {
		t.Errorf("unexpected product: %+v", p)
	}
	if got := len(cat.Active()); got != 1 {
		t.Errorf("Active() = %d products, want 1", got)
	}
}

func TestLintProblems(t *testing.T) {
	tests := []struct {
		name string
		file string
		body string
		want string // substring of one error
	}{
		{"unknown key", "acme-widget.yaml", goodYAML + "colour: red\n", "field colour not found"},
		{"file name mismatch", "acme.yaml", goodYAML, "rename it to acme-widget.yaml"},
		{"bad id", "Acme_Widget.yaml", strings.Replace(goodYAML, "id: acme-widget", "id: Acme_Widget", 1), "must be vendor-product"},
		{"no hyphen", "acme.yaml", strings.Replace(goodYAML, "id: acme-widget", "id: acme", 1), "must be vendor-product"},
		{"bad category", "acme-widget.yaml", strings.Replace(goodYAML, "firewall-vpn", "router", 1), `category "router"`},
		{"missing display", "acme-widget.yaml", strings.Replace(goodYAML, `display: "Acme Widget"`, "", 1), "display is required"},
		{"padded display", "acme-widget.yaml", strings.Replace(goodYAML, `"Acme Widget"`, `" Acme Widget"`, 1), "leading or trailing"},
		{"bad cpe", "acme-widget.yaml", strings.Replace(goodYAML, "cpe:2.3:o:acme:widget", "cpe:/o:acme:widget", 1), "cpe_prefixes[0]"},
		{"cpe with version", "acme-widget.yaml", strings.Replace(goodYAML, "cpe:2.3:o:acme:widget", "cpe:2.3:o:acme:widget:7.0", 1), "cpe_prefixes[0]"},
		{"bad slug", "acme-widget.yaml", strings.Replace(goodYAML, "eol_slug: acme-widget", "eol_slug: Acme Widget", 1), "eol_slug"},
		{"bad date", "acme-widget.yaml", strings.Replace(goodYAML, "2026-10-02", "02/10/2026", 1), "YYYY-MM-DD"},
		{"no date", "acme-widget.yaml", strings.Replace(goodYAML, "verified: 2026-10-02\n", "", 1), "verified is required"},
		{"half alias", "acme-widget.yaml", strings.Replace(goodYAML, `product: "Widget" }`, `product: " " }`, 1), "needs both vendor and product"},
		{"duplicate alias", "acme-widget.yaml", strings.Replace(goodYAML, `product: "Widget" }`,
			`product: "Widget" }`+"\n"+`  - { vendor: "ACME ", product: "widget" }`, 1), "duplicates an earlier alias"},
		{"empty mention", "acme-widget.yaml", strings.Replace(goodYAML, `mentions: ["Widget"]`, `mentions: [""]`, 1), "mentions[0] is empty"},
		{"advisory without url", "acme-widget.yaml", goodYAML + "advisory: { kind: rss }\n", "advisory.url is required"},
		{"advisory http", "acme-widget.yaml", goodYAML + "advisory: { kind: rss, url: \"http://x\" }\n", "https://"},
		{"deprecated target missing", "acme-widget.yaml", goodYAML + "deprecated: acme-gadget\n", "not a product in the catalog"},
		{"two documents", "acme-widget.yaml", goodYAML + "---\n" + goodYAML, "one product per file"},
		{"empty file", "acme-widget.yaml", "", "empty"},
		{"yml extension", "acme-widget.yml", goodYAML, "use the .yaml extension"},
		{"not yaml", "acme-widget.yaml", "id: [unclosed", "invalid YAML"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, problems := Lint(fsWith(map[string]string{tt.file: tt.body}), nil)
			var msgs []string
			found := false
			for _, p := range problems {
				msgs = append(msgs, p.String())
				if p.Severity == Error && strings.Contains(p.Message, tt.want) {
					found = true
				}
			}
			if !found {
				t.Errorf("want an error containing %q, got:\n%s", tt.want, strings.Join(msgs, "\n"))
			}
			if _, err := Load(fsWith(map[string]string{tt.file: tt.body})); err == nil {
				t.Error("Load accepted a catalog with errors")
			}
		})
	}
}

func TestLintDuplicateID(t *testing.T) {
	_, problems := Lint(fsWith(map[string]string{"acme-widget.yaml": goodYAML, "copy.yaml": goodYAML}), nil)
	if !hasError(problems, "already used by") {
		t.Errorf("duplicate id not reported: %v", problems)
	}
}

func TestLintDeprecatedChain(t *testing.T) {
	old := strings.Replace(goodYAML, "id: acme-widget", "id: acme-old", 1) + "deprecated: acme-widget\n"
	cat, problems := Lint(fsWith(map[string]string{"acme-widget.yaml": goodYAML, "acme-old.yaml": old}), nil)
	if len(errorsIn(problems)) != 0 {
		t.Fatalf("unexpected errors: %v", problems)
	}
	if len(cat.Active()) != 1 || len(cat.Products()) != 2 {
		t.Errorf("Active/Products = %d/%d, want 1/2", len(cat.Active()), len(cat.Products()))
	}
	chained := strings.Replace(goodYAML, "id: acme-widget", "id: acme-older", 1) + "deprecated: acme-old\n"
	_, problems = Lint(fsWith(map[string]string{"acme-widget.yaml": goodYAML, "acme-old.yaml": old, "acme-older.yaml": chained}), nil)
	if !hasError(problems, "itself deprecated") {
		t.Errorf("deprecation chain not reported: %v", problems)
	}
}

func TestLintCrossCheck(t *testing.T) {
	refs := &References{
		KEV:      []KEVEntry{{Vendor: "Acme ", Product: "widget", Text: []string{"Acme Widget flaw"}}},
		EOLSlugs: map[string]bool{"other": true},
	}
	_, problems := Lint(fsWith(map[string]string{"acme-widget.yaml": goodYAML}), refs)
	if !hasError(problems, `eol_slug "acme-widget" is not an endoflife.date product`) {
		t.Errorf("unknown slug not reported: %v", problems)
	}
	var warned []string
	for _, p := range problems {
		if p.Severity == Warning {
			warned = append(warned, p.Message)
		}
	}
	// The plain alias matches the KEV entry; the Multiple Products one does not.
	if len(warned) != 1 || !strings.Contains(warned[0], "kev_aliases[1]") {
		t.Errorf("want one warning for kev_aliases[1], got %v", warned)
	}
}

func TestMatches(t *testing.T) {
	plain := KEVAlias{Vendor: "Fortinet", Product: "FortiOS"}
	multi := KEVAlias{Vendor: "Fortinet", Product: "Multiple Products", Mentions: []string{"FortiOS"}}
	tests := []struct {
		alias           KEVAlias
		vendor, product string
		text            string
		want            bool
	}{
		{plain, "Fortinet", "FortiOS", "", true},
		{plain, " fortinet", "FORTIOS  ", "", true},
		{plain, "Fortinet", "FortiOS and FortiProxy", "", false},
		{plain, "Fortinet Inc", "FortiOS", "", false},
		{multi, "Fortinet", "Multiple Products", "Fortinet FortiOS, FortiProxy, and FortiWeb contain", true},
		{multi, "Fortinet", "Multiple Products", "Fortinet fortios contains", true},
		{multi, "Fortinet", "Multiple Products", "Fortinet FortiOSX contains", false},
		{multi, "Fortinet", "Multiple Products", "Fortinet FortiProxy and FortiWeb contain", false},
		{multi, "Fortinet", "FortiOS", "Fortinet FortiOS contains", false},
	}
	for _, tt := range tests {
		if got := tt.alias.Matches(tt.vendor, tt.product, tt.text); got != tt.want {
			t.Errorf("%+v.Matches(%q, %q, %q) = %v, want %v", tt.alias, tt.vendor, tt.product, tt.text, got, tt.want)
		}
	}
}

func TestContainsWord(t *testing.T) {
	tests := []struct {
		s, word string
		want    bool
	}{
		{"fortios", "fortios", true},
		{"a fortios, b", "fortios", true},
		{"fortiosx fortios", "fortios", true}, // second occurrence counts
		{"xfortios", "fortios", false},
		{"ivanti mobileiron's core & connector", "mobileiron's core", true},
		{"café", "caf", false}, // é is a letter
		{"", "x", false},
		{"x", "", false},
	}
	for _, tt := range tests {
		if got := containsWord(tt.s, tt.word); got != tt.want {
			t.Errorf("containsWord(%q, %q) = %v, want %v", tt.s, tt.word, got, tt.want)
		}
	}
}

// The catalog shipped in the binary must always load cleanly.
func TestEmbeddedCatalogIsValid(t *testing.T) {
	cat, problems := Lint(EmbeddedFS(), nil)
	for _, p := range problems {
		t.Errorf("%s", p)
	}
	if len(cat.Active()) == 0 {
		t.Error("embedded catalog has no products")
	}
}

func hasError(problems []Problem, substr string) bool {
	for _, p := range problems {
		if p.Severity == Error && strings.Contains(p.Message, substr) {
			return true
		}
	}
	return false
}

func errorsIn(problems []Problem) []Problem {
	var out []Problem
	for _, p := range problems {
		if p.Severity == Error {
			out = append(out, p)
		}
	}
	return out
}
