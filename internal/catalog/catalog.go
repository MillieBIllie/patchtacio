// Package catalog loads and checks the product catalog: one YAML file per
// product, mapping a canonical product to the free-text vendor/product names
// CISA KEV uses for it, its CPE prefixes and its endoflife.date slug.
//
// The catalog decides what a user's ticked product matches, so a wrong entry
// means a missed alert or a false alarm. Parsing is strict (unknown keys are
// errors) and Lint reports every problem it finds, not just the first.
package catalog

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"

	catalogfiles "github.com/milliebillie/patchtacio/catalog"
)

// Categories a product may belong to.
var Categories = []string{
	"firewall-vpn", "email", "os", "hypervisor", "web-app", "file-transfer", "remote-access", "other",
}

// Advisory feed kinds.
var AdvisoryKinds = []string{"csaf", "rss", "api", "none"}

// Product is one catalog entry. Field names match the YAML keys documented in
// the add-catalog-product skill.
type Product struct {
	ID            string     `yaml:"id" json:"id"`
	Display       string     `yaml:"display" json:"display"`
	Vendor        string     `yaml:"vendor" json:"vendor"`
	Category      string     `yaml:"category" json:"category"`
	KEVAliases    []KEVAlias `yaml:"kev_aliases" json:"kevAliases"`
	CPEPrefixes   []string   `yaml:"cpe_prefixes" json:"cpePrefixes"`
	EOLSlug       string     `yaml:"eol_slug" json:"eolSlug,omitempty"` // "" (or null) = not tracked
	Advisory      *Advisory  `yaml:"advisory,omitempty" json:"advisory,omitempty"`
	AliasesSearch []string   `yaml:"aliases_search" json:"aliasesSearch,omitempty"`
	Notes         string     `yaml:"notes" json:"notes,omitempty"`
	Verified      string     `yaml:"verified" json:"verified"`                         // YYYY-MM-DD
	Deprecated    string     `yaml:"deprecated,omitempty" json:"deprecated,omitempty"` // replacement product ID
}

// KEVAlias is one vendorProject/product pair exactly as it appears in KEV.
// Matching ignores case and repeated or surrounding spaces.
//
// Mentions narrows a broad pair such as Fortinet/"Multiple Products": the
// entry matches only if its name or description names one of these words as
// a whole word. The words come from CISA's own text, so nothing is guessed.
type KEVAlias struct {
	Vendor   string   `yaml:"vendor" json:"vendor"`
	Product  string   `yaml:"product" json:"product"`
	Mentions []string `yaml:"mentions,omitempty" json:"mentions,omitempty"`
}

// Advisory is the vendor's own advisory feed for the product.
type Advisory struct {
	Kind string `yaml:"kind" json:"kind"`
	URL  string `yaml:"url,omitempty" json:"url,omitempty"`
}

// Catalog is a parsed set of products.
type Catalog struct {
	products []Product // sorted by ID
	byID     map[string]int
}

// Products returns every product, including deprecated ones, sorted by ID.
func (c *Catalog) Products() []Product { return slices.Clone(c.products) }

// Active returns the products that are not deprecated, sorted by ID.
func (c *Catalog) Active() []Product {
	var out []Product
	for _, p := range c.products {
		if p.Deprecated == "" {
			out = append(out, p)
		}
	}
	return out
}

// Get returns the product with the given ID.
func (c *Catalog) Get(id string) (Product, bool) {
	i, ok := c.byID[id]
	if !ok {
		return Product{}, false
	}
	return c.products[i], true
}

// EmbeddedFS is the catalog directory compiled into the binary.
func EmbeddedFS() fs.FS { return catalogfiles.Products() }

// Embedded loads the catalog compiled into the binary.
func Embedded() (*Catalog, error) { return Load(EmbeddedFS()) }

// Load parses the products in fsys and fails if any has an error.
// Warnings do not stop loading.
func Load(fsys fs.FS) (*Catalog, error) {
	cat, problems := Lint(fsys, nil)
	var errs []error
	for _, p := range problems {
		if p.Severity == Error {
			errs = append(errs, errors.New(p.String()))
		}
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf("product catalog has %d problems (run `patchtacio catalog lint`): %w", len(errs), errors.Join(errs...))
	}
	return cat, nil
}

// Severity of a lint problem.
type Severity int

// Severities.
const (
	Warning Severity = iota
	Error
)

func (s Severity) String() string {
	if s == Error {
		return "error"
	}
	return "warning"
}

// Problem is one thing wrong with the catalog.
type Problem struct {
	File     string
	Severity Severity
	Message  string
}

func (p Problem) String() string {
	if p.File == "" {
		return fmt.Sprintf("%s: %s", p.Severity, p.Message)
	}
	return fmt.Sprintf("%s: %s: %s", p.File, p.Severity, p.Message)
}

// References is source data to check the catalog against. Either part may
// be nil when that feed has no saved copy.
type References struct {
	KEV      []KEVEntry      // every KEV entry
	EOLSlugs map[string]bool // every endoflife.date product slug
}

// KEVEntry is the part of a KEV record that matching looks at.
type KEVEntry struct {
	Vendor, Product string
	Text            []string // vulnerability name and short description
}

// Lint parses every product in fsys and returns the catalog built from the
// files that parsed, plus every problem found. refs, if not nil, adds checks
// against the real feeds.
func Lint(fsys fs.FS, refs *References) (*Catalog, []Problem) {
	var problems []Problem
	add := func(file string, sev Severity, format string, args ...any) {
		problems = append(problems, Problem{File: file, Severity: sev, Message: fmt.Sprintf(format, args...)})
	}

	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		add("", Error, "read catalog directory: %v", err)
		return &Catalog{byID: map[string]int{}}, problems
	}
	cat := &Catalog{byID: map[string]int{}}
	files := map[string]string{} // product ID -> file
	for _, e := range entries {
		name := e.Name()
		switch {
		case e.IsDir():
			add(name, Warning, "directories are ignored; put product files directly in the catalog directory")
			continue
		case strings.HasSuffix(name, ".yml"):
			add(name, Error, "use the .yaml extension")
			continue
		case !strings.HasSuffix(name, ".yaml"):
			continue // README and the like
		case !e.Type().IsRegular():
			add(name, Error, "must be a regular file (symlinks and special files are not allowed)")
			continue
		}
		raw, err := readLimited(fsys, name)
		if err != nil {
			add(name, Error, "read: %v", err)
			continue
		}
		p, err := decode(raw)
		if err != nil {
			add(name, Error, "%v", err)
			continue
		}
		for _, pr := range check(p) {
			add(name, pr.Severity, "%s", pr.Message)
		}
		if want := p.ID + ".yaml"; p.ID != "" && name != want {
			add(name, Error, "file name must match the id: rename it to %s", want)
		}
		if prev, dup := files[p.ID]; dup {
			add(name, Error, "id %q is already used by %s", p.ID, prev)
			continue
		}
		files[p.ID] = name
		cat.products = append(cat.products, p)
	}
	slices.SortFunc(cat.products, func(a, b Product) int { return strings.Compare(a.ID, b.ID) })
	for i, p := range cat.products {
		cat.byID[p.ID] = i
	}

	// Checks across products.
	for _, p := range cat.products {
		if p.Deprecated == "" {
			continue
		}
		target, ok := cat.Get(p.Deprecated)
		switch {
		case !ok:
			add(files[p.ID], Error, "deprecated: %q is not a product in the catalog", p.Deprecated)
		case target.Deprecated != "":
			add(files[p.ID], Error, "deprecated: %q is itself deprecated; point to the current product", p.Deprecated)
		}
	}
	if refs != nil {
		problems = append(problems, crossCheck(cat, files, refs)...)
	}
	if len(cat.products) == 0 {
		add("", Error, "the catalog has no products")
	}
	slices.SortStableFunc(problems, func(a, b Problem) int { return strings.Compare(a.File, b.File) })
	return cat, problems
}

// maxFileSize bounds one product file; real ones are about 1 KB.
const maxFileSize = 64 << 10

func readLimited(fsys fs.FS, name string) ([]byte, error) {
	f, err := fsys.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, maxFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxFileSize {
		return nil, fmt.Errorf("larger than %d KB", maxFileSize>>10)
	}
	return raw, nil
}

// decode parses one product file strictly: one document, no unknown keys.
func decode(raw []byte) (Product, error) {
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	var p Product
	if err := dec.Decode(&p); err != nil {
		if errors.Is(err, io.EOF) {
			return Product{}, errors.New("the file is empty")
		}
		return Product{}, fmt.Errorf("invalid YAML: %w", err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return Product{}, errors.New("one product per file: found more than one YAML document")
	}
	return p, nil
}

var (
	idPattern   = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)+$`)
	slugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._+-]*$`)
	// cpe:2.3:part:vendor:product, with no version: a prefix names a product.
	// Other punctuation is escaped with a backslash, as in NVD's
	// veeam_backup_\&_replication.
	cpePattern = regexp.MustCompile(`^cpe:2\.3:[aoh]:` + cpeName + `:` + cpeName + `$`)
)

// cpeName is one CPE 2.3 vendor or product name: lowercase letters, digits
// and . _ - ~, or a backslash-escaped punctuation character.
const cpeName = `(?:[a-z0-9._~-]|\\[[:punct:]])+`

const maxDisplay = 80

func check(p Product) []Problem {
	var out []Problem
	bad := func(format string, args ...any) {
		out = append(out, Problem{Severity: Error, Message: fmt.Sprintf(format, args...)})
	}

	switch {
	case p.ID == "":
		bad("id is required")
	case len(p.ID) > 64 || !idPattern.MatchString(p.ID):
		bad("id %q must be vendor-product: lowercase letters and digits joined by single hyphens", p.ID)
	}
	checkText := func(field, v string, required bool) {
		switch {
		case strings.TrimSpace(v) == "":
			if required {
				bad("%s is required", field)
			}
		case v != strings.TrimSpace(v):
			bad("%s has leading or trailing spaces", field)
		case hasControl(v):
			bad("%s contains control characters", field)
		}
	}
	checkText("display", p.Display, true)
	if utf8.RuneCountInString(p.Display) > maxDisplay {
		bad("display is longer than %d characters", maxDisplay)
	}
	checkText("vendor", p.Vendor, true)
	if p.Category == "" {
		bad("category is required")
	} else if !slices.Contains(Categories, p.Category) {
		bad("category %q must be one of: %s", p.Category, strings.Join(Categories, ", "))
	}

	if len(p.KEVAliases) == 0 {
		// A product that cannot match would be reported as "no matching KEV
		// entries", which reads as a result. Deprecated products keep theirs.
		bad("kev_aliases is required: without it this product can never match a KEV entry")
	}
	seen := map[string]bool{}
	for i, a := range p.KEVAliases {
		where := fmt.Sprintf("kev_aliases[%d]", i)
		if Normalize(a.Vendor) == "" || Normalize(a.Product) == "" {
			bad("%s needs both vendor and product", where)
			continue
		}
		if hasControl(a.Vendor) || hasControl(a.Product) {
			bad("%s contains control characters", where)
		}
		for j, m := range a.Mentions {
			if Normalize(m) == "" {
				bad("%s.mentions[%d] is empty", where, j)
			}
		}
		key := a.key() + "\x00" + strings.Join(normalizeAll(a.Mentions), "\x00")
		if seen[key] {
			bad("%s duplicates an earlier alias (matching ignores case and spacing)", where)
		}
		seen[key] = true
	}
	for i, c := range p.CPEPrefixes {
		if !cpePattern.MatchString(c) {
			bad("cpe_prefixes[%d] %q must look like cpe:2.3:<a|o|h>:<vendor>:<product>", i, c)
		}
	}
	if p.EOLSlug != "" && !slugPattern.MatchString(p.EOLSlug) {
		bad("eol_slug %q is not a valid endoflife.date slug", p.EOLSlug)
	}
	if a := p.Advisory; a != nil {
		switch {
		case !slices.Contains(AdvisoryKinds, a.Kind):
			bad("advisory.kind %q must be one of: %s", a.Kind, strings.Join(AdvisoryKinds, ", "))
		case a.Kind != "none" && a.URL == "":
			bad("advisory.url is required when advisory.kind is %q", a.Kind)
		}
		if a.URL != "" && !strings.HasPrefix(a.URL, "https://") {
			bad("advisory.url must start with https://")
		}
	}
	for i, s := range p.AliasesSearch {
		if strings.TrimSpace(s) == "" || hasControl(s) {
			bad("aliases_search[%d] is empty or contains control characters", i)
		}
	}
	if hasControl(strings.ReplaceAll(p.Notes, "\n", "")) {
		bad("notes contain control characters")
	}
	if p.Verified == "" {
		bad("verified is required: the date the identifiers were last checked (YYYY-MM-DD)")
	} else if _, err := time.Parse(time.DateOnly, p.Verified); err != nil {
		bad("verified %q must be a date written YYYY-MM-DD", p.Verified)
	}
	if p.Deprecated == p.ID && p.ID != "" {
		bad("deprecated must name a different product")
	}
	return out
}

// crossCheck compares the catalog with real feed data.
func crossCheck(cat *Catalog, files map[string]string, refs *References) []Problem {
	var out []Problem
	for _, p := range cat.products {
		file := files[p.ID]
		if refs.EOLSlugs != nil && p.EOLSlug != "" && !refs.EOLSlugs[p.EOLSlug] {
			out = append(out, Problem{File: file, Severity: Error,
				Message: fmt.Sprintf("eol_slug %q is not an endoflife.date product", p.EOLSlug)})
		}
		if refs.KEV == nil {
			continue
		}
		for i, a := range p.KEVAliases {
			if !slices.ContainsFunc(refs.KEV, func(e KEVEntry) bool { return a.Matches(e.Vendor, e.Product, e.Text...) }) {
				out = append(out, Problem{File: file, Severity: Warning,
					Message: fmt.Sprintf("kev_aliases[%d] (%s / %s) matches no entry in the saved KEV catalog; check the spelling", i, a.Vendor, a.Product)})
			}
		}
	}
	return out
}

// Normalize folds case and collapses whitespace, the way KEV names are
// compared: KEV is hand-written and has stray spaces ("SimpleHelp ").
func Normalize(s string) string { return strings.ToLower(strings.Join(strings.Fields(s), " ")) }

func normalizeAll(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = Normalize(s)
	}
	slices.Sort(out)
	return out
}

// Key is the lookup key for a KEV vendorProject/product pair.
func Key(vendor, product string) string { return Normalize(vendor) + "\x00" + Normalize(product) }

func (a KEVAlias) key() string { return Key(a.Vendor, a.Product) }

// Matches reports whether a KEV entry with this vendor and product, and with
// the given name/description text, is covered by the alias.
func (a KEVAlias) Matches(vendor, product string, text ...string) bool {
	if a.key() != Key(vendor, product) {
		return false
	}
	return a.MentionedIn(text...)
}

// MentionedIn reports whether the alias's Mentions filter accepts text. An
// alias without Mentions accepts everything.
func (a KEVAlias) MentionedIn(text ...string) bool {
	if len(a.Mentions) == 0 {
		return true
	}
	for _, m := range a.Mentions {
		for _, t := range text {
			if containsWord(Normalize(t), Normalize(m)) {
				return true
			}
		}
	}
	return false
}

// containsWord reports whether word occurs in s with no letter or digit
// directly before or after it. Both are already normalized.
func containsWord(s, word string) bool {
	if word == "" {
		return false
	}
	for start := 0; ; {
		i := strings.Index(s[start:], word)
		if i < 0 {
			return false
		}
		i += start
		end := i + len(word)
		before, _ := utf8.DecodeLastRuneInString(s[:i])
		after, _ := utf8.DecodeRuneInString(s[end:])
		if (i == 0 || !isWordRune(before)) && (end == len(s) || !isWordRune(after)) {
			return true
		}
		start = i + 1
	}
}

func isWordRune(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) }

func hasControl(s string) bool { return strings.ContainsFunc(s, unicode.IsControl) }
