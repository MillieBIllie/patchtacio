// Package match turns feed data and the user's ticked products into findings.
//
// Matching KEV to a product is by name only, through the catalog's KEV
// aliases: KEV has no structured product identifiers. Versions are not
// compared yet (NVD version ranges are Phase 3), so every finding says so and
// the user must check whether their version is affected. A missed match is
// worse than a false alarm, which is why the catalog may list one KEV pair on
// several products.
package match

import (
	"cmp"
	"slices"
	"strings"

	"github.com/milliebillie/patchtacio/internal/catalog"
	"github.com/milliebillie/patchtacio/internal/feeds/kev"
)

// Matcher maps KEV entries to catalog products.
type Matcher struct {
	cat   *catalog.Catalog
	index map[string][]ref // catalog.Key(vendor, product) -> aliases with that pair
}

type ref struct {
	productID string
	alias     catalog.KEVAlias
}

// New indexes every product in the catalog, including deprecated ones, so a
// configuration that still names a deprecated product keeps matching.
func New(cat *catalog.Catalog) *Matcher {
	m := &Matcher{cat: cat, index: map[string][]ref{}}
	for _, p := range cat.Products() {
		for _, a := range p.KEVAliases {
			k := catalog.Key(a.Vendor, a.Product)
			m.index[k] = append(m.index[k], ref{productID: p.ID, alias: a})
		}
	}
	return m
}

// Hit is one product a KEV entry maps to, and the alias that matched.
type Hit struct {
	ProductID string
	Alias     catalog.KEVAlias
}

// Products returns the catalog products a KEV entry maps to, sorted by
// product ID, at most one hit per product.
func (m *Matcher) Products(v kev.Vulnerability) []Hit {
	var hits []Hit
	for _, r := range m.index[catalog.Key(v.VendorProject, v.Product)] {
		if !r.alias.MentionedIn(v.Name, v.ShortDescription) {
			continue
		}
		if slices.ContainsFunc(hits, func(h Hit) bool { return h.ProductID == r.productID }) {
			continue
		}
		hits = append(hits, Hit{ProductID: r.productID, Alias: r.alias})
	}
	slices.SortFunc(hits, func(a, b Hit) int { return strings.Compare(a.ProductID, b.ProductID) })
	return hits
}

// Finding is a KEV entry that matches one of the user's products.
type Finding struct {
	Product catalog.Product
	Vuln    kev.Vulnerability
	Alias   catalog.KEVAlias // the catalog alias that matched
}

// KEV returns the findings for the given product IDs, newest KEV entry first.
// IDs not in the catalog are ignored; the caller validates them.
func (m *Matcher) KEV(vulns []kev.Vulnerability, productIDs []string) []Finding {
	want := map[string]bool{}
	for _, id := range productIDs {
		want[id] = true
	}
	var out []Finding
	for _, v := range vulns {
		for _, h := range m.Products(v) {
			if !want[h.ProductID] {
				continue
			}
			p, _ := m.cat.Get(h.ProductID)
			out = append(out, Finding{Product: p, Vuln: v, Alias: h.Alias})
		}
	}
	slices.SortStableFunc(out, func(a, b Finding) int {
		return cmp.Or(
			b.Vuln.DateAdded.Compare(a.Vuln.DateAdded.Time), // newest first
			strings.Compare(b.Vuln.CVEID, a.Vuln.CVEID),
			strings.Compare(a.Product.ID, b.Product.ID),
		)
	})
	return out
}
