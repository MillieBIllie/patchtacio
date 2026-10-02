package match

import (
	"cmp"
	"slices"
	"strings"

	"github.com/milliebillie/patchtacio/internal/catalog"
	"github.com/milliebillie/patchtacio/internal/feeds"
	"github.com/milliebillie/patchtacio/internal/feeds/kev"
)

// Coverage says how much of KEV the catalog can alert on.
type Coverage struct {
	Since     feeds.Date     `json:"since"` // entries added on or after this date are counted
	Total     int            `json:"total"`
	Mapped    int            `json:"mapped"` // entries that map to at least one product
	Percent   float64        `json:"percent"`
	ByProduct []ProductCount `json:"byProduct"` // most entries first
	Unmapped  []PairCount    `json:"unmapped"`  // most entries first
}

// ProductCount is how many counted entries map to a product.
type ProductCount struct {
	ID    string `json:"id"`
	Count int    `json:"count"`
}

// PairCount is a KEV vendorProject/product pair no product covers.
type PairCount struct {
	Vendor  string     `json:"vendor"`
	Product string     `json:"product"`
	Count   int        `json:"count"`
	Latest  feeds.Date `json:"latest"` // newest dateAdded among its entries
}

// Coverage counts the entries added on or after since that map to at least
// one catalog product, and lists the unmapped pairs.
func (m *Matcher) Coverage(vulns []kev.Vulnerability, since feeds.Date) Coverage {
	c := Coverage{Since: since, ByProduct: []ProductCount{}, Unmapped: []PairCount{}}
	perProduct := map[string]int{}
	unmapped := map[string]*PairCount{}
	for _, v := range vulns {
		if v.DateAdded.Before(since.Time) {
			continue
		}
		c.Total++
		hits := m.Products(v)
		if len(hits) > 0 {
			c.Mapped++
			for _, h := range hits {
				perProduct[h.ProductID]++
			}
			continue
		}
		k := catalog.Key(v.VendorProject, v.Product)
		pc := unmapped[k]
		if pc == nil {
			pc = &PairCount{Vendor: v.VendorProject, Product: v.Product}
			unmapped[k] = pc
		}
		pc.Count++
		if v.DateAdded.After(pc.Latest.Time) {
			pc.Latest = v.DateAdded
		}
	}
	if c.Total > 0 {
		c.Percent = float64(c.Mapped) * 100 / float64(c.Total)
	}
	for id, n := range perProduct {
		c.ByProduct = append(c.ByProduct, ProductCount{ID: id, Count: n})
	}
	slices.SortFunc(c.ByProduct, func(a, b ProductCount) int {
		return cmp.Or(cmp.Compare(b.Count, a.Count), strings.Compare(a.ID, b.ID))
	})
	for _, pc := range unmapped {
		c.Unmapped = append(c.Unmapped, *pc)
	}
	slices.SortFunc(c.Unmapped, func(a, b PairCount) int {
		return cmp.Or(cmp.Compare(b.Count, a.Count), b.Latest.Compare(a.Latest.Time),
			strings.Compare(catalog.Key(a.Vendor, a.Product), catalog.Key(b.Vendor, b.Product)))
	})
	return c
}
