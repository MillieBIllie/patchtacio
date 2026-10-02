// SPDX-License-Identifier: Apache-2.0
// (This file is code; the YAML files in products/ are CC0, see LICENSE.)

// Package catalog embeds Patchtacio's product catalog, products/*.yaml, so the
// binary works without the source tree. internal/catalog parses and checks it.
package catalog

import (
	"embed"
	"io/fs"
)

//go:embed products/*.yaml
var files embed.FS

// Products returns the embedded product files, one YAML file per product at
// the root of the returned FS.
func Products() fs.FS {
	sub, err := fs.Sub(files, "products")
	if err != nil {
		// fs.Sub only fails on an invalid path, and "products" is a constant.
		return files
	}
	return sub
}
