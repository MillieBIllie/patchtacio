// Package config reads and writes the user's configuration file: the
// products they run. It lives in the config directory (internal/paths) as
// config.yaml. Secrets never go in this file; they come from environment
// variables or the OS keychain (CLAUDE.md rule 5).
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/milliebillie/patchtacio/internal/catalog"
)

// FileName is the configuration file's name inside the config directory.
const FileName = "config.yaml"

// SchemaVersion is the configuration format this build reads and writes.
const SchemaVersion = 1

// maxSize bounds what Load reads; a real file is a few kilobytes.
const maxSize = 1 << 20

// Config is the configuration file.
type Config struct {
	Version  int       `yaml:"version"`
	Products []Product `yaml:"products"`
}

// Product is one product the user runs.
type Product struct {
	ID      string `yaml:"id"`                // catalog product ID
	Version string `yaml:"version,omitempty"` // optional; not compared yet
	Notes   string `yaml:"notes,omitempty"`   // optional, e.g. where it runs
}

// IDs returns the product IDs in file order.
func (c *Config) IDs() []string {
	out := make([]string, len(c.Products))
	for i, p := range c.Products {
		out[i] = p.ID
	}
	return out
}

// Load reads and strictly parses the configuration file. A missing file
// returns an error that matches fs.ErrNotExist.
func Load(path string) (*Config, error) {
	f, err := os.Open(filepath.Clean(path)) // the user's own config path
	if err != nil {
		return nil, fmt.Errorf("open configuration: %w", err)
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, maxSize+1))
	if err != nil {
		return nil, fmt.Errorf("read configuration: %w", err)
	}
	if len(raw) > maxSize {
		return nil, fmt.Errorf("configuration file %s is larger than %d bytes", path, maxSize)
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	var c Config
	if err := dec.Decode(&c); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("configuration file %s is empty", path)
		}
		return nil, fmt.Errorf("configuration file %s is not valid: %w", path, err)
	}
	// Products after a "---" would silently go unwatched.
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("configuration file %s has more than one YAML document (a line with ---); merge them into one", path)
	}
	if c.Version != SchemaVersion {
		return nil, fmt.Errorf("configuration file %s has version %d; this Patchtacio reads version %d", path, c.Version, SchemaVersion)
	}
	return &c, nil
}

// Validate checks the products against the catalog. Unknown or repeated IDs
// are errors: silently skipping one would hide a product the user expects to
// be watched. Deprecated IDs still match, with a warning.
func (c *Config) Validate(cat *catalog.Catalog) (warnings []string, err error) {
	var problems []string
	seen := map[string]bool{}
	for i, p := range c.Products {
		switch {
		case p.ID == "":
			problems = append(problems, fmt.Sprintf("products[%d] has no id", i))
			continue
		case seen[p.ID]:
			problems = append(problems, fmt.Sprintf("product %q is listed more than once", p.ID))
			continue
		}
		seen[p.ID] = true
		cp, ok := cat.Get(p.ID)
		if !ok {
			problems = append(problems, fmt.Sprintf("%q is not a product in the catalog (see `patchtacio catalog list`)", p.ID))
			continue
		}
		if cp.Deprecated != "" {
			warnings = append(warnings, fmt.Sprintf("%q has been replaced by %q, so Patchtacio checks that instead; "+
				"run `patchtacio init` to update your configuration", p.ID, cp.Deprecated))
		}
	}
	if len(problems) > 0 {
		return warnings, fmt.Errorf("configuration problems: %s", strings.Join(problems, "; "))
	}
	return warnings, nil
}

const header = "# Patchtacio configuration. Change it with `patchtacio init`, or edit it by hand.\n" +
	"# Product IDs come from `patchtacio catalog list`. version and notes are optional.\n" +
	"# Do not put passwords or tokens here: Patchtacio reads them from environment variables.\n"

// Save writes the configuration atomically (temp file, then rename) with
// owner-only permissions, creating the directory if needed.
func Save(path string, c *Config) error {
	c.Version = SchemaVersion
	var buf bytes.Buffer
	buf.WriteString(header)
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(c); err != nil {
		return fmt.Errorf("encode configuration: %w", err)
	}
	if err := enc.Close(); err != nil {
		return fmt.Errorf("encode configuration: %w", err)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, FileName+".tmp-*") // created 0600
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	cleanup := func() { _ = os.Remove(tmp.Name()) }
	if _, err := tmp.Write(buf.Bytes()); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("write configuration: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("write configuration: %w", err)
	}
	if err := tmp.Close(); err != nil { // Windows cannot rename an open file
		cleanup()
		return fmt.Errorf("write configuration: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		cleanup()
		return fmt.Errorf("save configuration: %w", err)
	}
	return nil
}

// Resolve returns the configuration with deprecated product IDs replaced by
// their successors (keeping version and notes) and duplicates dropped, so a
// renamed catalog entry keeps being checked. Call it after Validate.
func (c *Config) Resolve(cat *catalog.Catalog) *Config {
	out := &Config{Version: c.Version}
	seen := map[string]bool{}
	for _, p := range c.Products {
		if cp, ok := cat.Get(p.ID); ok && cp.Deprecated != "" {
			p.ID = cp.Deprecated
		}
		if seen[p.ID] {
			continue
		}
		seen[p.ID] = true
		out.Products = append(out.Products, p)
	}
	return out
}

// WithProducts returns a configuration holding ids in order, keeping the
// version and notes of products that were already configured.
func (c *Config) WithProducts(ids []string) *Config {
	out := &Config{Version: SchemaVersion}
	for _, id := range ids {
		i := slices.IndexFunc(c.Products, func(p Product) bool { return p.ID == id })
		if i >= 0 {
			out.Products = append(out.Products, c.Products[i])
		} else {
			out.Products = append(out.Products, Product{ID: id})
		}
	}
	return out
}
