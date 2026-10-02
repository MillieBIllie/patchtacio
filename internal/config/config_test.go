package config

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/milliebillie/patchtacio/internal/catalog"
)

func TestSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", FileName)
	in := &Config{Products: []Product{{ID: "fortinet-fortios", Version: "7.2.8", Notes: "edge firewall"}, {ID: "vmware-esxi"}}}
	if err := Save(path, in); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(raw), "# Patchtacio configuration.") {
		t.Errorf("missing header:\n%s", raw)
	}
	out, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if out.Version != SchemaVersion || len(out.Products) != 2 || out.Products[0] != in.Products[0] || out.Products[1].ID != "vmware-esxi" {
		t.Errorf("round trip changed the config: %+v", out)
	}
	if runtime.GOOS != "windows" {
		st, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0o600 {
			t.Errorf("config mode %v, want 0600", st.Mode().Perm())
		}
	}
	// Saving again replaces the file and leaves no temp files.
	if err := Save(path, in.WithProducts([]string{"vmware-esxi"})); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Errorf("want only %s in the directory, got %v", FileName, entries)
	}
}

func TestLoadErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := Load(filepath.Join(dir, "missing.yaml")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing file: got %v, want fs.ErrNotExist", err)
	}
	tests := []struct{ name, body, want string }{
		{"empty", "", "is empty"},
		{"unknown key", "version: 1\nproducts: []\nsmtp_password: hunter2\n", "field smtp_password not found"},
		{"wrong version", "version: 2\nproducts: []\n", "has version 2"},
		{"no version", "products: []\n", "has version 0"},
		{"bad yaml", "version: [", "not valid"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(dir, tt.name+".yaml")
			if err := os.WriteFile(path, []byte(tt.body), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := Load(path)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("got %v, want an error containing %q", err, tt.want)
			}
			if err != nil && strings.Contains(err.Error(), "hunter2") {
				t.Errorf("error repeats a value from the file: %v", err)
			}
		})
	}
}

func TestLoadTooLarge(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	if err := os.WriteFile(path, []byte("version: 1\n#"+strings.Repeat("x", maxSize)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("got %v", err)
	}
}

func TestValidate(t *testing.T) {
	product := func(id, extra string) string {
		return "id: " + id + "\ndisplay: X\nvendor: X\ncategory: other\nkev_aliases: [{vendor: X, product: " + id + "}]\nverified: 2026-10-02\n" + extra
	}
	cat, err := catalog.Load(fstest.MapFS{
		"acme-new.yaml": {Data: []byte(product("acme-new", ""))},
		"acme-old.yaml": {Data: []byte(product("acme-old", "deprecated: acme-new\n"))},
	})
	if err != nil {
		t.Fatal(err)
	}
	c := &Config{Version: 1, Products: []Product{{ID: "acme-old"}, {ID: "acme-new"}}}
	warns, err := c.Validate(cat)
	if err != nil {
		t.Fatal(err)
	}
	if len(warns) != 1 || !strings.Contains(warns[0], `replaced by "acme-new"`) {
		t.Errorf("warnings = %v", warns)
	}
	c = &Config{Version: 1, Products: []Product{{ID: "acme-new"}, {ID: "nope-nope"}, {ID: "acme-new"}, {}}}
	_, err = c.Validate(cat)
	for _, want := range []string{`"nope-nope" is not a product`, `"acme-new" is listed more than once`, "products[3] has no id"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("got %v, want it to mention %q", err, want)
		}
	}
}

func TestWithProductsKeepsDetails(t *testing.T) {
	c := &Config{Products: []Product{{ID: "a-b", Version: "1.0", Notes: "n"}, {ID: "c-d"}}}
	got := c.WithProducts([]string{"e-f", "a-b"})
	if len(got.Products) != 2 || got.Products[0] != (Product{ID: "e-f"}) || got.Products[1] != c.Products[0] {
		t.Errorf("got %+v", got.Products)
	}
}
