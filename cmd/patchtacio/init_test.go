package main

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"charm.land/huh/v2"

	"github.com/milliebillie/patchtacio/internal/catalog"
	"github.com/milliebillie/patchtacio/internal/config"
)

func defaultConfigPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(os.Getenv("PATCHTACIO_CONFIG_DIR"), config.FileName)
}

func TestInitWithProductsFlag(t *testing.T) {
	e := newTestEnv(t)
	out, errOut, code := e.exec(t, "init", "--products", "fortinet-fortios, citrix-netscaler,fortinet-fortios")
	requireCode(t, code, exitOK, out, errOut)
	requireContains(t, out, "Saved 2 products to ", "  - Fortinet FortiOS (FortiGate firewalls)", "Next: run `patchtacio check`")

	c, err := config.Load(defaultConfigPath(t))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(c.IDs(), []string{"fortinet-fortios", "citrix-netscaler"}) {
		t.Errorf("saved %v", c.IDs())
	}
}

func TestInitRejectsUnknownProducts(t *testing.T) {
	e := newTestEnv(t)
	out, errOut, code := e.exec(t, "init", "--products", "fortinet-fortios,acme-nothing")
	requireCode(t, code, exitToolError, out, errOut)
	requireContains(t, errOut, "not in the catalog: acme-nothing", "patchtacio catalog list")
	if _, err := os.Stat(defaultConfigPath(t)); !os.IsNotExist(err) {
		t.Errorf("config written despite the error: %v", err)
	}
}

func TestInitNoTerminal(t *testing.T) {
	e := newTestEnv(t)
	out, errOut, code := e.exec(t, "init")
	requireCode(t, code, exitToolError, out, errOut)
	requireContains(t, errOut, "needs an interactive terminal", "--products")
}

func TestInitPickerKeepsVersionsAndPreselects(t *testing.T) {
	e := newTestEnv(t)
	path := filepath.Join(t.TempDir(), "custom.yaml")
	if err := config.Save(path, &config.Config{Products: []config.Product{
		{ID: "fortinet-fortios", Version: "7.2.8", Notes: "head office"}, {ID: "vmware-esxi"},
	}}); err != nil {
		t.Fatal(err)
	}
	e.app.isTerminal = func() bool { return true }
	var gotPre []string
	var gotProducts []catalog.Product
	e.app.pick = func(_ context.Context, ps []catalog.Product, pre []string) ([]string, error) {
		gotProducts, gotPre = ps, pre
		return []string{"fortinet-fortios", "microsoft-exchange-server"}, nil
	}
	out, errOut, code := e.exec(t, "init", "--config", path)
	requireCode(t, code, exitOK, out, errOut)
	if !slices.Equal(gotPre, []string{"fortinet-fortios", "vmware-esxi"}) {
		t.Errorf("preselected %v", gotPre)
	}
	if len(gotProducts) < 30 {
		t.Errorf("picker offered only %d products", len(gotProducts))
	}
	c, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []config.Product{{ID: "fortinet-fortios", Version: "7.2.8", Notes: "head office"}, {ID: "microsoft-exchange-server"}}
	if !slices.Equal(c.Products, want) {
		t.Errorf("saved %+v, want %+v", c.Products, want)
	}
}

func TestInitCancelledSavesNothing(t *testing.T) {
	e := newTestEnv(t)
	e.app.isTerminal = func() bool { return true }
	e.app.pick = func(context.Context, []catalog.Product, []string) ([]string, error) { return nil, huh.ErrUserAborted }
	out, errOut, code := e.exec(t, "init")
	requireCode(t, code, exitToolError, out, errOut)
	requireContains(t, errOut, "Cancelled; nothing was saved.")
	if _, err := os.Stat(defaultConfigPath(t)); !os.IsNotExist(err) {
		t.Errorf("config written after cancel: %v", err)
	}
}

func TestInitDoesNotOverwriteBrokenConfig(t *testing.T) {
	e := newTestEnv(t)
	path := filepath.Join(t.TempDir(), "config.yaml")
	broken := "version: 1\nproducts: [\n"
	if err := os.WriteFile(path, []byte(broken), 0o600); err != nil {
		t.Fatal(err)
	}
	out, errOut, code := e.exec(t, "init", "--config", path, "--products", "fortinet-fortios")
	requireCode(t, code, exitToolError, out, errOut)
	requireContains(t, errOut, "is not valid", "Fix the file or move it away")
	if raw, _ := os.ReadFile(path); string(raw) != broken {
		t.Error("broken config was overwritten")
	}
}

func TestCatalogList(t *testing.T) {
	e := newTestEnv(t)
	out, errOut, code := e.exec(t, "catalog", "list")
	requireCode(t, code, exitOK, out, errOut)
	requireContains(t, out, "ID ", "fortinet-fortios", "Fortinet FortiOS (FortiGate firewalls)", "firewall-vpn")
	if n := strings.Count(out, "\n"); n < 31 {
		t.Errorf("only %d lines", n)
	}
}

// The real huh picker, in its plain accessible mode so the test can type.
func TestHuhPickerAccessible(t *testing.T) {
	cat, err := catalog.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	ps := pickerProducts(cat)
	idx := slices.IndexFunc(ps, func(p catalog.Product) bool { return p.ID == "fortinet-fortios" })
	if idx < 0 {
		t.Fatal("fortinet-fortios not offered")
	}
	// Toggle FortiOS (options are numbered from 1), then confirm with 0.
	in := strings.NewReader(strconv.Itoa(idx+1) + "\n0\n")
	var out strings.Builder
	got, err := huhPicker(in, &out, true)(context.Background(), ps, []string{"vmware-esxi"})
	if err != nil {
		t.Fatalf("%v\noutput:\n%s", err, out.String())
	}
	if !slices.Equal(got, []string{"fortinet-fortios", "vmware-esxi"}) {
		t.Errorf("picked %v", got)
	}
	requireContains(t, out.String(), "Which products do you run?", "FortiGate")
}
