package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/milliebillie/patchtacio/internal/testutil"
)

func TestCheckFindings(t *testing.T) {
	e := newTestEnv(t)
	e.exec(t, "init", "--products", "citrix-netscaler,vmware-vcenter,vmware-esxi")

	out, errOut, code := e.exec(t, "check")
	requireCode(t, code, exitFindings, out, errOut)
	if errOut != "" {
		t.Errorf("fresh data: no warnings expected:\n%s", errOut)
	}
	requireContains(t, out,
		"Checked 3 products against the CISA KEV catalog (19 entries, catalog 2026.09.30, published 30 Sep 2026).",
		"3 KEV entries match your products. Attackers are already using these vulnerabilities.",
		"did not compare versions",
		"VMware ESXi", "no matching KEV entries",
		"Citrix NetScaler ADC and NetScaler Gateway (formerly Citrix ADC)  2 KEV entries, newest added 27 Sep 2026",
		"CVE-2026-88772",
		"30 Sep 2026 (passed)", // clock is 1 Oct 2026
		"known use",            // vCenter entry has knownRansomwareCampaignUse: Known
		"patchtacio check --json")
	// Newest first: NetScaler (27 Sep) before vCenter (18 Aug).
	if strings.Index(out, "CVE-2026-88772") > strings.Index(out, "CVE-2026-59310") {
		t.Errorf("findings not newest first:\n%s", out)
	}
	for _, banned := range []string{"safe", "all clear", "not affected", "!"} {
		if strings.Contains(strings.ToLower(out), banned) {
			t.Errorf("output must not say %q:\n%s", banned, out)
		}
	}
	// check uses KEV only in M2: endoflife.date is not fetched.
	if n := e.eol.requests.Load(); n != 0 {
		t.Errorf("check made %d endoflife.date requests", n)
	}
}

func TestCheckJSON(t *testing.T) {
	e := newTestEnv(t)
	e.exec(t, "init", "--products", "citrix-netscaler,vmware-vcenter,checkpoint-security-gateway,vmware-esxi")
	out, errOut, code := e.exec(t, "check", "--json")
	requireCode(t, code, exitFindings, out, errOut)
	var rep map[string]any
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, out)
	}
	delete(rep["feed"].(map[string]any), "url") // the test server's port changes every run
	testutil.Golden(t, filepath.Join("..", "..", "testdata", "check", "findings.golden.json"), rep)
}

func TestCheckSince(t *testing.T) {
	e := newTestEnv(t)
	e.exec(t, "init", "--products", "citrix-netscaler,vmware-vcenter")
	out, errOut, code := e.exec(t, "check", "--since", "2026-09-01")
	requireCode(t, code, exitFindings, out, errOut)
	requireContains(t, out, "2 KEV entries added since 1 Sep 2026 match your products.")
	if strings.Contains(out, "CVE-2026-59310") {
		t.Errorf("entry added 18 Aug shown with --since 2026-09-01:\n%s", out)
	}
	_, errOut, code = e.exec(t, "check", "--since", "1 Sep")
	requireCode(t, code, exitToolError, "", errOut)
	requireContains(t, errOut, "want YYYY-MM-DD")
}

func TestCheckNoFindingsIsNotAnAllClear(t *testing.T) {
	e := newTestEnv(t)
	e.exec(t, "init", "--products", "vmware-esxi")
	out, errOut, code := e.exec(t, "check")
	requireCode(t, code, exitOK, out, errOut)
	requireContains(t, out, "None of your products matched a KEV entry.", "This is not an all clear")

	// Two days later, CISA is down: still no findings, but the data is out of
	// date, so the exit code is 3, never 0.
	e.setDown(http.StatusServiceUnavailable)
	e.clock = e.clock.Add(49 * time.Hour)
	out, errOut, code = e.exec(t, "check")
	requireCode(t, code, exitStale, out, errOut)
	requireContains(t, errOut, "CISA KEV catalog data is out of date")
	requireContains(t, out, "The KEV data is out of date")
}

func TestCheckFindingsWithStaleDataExitOne(t *testing.T) {
	e := newTestEnv(t)
	e.exec(t, "init", "--products", "citrix-netscaler")
	e.exec(t, "check")
	e.setDown(http.StatusServiceUnavailable)
	e.clock = e.clock.Add(72 * time.Hour)
	out, errOut, code := e.exec(t, "check")
	requireCode(t, code, exitFindings, out, errOut)
	requireContains(t, errOut, "could not be updated", "out of date")
	requireContains(t, out, "CVE-2026-88772")
}

func TestCheckOffline(t *testing.T) {
	e := newTestEnv(t)
	e.exec(t, "init", "--products", "citrix-netscaler")
	out, errOut, code := e.exec(t, "check", "--offline")
	requireCode(t, code, exitToolError, out, errOut)
	requireContains(t, errOut, "there is no saved copy of CISA KEV catalog", "Cannot check your products")
	if e.kev.requests.Load() != 0 {
		t.Error("--offline used the network")
	}

	e.exec(t, "feeds", "update")
	before := e.kev.requests.Load()
	out, errOut, code = e.exec(t, "check", "--offline")
	requireCode(t, code, exitFindings, out, errOut)
	if e.kev.requests.Load() != before {
		t.Error("--offline used the network")
	}
}

func TestCheckNoKEVAtAll(t *testing.T) {
	e := newTestEnv(t)
	e.exec(t, "init", "--products", "citrix-netscaler")
	e.setDown(http.StatusServiceUnavailable)
	out, errOut, code := e.exec(t, "check")
	requireCode(t, code, exitToolError, out, errOut)
	requireContains(t, errOut, "could not be downloaded and there is no saved copy", "Cannot check your products")
	if strings.Contains(out, "None of your products") {
		t.Errorf("no data must never read as no findings:\n%s", out)
	}
}

func TestCheckConfigProblems(t *testing.T) {
	e := newTestEnv(t)
	out, errOut, code := e.exec(t, "check")
	requireCode(t, code, exitToolError, out, errOut)
	requireContains(t, errOut, "no products chosen yet", "run `patchtacio init` first")

	bad := filepath.Join(t.TempDir(), "bad.yaml")
	writeFile(t, bad, "version: 1\nproducts:\n  - id: acme-nothing\n")
	out, errOut, code = e.exec(t, "check", "--config", bad)
	requireCode(t, code, exitToolError, out, errOut)
	requireContains(t, errOut, `"acme-nothing" is not a product in the catalog`)
	if e.kev.requests.Load() != 0 {
		t.Error("a bad config should fail before any download")
	}

	out, errOut, code = e.exec(t, "check", "--config", filepath.Join("..", "..", "testdata", "config", "example.yaml"))
	requireCode(t, code, exitFindings, out, errOut)
	requireContains(t, out, "Checked 4 products")
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
