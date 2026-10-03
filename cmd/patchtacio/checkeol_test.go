package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/milliebillie/patchtacio/internal/config"
	"github.com/milliebillie/patchtacio/internal/paths"
)

// writeConfig replaces the configuration file.
func writeConfig(t *testing.T, yaml string) {
	t.Helper()
	dir := os.Getenv(paths.EnvConfigDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, config.FileName), []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
}

const eolConfig = `version: 1
products:
  - id: fortinet-fortios
    version: "7.2.8"
    notes: "head office firewall"
  - id: atlassian-confluence
    version: "9.1.1"
  - id: microsoft-windows-server
    version: "2012 R2"
  - id: vmware-esxi
    version: "8.0"
  - id: citrix-netscaler
`

func TestCheckEndOfLife(t *testing.T) {
	e := newTestEnv(t) // clock: 1 Oct 2026
	writeConfig(t, eolConfig)
	out, errOut, code := e.exec(t, "check")
	requireCode(t, code, exitFindings, out, errOut)
	requireContains(t, out,
		"End of life (security support dates from endoflife.date):",
		"Fortinet FortiOS 7.2.8", "release 7.2", "security updates stopped on 30 Sep 2026; newest supported release: 8.0",
		"Atlassian Confluence 9.1.1", "security updates stop on 3 Oct 2026 (in 2 days)",
		"Microsoft Windows Server 2012 R2", "release 2012-r2",
		"VMware ESXi 8.0", "no saved endoflife.date data",
		"patchtacio ack eol/<product>/<release>")
	if strings.Contains(out, "NetScaler ADC and NetScaler Gateway (formerly Citrix ADC) 14") {
		t.Error("a product endoflife.date does not track is listed under end of life")
	}
	if e.eol.requests.Load() == 0 {
		t.Error("endoflife.date was not fetched although products have versions")
	}

	jsonOut, _, _ := e.exec(t, "check", "--json", "--offline")
	var rep struct {
		EndOfLife []struct {
			ID        string `json:"id"`
			ProductID string `json:"productId"`
			State     string `json:"state"`
			EOLDate   string `json:"eolDate"`
		} `json:"endOfLife"`
	}
	if err := json.Unmarshal([]byte(jsonOut), &rep); err != nil {
		t.Fatal(err)
	}
	ids := map[string]string{}
	for _, x := range rep.EndOfLife {
		ids[x.ProductID] = x.ID + " " + x.State
	}
	if ids["fortinet-fortios"] != "eol/fortinet-fortios/7.2 ended" || ids["atlassian-confluence"] != "eol/atlassian-confluence/9.1 ending" {
		t.Errorf("end-of-life entries: %v", ids)
	}
	if rep.EndOfLife[0].EOLDate != "2026-09-30" {
		t.Errorf("eolDate = %q, want 2026-09-30", rep.EndOfLife[0].EOLDate)
	}
}

func TestCheckEndOfLifeNoMatch(t *testing.T) {
	e := newTestEnv(t)
	writeConfig(t, "version: 1\nproducts:\n  - id: fortinet-fortios\n    version: \"7.20\"\n")
	out, _, _ := e.exec(t, "check")
	requireContains(t, out, "Fortinet FortiOS 7.20", "version matches no release on endoflife.date; use one of: 8.0, 7.6, 7.4, 7.2")
}

// End-of-life alerts: once, quiet after ack, and a notice if the data
// cannot be updated.
func TestNotifyEndOfLife(t *testing.T) {
	e := newTestEnv(t)
	chans := e.useFakeChannels()
	writeConfig(t, "version: 1\nproducts:\n  - id: fortinet-fortios\n    version: \"7.2.8\"\nnotify:\n  webhook:\n    kind: teams\n")

	out, errOut, code := e.exec(t, "check", "--notify")
	requireCode(t, code, exitFindings, out, errOut)
	requireContains(t, out, "Alerts by webhook: sent one alert about")
	msgs := chans.messages("webhook")
	if len(msgs) != 1 || len(msgs[0].EOL) != 1 || msgs[0].EOL[0].Release != "7.2" || !msgs[0].EOL[0].Ended || msgs[0].EOL[0].Successor != "8.0" {
		t.Fatalf("first run: %+v", msgs)
	}

	e.clock = e.clock.Add(24 * time.Hour)
	e.exec(t, "check", "--notify")
	if n := len(chans.messages("webhook")); n != 1 {
		t.Fatalf("end-of-life alert repeated (%d messages)", n)
	}

	out, errOut, code = e.exec(t, "ack", "eol/fortinet-fortios/7.2", "--note", "upgrading in November")
	requireCode(t, code, exitOK, out, errOut)
	out, _, _ = e.exec(t, "check", "--offline")
	requireContains(t, out, "ACK yes")

	// endoflife.date down for over a week: its own notice.
	e.eol.failWith.Store(503)
	e.clock = e.clock.Add(9 * 24 * time.Hour)
	e.exec(t, "check", "--notify")
	found := false
	for _, n := range chans.notices {
		if strings.Contains(n, "could not update the endoflife.date data") {
			found = true
		}
	}
	if !found {
		t.Errorf("no endoflife.date notice: %v", chans.notices)
	}
}

// Without any version there is nothing to look up: endoflife.date is not
// fetched, and check says how to turn the check on.
func TestCheckEndOfLifeNeedsVersions(t *testing.T) {
	e := newTestEnv(t)
	e.exec(t, "init", "--products", "fortinet-fortios,citrix-netscaler")
	out, _, _ := e.exec(t, "check")
	requireContains(t, out, "no version in your configuration", "add version: to those products")
	if n := e.eol.requests.Load(); n != 0 {
		t.Errorf("fetched endoflife.date %d times with no versions", n)
	}
}
