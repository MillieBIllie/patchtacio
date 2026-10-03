package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/milliebillie/patchtacio/internal/advice"
	"github.com/milliebillie/patchtacio/internal/config"
	"github.com/milliebillie/patchtacio/internal/notify"
	"github.com/milliebillie/patchtacio/internal/paths"
	"github.com/milliebillie/patchtacio/internal/store"
)

// fakeChannels records what each configured channel was asked to send.
type fakeChannels struct {
	mu      sync.Mutex
	sent    map[string][]advice.Message
	tests   []string
	notices []string
	failing map[string]bool
}

type fakeChan struct {
	name string
	f    *fakeChannels
}

func (c fakeChan) Name() string          { return c.name }
func (c fakeChan) Destination() []string { return nil }
func (c fakeChan) Send(_ context.Context, m advice.Message) error {
	c.f.mu.Lock()
	defer c.f.mu.Unlock()
	if c.f.failing[c.name] {
		return errors.New("connection refused")
	}
	c.f.sent[c.name] = append(c.f.sent[c.name], m)
	return nil
}
func (c fakeChan) SendNotice(_ context.Context, n advice.Notice) error {
	c.f.mu.Lock()
	defer c.f.mu.Unlock()
	if c.f.failing[c.name] {
		return errors.New("connection refused")
	}
	if n.Test {
		c.f.tests = append(c.f.tests, c.name)
	} else {
		c.f.notices = append(c.f.notices, c.name+": "+n.Subject)
	}
	return nil
}

func (f *fakeChannels) messages(name string) []advice.Message {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sent[name]
}

// useFakeChannels makes every configured channel a recorder.
func (e *testEnv) useFakeChannels() *fakeChannels {
	f := &fakeChannels{sent: map[string][]advice.Message{}, failing: map[string]bool{}}
	e.app.channels = func(n *config.Notify) ([]notify.Channel, error) {
		var out []notify.Channel
		for _, name := range n.Channels() {
			out = append(out, fakeChan{name: name, f: f})
		}
		return out, nil
	}
	return f
}

// addNotify appends a notify: section to the configuration init wrote.
func addNotify(t *testing.T, section string) {
	t.Helper()
	path := filepath.Join(os.Getenv(paths.EnvConfigDir), config.FileName)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteString(section); err != nil {
		t.Fatal(err)
	}
}

// publishKEVEntry adds an entry to the fake KEV feed, as CISA would.
func (e *testEnv) publishKEVEntry(t *testing.T, cve, vendor, product, added, due string) {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(e.kev.body, &doc); err != nil {
		t.Fatal(err)
	}
	vulns := doc["vulnerabilities"].([]any)
	entry := map[string]any{
		"cveID": cve, "vendorProject": vendor, "product": product,
		"vulnerabilityName": vendor + " " + product + " Authentication Bypass Vulnerability",
		"dateAdded":         added, "dueDate": due,
		"shortDescription":           vendor + " " + product + " contains an authentication bypass vulnerability.",
		"requiredAction":             "Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.",
		"knownRansomwareCampaignUse": "Unknown",
		"notes":                      "https://vendor.example/advisory/" + cve + " ; https://nvd.nist.gov/vuln/detail/" + cve,
		"cwes":                       []string{"CWE-288"},
	}
	doc["vulnerabilities"] = append([]any{entry}, vulns...)
	doc["count"] = len(vulns) + 1
	doc["catalogVersion"] = strings.ReplaceAll(added, "-", ".")
	doc["dateReleased"] = added + "T16:00:00.000Z"
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	e.kev.body = b
	e.kev.etagOverride.Store(true) // the content changed
}

func cvesIn(m advice.Message) []string {
	var out []string
	for _, it := range m.Items {
		out = append(out, it.Kind+":"+it.CVE)
	}
	return out
}

// The milestone's "done when": a new KEV entry for a ticked product produces
// exactly one clear alert.
func TestNotifyNewKEVEntryAlertsOnce(t *testing.T) {
	e := newTestEnv(t)
	chans := e.useFakeChannels()
	e.exec(t, "init", "--products", "citrix-netscaler,vmware-vcenter,vmware-esxi")
	addNotify(t, "notify:\n  webhook:\n    kind: slack\n")

	// First run: what is already on CISA's list arrives as one summary.
	out, errOut, code := e.exec(t, "check", "--notify")
	requireCode(t, code, exitFindings, out, errOut)
	requireContains(t, out, "Alerts by webhook: sent one alert about 3 vulnerabilities.")
	if msgs := chans.messages("webhook"); len(msgs) != 1 || len(msgs[0].Items) != 3 {
		t.Fatalf("first run: %d messages", len(msgs))
	}

	// Nothing new: nothing sent.
	e.clock = e.clock.Add(6 * time.Hour)
	out, errOut, code = e.exec(t, "check", "--notify")
	requireCode(t, code, exitFindings, out, errOut)
	requireContains(t, out, "Alerts by webhook: nothing new to send.")
	if n := len(chans.messages("webhook")); n != 1 {
		t.Fatalf("a run with nothing new sent a message (%d total)", n)
	}

	// CISA adds a NetScaler entry: exactly one alert, about it alone.
	e.clock = time.Date(2026, 10, 2, 18, 0, 0, 0, time.UTC)
	e.publishKEVEntry(t, "CVE-2026-99001", "Citrix", "NetScaler", "2026-10-02", "2026-10-16")
	out, errOut, code = e.exec(t, "check", "--notify")
	requireCode(t, code, exitFindings, out, errOut)
	msgs := chans.messages("webhook")
	if len(msgs) != 2 || strings.Join(cvesIn(msgs[1]), ",") != "new:CVE-2026-99001" {
		t.Fatalf("new entry: %d messages, last %v\n%s", len(msgs), cvesIn(msgs[len(msgs)-1]), out)
	}
	it := msgs[1].Items[0]
	if len(it.Products) != 1 || !strings.HasPrefix(it.Products[0].Display, "Citrix NetScaler") {
		t.Errorf("alert names %+v", it.Products)
	}
	chat, err := advice.ChatMessage(msgs[1])
	if err != nil {
		t.Fatal(err)
	}
	if chat.Title != "[Action needed by 16 Oct 2026] Citrix NetScaler ADC and NetScaler Gateway: actively exploited flaw (CVE-2026-99001)" {
		t.Errorf("headline: %q", chat.Title)
	}

	// And it is not repeated.
	e.clock = e.clock.Add(time.Hour)
	e.exec(t, "check", "--notify")
	if n := len(chans.messages("webhook")); n != 2 {
		t.Errorf("the new entry was alerted again (%d messages)", n)
	}
}

func TestAckStopsReminders(t *testing.T) {
	e := newTestEnv(t)
	chans := e.useFakeChannels()
	e.exec(t, "init", "--products", "citrix-netscaler")
	addNotify(t, "notify:\n  desktop: true\n")
	e.clock = time.Date(2026, 10, 2, 18, 0, 0, 0, time.UTC)
	e.publishKEVEntry(t, "CVE-2026-99001", "Citrix", "NetScaler", "2026-10-02", "2026-10-16")
	e.exec(t, "check", "--notify") // first summary

	out, errOut, code := e.exec(t, "ack", "cve-2026-99001", "--note", "patched to 14.1-47.48")
	requireCode(t, code, exitOK, out, errOut)
	requireContains(t, out, "Acknowledged CVE-2026-99001 for Citrix NetScaler", "will not alert or remind you")

	// Within 3 days of the deadline: no reminder for the acknowledged one.
	e.clock = time.Date(2026, 10, 14, 9, 0, 0, 0, time.UTC)
	out, _, _ = e.exec(t, "check", "--notify")
	if n := len(chans.messages("desktop")); n != 1 {
		t.Errorf("acknowledged finding was reminded (%d messages)", n)
	}
	requireContains(t, out, "CVE-2026-99001", "yes") // still listed, marked

	jsonOut, _, _ := e.exec(t, "check", "--json", "--offline")
	if !strings.Contains(jsonOut, `"acknowledged": true`) || !strings.Contains(jsonOut, `"id": "kev/citrix-netscaler/CVE-2026-99001"`) {
		t.Errorf("JSON lacks the acknowledgement:\n%.1500s", jsonOut)
	}

	// Undo: the reminder comes back.
	out, errOut, code = e.exec(t, "ack", "kev/citrix-netscaler/CVE-2026-99001", "--undo")
	requireCode(t, code, exitOK, out, errOut)
	e.exec(t, "check", "--notify")
	msgs := chans.messages("desktop")
	if len(msgs) != 2 || strings.Join(cvesIn(msgs[1]), ",") != "due-soon:CVE-2026-99001" {
		t.Errorf("after --undo: %d messages", len(msgs))
	}
}

func TestAckErrors(t *testing.T) {
	e := newTestEnv(t)
	e.exec(t, "init", "--products", "citrix-netscaler")
	_, errOut, code := e.exec(t, "ack", "CVE-2026-88772")
	if code != exitToolError || !strings.Contains(errOut, "run `patchtacio check` first") {
		t.Errorf("ack before check: code %d, %s", code, errOut)
	}
	e.exec(t, "check")
	if _, errOut, code := e.exec(t, "ack", "CVE-2026-88772", "--product", "vmware-esxi"); code != exitToolError || !strings.Contains(errOut, "no finding") {
		t.Errorf("wrong product: code %d, %s", code, errOut)
	}
	if _, errOut, code := e.exec(t, "ack", "CVE-2026-88772", "--product", "nonsense"); code != exitToolError || !strings.Contains(errOut, "not a product") {
		t.Errorf("unknown product: code %d, %s", code, errOut)
	}
	if out, errOut, code := e.exec(t, "ack", "CVE-2026-88772"); code != exitOK {
		t.Errorf("ack after check: code %d\n%s\n%s", code, out, errOut)
	}
}

// A channel that fails makes check exit 2, so a scheduled run is noticed, and
// it is retried next run.
func TestNotifyFailureExitsTwoAndRetries(t *testing.T) {
	e := newTestEnv(t)
	chans := e.useFakeChannels()
	e.exec(t, "init", "--products", "citrix-netscaler")
	addNotify(t, "notify:\n  webhook:\n    kind: teams\n  desktop: true\n")
	chans.failing["webhook"] = true
	out, errOut, code := e.exec(t, "check", "--notify")
	requireCode(t, code, exitToolError, out, errOut)
	requireContains(t, out, "Alerts by webhook: failed: connection refused", "Alerts by desktop: sent one alert")
	requireContains(t, errOut, "will be retried on the next run")

	chans.failing["webhook"] = false
	out, errOut, code = e.exec(t, "check", "--notify")
	requireCode(t, code, exitFindings, out, errOut)
	if len(chans.messages("webhook")) != 1 || len(chans.messages("desktop")) != 1 {
		t.Errorf("retry: webhook %d, desktop %d messages (want 1 each)", len(chans.messages("webhook")), len(chans.messages("desktop")))
	}
}

func TestNotifyWithoutChannels(t *testing.T) {
	e := newTestEnv(t)
	e.exec(t, "init", "--products", "citrix-netscaler")
	_, errOut, code := e.exec(t, "check", "--notify")
	if code != exitToolError || !strings.Contains(errOut, "no alert channels are configured") {
		t.Errorf("code %d, %s", code, errOut)
	}
	if n := e.kev.requests.Load(); n != 0 {
		t.Errorf("fetched KEV %d times before failing", n)
	}
}

func TestTestAlert(t *testing.T) {
	e := newTestEnv(t)
	chans := e.useFakeChannels()
	e.exec(t, "init", "--products", "citrix-netscaler")
	addNotify(t, "notify:\n  email:\n    host: smtp.example.org\n    from: alerts@example.org\n    to: [it@example.org]\n  ntfy: {}\n")

	out, errOut, code := e.exec(t, "test-alert")
	requireCode(t, code, exitOK, out, errOut)
	requireContains(t, out, "email: sent. Check the inbox of it@example.org", "ntfy: sent.")
	if strings.Join(chans.tests, ",") != "email,ntfy" {
		t.Errorf("tested %v", chans.tests)
	}

	chans.failing["ntfy"] = true
	out, errOut, code = e.exec(t, "test-alert", "--channel", "ntfy")
	requireCode(t, code, exitToolError, out, errOut)
	requireContains(t, out, "ntfy: failed: connection refused")

	if _, errOut, code := e.exec(t, "test-alert", "--channel", "desktop"); code != exitToolError || !strings.Contains(errOut, "not configured") {
		t.Errorf("unconfigured channel: code %d, %s", code, errOut)
	}
}

// A feed that cannot be updated is reported on the alert channels, at most
// once a day, so silence is never mistaken for an all clear; alerts from the
// saved copy still go out.
func TestNotifyStaleFeedSendsNotice(t *testing.T) {
	e := newTestEnv(t)
	chans := e.useFakeChannels()
	e.exec(t, "init", "--products", "citrix-netscaler")
	addNotify(t, "notify:\n  webhook:\n    kind: discord\n")
	e.exec(t, "check", "--notify") // fresh: summary, no notice
	if len(chans.notices) != 0 {
		t.Fatalf("notice while fresh: %v", chans.notices)
	}

	e.setDown(503)
	e.clock = e.clock.Add(72 * time.Hour) // KEV is stale after 48 h
	out, errOut, code := e.exec(t, "check", "--notify")
	requireCode(t, code, exitFindings, out, errOut)
	requireContains(t, out, "Notice by webhook: sent a notice that the KEV data could not be updated.")
	if len(chans.notices) != 1 || !strings.Contains(chans.notices[0], "[Check needed] Patchtacio could not update the CISA KEV catalog since 1 Oct 2026") {
		t.Fatalf("notices: %v", chans.notices)
	}

	e.clock = e.clock.Add(3 * time.Hour)
	out, _, _ = e.exec(t, "check", "--notify")
	requireContains(t, out, "already sent today")
	if len(chans.notices) != 1 {
		t.Errorf("notice repeated within the day: %v", chans.notices)
	}
	e.clock = e.clock.Add(24 * time.Hour)
	e.exec(t, "check", "--notify")
	if len(chans.notices) != 2 {
		t.Errorf("no notice the next day: %v", chans.notices)
	}
}

func TestNotifyNoDataSendsNotice(t *testing.T) {
	e := newTestEnv(t)
	chans := e.useFakeChannels()
	e.exec(t, "init", "--products", "citrix-netscaler")
	addNotify(t, "notify:\n  desktop: true\n")
	e.setDown(503)
	out, errOut, code := e.exec(t, "check", "--notify")
	requireCode(t, code, exitToolError, out, errOut)
	if len(chans.notices) != 1 || !strings.Contains(chans.notices[0], "could not update") {
		t.Errorf("notices: %v\n%s\n%s", chans.notices, out, errOut)
	}
}

// --since narrows what check shows, never what it alerts.
func TestNotifyIgnoresSince(t *testing.T) {
	e := newTestEnv(t)
	chans := e.useFakeChannels()
	e.exec(t, "init", "--products", "citrix-netscaler,vmware-vcenter")
	addNotify(t, "notify:\n  webhook:\n    kind: slack\n")
	out, errOut, code := e.exec(t, "check", "--notify", "--since", "2026-09-01")
	requireCode(t, code, exitFindings, out, errOut)
	if msgs := chans.messages("webhook"); len(msgs) != 1 || len(msgs[0].Items) != 3 {
		t.Errorf("--since limited the alert: %+v", msgs)
	}
}

// While a run sends, its heartbeat keeps the lock past the TTL.
func TestNotifyLockHeartbeat(t *testing.T) {
	e := newTestEnv(t)
	e.exec(t, "init", "--products", "citrix-netscaler")
	e.exec(t, "check") // creates the database
	st, err := store.Open(context.Background(), filepath.Join(os.Getenv(paths.EnvDataDir), dbFile))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	oldTTL, oldWait := notifyLockTTL, notifyLockWait
	notifyLockTTL, notifyLockWait = 400*time.Millisecond, 0
	defer func() { notifyLockTTL, notifyLockWait = oldTTL, oldWait }()

	release, err := e.app.notifyLock(context.Background(), st)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(3 * notifyLockTTL) // well past the TTL, but heartbeats ran
	if ok, err := st.AcquireLock(context.Background(), notifyLockName, "intruder", notifyLockTTL); err != nil || ok {
		t.Errorf("lock taken while its holder was still sending: %v %v", ok, err)
	}
	release()
	if ok, err := st.AcquireLock(context.Background(), notifyLockName, "next", notifyLockTTL); err != nil || !ok {
		t.Errorf("lock not free after release: %v %v", ok, err)
	}
}

// Two overlapping runs never both send: the second waits, then gives up and
// says so.
func TestNotifyLockHeld(t *testing.T) {
	e := newTestEnv(t)
	chans := e.useFakeChannels()
	e.exec(t, "init", "--products", "citrix-netscaler")
	addNotify(t, "notify:\n  webhook:\n    kind: slack\n")
	e.exec(t, "check") // creates the database

	st, err := store.Open(context.Background(), filepath.Join(os.Getenv(paths.EnvDataDir), dbFile))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	if ok, err := st.AcquireLock(context.Background(), notifyLockName, "other-run", time.Hour); !ok || err != nil {
		t.Fatalf("take lock: %v %v", ok, err)
	}
	old := notifyLockWait
	notifyLockWait = 0
	defer func() { notifyLockWait = old }()

	out, errOut, code := e.exec(t, "check", "--notify")
	requireCode(t, code, exitToolError, out, errOut)
	requireContains(t, errOut, "no alerts were sent", "another `patchtacio check --notify` is sending alerts")
	if len(chans.messages("webhook")) != 0 {
		t.Error("sent while another run held the lock")
	}
}
