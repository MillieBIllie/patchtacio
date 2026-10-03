package advice

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/milliebillie/patchtacio/internal/testutil"
)

var today = time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)

func d(s string) time.Time {
	t, err := time.Parse(time.DateOnly, s)
	if err != nil {
		panic(err)
	}
	return t
}

// fortios is a full KEV entry, with the user's version and notes.
func fortios() Item {
	return Item{
		Kind:           KindNew,
		CVE:            "CVE-2026-24858",
		Name:           "Fortinet Multiple Products Authentication Bypass Using an Alternate Path or Channel Vulnerability",
		Description:    "Fortinet FortiOS, FortiManager and FortiAnalyzer contain an authentication bypass that may allow an attacker with a FortiCloud account to log into other devices.",
		RequiredAction: "Apply mitigations per vendor instructions, follow applicable BOD 22-01 guidance for cloud services, or discontinue use of the product if mitigations are unavailable.",
		Products:       []Product{{Display: "Fortinet FortiOS (FortiGate firewalls)", Version: "7.4.2", Notes: "edge firewall, main office"}},
		DateAdded:      d("2026-09-28"),
		DueDate:        d("2026-10-12"),
		Links:          []string{"https://fortiguard.fortinet.com/psirt/FG-IR-26-060", "https://nvd.nist.gov/vuln/detail/CVE-2026-24858"},
	}
}

func cases() map[string]Message {
	full := fortios()

	noAdvisory := fortios()
	noAdvisory.Links = nil
	noAdvisory.RequiredAction = ""
	noAdvisory.Products[0].Version = ""
	noAdvisory.Products[0].Notes = ""

	pastDue := fortios()
	pastDue.DateAdded, pastDue.DueDate = d("2024-02-09"), d("2024-02-16")

	ransomware := fortios()
	ransomware.Ransomware = true

	long := fortios()
	long.Products = []Product{
		{Display: "Microsoft Windows (desktop: Windows 10, 11, and every older release still running somewhere in the building)"},
		{Display: "Microsoft Windows Server (including the domain controller under the stairs that nobody dares to reboot)"},
	}
	long.CVE = "CVE-2026-81963"
	long.Name = "Microsoft Windows Common Log File System (CLFS) Driver Heap-Based Buffer Overflow Vulnerability"

	noDue := fortios()
	noDue.DueDate = time.Time{}

	dueSoon := fortios()
	dueSoon.Kind = KindDueSoon
	dueSoon.DueDate = d("2026-10-05")

	overdue := fortios()
	overdue.Kind = KindOverdue
	overdue.DueDate = d("2026-10-01")

	// Feed text must not be able to fake lines, headers or terminal codes.
	hostile := fortios()
	hostile.Name = "Bad\nSubject: injected\r\n\x1b[31mred\x1b[0m \u202eevil"
	hostile.Links = []string{"javascript:alert(1)", "https://example.com/a b", "https://vendor.example/advisory"}

	exchange := Item{
		Kind: KindNew, CVE: "CVE-2023-21529",
		Name:           "Microsoft Exchange Server Deserialization of Untrusted Data Vulnerability",
		RequiredAction: "Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.",
		Products:       []Product{{Display: "Microsoft Exchange Server (on-premises)"}},
		DateAdded:      d("2026-04-13"), DueDate: d("2026-04-27"), Ransomware: true,
		Links: []string{"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-21529"},
	}
	ivanti := Item{
		Kind: KindOverdue, CVE: "CVE-2025-22457",
		Name:      "Ivanti Connect Secure, Policy Secure, and ZTA Gateways Stack-Based Buffer Overflow Vulnerability",
		Products:  []Product{{Display: "Ivanti Connect Secure (formerly Pulse Connect Secure VPN)"}},
		DateAdded: d("2025-04-04"), DueDate: d("2025-04-11"),
	}
	var many []Item
	for i := range 30 {
		it := fortios()
		it.CVE = fmt.Sprintf("CVE-2026-%05d", 10000+i)
		it.DueDate = d("2026-10-12").AddDate(0, 0, i-15) // half passed, half ahead
		many = append(many, it)
	}

	fos72 := EOLItem{
		Kind: KindNew, Product: Product{Display: "Fortinet FortiOS (FortiGate firewalls)", Version: "7.2.8", Notes: "head office firewall"},
		Release: "7.2", EOLDate: d("2026-11-30"), Successor: "8.0", SuccessorAt: "8.0.1",
		Page: "https://endoflife.date/fortios", Policy: "https://www.fortinet.com/support/product-life-cycle",
		AckID: "eol/fortinet-fortios/7.2",
	}
	ended := EOLItem{
		Kind: KindNew, Product: Product{Display: "Microsoft Windows Server", Version: "2016"},
		Release: "2016", EOLDate: d("2027-01-12"), Page: "https://endoflife.date/windows-server",
		AckID: "eol/microsoft-windows-server/2016",
	}
	ended.EOLDate = d("2026-09-30")
	ended.ExtendedUntil = d("2029-09-30")
	eolSoon := fos72
	eolSoon.Kind = KindDueSoon
	eolSoon.EOLDate = d("2026-10-20")
	noDate := ended
	noDate.EOLDate = time.Time{}
	noDate.Ended = true
	noDate.ExtendedUntil = time.Time{}
	longEOL := fos72
	longEOL.Product.Display = "Atlassian Confluence (Server and Data Center, the wiki the whole school has run on since before anyone can remember)"
	longEOL.Release = "7.19"

	return map[string]Message{
		"eol_upcoming":      {EOL: []EOLItem{fos72}},
		"eol_ended":         {EOL: []EOLItem{ended}},
		"eol_due_soon":      {EOL: []EOLItem{eolSoon}},
		"eol_ended_no_date": {EOL: []EOLItem{noDate}},
		"eol_long_name":     {EOL: []EOLItem{longEOL}},
		"eol_summary":       {EOL: []EOLItem{fos72, ended}},
		"mixed_summary":     {Items: []Item{full}, EOL: []EOLItem{ended}},
		"full":              {Items: []Item{full}},
		"no_advisory":       {Items: []Item{noAdvisory}},
		"past_due":          {Items: []Item{pastDue}},
		"ransomware":        {Items: []Item{ransomware}},
		"long_names":        {Items: []Item{long}},
		"no_due_date":       {Items: []Item{noDue}},
		"due_soon":          {Items: []Item{dueSoon}},
		"overdue":           {Items: []Item{overdue}},
		"hostile":           {Items: []Item{hostile}},
		"summary":           {Items: []Item{exchange, full, ivanti}},
		"summary_cap":       {Items: many},
	}
}

func TestGolden(t *testing.T) {
	for name, m := range cases() {
		t.Run(name, func(t *testing.T) {
			m.Today = today
			subject, body, err := Email(m)
			if err != nil {
				t.Fatal(err)
			}
			chat, err := ChatMessage(m)
			if err != nil {
				t.Fatal(err)
			}
			short := Short(m)
			got := "=== email subject\n" + subject + "\n=== email body\n" + body +
				"=== chat title\n" + chat.Title + "\n=== chat body\n" + chat.Body + "\n=== short\n" + short + "\n"
			testutil.GoldenText(t, filepath.Join("testdata", name+".golden"), got)

			if n := utf8.RuneCountInString(short); n > ShortLimit {
				t.Errorf("short message is %d characters, limit %d: %q", n, ShortLimit, short)
			}
			for _, bad := range []string{"\x1b", "\r", string(rune(0x202e)), "javascript:", "safe to ignore", "low risk", "not affected", "!"} {
				if strings.Contains(got, bad) {
					t.Errorf("output contains %q", bad)
				}
			}
			if strings.Contains(subject, "\n") || strings.Contains(chat.Title, "\n") {
				t.Error("a subject or title spans lines")
			}
		})
	}
}

// Rule 6: no fixed version is ever stated; the reader is sent to the advisory.
func TestNeverInventsFixedVersion(t *testing.T) {
	for name, m := range cases() {
		m.Today = today
		_, body, _ := Email(m)
		if strings.Contains(strings.ToLower(body), "update to ") {
			t.Errorf("%s: names an update target, which KEV never gives", name)
		}
	}
}

// Some KEV notes are sentences with a link inside (Citrix, 2026); the link
// inside is the advisory, and later ones are kept as further reading.
func TestLinksInsideNoteText(t *testing.T) {
	it := fortios()
	it.Links = []string{
		"Customers must conduct forensic triage. For more information, please see: https://community.citrix.com/bulletin-cve-2026-88772.",
		"https://support.citrix.com/article?articleNumber=CTX697096",
		"BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04",
		"https://nvd.nist.gov/vuln/detail/CVE-2026-88772",
	}
	v := newItemView(it, today)
	if v.Advisory != "https://community.citrix.com/bulletin-cve-2026-88772" {
		t.Errorf("advisory = %q", v.Advisory)
	}
	want := []string{"https://support.citrix.com/article?articleNumber=CTX697096", "https://www.cisa.gov/news-events/directives/bod-26-04"}
	if strings.Join(v.OtherLinks, " ") != strings.Join(want, " ") {
		t.Errorf("other links = %q", v.OtherLinks)
	}
}
