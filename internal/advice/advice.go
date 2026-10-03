// Package advice turns findings into plain-language alert text: an email, a
// chat message (Slack, Teams, Discord), and a short message (at most 160
// characters, for push and desktop notifications). The wording follows the
// alert-writing skill: what is affected, why it matters, what to do and by
// when, links, and how to acknowledge.
//
// Every fact comes from the feed. KEV never states a fixed version, so the
// text sends the reader to the vendor advisory for it and quotes CISA's
// required action; nothing is guessed, and nothing is ever called safe to
// ignore.
package advice

import (
	"bytes"
	"embed"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"text/template"
	"time"
	"unicode/utf8"

	"github.com/milliebillie/patchtacio/internal/logging"
)

// Alert kinds: a finding the user has not been told about, and the two
// reminders for one nobody has acknowledged.
const (
	KindNew     = "new"
	KindDueSoon = "due-soon"
	KindOverdue = "overdue"
)

// Product is an affected product as the user listed it.
type Product struct {
	Display string // catalog display name
	Version string // the user's version, if they gave one (not compared)
	Notes   string // the user's notes, e.g. where it runs
}

// Item is one vulnerability to alert about, with every product of the
// user's it affects (KEV does not say Windows desktop or server, so one CVE
// can hit two).
type Item struct {
	Kind           string
	CVE            string
	Name           string // KEV vulnerabilityName
	Description    string // KEV shortDescription
	RequiredAction string // KEV requiredAction, quoted as CISA's words
	Products       []Product
	DateAdded      time.Time // zero = not stated
	DueDate        time.Time // zero = not stated
	Ransomware     bool      // CISA says "Known"
	Links          []string  // KEV notes: usually the vendor advisory first
}

// Message is everything one channel sends in one run.
type Message struct {
	Items []Item
	Today time.Time // the reader's calendar date, for "passed" and "in N days"
}

// Limits on how many items each format lists in full.
const (
	maxEmailItems = 25
	maxChatItems  = 10
	// ShortLimit is the most characters a short message may have.
	ShortLimit = 160
)

//go:embed templates/*.tmpl
var templateFS embed.FS

var templates = template.Must(template.New("").Funcs(template.FuncMap{
	"inc":  func(i int) int { return i + 1 },
	"join": strings.Join,
}).ParseFS(templateFS, "templates/*.tmpl"))

// Email returns the subject and plain-text body of an alert email.
func Email(m Message) (subject, body string, err error) {
	v := newView(m, maxEmailItems)
	body, err = render("email.tmpl", v)
	return v.Headline, body, err
}

// Chat is a chat message: a title and a plain-text body. Webhook formatting
// (Slack, Teams, Discord) is the notifier's job, as is escaping.
type Chat struct {
	Title string
	Body  string
}

// ChatMessage returns the chat version of m.
func ChatMessage(m Message) (Chat, error) {
	v := newView(m, maxChatItems)
	body, err := render("chat.tmpl", v)
	return Chat{Title: v.Headline, Body: body}, err
}

// Short returns a message of at most ShortLimit characters.
func Short(m Message) string {
	v := newView(m, 0)
	var s string
	if len(v.all) == 1 {
		it := v.all[0]
		s = fmt.Sprintf("Patchtacio: %s exploited flaw %s. %s. Details: patchtacio check", "%s", it.CVE, it.shortDeadline())
		return fitName(s, it.ShortProducts)
	}
	s = fmt.Sprintf("Patchtacio: %d exploited flaws in your products (%s). %s. Details: patchtacio check",
		len(v.all), "%s", v.shortDeadline())
	return fitName(s, v.shortProducts())
}

// Test messages say plainly that they are tests.
const (
	TestSubject = "[Test] Patchtacio alerts work on this channel"
	TestBody    = "This is a test alert from Patchtacio. If you can read it, alerts on this channel work.\n" +
		"No vulnerability has been found; nothing needs doing.\n"
	TestShort = "Patchtacio test alert: this channel works. No action needed."
)

func render(name string, v view) (string, error) {
	var b bytes.Buffer
	if err := templates.ExecuteTemplate(&b, name, v); err != nil {
		return "", fmt.Errorf("render %s: %w", name, err)
	}
	return b.String(), nil
}

// view is a Message with every string the templates need worked out.
type view struct {
	Headline     string
	Count        int
	New          []itemView
	Reminders    []itemView
	Single       *itemView // the item, when there is exactly one
	More         int       // items not listed in full
	Products     string    // every affected product, for the footer
	ProductCount int
	FirstCVE     string // an example for "patchtacio ack"
	all          []itemView
}

type itemView struct {
	Kind, CVE, Name, Description, RequiredAction string
	Headline                                     string
	ProductLines                                 []string
	ShortProducts                                string
	Added                                        string // "" = not stated
	Due                                          string // "" = not stated
	DuePassed                                    bool
	DaysLeft                                     int
	Ransomware                                   bool
	Advisory                                     string // vendor advisory link, "" = none given
	OtherLinks                                   []string
	KEVURL, NVDURL                               string
	due                                          time.Time
}

func newView(m Message, limit int) view {
	today := day(m.Today)
	items := make([]itemView, 0, len(m.Items))
	for _, it := range m.Items {
		items = append(items, newItemView(it, today))
	}
	// Most urgent first: deadlines still ahead, soonest first; then passed
	// deadlines, most recent first; entries without one last.
	slices.SortStableFunc(items, func(a, b itemView) int {
		ra, rb := rank(a), rank(b)
		if ra != rb {
			return ra - rb
		}
		if ra == 0 {
			return a.due.Compare(b.due)
		}
		if c := b.due.Compare(a.due); c != 0 {
			return c
		}
		return strings.Compare(a.CVE, b.CVE)
	})

	v := view{Count: len(items), all: items}
	listed := items
	if limit > 0 && len(listed) > limit {
		v.More = len(listed) - limit
		listed = listed[:limit]
	}
	for _, it := range listed {
		if it.Kind == KindNew {
			v.New = append(v.New, it)
		} else {
			v.Reminders = append(v.Reminders, it)
		}
	}
	var names []string
	for _, it := range m.Items {
		for _, p := range it.Products {
			if n := clean(p.Display); !slices.Contains(names, n) {
				names = append(names, n)
			}
		}
	}
	v.Products = joinAnd(names)
	v.ProductCount = len(names)
	if len(items) > 0 {
		v.FirstCVE = items[0].CVE
	}
	if len(items) == 1 {
		v.Single = &items[0]
	}

	if len(items) == 1 {
		v.Headline = items[0].Headline
	} else {
		v.Headline = fmt.Sprintf("[%s] %d actively exploited flaws in your products", v.tag(), len(items))
	}
	return v
}

func rank(it itemView) int {
	switch {
	case it.due.IsZero():
		return 2
	case it.DuePassed:
		return 1
	default:
		return 0
	}
}

func newItemView(it Item, today time.Time) itemView {
	v := itemView{
		Kind:           it.Kind,
		CVE:            clean(it.CVE),
		Name:           oneLine(it.Name),
		Description:    oneLine(it.Description),
		RequiredAction: oneLine(it.RequiredAction),
		Ransomware:     it.Ransomware,
		NVDURL:         "https://nvd.nist.gov/vuln/detail/" + url.PathEscape(clean(it.CVE)),
		KEVURL:         "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=" + url.QueryEscape(clean(it.CVE)),
		due:            day(it.DueDate),
	}
	if !it.DateAdded.IsZero() {
		v.Added = date(it.DateAdded)
	}
	if !it.DueDate.IsZero() {
		v.Due = date(it.DueDate)
		v.DuePassed = v.due.Before(today)
		v.DaysLeft = int(v.due.Sub(today).Hours() / 24)
	}
	// KEV notes are usually bare links, vendor advisory first, but some are
	// sentences with a link inside ("For more information, please see:
	// https://..."), so every link is taken from the text. The NVD link most
	// end with is already in the links section.
	for _, note := range it.Links {
		for _, l := range urlPattern.FindAllString(clean(note), -1) {
			l = strings.TrimRight(l, ".,;:)]'\"")
			switch {
			case !isWebLink(l) || strings.HasPrefix(l, "https://nvd.nist.gov/"):
			case v.Advisory == "":
				v.Advisory = l
			case l != v.Advisory && !slices.Contains(v.OtherLinks, l):
				v.OtherLinks = append(v.OtherLinks, l)
			}
		}
	}
	var short []string
	for _, p := range it.Products {
		line := clean(p.Display)
		if p.Version != "" {
			line += ", version " + oneLine(p.Version)
		}
		if p.Notes != "" {
			line += " (your note: " + oneLine(p.Notes) + ")"
		}
		v.ProductLines = append(v.ProductLines, line)
		short = append(short, shortName(clean(p.Display)))
	}
	v.ShortProducts = strings.Join(short, " and ")
	v.Headline = fmt.Sprintf("[%s] %s: actively exploited flaw (%s)", v.tag(), v.ShortProducts, v.CVE)
	return v
}

func (it itemView) tag() string {
	switch {
	case it.Due == "":
		return "Action needed"
	case it.DuePassed && it.Kind == KindOverdue:
		return "Reminder: deadline passed " + it.Due
	case it.DuePassed:
		return "Action needed now"
	case it.Kind == KindDueSoon:
		return "Reminder: action needed by " + it.Due
	default:
		return "Action needed by " + it.Due
	}
}

// tag of a multi-item message: the earliest deadline still ahead, or "now"
// if every deadline has passed.
func (v view) tag() string {
	for _, it := range v.all {
		if it.Due != "" && !it.DuePassed {
			return "Action needed by " + it.Due
		}
	}
	for _, it := range v.all {
		if it.DuePassed {
			return "Action needed now"
		}
	}
	return "Action needed"
}

func (it itemView) shortDeadline() string {
	switch {
	case it.Due == "":
		return "Patch or mitigate now"
	case it.DuePassed:
		return "Deadline passed " + it.Due + ", act now"
	default:
		return "Patch or mitigate by " + it.Due
	}
}

func (v view) shortDeadline() string {
	t := v.tag()
	if d, ok := strings.CutPrefix(t, "Action needed by "); ok {
		return "Earliest deadline " + d
	}
	if t == "Action needed now" {
		return "Deadlines passed, act now"
	}
	return "Act now"
}

func (v view) shortProducts() string {
	var names []string
	for _, it := range v.all {
		for _, n := range strings.Split(it.ShortProducts, " and ") {
			if !slices.Contains(names, n) {
				names = append(names, n)
			}
		}
	}
	if len(names) > 2 {
		return fmt.Sprintf("%s, %s +%d", names[0], names[1], len(names)-2)
	}
	return strings.Join(names, ", ")
}

// joinAnd lists names as "A", "A and B" or "A, B and C".
func joinAnd(names []string) string {
	if len(names) < 2 {
		return strings.Join(names, "")
	}
	return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
}

// fitName puts name into format's %s, shortening name so the result fits
// ShortLimit. The rest of the message (CVE, deadline) is never cut.
func fitName(format, name string) string {
	room := ShortLimit - utf8.RuneCountInString(format) + 2 // the %s itself
	if utf8.RuneCountInString(name) > room {
		r := []rune(name)
		name = string(r[:max(room-1, 0)]) + "…"
	}
	return fmt.Sprintf(format, name)
}

// shortName drops a display name's parenthetical: "Fortinet FortiOS (FortiGate
// firewalls)" becomes "Fortinet FortiOS".
func shortName(display string) string {
	if i := strings.Index(display, " ("); i > 0 {
		return display[:i]
	}
	return display
}

// urlPattern finds http(s) links in KEV note text.
var urlPattern = regexp.MustCompile(`https?://[^\s<>"]+`)

func isWebLink(s string) bool {
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" && !strings.ContainsAny(s, " \t")
}

// clean drops control and bidi characters from feed or user text.
func clean(s string) string { return logging.Clean(s) }

// oneLine cleans s and folds all whitespace runs, newlines included, into one
// space, so feed text cannot fake extra lines or headers in a message.
func oneLine(s string) string {
	return strings.Join(strings.Fields(clean(strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		return r
	}, s))), " ")
}

func day(t time.Time) time.Time {
	if t.IsZero() {
		return t
	}
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
}

func date(t time.Time) string { return t.Format("2 Jan 2006") }
