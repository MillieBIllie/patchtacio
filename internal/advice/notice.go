package advice

import (
	"fmt"
	"strings"
	"time"
)

// Notice is a message that is not about a finding: a test, or a warning that
// alerts may be missing. Short is at most ShortLimit characters.
type Notice struct {
	Subject string
	Body    string
	Short   string
	Test    bool // a test: sent quietly (low priority where a channel has one)
}

// TestNotice says it is a test and checks nothing.
func TestNotice() Notice {
	return Notice{Subject: TestSubject, Body: TestBody, Short: TestShort, Test: true}
}

// FeedNotice warns that a feed could not be updated, so alerts may be
// missing. It is never worded as an all clear. lastGood is the last time the
// feed was reached (zero if never); problem is why it failed, in one line.
func FeedNotice(feedTitle string, lastGood time.Time, problem string) Notice {
	feedTitle = oneLine(feedTitle)
	if feedTitle == "" {
		feedTitle = "CISA KEV catalog"
	}
	problem = oneLine(problem)
	when := "Patchtacio has no saved copy of it at all"
	since := ""
	if !lastGood.IsZero() {
		when = "the copy Patchtacio has was last updated on " + date(lastGood)
		since = " since " + date(lastGood)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Patchtacio could not get the latest %s; %s.\n", feedTitle, when)
	b.WriteString("Until it can, alerts about newly exploited flaws in your products may be missing. This is not an all clear.\n\n")
	b.WriteString("What to do:\n")
	b.WriteString("  1. Check that the computer running Patchtacio can reach www.cisa.gov (and github.com, the backup source).\n")
	b.WriteString("  2. Then run: patchtacio feeds update\n")
	if problem != "" {
		fmt.Fprintf(&b, "\nWhat went wrong: %s\n", problem)
	}
	b.WriteString("\nPatchtacio sends this at most once a day while the problem lasts.\n")
	return Notice{
		Subject: "[Check needed] Patchtacio could not update the " + feedTitle + since,
		Body:    b.String(),
		Short:   fitName("Patchtacio could not update %s"+since+". Alerts may be missing. Run patchtacio feeds update", feedTitle),
	}
}
