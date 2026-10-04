package advice

import (
	"fmt"
	"strings"
	"time"
)

// Card is one finding as the web UI shows it, worded as the alerts are
// (the same template blocks). Every string is plain text and may contain web
// links; the UI escapes it and turns the links into anchors.
type Card struct {
	Headline string
	Affected []string // product, version and notes, one line each
	Caveat   string   // what Patchtacio did not check, "" if nothing
	Why      []string // why it matters, one paragraph each
	ToDo     string   // heading of the steps, e.g. "What to do by 12 Oct 2026"
	Steps    []string
	Deadline string // CISA's deadline explained, "" if none
	Links    []Link
}

// Link is a labelled web link.
type Link struct {
	Label, URL string
}

// matchCaveat is said on every KEV card: versions are not compared yet.
const matchCaveat = "Patchtacio matched this by product name and has not checked whether your version is affected."

// KEVCard returns the card for a known exploited vulnerability.
func KEVCard(it Item, today time.Time) (Card, error) {
	v := newItemView(it, today)
	why, err := block("why", v)
	if err != nil {
		return Card{}, err
	}
	update, err := block("update", v)
	if err != nil {
		return Card{}, err
	}
	mitigate, err := block("mitigate", v)
	if err != nil {
		return Card{}, err
	}
	deadline, err := block("deadline", v)
	if err != nil {
		return Card{}, err
	}
	c := Card{
		Headline: v.Headline,
		Affected: v.ProductLines,
		Caveat:   matchCaveat,
		Why:      []string{why},
		ToDo:     "What to do",
		Steps: []string{
			"Update: " + update,
			"If you cannot update yet, " + mitigate,
			"If neither is possible, disconnect it or restrict who can reach it until you can update.",
		},
		Deadline: deadline,
	}
	if v.Description != "" {
		c.Why = append(c.Why, v.Description)
	}
	if v.Due != "" && !v.DuePassed {
		c.ToDo += " by " + v.Due
	}
	if v.Advisory != "" {
		c.Links = append(c.Links, Link{"Vendor advisory", v.Advisory})
	}
	for _, l := range v.OtherLinks {
		c.Links = append(c.Links, Link{"More from CISA's entry", l})
	}
	c.Links = append(c.Links, Link{"CISA KEV entry", v.KEVURL}, Link{"NVD", v.NVDURL})
	return c, nil
}

// EOLCard returns the card for a release at or near end of life.
func EOLCard(it EOLItem, today time.Time) (Card, error) {
	v := newEOLView(it, today)
	why, err := block("eol-why", v)
	if err != nil {
		return Card{}, err
	}
	upgrade, err := block("eol-upgrade", v)
	if err != nil {
		return Card{}, err
	}
	c := Card{
		Headline: v.Headline,
		Affected: []string{v.ProductLine, "That is release " + v.Release + " on endoflife.date."},
		Why:      []string{why},
		ToDo:     "What to do",
		Steps: []string{
			upgrade,
			"Until you can upgrade, limit who can reach it (for example, no access from the internet) and keep an eye on its vendor's advisories.",
		},
	}
	if !v.Ended {
		c.ToDo += " before " + v.Date
	}
	if v.Page != "" {
		c.Links = append(c.Links, Link{"endoflife.date", v.Page})
	}
	if v.Policy != "" {
		c.Links = append(c.Links, Link{"Vendor lifecycle", v.Policy})
	}
	return c, nil
}

// block renders one shared template block as a single line of text.
func block(name string, data any) (string, error) {
	var b strings.Builder
	if err := templates.ExecuteTemplate(&b, name, data); err != nil {
		return "", fmt.Errorf("render %s: %w", name, err)
	}
	return strings.TrimSpace(b.String()), nil
}
