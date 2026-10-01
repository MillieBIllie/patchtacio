package feeds

import (
	"encoding/json"
	"fmt"
	"time"
)

// DateLayout is the calendar-date format both KEV and endoflife.date use.
const DateLayout = "2006-01-02"

// Date is a calendar date with no time of day, stored as UTC midnight.
// The zero Date means "not stated by the source" and marshals as null.
type Date struct{ time.Time }

// ParseDate parses a YYYY-MM-DD date strictly.
func ParseDate(s string) (Date, error) {
	t, err := time.ParseInLocation(DateLayout, s, time.UTC)
	if err != nil {
		return Date{}, fmt.Errorf("invalid date %q (want YYYY-MM-DD): %w", s, err)
	}
	return Date{t}, nil
}

// ParseOptionalDate parses a nullable YYYY-MM-DD date; nil or "" is the zero Date.
func ParseOptionalDate(s *string) (Date, error) {
	if s == nil || *s == "" {
		return Date{}, nil
	}
	return ParseDate(*s)
}

// String returns YYYY-MM-DD, or "" for the zero Date.
func (d Date) String() string {
	if d.IsZero() {
		return ""
	}
	return d.Format(DateLayout)
}

// MarshalJSON writes "YYYY-MM-DD" or null.
func (d Date) MarshalJSON() ([]byte, error) {
	if d.IsZero() {
		return []byte("null"), nil
	}
	return json.Marshal(d.String())
}
