package feeds

import (
	"context"
	"fmt"
	"time"
)

// State is how usable a source's cached data is.
type State string

// States, from best to worst.
const (
	Fresh   State = "fresh"   // valid cached copy, contacted within StaleAfter
	Stale   State = "stale"   // valid cached copy, but not contacted within StaleAfter
	Missing State = "missing" // no valid cached copy at all
)

// Status describes one source's cached copy.
type Status struct {
	Name        string        `json:"name"`
	Title       string        `json:"title"`
	State       State         `json:"state"`
	StaleAfter  time.Duration `json:"-"`
	Via         string        `json:"via,omitempty"`
	URL         string        `json:"url,omitempty"`
	Count       int           `json:"records"`
	Version     string        `json:"version,omitempty"`
	PublishedAt time.Time     `json:"publishedAt,omitzero"`
	FetchedAt   time.Time     `json:"fetchedAt,omitzero"`
	CheckedAt   time.Time     `json:"checkedAt,omitzero"`
	AttemptedAt time.Time     `json:"attemptedAt,omitzero"`
	LastError   string        `json:"lastError,omitempty"`
	// StaleReason says, in plain words, why State is Stale.
	StaleReason string `json:"staleReason,omitempty"`
	// LastUpdateFailed is set when the most recent attempt did not refresh the
	// copy, even if it is still within its freshness limit.
	LastUpdateFailed bool `json:"lastUpdateFailed"`
}

// MirrorMaxAge is how old (by its own publish date) a copy served by a mirror
// may be before it counts as stale. A mirror answering only proves the
// mirror is up, not that it is still in sync with the source.
const MirrorMaxAge = 7 * 24 * time.Hour

// clockSkew is how far in the future a recorded check may be before we stop
// trusting it (the clock was set ahead and later corrected).
const clockSkew = 5 * time.Minute

// Statuses reports the cached state of every source, without network use.
func (u *Updater) Statuses(ctx context.Context) ([]Status, error) {
	if err := checkSources(u.Sources); err != nil {
		return nil, err
	}
	out := make([]Status, 0, len(u.Sources))
	for _, src := range u.Sources {
		meta, _, err := u.Store.GetFeed(ctx, src.Name())
		if err != nil {
			return nil, fmt.Errorf("read %s metadata: %w", src.Name(), err)
		}
		meta.Name = src.Name()
		out = append(out, u.status(src, meta))
	}
	return out, nil
}

func (u *Updater) status(src Source, meta Feed) Status {
	st := Status{
		Name:        src.Name(),
		Title:       src.Title(),
		StaleAfter:  src.StaleAfter(),
		Via:         meta.Via,
		URL:         meta.URL,
		Count:       meta.RecordCount,
		Version:     meta.Version,
		PublishedAt: meta.PublishedAt,
		FetchedAt:   meta.FetchedAt,
		CheckedAt:   meta.CheckedAt,
		AttemptedAt: meta.AttemptedAt,
		LastError:   meta.LastError,

		LastUpdateFailed: meta.LastError != "", // every successful contact clears it
	}
	now := u.now()
	st.State = Stale
	switch {
	case !u.cacheValid(src, meta):
		st.State = Missing
		st.Count, st.Version, st.PublishedAt = 0, "", time.Time{}
	case meta.Rejected:
		st.StaleReason = "the newest download was rejected, so the saved copy is older than what the source now publishes"
	case meta.CheckedAt.IsZero():
		st.StaleReason = "it has never been checked"
	case meta.CheckedAt.After(now.Add(clockSkew)):
		st.StaleReason = "its last check time is in the future, so the computer's clock may have been wrong"
	case now.Sub(meta.CheckedAt) > src.StaleAfter():
		st.StaleReason = "it has not been checked for more than " + humanDuration(src.StaleAfter())
	case meta.Via == ViaMirror && !meta.PublishedAt.IsZero() && now.Sub(meta.PublishedAt) > MirrorMaxAge:
		st.StaleReason = "it came from a mirror and was published more than " + humanDuration(MirrorMaxAge) +
			" ago, so it may no longer match the source"
	default:
		st.State = Fresh
	}
	return st
}

func humanDuration(d time.Duration) string {
	if d%(24*time.Hour) == 0 && d >= 48*time.Hour {
		return fmt.Sprintf("%d days", d/(24*time.Hour))
	}
	return fmt.Sprintf("%d hours", d/time.Hour)
}
