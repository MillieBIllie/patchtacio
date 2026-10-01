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
}

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
	}
	switch {
	case !u.cacheValid(src, meta):
		st.State = Missing
		st.Count, st.Version, st.PublishedAt = 0, "", time.Time{}
	case meta.CheckedAt.IsZero() || u.now().Sub(meta.CheckedAt) > src.StaleAfter():
		st.State = Stale
	default:
		st.State = Fresh
	}
	return st
}
