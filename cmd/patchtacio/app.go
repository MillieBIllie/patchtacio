package main

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/milliebillie/patchtacio/internal/feeds"
	"github.com/milliebillie/patchtacio/internal/feeds/eol"
	"github.com/milliebillie/patchtacio/internal/feeds/kev"
	"github.com/milliebillie/patchtacio/internal/httpcache"
	"github.com/milliebillie/patchtacio/internal/logging"
	"github.com/milliebillie/patchtacio/internal/paths"
	"github.com/milliebillie/patchtacio/internal/store"
	"github.com/milliebillie/patchtacio/internal/version"
)

// dbFile is the database file name inside the data directory.
const dbFile = "patchtacio.db"

// app holds what commands depend on, so tests can substitute fakes.
type app struct {
	now       func() time.Time
	loc       *time.Location // for dates shown to the user
	sources   func() []feeds.Source
	newClient func(*slog.Logger) *httpcache.Client

	// Set from global flags before a command runs.
	verbosity int
	quiet     bool
	log       *slog.Logger
}

func defaultApp() *app {
	return &app{
		now: time.Now,
		loc: time.Local,
		sources: func() []feeds.Source {
			return []feeds.Source{kev.New(), eol.New()}
		},
		newClient: func(l *slog.Logger) *httpcache.Client { return httpcache.New(version.UserAgent(), l) },
		log:       slog.New(slog.DiscardHandler),
	}
}

// openUpdater resolves the directories, opens the database and returns an
// Updater over the configured sources. Call the returned func to close it.
func (a *app) openUpdater(ctx context.Context) (*feeds.Updater, func(), error) {
	dirs, err := paths.Resolve()
	if err != nil {
		return nil, nil, fmt.Errorf("find data directories: %w", err)
	}
	if err := dirs.Ensure(); err != nil {
		return nil, nil, fmt.Errorf("create data directories: %w", err)
	}
	a.log.Debug("using directories", "cache", dirs.Cache, "data", dirs.Data)
	st, err := store.Open(ctx, filepath.Join(dirs.Data, dbFile))
	if err != nil {
		return nil, nil, err
	}
	u := &feeds.Updater{
		Store:    st,
		Client:   a.newClient(a.log),
		CacheDir: dirs.Cache,
		Sources:  a.sources(),
		Logger:   a.log,
		Now:      a.now,
	}
	closeFn := func() {
		if err := st.Close(); err != nil {
			a.log.Warn("closing database", "err", err)
		}
	}
	return u, closeFn, nil
}

func (a *app) setupLogging(stderr interface{ Write([]byte) (int, error) }) {
	a.log = logging.New(stderr, logging.Level(a.verbosity, a.quiet))
}
