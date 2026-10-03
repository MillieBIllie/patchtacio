package main

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/milliebillie/patchtacio/internal/config"
	"github.com/milliebillie/patchtacio/internal/feeds"
	"github.com/milliebillie/patchtacio/internal/feeds/eol"
	"github.com/milliebillie/patchtacio/internal/feeds/kev"
	"github.com/milliebillie/patchtacio/internal/httpcache"
	"github.com/milliebillie/patchtacio/internal/logging"
	"github.com/milliebillie/patchtacio/internal/notify"
	"github.com/milliebillie/patchtacio/internal/paths"
	"github.com/milliebillie/patchtacio/internal/schedule"
	"github.com/milliebillie/patchtacio/internal/secrets"
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
	// channels builds the configured alert channels; fakes in tests.
	channels func(*config.Notify) ([]notify.Channel, error)
	// secrets finds alert secrets: environment first, then the OS keychain.
	// Built on first use (it needs the config directory); tests set it.
	secrets *secrets.Store

	// The product picker and whether it can run; fakes in tests.
	pick       pickFunc
	isTerminal func() bool

	// The scheduled check: the OS scheduler, this program and how to find
	// it on PATH, and the random install minute; fakes in tests.
	scheduler  func(logDir, tempDir string) (schedule.Scheduler, error)
	executable func() (string, error)
	lookPath   func(string) (string, error)
	randIntN   func(int) int

	// Set from global flags before a command runs.
	verbosity  int
	quiet      bool
	configFile string // --config; "" means config.yaml in the config directory
	log        *slog.Logger
}

func defaultApp() *app {
	a := &app{
		now: time.Now,
		loc: time.Local,
		sources: func() []feeds.Source {
			return []feeds.Source{kev.New(), eol.New()}
		},
		newClient:  func(l *slog.Logger) *httpcache.Client { return httpcache.New(version.UserAgent(), l) },
		pick:       huhPicker(os.Stdin, os.Stdout, os.Getenv("ACCESSIBLE") != ""),
		isTerminal: stdinIsTerminal,
		scheduler:  realScheduler,
		executable: os.Executable,
		lookPath:   exec.LookPath,
		randIntN:   rand.IntN, // spreads install times; not security relevant
		log:        slog.New(slog.DiscardHandler),
	}
	a.channels = func(n *config.Notify) ([]notify.Channel, error) { return realChannels(n, a.secretStore().Getenv) }
	return a
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

// secretStore returns the secrets store, building it on first use.
func (a *app) secretStore() *secrets.Store {
	if a.secrets == nil {
		if dirs, err := paths.Resolve(); err == nil {
			a.secrets = secrets.New(dirs.Config)
		} else {
			a.secrets = &secrets.Store{Env: os.Getenv} // no config directory: environment only
		}
	}
	return a.secrets
}

func (a *app) setupLogging(stderr interface{ Write([]byte) (int, error) }) {
	a.log = logging.New(stderr, logging.Level(a.verbosity, a.quiet))
}

// realScheduler is this computer's scheduler, for the current user.
func realScheduler(logDir, tempDir string) (schedule.Scheduler, error) {
	o, err := schedule.DefaultOptions(logDir, tempDir)
	if err != nil {
		return nil, err
	}
	return schedule.New(o), nil
}
