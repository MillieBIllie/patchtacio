// Package ui is Patchtacio's local web UI: product picker, alert setup with a
// test button, findings with acknowledgements, and the daily check
// (docs/decisions/0005-m5-web-ui.md).
//
// The server listens on 127.0.0.1 only and answers only requests for its own
// host and port (no DNS rebinding). Every page needs the session cookie that
// the one-time launch link sets, so other users of the same computer cannot
// use it, and every POST needs the session's CSRF token. Secrets are written
// to the OS keychain and never sent back to the page.
//
// The work itself (configuration, checks, alerts, scheduling) is done by a
// Backend, which the command implements over the same code as the CLI.
package ui

import (
	"context"
	"errors"

	"github.com/milliebillie/patchtacio/internal/advice"
	"github.com/milliebillie/patchtacio/internal/catalog"
	"github.com/milliebillie/patchtacio/internal/config"
)

// Backend does what the UI asks. Implementations need not be safe for
// concurrent use: the server calls one method at a time.
type Backend interface {
	// Config reads the configuration file and the catalog.
	Config(ctx context.Context) (*Config, error)
	// SaveConfig writes c, but only if the file still has the hash it had
	// when it was read ("" = no file); otherwise it returns ErrConflict.
	SaveConfig(ctx context.Context, hash string, c *config.Config) error

	// Secrets says where each alert secret comes from, never its value.
	Secrets(ctx context.Context) []Secret
	// CheckSecret says whether value can be used for env (a webhook URL
	// must be https, for example), without saving it.
	CheckSecret(env, value string) error
	// SetSecret checks value and saves it in the OS keychain.
	SetSecret(ctx context.Context, env, value string) error
	// DeleteSecret removes a secret from the OS keychain.
	DeleteSecret(ctx context.Context, env string) error
	// Test sends a test message on one configured channel.
	Test(ctx context.Context, channel string) error

	// Report checks the configured products against the saved feed data,
	// after downloading the latest data if update is set. Nothing is sent.
	Report(ctx context.Context, update bool) (*Report, error)
	// Ack acknowledges a finding by its ID; Unack removes that.
	Ack(ctx context.Context, id, note string) error
	Unack(ctx context.Context, id string) error

	// Schedule says how the daily check is set up and how it last went.
	Schedule(ctx context.Context) (*Schedule, error)
	// InstallSchedule sets up the daily check at at (HH:MM, "" = a time
	// from 08:00 to 08:59).
	InstallSchedule(ctx context.Context, at string) (*ScheduleSetup, error)
	// UninstallSchedule removes the daily check and names what it removed.
	UninstallSchedule(ctx context.Context) ([]string, error)
	// RunScheduleNow asks the scheduler to start the daily check now and
	// returns the log file it writes.
	RunScheduleNow(ctx context.Context) (string, error)
}

// ErrConflict means the configuration file changed after the page was loaded.
var ErrConflict = errors.New("the configuration file was changed after this page was loaded")

// Config is the configuration file and the products the user can pick from.
type Config struct {
	Path     string
	Hash     string            // of the file as read; "" when there is no file yet
	Problem  string            // why the file cannot be used; nothing is saved over it
	File     *config.Config    // never nil; empty when missing or unusable
	Products []catalog.Product // active catalog products, in picker order
}

// Secret is where one alert secret comes from.
type Secret struct {
	Env     string // environment variable, e.g. PATCHTACIO_WEBHOOK_URL
	Name    string // e.g. webhook-url
	What    string
	Source  string // "environment", "keychain" or "" (not set)
	Problem string // why the keychain could not be asked, if it could not
}

// Report is the result of checking the configured products.
type Report struct {
	NoData    bool     // no usable KEV data at all: nothing could be checked
	Warnings  []string // anything that limits how far the report can be trusted
	Feed      string   // the KEV data used, in words
	EOLFeed   string   // the endoflife.date data used, "" when not looked up
	Products  []ReportProduct
	Findings  []Finding  // known exploited vulnerabilities, newest first
	EOL       []EOLEntry // end of life, for products endoflife.date tracks
	NoVersion int        // tracked products without a version (end of life not checked)
}

// ReportProduct is one configured product and its number of KEV findings.
type ReportProduct struct {
	Display, Version string
	Findings         int
}

// Finding is one KEV entry matching one of the user's products.
type Finding struct {
	ID     string // kev/<product>/<CVE>
	CVE    string
	Added  string // when CISA added it, e.g. "2 Oct 2026"
	Recent bool   // added in the last 30 days
	Acked  bool
	Card   advice.Card
}

// EOLEntry is one product's end-of-life answer.
type EOLEntry struct {
	ID      string // eol/<product>/<release> when ended or ending, else ""
	Product string
	Version string
	Release string
	What    string       // in words
	Card    *advice.Card // when ended or ending
	Acked   bool
}

// Schedule is how the daily check is set up.
type Schedule struct {
	Installed bool
	Method    string
	At        string // HH:MM, "" when unknown
	Command   string
	NextRun   string // "" when unknown
	LastRun   string
	LogFile   string
	Notes     []string
	Problems  []string
}

// ScheduleSetup is what InstallSchedule set up.
type ScheduleSetup struct {
	Method, At, NextRun, LogFile string
	Notes, Warnings              []string
}
