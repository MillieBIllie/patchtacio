// Package secrets finds Patchtacio's secrets (the SMTP password, webhook and
// ntfy URLs, ntfy token): first in the environment variable, then in the OS
// keychain (Credential Manager on Windows, Keychain on macOS, the Secret
// Service on Linux desktops). Secrets never go in the configuration file
// (CLAUDE.md rule 5), and values are never printed or logged.
//
// It uses github.com/zalando/go-keyring: pure Go on Linux, macOS and Windows
// (no cgo); on macOS it drives /usr/bin/security, sending the secret over
// stdin rather than as an argument.
package secrets

import (
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/zalando/go-keyring"

	"github.com/milliebillie/patchtacio/internal/config"
)

// Service is the keychain service name entries are stored under; the
// account is the environment variable's name.
const Service = "patchtacio"

// Secret is one secret Patchtacio can use.
type Secret struct {
	Name string // command-line name, e.g. "webhook-url"
	Env  string // environment variable, e.g. PATCHTACIO_WEBHOOK_URL
	What string // plain description
}

// All lists the secrets, in a fixed order.
var All = []Secret{
	{Name: "smtp-password", Env: config.EnvSMTPPassword, What: "password for email.username on the mail server"},
	{Name: "webhook-url", Env: config.EnvWebhookURL, What: "Slack, Teams or Discord webhook URL"},
	{Name: "ntfy-url", Env: config.EnvNtfyURL, What: "ntfy topic URL"},
	{Name: "ntfy-token", Env: config.EnvNtfyToken, What: "ntfy access token (optional)"},
}

// ByName returns the secret called name (or named by its variable).
func ByName(name string) (Secret, bool) {
	for _, s := range All {
		if s.Name == name || s.Env == name {
			return s, true
		}
	}
	return Secret{}, false
}

// Source says where a secret was found.
type Source string

// Sources.
const (
	FromEnv      Source = "environment"
	FromKeychain Source = "keychain"
	NotSet       Source = ""
)

// Store looks secrets up, caching keychain answers for the life of the
// process (a run may ask several times; on macOS each ask runs a program).
type Store struct {
	Env func(string) string // the environment; defaults to os.Getenv

	mu    sync.Mutex
	cache map[string]lookup
}

type lookup struct {
	value string
	src   Source
	err   error
}

// New returns a Store over the real environment and keychain.
func New() *Store { return &Store{Env: os.Getenv} }

// Lookup returns the value of the secret held in env, and where it came
// from. A keychain that cannot be reached (a server without a desktop
// session, for example) is not an error here: the secret is simply not set,
// and err says why for diagnostics.
func (s *Store) Lookup(env string) (string, Source, error) {
	getenv := s.Env
	if getenv == nil {
		getenv = os.Getenv
	}
	if v := getenv(env); v != "" {
		return v, FromEnv, nil
	}
	if _, ok := ByName(env); !ok {
		return "", NotSet, nil // only known secrets live in the keychain
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if l, ok := s.cache[env]; ok {
		return l.value, l.src, l.err
	}
	l := lookup{}
	v, err := keyring.Get(Service, env)
	switch {
	case err == nil && v != "":
		l = lookup{value: v, src: FromKeychain}
	case err == nil || errors.Is(err, keyring.ErrNotFound):
	default:
		l.err = fmt.Errorf("keychain: %w", err)
	}
	if s.cache == nil {
		s.cache = map[string]lookup{}
	}
	s.cache[env] = l
	return l.value, l.src, l.err
}

// Getenv is Lookup for code that only wants the value: it has the shape of
// os.Getenv, so channels take it unchanged.
func (s *Store) Getenv(env string) string {
	v, _, _ := s.Lookup(env)
	return v
}

// Set saves a secret in the keychain.
func (s *Store) Set(sec Secret, value string) error {
	if err := keyring.Set(Service, sec.Env, value); err != nil {
		return fmt.Errorf("save %s in the keychain: %w", sec.Name, explain(err))
	}
	s.forget(sec.Env)
	return nil
}

// Delete removes a secret from the keychain. Removing one that is not there
// is not an error.
func (s *Store) Delete(sec Secret) error {
	if err := keyring.Delete(Service, sec.Env); err != nil && !errors.Is(err, keyring.ErrNotFound) {
		return fmt.Errorf("remove %s from the keychain: %w", sec.Name, explain(err))
	}
	s.forget(sec.Env)
	return nil
}

func (s *Store) forget(env string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.cache, env)
}

func explain(err error) error {
	switch {
	case errors.Is(err, keyring.ErrSetDataTooBig):
		return fmt.Errorf("%w (the keychain on this system cannot hold a value that long; use the environment variable instead)", err)
	case errors.Is(err, keyring.ErrUnsupportedPlatform):
		return fmt.Errorf("%w (no keychain on this system; use the environment variable instead)", err)
	default:
		return err
	}
}
