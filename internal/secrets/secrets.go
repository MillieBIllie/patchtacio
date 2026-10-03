// Package secrets finds Patchtacio's secrets (the SMTP password, webhook and
// ntfy URLs, ntfy token): first in the environment variable, then in the OS
// keychain (Credential Manager on Windows, Keychain on macOS, the Secret
// Service on Linux desktops). Secrets never go in the configuration file
// (CLAUDE.md rule 5), and values are never printed or logged.
//
// The keychain is opt-in per secret: it is asked only for secrets saved with
// `patchtacio secret set`, listed by name (never value) in a marker file, so
// nobody who uses environment variables meets a keychain unlock prompt. Each
// keychain call has a time limit, so a prompt nobody answers can never stall
// a scheduled run (and with it every later alert).
//
// It uses github.com/zalando/go-keyring: pure Go on Linux, macOS and Windows
// (no cgo); on macOS it drives /usr/bin/security, sending the secret over
// stdin rather than as an argument.
package secrets

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zalando/go-keyring"

	"github.com/milliebillie/patchtacio/internal/atomicfile"
	"github.com/milliebillie/patchtacio/internal/config"
)

// Service is the keychain service name entries are stored under; the
// account is the environment variable's name.
const Service = "patchtacio"

// MarkerFileName is the file, in the config directory, listing which secrets
// are in the keychain (names only).
const MarkerFileName = "secrets-in-keychain"

// Time limits for keychain calls. Reads happen in unattended runs and must
// give up quickly; saving and removing are interactive and may wait for the
// user to unlock the keychain.
var (
	readTimeout  = 5 * time.Second // a variable so tests need not wait
	writeTimeout = 2 * time.Minute
)

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

// backend is the keychain; tests swap it.
type backend struct {
	get    func(service, user string) (string, error)
	set    func(service, user, password string) error
	delete func(service, user string) error
	// reachable reports why the keychain cannot be used here, or nil.
	reachable func() error
}

var realBackend = backend{get: keyring.Get, set: keyring.Set, delete: keyring.Delete, reachable: keychainReachable}

// Store looks secrets up, caching answers for the life of the process (a run
// may ask several times; on macOS each ask runs a program).
type Store struct {
	Env        func(string) string // the environment; defaults to os.Getenv
	MarkerFile string              // "" = keychain never used

	kc      backend
	mu      sync.Mutex
	cache   map[string]lookup
	marked  []string
	loaded  bool
	markErr error
}

type lookup struct {
	value string
	src   Source
	err   error
}

// New returns a Store over the real environment and keychain, with the
// marker file in configDir.
func New(configDir string) *Store {
	return &Store{Env: os.Getenv, MarkerFile: filepath.Join(configDir, MarkerFileName), kc: realBackend}
}

// Mock returns a Store over an in-memory keychain (go-keyring's mock) that
// is always reachable, with its marker file in dir. For tests only.
func Mock(dir string, env func(string) string) *Store {
	if !testing.Testing() {
		panic("secrets.Mock is for tests only")
	}
	keyring.MockInit()
	b := realBackend
	b.reachable = func() error { return nil }
	return &Store{Env: env, MarkerFile: filepath.Join(dir, MarkerFileName), kc: b}
}

// Lookup returns the value of the secret held in env, and where it came
// from. A keychain that cannot be reached, or does not answer in time, is
// not an error here: the secret is simply not set, and err says why, for
// diagnostics (see Problems).
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
	l := s.fromKeychain(env)
	if s.cache == nil {
		s.cache = map[string]lookup{}
	}
	s.cache[env] = l
	return l.value, l.src, l.err
}

// fromKeychain asks the keychain, only for a secret `secret set` saved.
// Callers hold s.mu.
func (s *Store) fromKeychain(env string) lookup {
	s.loadMarks()
	if s.markErr != nil {
		return lookup{err: s.markErr}
	}
	if !slices.Contains(s.marked, env) {
		return lookup{}
	}
	if s.kc.get == nil {
		return lookup{err: errors.New("keychain: not available")}
	}
	if err := s.kc.reachable(); err != nil {
		return lookup{err: fmt.Errorf("keychain: %w", err)}
	}
	v, err := withTimeout(readTimeout, func() (string, error) { return s.kc.get(Service, env) })
	switch {
	case err == nil && v != "":
		return lookup{value: v, src: FromKeychain}
	case err == nil || errors.Is(err, keyring.ErrNotFound):
		return lookup{err: errors.New("keychain: saved with `patchtacio secret set` but no longer in the keychain")}
	default:
		return lookup{err: fmt.Errorf("keychain: %w", err)}
	}
}

// Getenv is Lookup for code that only wants the value: it has the shape of
// os.Getenv, so channels take it unchanged.
func (s *Store) Getenv(env string) string {
	v, _, _ := s.Lookup(env)
	return v
}

// Problem is a secret saved in the keychain that could not be read.
type Problem struct {
	Secret Secret
	Err    error
}

// Problems lists, in a fixed order, the secrets saved in the keychain that
// could not be read in this run (for example a scheduled task that cannot
// reach the user's keychain). Call it after the lookups.
func (s *Store) Problems() []Problem {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Problem
	for _, sec := range All {
		if l, ok := s.cache[sec.Env]; ok && l.err != nil {
			out = append(out, Problem{Secret: sec, Err: l.err})
		}
	}
	return out
}

// Prefetch looks up every secret now, so later lookups (for example while a
// lock is held) are answered from memory.
func (s *Store) Prefetch() {
	for _, sec := range All {
		_, _, _ = s.Lookup(sec.Env)
	}
}

// Set saves a secret in the keychain and marks it as kept there.
func (s *Store) Set(sec Secret, value string) error {
	if s.kc.set == nil {
		return errors.New("keychain: not available")
	}
	if err := s.kc.reachable(); err != nil {
		return fmt.Errorf("save %s in the keychain: %w; use the %s environment variable instead", sec.Name, err, sec.Env)
	}
	if _, err := withTimeout(writeTimeout, func() (string, error) { return "", s.kc.set(Service, sec.Env, value) }); err != nil {
		return fmt.Errorf("save %s in the keychain: %w", sec.Name, explain(err))
	}
	if err := s.mark(sec.Env, true); err != nil {
		return fmt.Errorf("saved %s in the keychain, but could not record that: %w", sec.Name, err)
	}
	s.forget(sec.Env)
	return nil
}

// Delete stops using a secret from the keychain and removes it there. If the
// keychain cannot be reached, the secret is no longer used but may still be
// stored, and the error says so: someone revoking a leaked token must not be
// told it is gone when it is not.
func (s *Store) Delete(sec Secret) error {
	if err := s.mark(sec.Env, false); err != nil {
		return fmt.Errorf("stop using %s from the keychain: %w", sec.Name, err)
	}
	s.forget(sec.Env)
	if s.kc.delete == nil {
		return fmt.Errorf("%s will no longer be used, but the keychain is not available here, so any stored value was not removed", sec.Name)
	}
	if err := s.kc.reachable(); err != nil {
		return fmt.Errorf("%s will no longer be used, but the keychain could not be reached (%v), so its stored value may still be there; "+
			"run `patchtacio secret delete %s` again from a desktop session to remove it", sec.Name, err, sec.Name)
	}
	if _, err := withTimeout(writeTimeout, func() (string, error) { return "", s.kc.delete(Service, sec.Env) }); err != nil &&
		!errors.Is(err, keyring.ErrNotFound) {
		return fmt.Errorf("%s will no longer be used, but removing it from the keychain failed: %w", sec.Name, explain(err))
	}
	return nil
}

func (s *Store) forget(env string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.cache, env)
}

// loadMarks reads the marker file once. Callers hold s.mu.
func (s *Store) loadMarks() {
	if s.loaded {
		return
	}
	s.loaded = true
	if s.MarkerFile == "" {
		return
	}
	b, err := os.ReadFile(filepath.Clean(s.MarkerFile)) // our own file in the config directory
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		s.markErr = fmt.Errorf("read %s: %w", s.MarkerFile, err)
		return
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if _, ok := ByName(line); ok && !strings.HasPrefix(line, "#") {
			s.marked = append(s.marked, line)
		}
	}
}

// mark adds or removes env in the marker file.
func (s *Store) mark(env string, on bool) error {
	if s.MarkerFile == "" {
		return errors.New("no marker file")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.loadMarks()
	if s.markErr != nil {
		return s.markErr
	}
	s.marked = slices.DeleteFunc(s.marked, func(m string) bool { return m == env })
	if on {
		s.marked = append(s.marked, env)
	}
	slices.Sort(s.marked)
	var b strings.Builder
	b.WriteString("# Secrets Patchtacio looks up in the OS keychain (names only, never values).\n")
	b.WriteString("# Managed by `patchtacio secret set` and `patchtacio secret delete`.\n")
	for _, m := range s.marked {
		b.WriteString(m + "\n")
	}
	if err := os.MkdirAll(filepath.Dir(s.MarkerFile), 0o700); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}
	return atomicfile.Write(s.MarkerFile, []byte(b.String()))
}

// withTimeout runs f, giving up after d. A call that never returns is left
// running; it ends with the process.
func withTimeout(d time.Duration, f func() (string, error)) (string, error) {
	type result struct {
		v   string
		err error
	}
	ch := make(chan result, 1)
	go func() {
		v, err := f()
		ch <- result{v, err}
	}()
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case r := <-ch:
		return r.v, r.err
	case <-t.C:
		return "", fmt.Errorf("no answer within %s (is the keychain locked, waiting for a password?)", d)
	}
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
