package secrets

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/zalando/go-keyring"

	"github.com/milliebillie/patchtacio/internal/config"
)

func TestLookupOrder(t *testing.T) {
	env := map[string]string{}
	s := Mock(t.TempDir(), func(k string) string { return env[k] }) // in-memory keychain
	wh, _ := ByName("webhook-url")

	if v, src, err := s.Lookup(config.EnvWebhookURL); v != "" || src != NotSet || err != nil {
		t.Fatalf("empty: %q %q %v", v, src, err)
	}
	if err := s.Set(wh, "https://hooks.slack.com/services/T/B/KEYCHAIN"); err != nil {
		t.Fatal(err)
	}
	if v, src, _ := s.Lookup(config.EnvWebhookURL); v != "https://hooks.slack.com/services/T/B/KEYCHAIN" || src != FromKeychain {
		t.Errorf("keychain: %q %q", v, src)
	}
	// The environment wins over the keychain.
	env[config.EnvWebhookURL] = "https://hooks.slack.com/services/T/B/ENV"
	if v, src, _ := s.Lookup(config.EnvWebhookURL); v != "https://hooks.slack.com/services/T/B/ENV" || src != FromEnv {
		t.Errorf("env: %q %q", v, src)
	}
	delete(env, config.EnvWebhookURL)
	if err := s.Delete(wh); err != nil {
		t.Fatal(err)
	}
	if v := s.Getenv(config.EnvWebhookURL); v != "" {
		t.Errorf("still found after Delete: %q", v)
	}
	if err := s.Delete(wh); err != nil {
		t.Errorf("deleting twice: %v", err)
	}
	// Only known secrets are looked up in the keychain.
	if v, src, _ := s.Lookup("HOME_NOT_A_SECRET"); v != "" || src != NotSet {
		t.Errorf("unknown name: %q %q", v, src)
	}
}

// Without `secret set`, the keychain is never asked, so nobody who uses
// environment variables meets an unlock prompt.
func TestKeychainOnlyForMarkedSecrets(t *testing.T) {
	s := Mock(t.TempDir(), func(string) string { return "" })
	if err := keyring.Set(Service, config.EnvNtfyToken, "set by something else"); err != nil {
		t.Fatal(err)
	}
	called := false
	s.kc.get = func(string, string) (string, error) { called = true; return "", nil }
	if v, src, err := s.Lookup(config.EnvNtfyToken); v != "" || src != NotSet || err != nil || called {
		t.Errorf("unmarked secret: %q %q %v, keychain asked: %v", v, src, err, called)
	}
}

// A keychain that never answers (an unlock prompt nobody sees) must not
// stall the run.
func TestKeychainTimeout(t *testing.T) {
	old := readTimeout
	readTimeout = 50 * time.Millisecond
	defer func() { readTimeout = old }()
	s := Mock(t.TempDir(), func(string) string { return "" })
	wh, _ := ByName("webhook-url")
	if err := s.Set(wh, "https://example.invalid/hook"); err != nil {
		t.Fatal(err)
	}
	block := make(chan struct{})
	defer close(block)
	s.kc.get = func(string, string) (string, error) { <-block; return "", nil }
	start := time.Now()
	v, _, err := s.Lookup(config.EnvWebhookURL)
	if v != "" || err == nil || time.Since(start) > 2*time.Second {
		t.Errorf("hung keychain: %q, %v after %v", v, err, time.Since(start))
	}
	if p := s.Problems(); len(p) != 1 || p[0].Secret.Env != config.EnvWebhookURL {
		t.Error("the timeout is not reported in Problems")
	}
	// The answer is remembered: a second lookup does not wait again.
	start = time.Now()
	_, _, _ = s.Lookup(config.EnvWebhookURL)
	if time.Since(start) > 20*time.Millisecond {
		t.Error("second lookup waited again")
	}
}

func TestKeychainUnreachableNotCalled(t *testing.T) {
	s := Mock(t.TempDir(), func(string) string { return "" })
	wh, _ := ByName("webhook-url")
	if err := s.Set(wh, "https://example.invalid/hook"); err != nil {
		t.Fatal(err)
	}
	s.forget(config.EnvWebhookURL)
	s.kc.reachable = func() error { return errors.New("no session bus") }
	s.kc.get = func(string, string) (string, error) { t.Error("keychain called while unreachable"); return "", nil }
	if _, _, err := s.Lookup(config.EnvWebhookURL); err == nil {
		t.Error("want an error saying the keychain is unreachable")
	}
}

// Delete without a reachable keychain stops using the secret, and says the
// value may still be stored rather than claiming it is gone.
func TestDeleteUnreachableSaysSo(t *testing.T) {
	s := Mock(t.TempDir(), func(string) string { return "" })
	tok, _ := ByName("ntfy-token")
	if err := s.Set(tok, "tk_secret"); err != nil {
		t.Fatal(err)
	}
	s.kc.reachable = func() error { return errors.New("no session bus") }
	err := s.Delete(tok)
	if err == nil || !strings.Contains(err.Error(), "may still be there") {
		t.Fatalf("Delete while unreachable: %v", err)
	}
	if strings.Contains(err.Error(), "tk_secret") {
		t.Error("error shows the value")
	}
	s.kc.reachable = func() error { return nil }
	if v, src, _ := s.Lookup(config.EnvNtfyToken); v != "" || src != NotSet {
		t.Errorf("still used after delete: %q %q", v, src)
	}
}

func TestByName(t *testing.T) {
	for _, n := range []string{"smtp-password", config.EnvSMTPPassword, "ntfy-token"} {
		if _, ok := ByName(n); !ok {
			t.Errorf("ByName(%q) not found", n)
		}
	}
	if _, ok := ByName("nvd-api-key"); ok {
		t.Error("unexpected secret name accepted")
	}
}
