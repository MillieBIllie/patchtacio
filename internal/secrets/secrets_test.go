package secrets

import (
	"testing"

	"github.com/zalando/go-keyring"

	"github.com/milliebillie/patchtacio/internal/config"
)

func TestLookupOrder(t *testing.T) {
	keyring.MockInit() // in-memory keychain; tests never touch the real one
	env := map[string]string{}
	s := &Store{Env: func(k string) string { return env[k] }}
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
