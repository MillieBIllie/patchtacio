package config

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestNotifyValidateDefaults(t *testing.T) {
	n := &Notify{
		Email:   &Email{Host: "smtp.example.org", From: "alerts@example.org", To: []string{"it@example.org"}},
		Webhook: &Webhook{Kind: "teams"},
		Ntfy:    &Ntfy{},
		Desktop: true,
	}
	if p := n.Validate(); len(p) != 0 {
		t.Fatalf("problems: %v", p)
	}
	if n.Digest != "off" || n.Email.Security != "starttls" || n.Email.Port != 587 || n.Ntfy.Priority != 4 {
		t.Errorf("defaults not filled: %+v %+v %+v", n, n.Email, n.Ntfy)
	}
	if got := strings.Join(n.Channels(), ","); got != "email,webhook,ntfy,desktop" {
		t.Errorf("Channels = %s", got)
	}
	tls := &Notify{Email: &Email{Host: "smtp.example.org", Security: "tls", From: "a@example.org", To: []string{"b@example.org"}}}
	if p := tls.Validate(); len(p) != 0 || tls.Email.Port != 465 {
		t.Errorf("tls: port %d, problems %v", tls.Email.Port, p)
	}
	var none *Notify
	if none.Validate() != nil || none.Channels() != nil {
		t.Error("a nil Notify must be valid and have no channels")
	}
}

func TestNotifyValidateProblems(t *testing.T) {
	tests := []struct {
		name string
		n    Notify
		want string
	}{
		{"digest", Notify{Digest: "hourly"}, "digest must be"},
		{"no host", Notify{Email: &Email{From: "a@example.org", To: []string{"b@example.org"}}}, "email.host is required"},
		{"plaintext remote", Notify{Email: &Email{Host: "mail.example.org", Security: "none", From: "a@example.org", To: []string{"b@example.org"}}}, "only allowed for a mail server on this computer"},
		{"bad security", Notify{Email: &Email{Host: "h", Security: "ssl", From: "a@example.org", To: []string{"b@example.org"}}}, "email.security must be"},
		{"bad from", Notify{Email: &Email{Host: "h", From: "not an address", To: []string{"b@example.org"}}}, "email.from"},
		{"no to", Notify{Email: &Email{Host: "h", From: "a@example.org"}}, "email.to needs"},
		{"bad to", Notify{Email: &Email{Host: "h", From: "a@example.org", To: []string{"b@example.org\r\nBcc: x@evil.example"}}}, "email.to"},
		{"bad port", Notify{Email: &Email{Host: "h", Port: 70000, From: "a@example.org", To: []string{"b@example.org"}}}, "not a valid port"},
		{"webhook kind", Notify{Webhook: &Webhook{Kind: "mattermost"}}, "webhook.kind must be"},
		{"ntfy priority", Notify{Ntfy: &Ntfy{Priority: 9}}, "ntfy.priority"},
	}
	for _, tt := range tests {
		got := strings.Join(tt.n.Validate(), "; ")
		if !strings.Contains(got, tt.want) {
			t.Errorf("%s: problems %q, want one containing %q", tt.name, got, tt.want)
		}
	}
	local := Notify{Email: &Email{Host: "127.0.0.1", Security: "none", Port: 25, From: "a@example.org", To: []string{"b@example.org"}}}
	if p := local.Validate(); len(p) != 0 {
		t.Errorf("plaintext to 127.0.0.1 must be allowed: %v", p)
	}
	byName := Notify{Email: &Email{Host: "localhost", Security: "none", Port: 25, From: "a@example.org", To: []string{"b@example.org"}}}
	if p := byName.Validate(); len(p) == 0 {
		t.Error("plaintext to the name localhost must be refused (DNS could resolve it elsewhere)")
	}
}

// `patchtacio init` rewrites the file through WithProducts; it must keep the
// notification settings.
func TestNotifySurvivesInitAndRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	in := &Config{
		Products: []Product{{ID: "fortinet-fortios"}},
		Notify:   &Notify{Digest: "daily", Webhook: &Webhook{Kind: "slack"}, Desktop: true},
	}
	if err := Save(path, in.WithProducts([]string{"fortinet-fortios", "vmware-esxi"})); err != nil {
		t.Fatal(err)
	}
	out, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if out.Notify == nil || out.Notify.Digest != "daily" || out.Notify.Webhook == nil || out.Notify.Webhook.Kind != "slack" || !out.Notify.Desktop {
		t.Errorf("notify settings lost: %+v", out.Notify)
	}
}
