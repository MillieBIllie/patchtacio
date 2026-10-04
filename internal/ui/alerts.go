package ui

import (
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/milliebillie/patchtacio/internal/config"
)

// notifyForm is the alert settings as the form shows them.
type notifyForm struct {
	Digest   string
	Email    bool
	Host     string
	Port     string
	Security string
	Username string
	From     string
	To       string // one address per line
	Webhook  bool
	Kind     string
	Ntfy     bool
	Priority string
	Desktop  bool
}

type alertsData struct {
	Path, Hash, Problem string
	Form                notifyForm
	Secrets             map[string]Secret // by environment variable
	Saved               []string          // channels in the saved configuration, for the test buttons
	Problems            []string          // why the submitted form was not saved
}

func formFromNotify(n *config.Notify) notifyForm {
	f := notifyForm{Digest: "off", Security: "starttls", Kind: "teams", Priority: "4"}
	if n == nil {
		return f
	}
	if n.Digest != "" {
		f.Digest = n.Digest
	}
	if e := n.Email; e != nil {
		f.Email, f.Host, f.Username, f.From, f.To = true, e.Host, e.Username, e.From, strings.Join(e.To, "\n")
		if e.Security != "" {
			f.Security = e.Security
		}
		if e.Port != 0 {
			f.Port = strconv.Itoa(e.Port)
		}
	}
	if n.Webhook != nil {
		f.Webhook, f.Kind = true, n.Webhook.Kind
	}
	if n.Ntfy != nil {
		f.Ntfy = true
		if n.Ntfy.Priority != 0 {
			f.Priority = strconv.Itoa(n.Ntfy.Priority)
		}
	}
	f.Desktop = n.Desktop
	return f
}

// parseNotifyForm reads the submitted settings. Problems that Validate
// cannot see (a port that is not a number) are returned.
func parseNotifyForm(r *http.Request) (notifyForm, *config.Notify, []string) {
	v := r.PostForm
	f := notifyForm{
		Digest: v.Get("digest"),
		Email:  v.Get("email") == "on", Host: strings.TrimSpace(v.Get("host")), Port: strings.TrimSpace(v.Get("port")),
		Security: v.Get("security"), Username: strings.TrimSpace(v.Get("username")),
		From: strings.TrimSpace(v.Get("from")), To: strings.TrimSpace(v.Get("to")),
		Webhook: v.Get("webhook") == "on", Kind: v.Get("kind"),
		Ntfy: v.Get("ntfy") == "on", Priority: v.Get("priority"),
		Desktop: v.Get("desktop") == "on",
	}
	var problems []string
	n := &config.Notify{Digest: f.Digest, Desktop: f.Desktop}
	if f.Email {
		e := &config.Email{Host: f.Host, Security: f.Security, Username: f.Username, From: f.From}
		if f.Port != "" {
			p, err := strconv.Atoi(f.Port)
			if err != nil {
				problems = append(problems, "Email: the port must be a number, like 587.")
			}
			e.Port = p
		}
		for _, to := range strings.FieldsFunc(f.To, func(r rune) bool { return r == '\n' || r == ',' || r == ';' }) {
			if to = strings.TrimSpace(to); to != "" {
				e.To = append(e.To, to)
			}
		}
		n.Email = e
	}
	if f.Webhook {
		n.Webhook = &config.Webhook{Kind: f.Kind}
	}
	if f.Ntfy {
		p, err := strconv.Atoi(f.Priority)
		if err != nil {
			problems = append(problems, "ntfy: choose a priority.")
		}
		n.Ntfy = &config.Ntfy{Priority: p}
	}
	for _, field := range []string{f.Host, f.Username, f.From, f.Digest, f.Security, f.Kind} {
		if _, err := oneLine(field, 254); err != nil {
			problems = append(problems, "Each field must be one line of at most 254 characters.")
			break
		}
	}
	return f, n, problems
}

func (s *Server) alertsPage(w http.ResponseWriter, r *http.Request, sess *session, form *notifyForm, problems []string) {
	s.work.Lock()
	ctx := r.Context()
	cfg, err := s.b.Config(ctx)
	secrets := s.b.Secrets(ctx)
	s.work.Unlock()
	if err != nil {
		s.addFlash(sess, errorFlash("Could not read the configuration", err))
		s.render(w, sess, "alerts", "Alerts", alertsData{Form: formFromNotify(nil)})
		return
	}
	d := alertsData{Path: cfg.Path, Hash: cfg.Hash, Problem: cfg.Problem, Secrets: map[string]Secret{}, Problems: problems}
	for _, sec := range secrets {
		d.Secrets[sec.Env] = sec
	}
	d.Saved = cfg.File.Notify.Channels()
	if form != nil {
		d.Form = *form
	} else {
		d.Form = formFromNotify(cfg.File.Notify)
	}
	s.render(w, sess, "alerts", "Alerts", d)
}

// secretFields are the form's secret inputs, by environment variable, and
// whether the submitted settings use each.
func secretFields(n *config.Notify) map[string]bool {
	return map[string]bool{
		config.EnvSMTPPassword: n.Email != nil && n.Email.Username != "",
		config.EnvWebhookURL:   n.Webhook != nil,
		config.EnvNtfyURL:      n.Ntfy != nil,
		config.EnvNtfyToken:    n.Ntfy != nil,
	}
}

func (s *Server) saveAlerts(w http.ResponseWriter, r *http.Request, sess *session) {
	form, n, problems := parseNotifyForm(r)
	problems = append(problems, n.Validate()...)
	// Secrets are checked before anything is saved, so a bad one does not
	// leave half the settings written.
	values := map[string]string{}
	for env, used := range secretFields(n) {
		raw := r.PostForm.Get("secret." + env)
		if !used || strings.TrimSpace(raw) == "" {
			continue
		}
		if len(raw) > maxSecret || strings.ContainsAny(strings.TrimSpace(raw), "\r\n") {
			problems = append(problems, secretLabel(env)+" must be one line of at most 8 KB.")
			continue
		}
		values[env] = strings.TrimSpace(raw)
	}
	if len(problems) > 0 {
		s.alertsPage(w, r, sess, &form, cleanProblems(problems))
		return
	}

	s.work.Lock()
	defer s.work.Unlock()
	ctx := r.Context()
	cfg, err := s.b.Config(ctx)
	if err != nil {
		s.addFlash(sess, errorFlash("Could not read the configuration", err))
		redirect(w, r, "/alerts")
		return
	}
	if cfg.Problem != "" {
		s.addFlash(sess, Flash{Kind: "error", Title: "Nothing was saved", Lines: []string{cfg.Problem}})
		redirect(w, r, "/alerts")
		return
	}
	next := *cfg.File
	next.Notify = n
	if len(n.Channels()) == 0 {
		next.Notify = nil
	}
	if err := s.b.SaveConfig(ctx, r.PostForm.Get("hash"), &next); err != nil {
		s.addFlash(sess, saveError(err))
		redirect(w, r, "/alerts")
		return
	}
	ok := Flash{Kind: "ok", Title: "Saved the alert settings."}
	var failed []string
	for _, env := range sortedKeys(values) {
		if err := s.b.SetSecret(ctx, env, values[env]); err != nil {
			failed = append(failed, secretLabel(env)+": "+err.Error())
			continue
		}
		ok.Lines = append(ok.Lines, "Saved the "+secretLabel(env)+" in the keychain.")
	}
	if missing := unsetSecrets(next.Notify, s.b.Secrets(ctx)); len(missing) > 0 {
		failed = append(failed, "Still needed: "+strings.Join(missing, ", ")+".")
	}
	if next.Notify != nil {
		ok.Lines = append(ok.Lines, "Next: send a test message with the buttons below.")
	}
	s.addFlash(sess, ok)
	if len(failed) > 0 {
		s.addFlash(sess, Flash{Kind: "error", Title: "Some secrets were not saved", Lines: failed})
	}
	redirect(w, r, "/alerts")
}

// cleanProblems turns Validate's "notify: email.host is required" into text
// that names the form, not the file.
func cleanProblems(ps []string) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		p = strings.TrimPrefix(p, "notify: ")
		if p != "" {
			p = strings.ToUpper(p[:1]) + p[1:]
		}
		if !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

func secretLabel(env string) string {
	switch env {
	case config.EnvSMTPPassword:
		return "email password"
	case config.EnvWebhookURL:
		return "webhook URL"
	case config.EnvNtfyURL:
		return "ntfy topic URL"
	case config.EnvNtfyToken:
		return "ntfy access token"
	}
	return env
}

func (s *Server) deleteSecret(w http.ResponseWriter, r *http.Request, sess *session) {
	env := r.PostForm.Get("env")
	if secretLabel(env) == env {
		http.Error(w, "unknown secret", http.StatusBadRequest)
		return
	}
	s.work.Lock()
	err := s.b.DeleteSecret(r.Context(), env)
	s.work.Unlock()
	if err != nil {
		s.addFlash(sess, errorFlash("Could not remove the "+secretLabel(env), err))
	} else {
		s.addFlash(sess, Flash{Kind: "ok", Title: "Removed the " + secretLabel(env) + " from the keychain."})
	}
	redirect(w, r, "/alerts")
}

func (s *Server) testAlerts(w http.ResponseWriter, r *http.Request, sess *session) {
	s.work.Lock()
	defer s.work.Unlock()
	ctx := r.Context()
	cfg, err := s.b.Config(ctx)
	if err != nil {
		s.addFlash(sess, errorFlash("Could not read the configuration", err))
		redirect(w, r, "/alerts")
		return
	}
	chans := cfg.File.Notify.Channels()
	if want := r.PostForm.Get("channel"); want != "all" {
		if !slices.Contains(chans, want) {
			s.addFlash(sess, Flash{Kind: "error", Title: "That channel is not set up", Lines: []string{"Save the alert settings first."}})
			redirect(w, r, "/alerts")
			return
		}
		chans = []string{want}
	}
	if len(chans) == 0 {
		s.addFlash(sess, Flash{Kind: "error", Title: "No alert channel is set up yet", Lines: []string{"Turn one on below and save."}})
		redirect(w, r, "/alerts")
		return
	}
	var sent, failed []string
	for _, c := range chans {
		if err := s.b.Test(ctx, c); err != nil {
			failed = append(failed, channelLabel(c)+": "+err.Error())
			continue
		}
		sent = append(sent, channelLabel(c)+": sent. "+testHint(c, cfg.File.Notify))
	}
	if len(sent) > 0 {
		s.addFlash(sess, Flash{Kind: "ok", Title: "Test message sent", Lines: sent})
	}
	if len(failed) > 0 {
		s.addFlash(sess, Flash{Kind: "error", Title: "Test message failed", Lines: append(failed, "Fix the setting, save, and try again.")})
	}
	redirect(w, r, "/alerts")
}

func channelLabel(c string) string {
	switch c {
	case config.ChannelEmail:
		return "Email"
	case config.ChannelWebhook:
		return "Chat webhook"
	case config.ChannelNtfy:
		return "ntfy"
	case config.ChannelDesktop:
		return "Desktop notification"
	}
	return c
}

func testHint(c string, n *config.Notify) string {
	switch c {
	case config.ChannelEmail:
		return "Check the inbox of " + strings.Join(n.Email.To, ", ") + " (and the spam folder)."
	case config.ChannelWebhook:
		return "Check the " + n.Webhook.Kind + " channel."
	case config.ChannelNtfy:
		return "Check the ntfy app subscribed to your topic."
	case config.ChannelDesktop:
		return "A notification should have appeared on this computer."
	}
	return ""
}
