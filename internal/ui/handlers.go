package ui

import (
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/milliebillie/patchtacio/internal/config"
)

// Field limits. Versions and notes are one line in the configuration.
const (
	maxVersion = 64
	maxNotes   = 200
	maxAckNote = 500
	maxSecret  = 8192
	maxIDLen   = 200
)

// route sends a checked request to its page.
func (s *Server) route(w http.ResponseWriter, r *http.Request, sess *session) {
	post := r.Method == http.MethodPost
	switch r.URL.Path {
	case "/":
		if post {
			break
		}
		s.setupPage(w, r, sess)
		return
	case "/products":
		if post {
			s.saveProducts(w, r, sess)
		} else {
			s.productsPage(w, r, sess)
		}
		return
	case "/alerts":
		if post {
			s.saveAlerts(w, r, sess)
		} else {
			s.alertsPage(w, r, sess, nil, nil)
		}
		return
	case "/alerts/test":
		if post {
			s.testAlerts(w, r, sess)
			return
		}
	case "/alerts/secret/delete":
		if post {
			s.deleteSecret(w, r, sess)
			return
		}
	case "/findings":
		if !post {
			s.findingsPage(w, r, sess)
			return
		}
	case "/findings/update":
		if post {
			s.updateFeeds(w, r, sess)
			return
		}
	case "/findings/ack", "/findings/unack":
		if post {
			s.ack(w, r, sess, r.URL.Path == "/findings/ack")
			return
		}
	case "/schedule":
		if !post {
			s.schedulePage(w, r, sess)
			return
		}
	case "/schedule/install", "/schedule/uninstall", "/schedule/run":
		if post {
			s.scheduleAction(w, r, sess, strings.TrimPrefix(r.URL.Path, "/schedule/"))
			return
		}
	case "/quit":
		if post {
			s.renderStatus(w, http.StatusOK, "stopped")
			s.stopServer()
			return
		}
	default:
		http.NotFound(w, r)
		return
	}
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

func redirect(w http.ResponseWriter, r *http.Request, to string) {
	http.Redirect(w, r, to, http.StatusSeeOther)
}

func errorFlash(title string, err error) Flash {
	return Flash{Kind: "error", Title: title, Lines: []string{err.Error()}}
}

// --- Setup (home) ---

type setupData struct {
	Config      *Config
	ConfigErr   string
	Channels    []string
	Unset       []string // secrets a configured channel needs but that are not set
	Report      *Report
	ReportErr   string
	Open        int // findings not yet acknowledged
	Schedule    *Schedule
	ScheduleErr string
}

func (s *Server) setupPage(w http.ResponseWriter, r *http.Request, sess *session) {
	s.work.Lock()
	defer s.work.Unlock()
	ctx := r.Context()
	d := setupData{}
	cfg, err := s.b.Config(ctx)
	if err != nil {
		d.ConfigErr = err.Error()
	} else {
		d.Config = cfg
		d.Channels = cfg.File.Notify.Channels()
		d.Unset = unsetSecrets(cfg.File.Notify, s.b.Secrets(ctx))
	}
	if d.Config != nil && d.Config.Problem == "" && len(d.Config.File.Products) > 0 {
		rep, err := s.b.Report(ctx, false)
		if err != nil {
			d.ReportErr = err.Error()
		} else {
			d.Report = rep
			for _, f := range rep.Findings {
				if !f.Acked {
					d.Open++
				}
			}
			for _, e := range rep.EOL {
				if e.Card != nil && !e.Acked {
					d.Open++
				}
			}
		}
	}
	if sch, err := s.b.Schedule(ctx); err != nil {
		d.ScheduleErr = err.Error()
	} else {
		d.Schedule = sch
	}
	s.render(w, sess, "setup", "Set up Patchtacio", d)
}

// unsetSecrets names the secrets the configured channels need but that are
// set nowhere.
func unsetSecrets(n *config.Notify, secrets []Secret) []string {
	if n == nil {
		return nil
	}
	var need []string
	if n.Email != nil && n.Email.Username != "" {
		need = append(need, config.EnvSMTPPassword)
	}
	if n.Webhook != nil {
		need = append(need, config.EnvWebhookURL)
	}
	if n.Ntfy != nil {
		need = append(need, config.EnvNtfyURL)
	}
	var out []string
	for _, sec := range secrets {
		if slices.Contains(need, sec.Env) && sec.Source == "" {
			out = append(out, sec.What)
		}
	}
	return out
}

// --- Products ---

type productRow struct {
	ID, Display, Category, Search, Version, Notes string
	Ticked, EOL                                   bool
}

type productsData struct {
	Path, Hash, Problem string
	Rows                []productRow
	Ticked              int
}

func (s *Server) productsPage(w http.ResponseWriter, r *http.Request, sess *session) {
	s.work.Lock()
	cfg, err := s.b.Config(r.Context())
	s.work.Unlock()
	if err != nil {
		s.addFlash(sess, errorFlash("Could not read the configuration", err))
		s.render(w, sess, "products", "Your products", productsData{})
		return
	}
	d := productsData{Path: cfg.Path, Hash: cfg.Hash, Problem: cfg.Problem}
	for _, p := range cfg.Products {
		row := productRow{
			ID: p.ID, Display: p.Display, Category: p.Category, EOL: p.EOLSlug != "",
			Search: strings.ToLower(strings.Join(strings.Fields(strings.Join(append([]string{p.Display, p.Vendor, p.ID}, p.AliasesSearch...), " ")), " ")),
		}
		for _, c := range cfg.File.Products {
			if c.ID == p.ID {
				row.Ticked, row.Version, row.Notes = true, c.Version, c.Notes
				d.Ticked++
			}
		}
		d.Rows = append(d.Rows, row)
	}
	s.render(w, sess, "products", "Your products", d)
}

func (s *Server) saveProducts(w http.ResponseWriter, r *http.Request, sess *session) {
	s.work.Lock()
	defer s.work.Unlock()
	ctx := r.Context()
	cfg, err := s.b.Config(ctx)
	if err != nil {
		s.addFlash(sess, errorFlash("Could not read the configuration", err))
		redirect(w, r, "/products")
		return
	}
	if cfg.Problem != "" {
		s.addFlash(sess, Flash{Kind: "error", Title: "Nothing was saved", Lines: []string{cfg.Problem}})
		redirect(w, r, "/products")
		return
	}
	picked := r.PostForm["pick"]
	var problems []string
	var ids []string
	extra := map[string]config.Product{}
	for _, p := range cfg.Products {
		if !slices.Contains(picked, p.ID) {
			continue
		}
		version, err := oneLine(r.PostForm.Get("version."+p.ID), maxVersion)
		if err != nil {
			problems = append(problems, p.Display+": version "+err.Error())
		}
		notes, err := oneLine(r.PostForm.Get("notes."+p.ID), maxNotes)
		if err != nil {
			problems = append(problems, p.Display+": notes "+err.Error())
		}
		ids = append(ids, p.ID)
		extra[p.ID] = config.Product{ID: p.ID, Version: version, Notes: notes}
	}
	for _, id := range picked {
		if _, ok := extra[id]; !ok {
			problems = append(problems, "not a product in the catalog: "+id)
		}
	}
	if len(ids) == 0 {
		problems = append(problems, "Tick at least one product.")
	}
	if len(problems) > 0 {
		s.addFlash(sess, Flash{Kind: "error", Title: "Nothing was saved", Lines: problems})
		redirect(w, r, "/products")
		return
	}
	// Products already in the file keep their place; new ones follow in
	// picker order.
	var order []string
	for _, p := range cfg.File.Products {
		if slices.Contains(ids, p.ID) {
			order = append(order, p.ID)
		}
	}
	for _, id := range ids {
		if !slices.Contains(order, id) {
			order = append(order, id)
		}
	}
	next := cfg.File.WithProducts(order)
	for i, p := range next.Products {
		next.Products[i].Version, next.Products[i].Notes = extra[p.ID].Version, extra[p.ID].Notes
	}
	if err := s.b.SaveConfig(ctx, r.PostForm.Get("hash"), next); err != nil {
		s.addFlash(sess, saveError(err))
		redirect(w, r, "/products")
		return
	}
	f := Flash{Kind: "ok", Title: "Saved " + countWord(len(order), "product", "products") + "."}
	if cfg.File.Notify == nil || len(cfg.File.Notify.Channels()) == 0 {
		f.Lines = append(f.Lines, "Next: choose how Patchtacio should alert you.")
		s.addFlash(sess, f)
		redirect(w, r, "/alerts")
		return
	}
	s.addFlash(sess, f)
	redirect(w, r, "/products")
}

func saveError(err error) Flash {
	if errors.Is(err, ErrConflict) {
		return Flash{Kind: "error", Title: "Nothing was saved",
			Lines: []string{"The configuration file was changed (perhaps by hand, or in another tab) after this page was loaded. The page now shows the file as it is: make your changes again."}}
	}
	return errorFlash("Could not save the configuration", err)
}

// oneLine trims s and checks it is one line of at most limit characters.
func oneLine(s string, limit int) (string, error) {
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) > limit {
		return "", errors.New("is too long")
	}
	if strings.ContainsFunc(s, unicode.IsControl) {
		return "", errors.New("must be one line of text")
	}
	return s, nil
}

func countWord(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}
