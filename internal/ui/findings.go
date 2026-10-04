package ui

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"slices"
	"strconv"
	"strings"
)

type findingsData struct {
	Report     *Report
	Err        string
	NoProducts bool
	Open       []Finding // not acknowledged
	Recent     []Finding // of Open: added to KEV in the last 30 days
	Older      []Finding // of Open: the rest
	Acked      []Finding
	EOLCards   []EOLEntry // ended or ending
	EOLOther   []EOLEntry // supported, unknown, not checked
	Summary    []summaryRow
	Seen       string // fingerprint of the KEV list shown, for the bulk forms
	BulkOpen   []bulkProduct
	BulkAcked  []bulkProduct
	Feeds      []FeedStatus
	FeedsErr   string
}

// bulkProduct is one product in the "many at once" forms.
type bulkProduct struct {
	ID, Display  string
	Count, Older int // findings in the list; of those, added more than 30 days ago
}

// summaryRow is one product's KEV findings, open and dealt with.
type summaryRow struct {
	Display, Version string
	Open, Acked      int
}

// fingerprint identifies the KEV findings as a page shows them: which
// ones, which are dealt with, and which count as recent. A bulk action is
// refused if it changed after the page was loaded, so it never covers an
// entry the user did not see (one a scheduled check added meanwhile, or one
// that turned "older" at midnight).
func fingerprint(fs []Finding) string {
	lines := make([]string, len(fs))
	for i, f := range fs {
		lines[i] = f.ID + "|" + strconv.FormatBool(f.Acked) + "|" + strconv.FormatBool(f.Recent)
	}
	slices.Sort(lines)
	h := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return hex.EncodeToString(h[:])
}

// countByProduct groups findings by product, in first-seen order.
func countByProduct(fs []Finding) []bulkProduct {
	var out []bulkProduct
	for _, f := range fs {
		i := slices.IndexFunc(out, func(p bulkProduct) bool { return p.ID == f.ProductID })
		if i < 0 {
			out = append(out, bulkProduct{ID: f.ProductID, Display: f.Product})
			i = len(out) - 1
		}
		out[i].Count++
		if !f.Recent {
			out[i].Older++
		}
	}
	return out
}

func (s *Server) findingsPage(w http.ResponseWriter, r *http.Request, sess *session) {
	s.work.Lock()
	ctx := r.Context()
	d := findingsData{}
	cfg, err := s.b.Config(ctx)
	switch {
	case err != nil:
		d.Err = err.Error()
	case cfg.Problem != "":
		d.Err = cfg.Problem
	case len(cfg.File.Products) == 0:
		d.NoProducts = true
	default:
		rep, err := s.b.Report(ctx, false)
		if err != nil {
			d.Err = err.Error()
		} else {
			d.Report = rep
		}
	}
	if fs, err := s.b.Feeds(ctx); err != nil {
		d.FeedsErr = err.Error()
	} else {
		d.Feeds = fs
	}
	s.work.Unlock()
	if d.Report != nil {
		for _, f := range d.Report.Findings {
			if f.Acked {
				d.Acked = append(d.Acked, f)
			} else {
				d.Open = append(d.Open, f)
				if f.Recent {
					d.Recent = append(d.Recent, f)
				} else {
					d.Older = append(d.Older, f)
				}
			}
		}
		for _, e := range d.Report.EOL {
			if e.Card != nil {
				d.EOLCards = append(d.EOLCards, e)
			} else {
				d.EOLOther = append(d.EOLOther, e)
			}
		}
		d.Seen = fingerprint(d.Report.Findings)
		d.BulkOpen = countByProduct(d.Open)
		d.BulkAcked = countByProduct(d.Acked)
		for _, p := range d.Report.Products {
			row := summaryRow{Display: p.Display, Version: p.Version}
			for _, f := range d.Report.Findings {
				switch {
				case f.ProductID != p.ID:
				case f.Acked:
					row.Acked++
				default:
					row.Open++
				}
			}
			d.Summary = append(d.Summary, row)
		}
	}
	s.render(w, sess, "findings", "Findings", d)
}

func (s *Server) updateFeeds(w http.ResponseWriter, r *http.Request, sess *session) {
	s.work.Lock()
	rep, err := s.b.Report(r.Context(), true)
	s.work.Unlock()
	switch {
	case err != nil:
		s.addFlash(sess, errorFlash("Could not check your products", err))
	case rep.NoData:
		s.addFlash(sess, Flash{Kind: "error", Title: "Could not download the data, and there is no saved copy", Lines: rep.Warnings, Linkify: true})
	case len(rep.Warnings) > 0:
		s.addFlash(sess, Flash{Kind: "warn", Title: "Checked, but with problems", Lines: rep.Warnings, Linkify: true})
	default:
		s.addFlash(sess, Flash{Kind: "ok", Title: "Downloaded the latest data and checked your products."})
	}
	redirect(w, r, "/findings")
}

func (s *Server) ack(w http.ResponseWriter, r *http.Request, sess *session, ack bool) {
	id := strings.TrimSpace(r.PostForm.Get("id"))
	if len(id) > maxIDLen || (!strings.HasPrefix(id, "kev/") && !strings.HasPrefix(id, "eol/")) {
		http.Error(w, "not a finding ID", http.StatusBadRequest)
		return
	}
	note, err := oneLine(r.PostForm.Get("note"), maxAckNote)
	if err != nil {
		s.addFlash(sess, Flash{Kind: "error", Title: "Not acknowledged", Lines: []string{"The note " + err.Error() + "."}})
		redirect(w, r, "/findings")
		return
	}
	s.work.Lock()
	if ack {
		err = s.b.Ack(r.Context(), []string{id}, note)
	} else {
		err = s.b.Unack(r.Context(), []string{id})
	}
	s.work.Unlock()
	switch {
	case err != nil:
		s.addFlash(sess, errorFlash("Could not change the acknowledgement", err))
	case ack:
		s.addFlash(sess, Flash{Kind: "ok", Title: "Marked as dealt with.",
			Lines: []string{"Patchtacio will not alert or remind you about it again. It stays listed under \"Dealt with\"."}})
	default:
		s.addFlash(sess, Flash{Kind: "ok", Title: "Moved back to the open list.",
			Lines: []string{"Reminders about it resume with the next daily check."}})
	}
	redirect(w, r, "/findings")
}

// ackBulk marks every open KEV finding of one product as dealt with (or,
// with scope "older", those added more than 30 days ago), or moves every
// dealt-with one back. It acts on the findings the page showed, worked out
// again from the saved data, never on IDs sent by the browser.
func (s *Server) ackBulk(w http.ResponseWriter, r *http.Request, sess *session, ack bool) {
	product := r.PostForm.Get("product")
	scope := r.PostForm.Get("scope")
	var problems []string
	note := ""
	if ack {
		var err error
		note, err = oneLine(r.PostForm.Get("note"), maxAckNote)
		switch {
		case err != nil:
			problems = append(problems, "The note "+err.Error()+".")
		case note == "":
			problems = append(problems, "Say what you did, for example \"all updates installed on 4 Oct\": it is kept with each entry.")
		}
		if r.PostForm.Get("confirm") != "yes" {
			problems = append(problems, "Tick the box to confirm you have checked these entries against the version you run.")
		}
		if scope != "older" && scope != "all" {
			problems = append(problems, "Choose which entries.")
		}
	}
	if len(problems) > 0 {
		s.addFlash(sess, Flash{Kind: "error", Title: "Nothing was marked", Lines: problems})
		redirect(w, r, "/findings")
		return
	}

	s.work.Lock()
	defer s.work.Unlock()
	ctx := r.Context()
	rep, err := s.b.Report(ctx, false)
	if err != nil {
		s.addFlash(sess, errorFlash("Could not read the findings", err))
		redirect(w, r, "/findings")
		return
	}
	if r.PostForm.Get("seen") != fingerprint(rep.Findings) {
		s.addFlash(sess, Flash{Kind: "error", Title: "Nothing was marked",
			Lines: []string{"The list changed after this page was loaded (new data, or a change in another tab). Check the list below again, then try again."}})
		redirect(w, r, "/findings")
		return
	}
	var ids []string
	name := product
	for _, f := range rep.Findings {
		if f.ProductID != product || f.Acked != !ack || (ack && scope == "older" && f.Recent) {
			continue
		}
		ids = append(ids, f.ID)
		name = f.Product
	}
	if len(ids) == 0 {
		s.addFlash(sess, Flash{Kind: "error", Title: "Nothing was marked", Lines: []string{"No matching entries for that product."}})
		redirect(w, r, "/findings")
		return
	}
	if ack {
		err = s.b.Ack(ctx, ids, note)
	} else {
		err = s.b.Unack(ctx, ids)
	}
	switch {
	case err != nil:
		s.addFlash(sess, errorFlash("Could not change the acknowledgements", err))
	case ack:
		s.addFlash(sess, Flash{Kind: "ok", Title: "Marked " + countWord(len(ids), "entry", "entries") + " for " + name + " as dealt with.",
			Lines: []string{"Patchtacio will not alert or remind you about them again. They are listed under \"Dealt with\", " +
				"where you can move them back to open (all at once, or one by one)."}})
	default:
		s.addFlash(sess, Flash{Kind: "ok", Title: "Moved " + countWord(len(ids), "entry", "entries") + " for " + name + " back to the open list.",
			Lines: []string{"Reminders about them resume with the next daily check."}})
	}
	redirect(w, r, "/findings")
}

type scheduleData struct {
	Schedule *Schedule
	Err      string
	Ready    bool   // products and a channel configured
	Why      string // why not ready
}

func (s *Server) schedulePage(w http.ResponseWriter, r *http.Request, sess *session) {
	s.work.Lock()
	ctx := r.Context()
	d := scheduleData{}
	if sch, err := s.b.Schedule(ctx); err != nil {
		d.Err = err.Error()
	} else {
		d.Schedule = sch
	}
	if cfg, err := s.b.Config(ctx); err == nil && cfg.Problem == "" {
		switch {
		case len(cfg.File.Products) == 0:
			d.Why = "Choose your products first."
		case len(cfg.File.Notify.Channels()) == 0:
			d.Why = "Set up at least one alert channel first: a daily check that alerts nobody would only look like protection."
		default:
			d.Ready = true
		}
	}
	s.work.Unlock()
	s.render(w, sess, "schedule", "Daily check", d)
}

func (s *Server) scheduleAction(w http.ResponseWriter, r *http.Request, sess *session, action string) {
	s.work.Lock()
	defer s.work.Unlock()
	ctx := r.Context()
	switch action {
	case "install":
		at := strings.TrimSpace(r.PostForm.Get("at"))
		if len(at) > 5 {
			http.Error(w, "not a time", http.StatusBadRequest)
			return
		}
		res, err := s.b.InstallSchedule(ctx, at)
		if err != nil {
			s.addFlash(sess, errorFlash("Could not set up the daily check", err))
			break
		}
		f := Flash{Kind: "ok", Title: "The daily check is set up: every day at " + res.At + ".",
			Lines: []string{"Next run: " + res.NextRun + ".", "Log file: " + res.LogFile}}
		f.Lines = append(f.Lines, res.Notes...)
		s.addFlash(sess, f)
		if len(res.Warnings) > 0 {
			s.addFlash(sess, Flash{Kind: "warn", Title: "Check these before relying on it", Lines: res.Warnings})
		}
	case "uninstall":
		removed, err := s.b.UninstallSchedule(ctx)
		switch {
		case err != nil:
			s.addFlash(sess, errorFlash("Could not remove the daily check", err))
		case len(removed) == 0:
			s.addFlash(sess, Flash{Kind: "ok", Title: "The daily check was not set up; nothing to remove."})
		default:
			s.addFlash(sess, Flash{Kind: "ok", Title: "Removed the daily check.",
				Lines: []string{"Alerts are now sent only when you run a check yourself."}})
		}
	case "run":
		logFile, err := s.b.RunScheduleNow(ctx)
		if err != nil {
			s.addFlash(sess, errorFlash("Could not start the daily check", err))
			break
		}
		s.addFlash(sess, Flash{Kind: "ok", Title: "Started the daily check.",
			Lines: []string{"It runs in the background and sends alerts as it would every day. Reload this page in a minute to see how it went.", "Log file: " + logFile}})
	default:
		http.NotFound(w, r)
		return
	}
	redirect(w, r, "/schedule")
}
