package ui

import (
	"net/http"
	"strings"
)

type findingsData struct {
	Report     *Report
	Err        string
	NoProducts bool
	Open       []Finding // not acknowledged
	Acked      []Finding
	EOLCards   []EOLEntry // ended or ending
	EOLOther   []EOLEntry // supported, unknown, not checked
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
	s.work.Unlock()
	if d.Report != nil {
		for _, f := range d.Report.Findings {
			if f.Acked {
				d.Acked = append(d.Acked, f)
			} else {
				d.Open = append(d.Open, f)
			}
		}
		for _, e := range d.Report.EOL {
			if e.Card != nil {
				d.EOLCards = append(d.EOLCards, e)
			} else {
				d.EOLOther = append(d.EOLOther, e)
			}
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
		s.addFlash(sess, Flash{Kind: "error", Title: "Could not download the data, and there is no saved copy", Lines: rep.Warnings})
	case len(rep.Warnings) > 0:
		s.addFlash(sess, Flash{Kind: "warn", Title: "Checked, but with problems", Lines: rep.Warnings})
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
		err = s.b.Ack(r.Context(), id, note)
	} else {
		err = s.b.Unack(r.Context(), id)
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
