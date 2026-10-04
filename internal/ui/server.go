package ui

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Limits and timeouts.
const (
	maxBody          = 64 << 10 // POST bodies: forms are a few kilobytes
	defaultLaunchTTL = 2 * time.Minute
	shutdownWait     = 5 * time.Second
)

// Options configure a Server.
type Options struct {
	Version   string
	Now       func() time.Time // defaults to time.Now
	LaunchTTL time.Duration    // how long the launch link works; default 2 minutes
	Logger    *slog.Logger
}

// Server is the web UI for one run of `patchtacio ui`.
type Server struct {
	b     Backend
	opt   Options
	pages map[string]*template.Template

	work sync.Mutex // one Backend call at a time

	mu          sync.Mutex
	host        string // "127.0.0.1:<port>", set by Listen
	launch      string // the one-time launch token; "" once used
	launchUntil time.Time
	sess        *session // the one session the launch link created

	stop     chan struct{}
	stopOnce sync.Once
}

type session struct {
	token string // cookie value
	csrf  string
	flash []Flash
}

// Flash is a message shown once, on the next page.
type Flash struct {
	Kind  string // "ok", "warn" or "error"
	Title string
	Lines []string
}

// New returns a server over b.
func New(b Backend, o Options) (*Server, error) {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.LaunchTTL == 0 {
		o.LaunchTTL = defaultLaunchTTL
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	pages, err := parsePages()
	if err != nil {
		return nil, err
	}
	return &Server{b: b, opt: o, pages: pages, stop: make(chan struct{})}, nil
}

// Listen opens a random port on 127.0.0.1 (never another interface) and
// makes the one-time launch token.
func (s *Server) Listen(ctx context.Context) (net.Listener, error) {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("open a port on 127.0.0.1: %w", err)
	}
	tok, err := randomToken()
	if err != nil {
		_ = ln.Close()
		return nil, err
	}
	s.mu.Lock()
	s.host = ln.Addr().String()
	s.launch = tok
	s.launchUntil = s.opt.Now().Add(s.opt.LaunchTTL)
	s.mu.Unlock()
	return ln, nil
}

// URL is the address of the UI, without the launch token: it works in the
// browser that has already opened the launch link.
func (s *Server) URL() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return "http://" + s.host + "/"
}

// LaunchURL is the one-time link that starts a session. It works once, for
// Options.LaunchTTL after Listen.
func (s *Server) LaunchURL() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return "http://" + s.host + "/login?token=" + url.QueryEscape(s.launch)
}

// Serve answers requests on ln until ctx is done or the user clicks Stop.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{
		Handler:           s,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		// No WriteTimeout: downloading the feeds may take minutes, and
		// each feed has its own time limits.
		MaxHeaderBytes: 16 << 10,
		BaseContext:    func(net.Listener) context.Context { return ctx },
		ErrorLog:       slog.NewLogLogger(s.opt.Logger.Handler(), slog.LevelDebug),
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	case <-s.stop:
	}
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownWait)
	defer cancel()
	if err := srv.Shutdown(sctx); err != nil {
		_ = srv.Close()
	}
	if err := <-errc; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// Stopped is closed when the user clicks Stop.
func (s *Server) Stopped() <-chan struct{} { return s.stop }

// ServeHTTP checks every request before it reaches a page.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; script-src 'self'; img-src 'self'; "+
		"form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")

	// Only our own address: a page on another site whose name is made to
	// resolve to 127.0.0.1 (DNS rebinding) sends its own name here.
	s.mu.Lock()
	host := s.host
	s.mu.Unlock()
	if host == "" || r.Host != host {
		http.Error(w, "wrong host", http.StatusMisdirectedRequest)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/static/") {
		if r.Method == http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		serveStatic(w, r)
		return
	}
	if r.URL.Path == "/login" {
		s.login(w, r)
		return
	}
	sess := s.session(r)
	if sess == nil {
		s.renderStatus(w, http.StatusUnauthorized, "noSession")
		return
	}
	if r.Method == http.MethodPost {
		if !s.checkPost(w, r, sess) {
			return
		}
	}
	s.route(w, r, sess)
}

// login exchanges the one-time launch token for the session cookie.
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	got := r.URL.Query().Get("token")
	s.mu.Lock()
	ok := s.launch != "" && got != "" && subtle.ConstantTimeCompare([]byte(got), []byte(s.launch)) == 1 &&
		s.opt.Now().Before(s.launchUntil)
	var sess *session
	if ok {
		s.launch = "" // once only
		var err error
		if sess, err = newSession(); err != nil {
			s.mu.Unlock()
			http.Error(w, "could not start a session", http.StatusInternalServerError)
			return
		}
		s.sess = sess
	}
	cookie := s.cookieName()
	s.mu.Unlock()
	if !ok {
		s.renderStatus(w, http.StatusForbidden, "linkUsed")
		return
	}
	// Not Secure: the UI is plain http on 127.0.0.1, where browsers do not
	// reliably keep Secure cookies. HttpOnly and SameSite=Strict are set.
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // see above
		Name: cookie, Value: sess.token, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
	// Off the address bar, so the token is not reloaded or shared.
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// session returns the request's session, or nil.
func (s *Server) session(r *http.Request) *session {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, err := r.Cookie(s.cookieName())
	if err != nil || s.sess == nil {
		return nil
	}
	if subtle.ConstantTimeCompare([]byte(c.Value), []byte(s.sess.token)) != 1 {
		return nil
	}
	return s.sess
}

// cookieName carries the port, so two runs do not overwrite each other's
// cookie (cookies are per host, not per port). Call with s.mu held.
func (s *Server) cookieName() string {
	_, port, _ := net.SplitHostPort(s.host)
	return "patchtacio_" + port
}

// checkPost rejects a POST from another site or without the CSRF token, and
// parses the form within maxBody.
func (s *Server) checkPost(w http.ResponseWriter, r *http.Request, sess *session) bool {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" {
		http.Error(w, "cross-site request refused", http.StatusForbidden)
		return false
	}
	if o := r.Header.Get("Origin"); o != "" && o != "http://"+r.Host {
		http.Error(w, "cross-site request refused", http.StatusForbidden)
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "form too large or not valid", http.StatusRequestEntityTooLarge)
		return false
	}
	tok := r.PostForm.Get("csrf")
	s.mu.Lock()
	ok := tok != "" && subtle.ConstantTimeCompare([]byte(tok), []byte(sess.csrf)) == 1
	s.mu.Unlock()
	if !ok {
		http.Error(w, "this form has expired: reload the page and try again", http.StatusForbidden)
		return false
	}
	return true
}

func newSession() (*session, error) {
	tok, err := randomToken()
	if err != nil {
		return nil, err
	}
	csrf, err := randomToken()
	if err != nil {
		return nil, err
	}
	return &session{token: tok, csrf: csrf}, nil
}

// randomToken is 256 random bits, hex encoded.
func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("make a random token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// addFlash queues a message for the next page.
func (s *Server) addFlash(sess *session, f Flash) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess.flash = append(sess.flash, f)
}

// takeFlash returns and clears the queued messages.
func (s *Server) takeFlash(sess *session) []Flash {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := sess.flash
	sess.flash = nil
	return f
}

func (s *Server) csrf(sess *session) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return sess.csrf
}

// stopServer asks Serve to finish once the current request is answered.
func (s *Server) stopServer() {
	s.stopOnce.Do(func() { close(s.stop) })
}
