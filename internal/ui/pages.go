package ui

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"path"
	"regexp"
	"strings"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

// Pages with the full layout (navigation and forms).
var pageNames = []string{"setup", "products", "alerts", "findings", "schedule"}

var funcs = template.FuncMap{
	"linkify": linkify,
	"join":    strings.Join,
	"inc":     func(i int) int { return i + 1 },
	"list":    func(s ...string) []string { return s },
	"dict":    dict,
	"plural": func(n int, one, many string) string {
		if n == 1 {
			return fmt.Sprintf("%d %s", n, one)
		}
		return fmt.Sprintf("%d %s", n, many)
	},
	"weblink": func(s string) bool { return strings.HasPrefix(s, "https://") || strings.HasPrefix(s, "http://") },
}

func parsePages() (map[string]*template.Template, error) {
	out := map[string]*template.Template{}
	for _, name := range pageNames {
		t, err := template.New("layout.html").Funcs(funcs).ParseFS(templateFS, "templates/layout.html", "templates/"+name+".html")
		if err != nil {
			return nil, fmt.Errorf("parse %s page: %w", name, err)
		}
		out[name] = t
	}
	t, err := template.New("bare.html").Funcs(funcs).ParseFS(templateFS, "templates/bare.html")
	if err != nil {
		return nil, fmt.Errorf("parse status pages: %w", err)
	}
	out["bare"] = t
	return out, nil
}

// view is what every full page gets.
type view struct {
	Title   string
	Nav     string // which navigation entry is current
	CSRF    string
	Version string
	Flash   []Flash
	Data    any
}

// render writes a full page. The template runs into a buffer first, so a
// template error never leaves half a page.
func (s *Server) render(w http.ResponseWriter, sess *session, name, title string, data any) {
	v := view{Title: title, Nav: name, CSRF: s.csrf(sess), Version: s.opt.Version, Flash: s.takeFlash(sess), Data: data}
	var b bytes.Buffer
	if err := s.pages[name].Execute(&b, v); err != nil {
		s.opt.Logger.Error("render page", "page", name, "err", err)
		http.Error(w, "could not show this page", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(b.Bytes())
}

// renderStatus writes a page without navigation: no session, a used launch
// link, or Patchtacio stopped.
func (s *Server) renderStatus(w http.ResponseWriter, code int, which string) {
	var b bytes.Buffer
	if err := s.pages["bare"].Execute(&b, map[string]any{"Which": which, "Version": s.opt.Version}); err != nil {
		http.Error(w, http.StatusText(code), code)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	_, _ = w.Write(b.Bytes())
}

// serveStatic serves the embedded stylesheet and script.
func serveStatic(w http.ResponseWriter, r *http.Request) {
	name := path.Clean(strings.TrimPrefix(r.URL.Path, "/"))
	b, err := fs.ReadFile(staticFS, name)
	if err != nil || !strings.HasPrefix(name, "static/") {
		http.NotFound(w, r)
		return
	}
	switch path.Ext(name) {
	case ".css":
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	case ".js":
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	default:
		http.NotFound(w, r)
		return
	}
	_, _ = w.Write(b) //nolint:gosec // embedded files of our own, not user input
}

var urlPattern = regexp.MustCompile(`https?://[^\s<>"]+`)

// linkify escapes plain text and turns its http(s) links into links that
// open in a new tab without telling the site where they came from.
func linkify(s string) template.HTML {
	var b strings.Builder
	last := 0
	for _, m := range urlPattern.FindAllStringIndex(s, -1) {
		start, end := m[0], m[1]
		// Trailing punctuation belongs to the sentence, not the link.
		for end > start && strings.ContainsRune(".,;:)]'\"", rune(s[end-1])) {
			end--
		}
		link := s[start:end]
		b.WriteString(template.HTMLEscapeString(s[last:start]))
		fmt.Fprintf(&b, `<a href="%s" rel="noopener noreferrer" target="_blank">%s</a>`,
			template.HTMLEscapeString(link), template.HTMLEscapeString(link))
		last = end
	}
	b.WriteString(template.HTMLEscapeString(s[last:]))
	return template.HTML(b.String()) //nolint:gosec // every part is escaped above; links are http(s) only
}

// dict builds a map from key, value pairs, to pass several values to a
// template block.
func dict(kv ...any) (map[string]any, error) {
	if len(kv)%2 != 0 {
		return nil, errors.New("dict needs key, value pairs")
	}
	m := make(map[string]any, len(kv)/2)
	for i := 0; i < len(kv); i += 2 {
		k, ok := kv[i].(string)
		if !ok {
			return nil, errors.New("dict keys must be strings")
		}
		m[k] = kv[i+1]
	}
	return m, nil
}
