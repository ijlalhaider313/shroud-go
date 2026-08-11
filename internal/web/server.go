// Package web is the local-only browser console for shroud. It serves a single-page
// frontend plus a small JSON API that calls the same internal/* packages the CLI
// uses (via internal/ops), so there is one implementation of generate/deliver behind
// two fronts.
//
// Security model:
//   - bound to 127.0.0.1 only (loopback; never 0.0.0.0);
//   - every /api/* endpoint requires an Authorization: Bearer <token> header (the
//     token is crypto-random hex generated once at startup and printed to stdout);
//   - the generate/deliver endpoints additionally call authorize.Require() and
//     return 403 when the one-time `shroud authorize` gate has not been satisfied;
//   - artifact downloads are restricted to out-dirs that a generate/deliver call
//     registered this session (path-traversal guarded: the cleaned absolute path
//     must be inside a registered dir, with no ".." escape).
//
// The static frontend (/, /static/*) is served WITHOUT the bearer gate so the
// browser can load the page; the token is delivered to the SPA via ?token=<hex>
// (the CLI's --browser flag opens the URL with it appended) or pasted by the
// operator. Only /api/* is gated.
package web

import (
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"shroud/internal/authorize"
)

// frontendFiles holds the embedded SPA (frontend/index.html, app.js, style.css).
//
//go:embed frontend
var frontendFiles embed.FS

// Server is the local web console.
type Server struct {
	addr  string
	token string
	mux   *http.ServeMux
	mu    sync.Mutex
	dirs  []string // allowlisted artifact out-dirs (absolute, cleaned)
}

// New builds a Server. If token is empty, a crypto-random hex token is generated.
// addr should be a 127.0.0.1:<port> loopback address.
func New(addr, token string) (*Server, error) {
	if token == "" {
		b := make([]byte, 24)
		if _, err := rand.Read(b); err != nil {
			return nil, fmt.Errorf("generate token: %w", err)
		}
		token = hex.EncodeToString(b)
	}
	if addr == "" {
		addr = "127.0.0.1:7780"
	}
	if !strings.HasPrefix(addr, "127.0.0.1") && !strings.HasPrefix(addr, "localhost") {
		return nil, fmt.Errorf("refusing non-loopback bind %q (web is local-only; use 127.0.0.1:<port>)", addr)
	}
	s := &Server{addr: addr, token: token, mux: http.NewServeMux()}
	s.routes()
	return s, nil
}

// Addr returns the configured listen address.
func (s *Server) Addr() string { return s.addr }

// Token returns the bearer token (printed by the CLI for the operator).
func (s *Server) Token() string { return s.token }

// ListenAndServe starts the HTTP server. It blocks until the server stops.
func (s *Server) ListenAndServe() error {
	return http.ListenAndServe(s.addr, s.mux)
}

// Handler returns the mux, for httptest-based tests.
func (s *Server) Handler() http.Handler { return s.mux }

// requireBearer wraps a handler so it 401s without a valid Bearer token.
func (s *Server) requireBearer(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.checkBearer(r) {
			jsonError(w, "unauthorized: bearer token required", http.StatusUnauthorized)
			return
		}
		h(w, r)
	}
}

// requireAuthz wraps a handler so it additionally enforces the authorize gate (403).
func (s *Server) requireAuthz(h http.HandlerFunc) http.HandlerFunc {
	return s.requireBearer(func(w http.ResponseWriter, r *http.Request) {
		if err := authorize.Require(); err != nil {
			jsonError(w, "forbidden: "+err.Error(), http.StatusForbidden)
			return
		}
		h(w, r)
	})
}

func (s *Server) checkBearer(r *http.Request) bool {
	v := r.Header.Get("Authorization")
	if !strings.HasPrefix(v, "Bearer ") {
		return false
	}
	return strings.TrimSpace(v[len("Bearer "):]) == s.token
}

// allowDir registers an out-dir as a permitted artifact root for this session.
func (s *Server) allowDir(dir string) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return
	}
	abs = filepath.Clean(abs)
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, d := range s.dirs {
		if d == abs {
			return
		}
	}
	s.dirs = append(s.dirs, abs)
}

// safePath returns the cleaned absolute path if it is inside a registered out-dir
// (or is one), else "" — the path-traversal guard. rel must not start with "..".
func (s *Server) safePath(query string) string {
	abs, err := filepath.Abs(query)
	if err != nil {
		return ""
	}
	abs = filepath.Clean(abs)
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, d := range s.dirs {
		if abs == d {
			return abs
		}
		rel, err := filepath.Rel(d, abs)
		if err != nil {
			continue
		}
		if rel == "." {
			return abs
		}
		if !strings.HasPrefix(rel, "..") && !strings.HasPrefix(rel, string(filepath.Separator)) {
			return abs
		}
	}
	return ""
}

// writeJSON writes a JSON response.
func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// jsonError writes a {error: ...} JSON response.
func jsonError(w http.ResponseWriter, msg string, code int) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// static handlers ---------------------------------------------------------------

func (s *Server) serveIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	b, err := frontendFiles.ReadFile("frontend/index.html")
	if err != nil {
		http.Error(w, "index not found", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'")
	_, _ = w.Write(b)
}

func (s *Server) serveStatic(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/static/")
	if name == "" || strings.Contains(name, "..") {
		http.NotFound(w, r)
		return
	}
	b, err := frontendFiles.ReadFile("frontend/" + name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	switch {
	case strings.HasSuffix(name, ".css"):
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	case strings.HasSuffix(name, ".js"):
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	default:
		w.Header().Set("Content-Type", "application/octet-stream")
	}
	_, _ = w.Write(b)
}

// routes wires the mux. Static + SPA are ungated; /api/* is bearer-gated (and
// generate/deliver are additionally authorize-gated).
func (s *Server) routes() {
	s.mux.HandleFunc("/", s.serveIndex)
	s.mux.HandleFunc("/static/", s.serveStatic)

	s.mux.HandleFunc("/api/status", s.requireBearer(s.handleStatus))
	s.mux.HandleFunc("/api/catalog", s.requireBearer(s.handleCatalog))
	s.mux.HandleFunc("/api/evasion", s.requireBearer(s.handleEvasion))
	s.mux.HandleFunc("/api/formats", s.requireBearer(s.handleFormats))
	s.mux.HandleFunc("/api/c2", s.requireBearer(s.handleC2))
	s.mux.HandleFunc("/api/c2/", s.requireBearer(s.handleC2Flags))
	s.mux.HandleFunc("/api/generate", s.requireAuthz(s.handleGenerate))
	s.mux.HandleFunc("/api/artifact", s.requireBearer(s.handleArtifact))
	s.mux.HandleFunc("/api/authorize", s.requireBearer(s.handleAuthorize))
}

// OpenBrowser attempts to open the default browser to the console URL (best-effort;
// failures are ignored — the URL + token are also printed to the terminal).
func OpenBrowser(url string) {
	for _, name := range []string{"xdg-open", "sensible-browser", "x-www-browser"} {
		if _, err := exec.LookPath(name); err == nil {
			_ = exec.Command(name, url).Start()
			return
		}
	}
}