package web

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"shroud/internal/authorize"
	"shroud/internal/catalog"
	"shroud/internal/c2"
	"shroud/internal/delivery"
	"shroud/internal/evasion"
	"shroud/internal/ops"

	"github.com/spf13/cobra"
)

// ---------------------------------------------------------------------------
// read-only metadata handlers
// ---------------------------------------------------------------------------

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"authorized": authorize.Authorized(),
		"c2":         c2.Names(),
		"formats": map[string]any{
			"implant":  []string{"exe", "dll", "c"},
			"delivery": delivery.Formats(),
		},
		"techniques": len(catalog.All()),
	})
}

func (s *Server) handleCatalog(w http.ResponseWriter, r *http.Request) {
	type t struct {
		ID          string   `json:"id"`
		Name        string   `json:"name"`
		Category    string   `json:"category"`
		Subtech     string   `json:"subtech"`
		Implemented bool     `json:"implemented"`
		Summary     string   `json:"summary"`
		Flow        []string `json:"flow,omitempty"`
		Notes       string   `json:"notes,omitempty"`
	}
	out := make([]t, 0, len(catalog.All()))
	for _, x := range catalog.All() {
		out = append(out, t{
			ID: x.ID, Name: x.Name, Category: string(x.Category),
			Subtech: x.Subtech, Implemented: x.Implemented, Summary: x.Summary,
			Flow: x.Flow, Notes: x.Notes,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleEvasion(w http.ResponseWriter, r *http.Request) {
	type l struct {
		Layer       string `json:"layer"`
		Help        string `json:"help"`
		Implemented bool   `json:"implemented"`
	}
	out := make([]l, 0, len(evasion.All))
	for _, layer := range evasion.All {
		out = append(out, l{
			Layer:       string(layer),
			Help:        evasion.Help[layer],
			Implemented: evasion.Implemented[layer],
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleFormats(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"implant":  []string{"exe", "dll", "c"},
		"delivery": delivery.Formats(),
	})
}

func (s *Server) handleC2(w http.ResponseWriter, r *http.Request) {
	type p struct {
		Name string             `json:"name"`
		Help string             `json:"help"`
		Flags []ops.C2FlagSpec  `json:"flags"`
	}
	names := c2.Names()
	sort.Strings(names)
	out := make([]p, 0, len(names))
	for _, name := range names {
		prov, err := c2.Resolve(name)
		if err != nil {
			continue
		}
		out = append(out, p{Name: name, Help: prov.Help(), Flags: ops.ProviderFlags(prov)})
	}
	writeJSON(w, http.StatusOK, out)
}

// handleC2Flags serves GET /api/c2/{name}/flags — the per-provider flag schema for the
// dynamic form. Trailing "/flags" is required; bare /api/c2/{name} falls through to
// the /api/c2 list handler (the mux matches /api/c2/ here, so guard the suffix).
func (s *Server) handleC2Flags(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/c2/")
	if rest == "" || !strings.HasSuffix(rest, "/flags") {
		// bare /api/c2/<name> isn't a separate route — treat as 404 (list is at /api/c2)
		http.NotFound(w, r)
		return
	}
	name := strings.TrimSuffix(rest, "/flags")
	prov, err := c2.Resolve(name)
	if err != nil {
		jsonError(w, err.Error(), http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, ops.ProviderFlags(prov))
}

// ---------------------------------------------------------------------------
// authorize (convenience — the operator can also run `shroud authorize`)
// ---------------------------------------------------------------------------

func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Confirm bool `json:"confirm"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}
	if !req.Confirm {
		jsonError(w, "confirm=true required to acknowledge the authorization gate", http.StatusBadRequest)
		return
	}
	if err := authorize.Authorize(strings.NewReader(""), io.Discard, true); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"authorized": true})
}

// ---------------------------------------------------------------------------
// generate / deliver (one endpoint — dispatches on the format flag)
// ---------------------------------------------------------------------------

type generateRequest struct {
	ID    string         `json:"id"`
	Flags map[string]any `json:"flags"`
}

// artifactJSON is one emitted/downloadable file in the response.
type artifactJSON struct {
	Path        string `json:"path"`
	Bytes       int    `json:"bytes"`
	DownloadURL string `json:"download_url,omitempty"`
}

// generateResponse is the unified result the SPA renders.
type generateResponse struct {
	TechniqueID   string        `json:"technique_id,omitempty"`
	TechniqueName string        `json:"technique_name,omitempty"`
	Format        string        `json:"format"`
	Mode          string        `json:"mode,omitempty"`
	Evasion       string        `json:"evasion,omitempty"`
	Source        string        `json:"source,omitempty"`
	OutDir        string        `json:"outdir"`
	Built         bool          `json:"built"`
	BuiltPath     string        `json:"built_path,omitempty"`
	BuiltBytes    int64         `json:"built_bytes,omitempty"`
	SleepMS       uint32        `json:"sleep_ms,omitempty"`
	Artifacts     []artifactJSON `json:"artifacts,omitempty"`
	ProjectFiles  []string      `json:"project_files,omitempty"`
	Note          string        `json:"note,omitempty"`
}

func (s *Server) handleGenerate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	var req generateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Build a cobra command with the same flag surface as `shroud generate`, set the
	// flags from the request, then call ops — one implementation, two fronts.
	cmd := &cobra.Command{Use: "generate"}
	ops.AddGenerateFlags(cmd.Flags())
	for name, v := range req.Flags {
		if err := ops.FlagValue(cmd.Flags(), name, v); err != nil {
			jsonError(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	format, _ := cmd.Flags().GetString("format")
	if format == "" {
		format = "exe"
	}

	var args []string
	if req.ID != "" {
		args = []string{req.ID}
	}

	resp := generateResponse{Format: format}

	if delivery.IsDelivery(format) {
		res, err := ops.Deliver(cmd, args, format)
		if err != nil {
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		s.allowDir(res.OutDir)
		resp.Mode = res.Mode
		resp.Source = res.Source
		resp.OutDir = res.OutDir
		resp.TechniqueID = res.Technique
		for _, a := range res.Artifacts {
			resp.Artifacts = append(resp.Artifacts, s.artifactJSON(a.Path, a.Bytes))
		}
		writeJSON(w, http.StatusOK, resp)
		return
	}

	// implant path
	res, err := ops.Generate(cmd, args)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.allowDir(res.OutDir)
	resp.TechniqueID = res.TechniqueID
	resp.TechniqueName = res.TechniqueName
	resp.Format = res.Format
	resp.Evasion = joinLayers(res.Evasion, res.Crypto)
	resp.Source = res.Source
	resp.OutDir = res.OutDir
	resp.Built = res.Built
	resp.BuiltPath = res.BuiltPath
	resp.BuiltBytes = res.BuiltBytes
	resp.SleepMS = res.SleepMS
	if !res.Built {
		resp.Note = "source only (--no-build or format=c); build with: cd " + res.OutDir + " && go mod tidy && ./build.sh"
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) artifactJSON(path string, bytes int) artifactJSON {
	return artifactJSON{
		Path:        path,
		Bytes:       bytes,
		DownloadURL: "/api/artifact?path=" + url.QueryEscape(path),
	}
}

// joinLayers renders the resolved evasion stack (including the crypto layer) as csv.
func joinLayers(layers []evasion.Layer, crypto evasion.Layer) string {
	if len(layers) == 0 {
		return ""
	}
	ss := make([]string, 0, len(layers))
	for _, l := range layers {
		ss = append(ss, string(l))
	}
	return strings.Join(ss, ", ")
}

// ---------------------------------------------------------------------------
// artifact download (path-traversal guarded)
// ---------------------------------------------------------------------------

func (s *Server) handleArtifact(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("path")
	if q == "" {
		jsonError(w, "path parameter required", http.StatusBadRequest)
		return
	}
	safe := s.safePath(q)
	if safe == "" {
		jsonError(w, "forbidden: path outside registered out-dirs", http.StatusForbidden)
		return
	}
	f, err := os.Open(safe)
	if err != nil {
		jsonError(w, "open: "+err.Error(), http.StatusNotFound)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename="+filepath.Base(safe))
	_, _ = io.Copy(w, f)
}