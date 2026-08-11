package web

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"shroud/internal/authorize"
	"shroud/internal/catalog"
	_ "shroud/internal/c2/donut"      // register donut provider for the test binary
	_ "shroud/internal/c2/metasploit" // register metasploit provider for the test binary
	_ "shroud/internal/c2/sliver"    // register sliver provider for the test binary
	"shroud/internal/delivery"
)

// withServer builds a Server with a known token and a temp authorize marker so tests
// are hermetic (the real ~/.shroud_authorized is untouched).
func withServer(t *testing.T, authorized bool, fn func(*Server, string)) {
	t.Helper()
	saved := authorize.MarkerFile
	dir := t.TempDir()
	authorize.MarkerFile = filepath.Join(dir, "marker")
	if authorized {
		if err := os.WriteFile(authorize.MarkerFile, []byte("test"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { authorize.MarkerFile = saved })

	srv, err := New("127.0.0.1:0", "testtoken")
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	fn(srv, ts.URL)
}

func authReq(method, urlStr, token string, body io.Reader) *http.Request {
	r, err := http.NewRequest(method, urlStr, body)
	if err != nil {
		panic(err)
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	return r
}

func do(t *testing.T, c *http.Client, r *http.Request) (int, []byte) {
	t.Helper()
	resp, err := c.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func TestNoBearerIs401(t *testing.T) {
	withServer(t, true, func(_ *Server, base string) {
		code, _ := do(t, http.DefaultClient, authReq("GET", base+"/api/status", "", nil))
		if code != http.StatusUnauthorized {
			t.Fatalf("no-token status = %d, want 401", code)
		}
		// bad token also 401
		code, _ = do(t, http.DefaultClient, authReq("GET", base+"/api/status", "wrong", nil))
		if code != http.StatusUnauthorized {
			t.Fatalf("bad-token status = %d, want 401", code)
		}
	})
}

func TestCatalogCount(t *testing.T) {
	withServer(t, true, func(_ *Server, base string) {
		code, b := do(t, http.DefaultClient, authReq("GET", base+"/api/catalog", "testtoken", nil))
		if code != 200 {
			t.Fatalf("status=%d body=%s", code, b)
		}
		var techs []map[string]any
		if err := json.Unmarshal(b, &techs); err != nil {
			t.Fatal(err)
		}
		if len(techs) != len(catalog.All()) {
			t.Fatalf("catalog count = %d, want %d", len(techs), len(catalog.All()))
		}
		// every entry has the required fields
		for _, tc := range techs {
			if tc["id"] == nil || tc["name"] == nil || tc["category"] == nil || tc["implemented"] == nil {
				t.Fatalf("catalog entry missing fields: %v", tc)
			}
		}
	})
}

func TestFormatsAndC2(t *testing.T) {
	withServer(t, true, func(_ *Server, base string) {
		// formats
		_, b := do(t, http.DefaultClient, authReq("GET", base+"/api/formats", "testtoken", nil))
		var fmts map[string]any
		if err := json.Unmarshal(b, &fmts); err != nil {
			t.Fatal(err)
		}
		deliv, _ := fmts["delivery"].([]any)
		if len(deliv) != len(delivery.Formats()) {
			t.Fatalf("delivery formats = %v, want %v", deliv, delivery.Formats())
		}
		// c2 names (must include metasploit + donut, registered via blank import in main;
		// but this package's tests don't blank-import them, so only test what's registered).
		_, b = do(t, http.DefaultClient, authReq("GET", base+"/api/c2", "testtoken", nil))
		var c2list []map[string]any
		if err := json.Unmarshal(b, &c2list); err != nil {
			t.Fatal(err)
		}
		if len(c2list) == 0 {
			t.Fatalf("expected at least one c2 provider registered, got 0")
		}
		// each c2 entry has name, help, flags
		for _, p := range c2list {
			if p["name"] == nil || p["help"] == nil || p["flags"] == nil {
				t.Fatalf("c2 entry missing fields: %v", p)
			}
		}
	})
}

func TestGenerateForbiddenWhenUnauthorized(t *testing.T) {
	withServer(t, false, func(_ *Server, base string) {
		body := bytes.NewReader([]byte(`{"flags":{"format":"vbs"}}`))
		code, b := do(t, http.DefaultClient, authReq("POST", base+"/api/generate", "testtoken", body))
		if code != http.StatusForbidden {
			t.Fatalf("unauthorized generate status = %d body=%s, want 403", code, b)
		}
	})
}

func TestGenerateDeliveryAndArtifactDownload(t *testing.T) {
	withServer(t, true, func(_ *Server, base string) {
		outDir := filepath.Join(t.TempDir(), "deliv")
		// delivery: vbs inline (demo stub fallback, no -s)
		reqBody := map[string]any{"flags": map[string]any{"format": "vbs", "out": outDir}}
		rb, _ := json.Marshal(reqBody)
		code, b := do(t, http.DefaultClient, authReq("POST", base+"/api/generate", "testtoken", bytes.NewReader(rb)))
		if code != 200 {
			t.Fatalf("delivery generate status=%d body=%s", code, b)
		}
		var resp generateResponse
		if err := json.Unmarshal(b, &resp); err != nil {
			t.Fatal(err)
		}
		if resp.Format != "vbs" {
			t.Fatalf("format = %q, want vbs", resp.Format)
		}
		if resp.Mode != "inline" {
			t.Fatalf("mode = %q, want inline", resp.Mode)
		}
		if len(resp.Artifacts) == 0 {
			t.Fatalf("no artifacts emitted")
		}
		art := resp.Artifacts[0]
		if art.DownloadURL == "" {
			t.Fatalf("artifact missing download_url")
		}
		// download the artifact via the download_url (bearer-gated)
		u := base + art.DownloadURL
		code, body := do(t, http.DefaultClient, authReq("GET", u, "testtoken", nil))
		if code != 200 {
			t.Fatalf("artifact download status=%d body=%s", code, body)
		}
		if len(body) != art.Bytes {
			t.Fatalf("downloaded %d bytes, artifact said %d", len(body), art.Bytes)
		}
		if !strings.Contains(string(body), "WScript.Shell") {
			t.Fatalf("artifact body missing WScript.Shell marker (not a vbs?)")
		}
	})
}

func TestGenerateImplantSourceOnly(t *testing.T) {
	withServer(t, true, func(_ *Server, base string) {
		outDir := filepath.Join(t.TempDir(), "impl")
		reqBody := map[string]any{"id": "pe26", "flags": map[string]any{"format": "c", "out": outDir, "no-build": true}}
		rb, _ := json.Marshal(reqBody)
		code, b := do(t, http.DefaultClient, authReq("POST", base+"/api/generate", "testtoken", bytes.NewReader(rb)))
		if code != 200 {
			t.Fatalf("implant generate status=%d body=%s", code, b)
		}
		var resp generateResponse
		if err := json.Unmarshal(b, &resp); err != nil {
			t.Fatal(err)
		}
		if resp.TechniqueID != "pe26" {
			t.Fatalf("technique_id = %q, want pe26", resp.TechniqueID)
		}
		if resp.Built {
			t.Fatalf("expected Built=false for format=c")
		}
		// payload.h should exist in the outdir
		hdr := filepath.Join(outDir, "payload.h")
		if _, err := os.Stat(hdr); err != nil {
			t.Fatalf("expected %s to exist: %v", hdr, err)
		}
	})
}

func TestArtifactPathTraversalGuarded(t *testing.T) {
	withServer(t, true, func(_ *Server, base string) {
		// generate something first so an out-dir is registered
		outDir := filepath.Join(t.TempDir(), "deliv2")
		rb, _ := json.Marshal(map[string]any{"flags": map[string]any{"format": "ps1", "out": outDir}})
		_, _ = do(t, http.DefaultClient, authReq("POST", base+"/api/generate", "testtoken", bytes.NewReader(rb)))

		// a path nowhere near a registered out-dir → 403
		esc := base + "/api/artifact?path=" + url.QueryEscape("/etc/passwd")
		code, _ := do(t, http.DefaultClient, authReq("GET", esc, "testtoken", nil))
		if code != http.StatusForbidden {
			t.Fatalf("/etc/passwd status = %d, want 403", code)
		}
		// traversal inside the registered dir is rejected when it escapes
		// (the artifact from ps1 is payload.ps1; asking for ../sibling is outside)
		esc2 := base + "/api/artifact?path=" + url.QueryEscape(filepath.Join(outDir, "..", "..", "passwd"))
		code, _ = do(t, http.DefaultClient, authReq("GET", esc2, "testtoken", nil))
		if code != http.StatusForbidden {
			t.Fatalf("traversal escape status = %d, want 403", code)
		}
		// the real artifact IS downloadable
		artPath := filepath.Join(outDir, "payload.ps1")
		ok := base + "/api/artifact?path=" + url.QueryEscape(artPath)
		code, _ = do(t, http.DefaultClient, authReq("GET", ok, "testtoken", nil))
		if code != 200 {
			t.Fatalf("legitimate artifact status = %d, want 200", code)
		}
	})
}

func TestAuthorizeEndpoint(t *testing.T) {
	withServer(t, false, func(_ *Server, base string) {
		// marker absent → generate 403
		rb, _ := json.Marshal(map[string]any{"flags": map[string]any{"format": "vbs"}})
		code, _ := do(t, http.DefaultClient, authReq("POST", base+"/api/generate", "testtoken", bytes.NewReader(rb)))
		if code != http.StatusForbidden {
			t.Fatalf("pre-authorize generate = %d, want 403", code)
		}
		// call the authorize endpoint (confirm=true writes the marker)
		rb2, _ := json.Marshal(map[string]any{"confirm": true})
		code, _ = do(t, http.DefaultClient, authReq("POST", base+"/api/authorize", "testtoken", bytes.NewReader(rb2)))
		if code != 200 {
			t.Fatalf("authorize endpoint status = %d, want 200", code)
		}
		// now generate should be 200
		rb3, _ := json.Marshal(map[string]any{"flags": map[string]any{"format": "vbs", "out": filepath.Join(t.TempDir(), "a")}})
		code, _ = do(t, http.DefaultClient, authReq("POST", base+"/api/generate", "testtoken", bytes.NewReader(rb3)))
		if code != 200 {
			t.Fatalf("post-authorize generate = %d, want 200", code)
		}
	})
}

func TestRefusesNonLoopbackBind(t *testing.T) {
	if _, err := New("0.0.0.0:7780", "x"); err == nil {
		t.Fatal("expected error binding 0.0.0.0, got nil")
	}
}

func TestStaticIndexServed(t *testing.T) {
	withServer(t, true, func(_ *Server, base string) {
		// index is served at / without auth
		code, b := do(t, http.DefaultClient, authReq("GET", base+"/", "", nil))
		if code != 200 {
			t.Fatalf("index status = %d", code)
		}
		if !strings.Contains(string(b), "shroud") {
			t.Fatalf("index body missing 'shroud'")
		}
		// static js served
		code, b = do(t, http.DefaultClient, authReq("GET", base+"/static/app.js", "", nil))
		if code != 200 {
			t.Fatalf("app.js status = %d", code)
		}
		if !strings.Contains(string(b), "TOKEN") {
			t.Fatalf("app.js body missing token logic")
		}
	})
}