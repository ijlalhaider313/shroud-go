// Package delivery emits payload-delivery artifacts (LNK, HTA, SCT, VBA, PS1,
// XSL, JS, JSE) and raw shellcode (.bin). It is the "delivery" side of shroud:
// take shellcode (from -s a raw file, or --c2 sliver/metasploit) and wrap it into
// the format your engagement calls for, with either inline embedding or a
// --url remote fetch primitive.
//
// Delivery formats are launchers/droppers — they do NOT host the heavy Go
// implant evasion stack (-e dynamic-api/unhook/stomp/callbacks/amsi/etw), which
// lives only inside the compiled EXE/DLL/C implant. Delivery stagers use their
// own native tricks (base64 transport encoding, a default AMSI-bypass prologue
// in the PowerShell stager, LOLBin choice). See README "Delivery formats".
//
// Reached only through `shroud generate -f <format>`, which is gated behind
// `shroud authorize`. The package never executes its output. See SECURITY.md —
// authorized use only.
package delivery

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Spec describes a delivery emission request.
type Spec struct {
	// Format selects the emitter:
	//   raw|ps1|hta|sct|vba|xsl|js|jse|lnk|vbs|wsf|bat|psm1|zip|html|iso.
	Format string

	// Shellcode is the raw PIC blob to embed in inline mode. Nil in pure-remote
	// mode (URL set, Shellcode nil). Emitters that require payload (raw, inline
	// scripts) error if Shellcode is empty when URL is empty.
	Shellcode []byte

	// URL is the remote stage-2 URL for remote mode. Empty in inline mode.
	// Shellcode and URL are mutually exclusive — the CLI enforces this before
	// calling Emit.
	URL string

	// OutDir is where artifacts are written. Created if missing.
	OutDir string

	// Launcher selects the LOLBin/host for lnk (and is reused as the remote
	// primitive selector where relevant): powershell|cmd|mshta|regsvr32|wmic|cscript.
	// Empty defaults to "powershell".
	Launcher string

	// Arch is the target architecture (default amd64). Currently informational
	// for most emitters; the PS1 stager uses it for Add-Type pointer width.
	Arch string

	// Technique is the optional technique-id hint (e.g. "pe26") passed through
	// from `generate <id> -f <delivery>`. Informational; reserved for future
	// per-technique inline-stager variants.
	Technique string
}

// Inline reports whether this spec is inline-embed mode (Shellcode present, no URL).
func (s *Spec) Inline() bool { return s.URL == "" }

// Remote reports whether this spec is remote-fetch mode (URL set).
func (s *Spec) Remote() bool { return s.URL != "" }

// Artifact is one emitted file.
type Artifact struct {
	Path  string
	Bytes []byte
}

// Emitter produces one or more artifacts for a format.
type Emitter interface {
	Name() string // format id, e.g. "lnk"
	Ext() string  // file extension without dot, e.g. "lnk" (raw -> "bin")
	Emit(s *Spec) ([]Artifact, error)
}

var emitters = map[string]Emitter{}

// Register adds an emitter. Duplicate names panic.
func Register(e Emitter) {
	name := e.Name()
	if _, dup := emitters[name]; dup {
		panic(fmt.Sprintf("delivery: duplicate emitter %q", name))
	}
	emitters[name] = e
}

// Resolve looks up an emitter by format name.
func Resolve(name string) (Emitter, error) {
	e, ok := emitters[name]
	if !ok {
		return nil, fmt.Errorf("unknown delivery format %q (available: %s)", name, Formats())
	}
	return e, nil
}

// Formats returns sorted registered format names.
func Formats() []string {
	out := make([]string, 0, len(emitters))
	for n := range emitters {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// IsDelivery reports whether the format is a delivery/raw format (emitter
// registered) vs an implant format (exe|dll|c, handled by internal/payload).
func IsDelivery(format string) bool {
	_, ok := emitters[strings.ToLower(format)]
	return ok
}

// Emit resolves the emitter for s.Format, writes each artifact into s.OutDir,
// and returns the written artifacts. It does NOT create OutDir if the emitter
// returns no artifacts (so a no-op doesn't litter the fs).
func Emit(s *Spec) ([]Artifact, error) {
	if s.OutDir == "" {
		return nil, fmt.Errorf("delivery: OutDir is empty")
	}
	e, err := Resolve(strings.ToLower(s.Format))
	if err != nil {
		return nil, err
	}
	arts, err := e.Emit(s)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(s.OutDir, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", s.OutDir, err)
	}
	for i, a := range arts {
		if a.Path == "" {
			return nil, fmt.Errorf("emitter %q produced artifact %d with empty path", s.Format, i)
		}
		full := a.Path
		if !filepath.IsAbs(full) {
			full = filepath.Join(s.OutDir, full)
		}
		if err := os.WriteFile(full, a.Bytes, 0o644); err != nil {
			return nil, fmt.Errorf("write %s: %w", full, err)
		}
		arts[i].Path = full
	}
	return arts, nil
}

// writeFile is a convenience for emitters that emit a single file into OutDir.
// It returns the Artifact with the absolute path resolved by Emit.
func writeFile(filename string, data []byte) Artifact {
	return Artifact{Path: filename, Bytes: data}
}

// ValidatePayload ensures inline-embedding emitters have shellcode. Emitters
// that don't need payload (remote-only paths) skip this.
func ValidatePayload(s *Spec) error {
	if s.Remote() {
		return nil
	}
	if len(s.Shellcode) == 0 {
		return fmt.Errorf("delivery: %s requires shellcode in inline mode (supply -s <file> or --c2 <backend>)", s.Format)
	}
	return nil
}

// init registers every built-in emitter. All emitter structs live in this
// package; keep this list in sync when adding a format.
func init() {
	Register(rawEmitter{})
	Register(ps1Emitter{})
	Register(htaEmitter{})
	Register(sctEmitter{})
	Register(vbaEmitter{})
	Register(xslEmitter{})
	Register(jsEmitter{})
	Register(jseEmitter{})
	Register(lnkEmitter{})
	Register(vbsEmitter{})
	Register(wsfEmitter{})
	Register(batEmitter{})
	Register(psm1Emitter{})
	Register(zipEmitter{})
	Register(htmlEmitter{})
	Register(isoEmitter{})
}
