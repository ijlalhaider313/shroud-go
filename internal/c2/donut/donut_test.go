package donut

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

// TestBuildArgsBase verifies the core argv shape: -i file -a arch -f format, with
// the input basename used as the label.
func TestBuildArgsBase(t *testing.T) {
	c := newCmd(t, map[string]interface{}{
		"donut-file": "/tmp/payload.exe",
	})
	args, label, err := buildArgs(c)
	if err != nil {
		t.Fatal(err)
	}
	if label != "payload.exe" {
		t.Errorf("label = %q, want payload.exe", label)
	}
	wantContains(t, args, "-i", "/tmp/payload.exe", "-a", "2", "-f", "1")
}

// TestBuildArgsArchOverride asserts -a reflects an explicit arch override.
func TestBuildArgsArchOverride(t *testing.T) {
	c := newCmd(t, map[string]interface{}{
		"donut-file": "/tmp/x.dll",
		"donut-arch": 3,
	})
	args, _, err := buildArgs(c)
	if err != nil {
		t.Fatal(err)
	}
	wantContains(t, args, "-a", "3")
}

// TestBuildArgsOptionalFlags asserts entropy/exit/bypass/args/method/class are
// added only when set (0/empty = unset).
func TestBuildArgsOptionalFlags(t *testing.T) {
	c := newCmd(t, map[string]interface{}{
		"donut-file":    "/tmp/x.dll",
		"donut-entropy": 1,
		"donut-exit":    2,
		"donut-bypass":  1,
		"donut-args":    "calc notepad",
		"donut-method":  "RunProcess",
		"donut-class":   "TestClass",
	})
	args, _, err := buildArgs(c)
	if err != nil {
		t.Fatal(err)
	}
	wantContains(t, args, "-e", "1", "-x", "2", "-b", "1", "-p", "calc notepad", "-m", "RunProcess", "-c", "TestClass")
}

// TestBuildArgsOptionalsOmitted confirms the 0/empty optional flags are omitted.
func TestBuildArgsOptionalsOmitted(t *testing.T) {
	c := newCmd(t, map[string]interface{}{
		"donut-file": "/tmp/x.exe",
	})
	args, _, err := buildArgs(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range args {
		if a == "-e" || a == "-x" || a == "-b" || a == "-p" || a == "-m" || a == "-c" {
			t.Errorf("optional flag %q present in args %v (should be omitted)", a, args)
		}
	}
}

// TestBuildArgsExtra confirms --donut-extra tokens are appended.
func TestBuildArgsExtra(t *testing.T) {
	c := newCmd(t, map[string]interface{}{
		"donut-file":  "/tmp/x.exe",
		"donut-extra": "-y 4096 -k 2",
	})
	args, _, err := buildArgs(c)
	if err != nil {
		t.Fatal(err)
	}
	wantContains(t, args, "-y", "4096", "-k", "2")
}

// TestBuildArgsMissingFile confirms buildArgs errors when --donut-file is unset.
func TestBuildArgsMissingFile(t *testing.T) {
	c := newCmd(t, nil)
	if _, _, err := buildArgs(c); err == nil {
		t.Error("expected error when --donut-file is unset")
	}
}

// TestPreflightMissingFile confirms Preflight errors when --donut-file is unset.
func TestPreflightMissingFile(t *testing.T) {
	c := newCmd(t, nil)
	err := (provider{}).Preflight(c)
	if err == nil {
		t.Error("expected error when --donut-file is unset")
	}
}

// TestPreflightBadBinOverride confirms Preflight errors when --donut-bin points
// at a nonexistent path (without needing donut on PATH).
func TestPreflightBadBinOverride(t *testing.T) {
	c := newCmd(t, map[string]interface{}{
		"donut-file": "/tmp/x.exe",
		"donut-bin":  "/nonexistent/donut-binary",
	})
	err := (provider{}).Preflight(c)
	if err == nil {
		t.Error("expected error when --donut-bin points at a missing binary")
	}
}

// TestProviderRegistered confirms init() registered the provider under "donut".
func TestProviderRegistered(t *testing.T) {
	p, err := c2.Resolve("donut")
	if err != nil {
		t.Fatal(err)
	}
	if p.Name() != "donut" {
		t.Errorf("registered name = %q, want donut", p.Name())
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