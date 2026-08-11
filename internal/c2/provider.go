// Package c2 defines the pluggable C2 / shellcode-source framework for shroud.
//
// A Provider supplies raw shellcode bytes to the generator pipeline. Shroud
// ships two providers — Sliver (CLI shell-out to `sliver-client`) and Metasploit
// (CLI shell-out to `msfvenom`) — and the registry is open: a new framework
// (Mythic, Havoc, Brute Ratel, …) is added by implementing Provider in its own
// subpackage and calling Register from an init() that runs via a blank import
// in cmd/shroud. See internal/c2/sliver and internal/c2/metasploit for
// reference implementations.
//
// All providers are reached only through `shroud generate`, which is gated
// behind `shroud authorize`. See SECURITY.md — authorized use only.
package c2

import (
	"fmt"
	"sort"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// ShellcodeResult is the common return type from every Provider's Fetch.
type ShellcodeResult struct {
	// Bytes is the position-independent shellcode blob to be embedded/staged.
	Bytes []byte

	// SavePath is where the blob was collected from (for display only).
	SavePath string

	// Name is the implant/session name the provider used.
	Name string

	// Source is a short display label, e.g. "sliver:shroud-1",
	// "metasploit:windows/x64/exec", "raw:shellcode.bin".
	Source string

	// BuildTime is how long the provider took to produce the blob.
	BuildTime time.Duration
}

// Provider is the contract a C2 / shellcode-source framework implements.
//
// Each provider owns its own namespaced flags (e.g. --sliver-*, --msf-*) which
// it registers onto the `generate` command via AddFlags. Fetch reads those same
// flags from the command and produces shellcode. Preflight validates the
// environment (binaries on PATH, config files present) without contacting any
// server, so `shroud c2 <name> preflight` can fail fast.
type Provider interface {
	// Name is the lowercase identifier selected via --c2 (e.g. "sliver").
	Name() string

	// AddFlags registers the provider's flags on the given flag set. Called
	// once during generate-command construction for every registered provider.
	AddFlags(fs *pflag.FlagSet)

	// Preflight checks deps/config without generating anything.
	Preflight(cmd *cobra.Command) error

	// Fetch reads the provider's flags from cmd and returns the shellcode blob.
	Fetch(cmd *cobra.Command) (*ShellcodeResult, error)

	// Help is a one-line usage string shown by `shroud c2 list`.
	Help() string
}

// registry maps lowercase provider name -> Provider.
var registry = map[string]Provider{}

// Register adds a provider to the registry. Called from each provider
// subpackage's init(). A duplicate registration panics — names must be unique.
func Register(p Provider) {
	name := p.Name()
	if _, dup := registry[name]; dup {
		panic(fmt.Sprintf("c2: duplicate provider %q", name))
	}
	registry[name] = p
}

// Resolve looks up a provider by name. Returns an error if unknown.
func Resolve(name string) (Provider, error) {
	p, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("unknown --c2 backend %q (available: %s)", name, commaNames())
	}
	return p, nil
}

// Names returns the sorted registered provider names.
func Names() []string {
	out := make([]string, 0, len(registry))
	for n := range registry {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// commaNames joins Names with ", " for error/help strings.
func commaNames() string {
	return joinComma(Names())
}

// AddAllFlags registers every provider's flags on fs. Used by the generate
// command so all providers' flags are present (only the selected one is read).
func AddAllFlags(fs *pflag.FlagSet) {
	for _, name := range Names() {
		registry[name].AddFlags(fs)
	}
}

func joinComma(ss []string) string {
	if len(ss) == 0 {
		return "(none)"
	}
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += ", "
		}
		out += s
	}
	return out
}