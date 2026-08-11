// provider.go adapts the existing sliver engine (FetchShellcode) to the
// generic c2.Provider interface, so `shroud generate --c2 sliver` is routed
// through the c2 registry rather than a hardcoded branch in cmd/shroud.
//
// The engine in sliver.go and its tests are untouched — this file only adds the
// adapter + flag registration + registry self-registration via init().
package sliver

import (
	"time"

	"shroud/internal/c2"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

const providerName = "sliver"

// provider implements c2.Provider.
type provider struct{}

func (provider) Name() string { return providerName }

func (provider) Help() string {
	return "Sliver C2 — shellcode-format implant generated via the `sliver-client` operator binary (--sliver-config, --lhost, --lport, --transport)."
}

// AddFlags registers sliver's flags on a flag set. These are the same flags the
// standalone `shroud sliver fetch` subcommand uses, but scoped to `generate`.
func (provider) AddFlags(fs *pflag.FlagSet) {
	fs.String("sliver-config", "", "operator .cfg for --c2 sliver (from sliver `new-operator`)")
	fs.String("lhost", "", "implant callback host for --c2 sliver")
	fs.Int("lport", 0, "implant callback port for --c2 sliver")
	fs.String("transport", "mtls", "sliver transport: mtls|https|wg")
}

func (provider) Preflight(cmd *cobra.Command) error {
	return Preflight(optsFromCmd(cmd))
}

func (provider) Fetch(cmd *cobra.Command) (*c2.ShellcodeResult, error) {
	opts := optsFromCmd(cmd)
	if err := Preflight(opts); err != nil {
		return nil, err
	}
	res, err := FetchShellcode(opts)
	if err != nil {
		return nil, err
	}
	return &c2.ShellcodeResult{
		Bytes:     res.Bytes,
		SavePath:  res.SavePath,
		Name:      res.Name,
		Source:    "sliver:" + res.Name,
		BuildTime: res.BuildTime.Round(time.Millisecond),
	}, nil
}

// optsFromCmd reads sliver's flags off the command (registered by AddFlags).
func optsFromCmd(cmd *cobra.Command) Options {
	return Options{
		Config:    stringFlag(cmd, "sliver-config"),
		LHost:     stringFlag(cmd, "lhost"),
		LPort:     intFlag(cmd, "lport"),
		Transport: stringFlag(cmd, "transport"),
	}
}

// stringFlag/intFlag avoid pulling cobra into the engine files; defined here
// next to the adapter that needs them.
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