// Package catalog holds the Offensive-Panda "Process Injection Series"
// technique registry (pe01..pe26), ported from ~/shroud/lib/registry.py.
//
// `implemented` flags reflect the Go port: all 26 techniques are code-generated.
// pe03 reuses the pe02 body (dynamic-api is universal in the Go rewrite).
// pe07/pe17/pe18 are "via layer" aliases — they map to the unhook / dynamic-api
// evasion layers applied to the pe01/pe02 primitive (generate with -e unhook /
// -e dynamic-api). pe06/pe09/pe10/pe13/pe16/pe19/pe20 are the Phase K techniques
// (PE manual-mapping, RWX hunting, AddressOfEntryPoint, module stomping, section
// mapping, Mokingjay). pe14 (ghosting), pe21 (dirty vanity), pe06/pe09 (manual
// PE mapping) and pe20 (Mokingjay) are code-generated but EXPERIMENTAL — they
// encode the correct API call sequence and cross-compile clean, but require
// Windows on-target runtime verification.
package catalog

import (
	"fmt"
	"strings"
)

const MITREFamily = "T1055"

// Category is a coarse grouping for the catalog listing.
type Category string

const (
	CatClassic   Category = "classic"
	CatDLL       Category = "dll"
	CatHollowing Category = "hollowing"
	CatPE        Category = "pe"
	CatAPC       Category = "apc"
	CatMemory    Category = "memory"
	CatGhosting  Category = "ghosting"
	CatHijack    Category = "hijack"
	CatStomp     Category = "stomp"
	CatPEB       Category = "peb"
	CatNTAPI     Category = "ntapi"
	CatAbuse     Category = "abuse"
	CatFibers    Category = "fibers"
	CatSyscalls  Category = "syscalls"
)

// CategoryLabel is the short human label shown in `list`.
var CategoryLabel = map[Category]string{
	CatClassic:   "Classic code injection",
	CatDLL:       "DLL injection",
	CatHollowing: "Process hollowing / replacement",
	CatPE:        "Whole-PE injection",
	CatAPC:       "APC-based injection",
	CatMemory:    "Memory-region abuse",
	CatGhosting:  "Fileless / section-based spawning",
	CatHijack:    "Thread / context hijacking",
	CatStomp:     "Module stomping",
	CatPEB:       "PEB walk / dynamic resolution",
	CatNTAPI:     "NT (undocumented) API",
	CatAbuse:     "Vulnerable-DLL / fork abuse",
	CatFibers:    "Cooperative threading",
	CatSyscalls:  "Direct / indirect syscalls",
}

// CategoryOrder is the display order of categories.
var CategoryOrder = []Category{
	CatClassic, CatDLL, CatHollowing, CatPE, CatAPC, CatMemory, CatGhosting,
	CatHijack, CatStomp, CatPEB, CatNTAPI, CatAbuse, CatFibers, CatSyscalls,
}

// Technique is one catalog entry.
type Technique struct {
	ID          string   // "pe01".."pe26"
	Name        string   // human name
	Category    Category // grouping
	Subtech     string   // MITRE sub-technique
	Tags        []string // search/telemetry tags
	Implemented bool     // shroud emits a working Go payload for it
	Summary     string   // one-line
	Flow        []string // ordered execution steps
	Notes       string   // caveats / pairing advice
}

// Techniques is the ordered registry.
var Techniques = []Technique{
	{
		ID: "pe01", Name: "Local Process Shellcode", Category: CatClassic, Subtech: "T1055",
		Tags:        []string{"local", "VirtualAlloc", "CreateThread"},
		Implemented: true,
		Summary:     "Allocate RWX (or RW->RX) memory in the current process, copy shellcode, execute via a local thread.",
		Flow: []string{
			"VirtualAlloc executable memory in self",
			"memcpy shellcode into the region",
			"CreateThread on the region (or cast to function pointer)",
		},
		Notes: "Simplest possible primitive. Pair with dynamic-api + encryption to defeat static and IAT checks.",
	},
	{
		ID: "pe02", Name: "Remote Thread Injection", Category: CatClassic, Subtech: "T1055.003",
		Tags:        []string{"remote", "OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"},
		Implemented: true,
		Summary:     "Open a remote process, allocate+write shellcode, kick it off with CreateRemoteThread.",
		Flow: []string{
			"OpenProcess(target pid) -> PROCESS_ALL_ACCESS",
			"VirtualAllocEx(RWX) in target",
			"WriteProcessMemory(shellcode)",
			"CreateRemoteThread(entry = shellcode base)",
		},
		Notes: "Noisy: CreateRemoteThread + cross-process WPM are heavily telemetry'd. Reserve for lab/legacy targets.",
	},
	{
		ID: "pe03", Name: "Classic Injection + API Obfuscation", Category: CatClassic, Subtech: "T1055.001",
		Tags:        []string{"remote", "dynamic-api", "iat-bypass"},
		Implemented: true,
		Summary:     "PE02 flow but every Win32 API resolved at runtime via PEB walk + hashing -> clean IAT.",
		Flow: []string{
			"Resolve OpenProcess/VirtualAllocEx/WPM/CreateRemoteThread by hash",
			"Execute the PE02 flow through resolved pointers",
			"Resulting binary imports nothing suspicious",
		},
		Notes: "This is PE02 with -e dynamic-api. Generate pe02 and enable the dynamic-api evasion layer.",
	},
	{
		ID: "pe04", Name: "VirtualProtect RW->RX Bypass", Category: CatClassic, Subtech: "T1055",
		Tags:        []string{"local", "VirtualProtect", "rwx-avoid"},
		Implemented: true,
		Summary:     "Allocate RW, write shellcode, flip to RX with VirtualProtect only before execution — never RWX.",
		Flow: []string{
			"VirtualAlloc(PAGE_READWRITE)",
			"memcpy shellcode",
			"VirtualProtect(PAGE_EXECUTE_READ)",
			"execute",
		},
		Notes: "Avoids the standalone-RWX allocation heuristic that most EDRs flag.",
	},
	{
		ID: "pe05", Name: "Classic DLL Injection (LoadLibrary)", Category: CatDLL, Subtech: "T1055.001",
		Tags:        []string{"remote", "LoadLibrary", "dll"},
		Implemented: true,
		Summary:     "Force a remote process to LoadLibrary a path by injecting the path and calling LoadLibrary via CreateRemoteThread.",
		Flow: []string{
			"OpenProcess(target)",
			"VirtualAllocEx room for DLL path string",
			"WriteProcessMemory the ASCII path",
			"CreateRemoteThread(LoadLibraryA, arg = path)",
		},
		Notes: "Path is written to the target's memory and the DLL hits disk — detectable. Use reflective (pe06) or memory-only techniques for evasion.",
	},
	{
		ID: "pe06", Name: "Reflective DLL Injection", Category: CatDLL, Subtech: "T1055.001",
		Tags:        []string{"fileless", "reflective", "manual-map"},
		Implemented: true,
		Summary:     "Load a DLL straight from a memory buffer in the target — a manual mapper resolves imports/relocs and calls DllMain; nothing touches disk.",
		Flow: []string{
			"OpenProcess(target)",
			"VirtualAllocEx SizeOfImage RW + WriteProcessMemory headers + sections",
			"Resolve imports (LoadLibraryA/GetProcAddress in injector) + patch remote IAT",
			"Apply base relocations for the load bias",
			"VirtualProtectEx -> RX, CreateRemoteThread(DllMain, hinstDLL=base)",
		},
		Notes: "Manual-map variant. Supply a PE/DLL file via -s. EXPERIMENTAL: imports resolved in the injector (correct for system DLLs whose base is shared across processes; non-system imports may need an in-target resolver); DllMain is called via CreateRemoteThread with hinstDLL=base (fdwReason not set to DLL_PROCESS_ATTACH by this path). On-target verification required.",
	},
	{
		ID: "pe07", Name: "Lagos Island — Manual NTDLL Map (unhook)", Category: CatNTAPI, Subtech: "T1055.001",
		Tags:        []string{"unhook", "ntdll", "manual-map"},
		Implemented: true,
		Summary:     "Manually map a fresh copy of ntdll.dll without adding it to the PEB module list — overwrite EDR hooks with clean .text.",
		Flow: []string{
			"Open \\KnownDlls\\ntdll.dll (or read from disk)",
			"Map section privately",
			"Copy clean .text over the hooked ntdll .text",
		},
		Notes: "ALIAS (via layer) — this is the unhook evasion layer applied standalone to a local inject. Generate `pe07 -e unhook` for the full manual-ntdll-map + inject behavior; without -e unhook pe07 emits the local inject primitive (pe01-style RW->RX stage) that the unhook layer augments.",
	},
	{
		ID: "pe08", Name: "Process Hollowing", Category: CatHollowing, Subtech: "T1055.012",
		Tags:        []string{"suspended", "unmap", "hollow"},
		Implemented: true,
		Summary:     "Start a legit process suspended, unmap its image, write your shellcode in its place, fix contexts, resume — runs under a trusted identity.",
		Flow: []string{
			"CreateProcess(suspended) a signed binary (e.g. notepad)",
			"Read PEB.ImageBaseAddress of the suspended process",
			"NtUnmapViewOfSection(old image)",
			"Write payload (raw shellcode into hollowed base, or map a full PE)",
			"Update PEB.ImageBaseAddress + thread context Rip/Rcx",
			"ResumeThread",
		},
		Notes: "Image path on disk is legitimate; memory is the lie. Strong default for stealthy execution.",
	},
	{
		ID: "pe09", Name: "PE Injection (whole image)", Category: CatPE, Subtech: "T1055",
		Tags:        []string{"remote", "manual-map", "pe"},
		Implemented: true,
		Summary:     "Copy an entire portable executable into another process, apply relocations, execute its entrypoint in the remote context.",
		Flow: []string{
			"OpenProcess(target)",
			"VirtualAllocEx SizeOfImage RW + WriteProcessMemory headers + sections",
			"Resolve imports + patch remote IAT, apply base relocations",
			"VirtualProtectEx -> RX, CreateRemoteThread(AddressOfEntryPoint)",
		},
		Notes: "Manual-map variant. Supply a PE/EXE file via -s. EXPERIMENTAL: same import-resolution caveat as pe06 (system DLLs only). Combine with pe16 (module stomping) to land inside an existing legit module. On-target verification required.",
	},
	{
		ID: "pe10", Name: "AddressOfEntryPoint Injection (WPM magic)", Category: CatClassic, Subtech: "T1055",
		Tags:        []string{"remote", "wpm", "rx-region"},
		Implemented: true,
		Summary:     "Reuse the already-RX AddressOfEntryPoint region of the target via WriteProcessMemory — no VirtualAlloc(Ex) or VirtualProtect.",
		Flow: []string{
			"OpenProcess(target)",
			"moduleBaseByPID -> main module base (toolhelp module snapshot)",
			"ReadProcessMemory e_lfanew -> OptionalHeader.AddressOfEntryPoint",
			"WriteProcessMemory(shellcode) directly into the RX entry region",
			"CreateRemoteThread at the overwritten entrypoint",
		},
		Notes: "Avoids both alloc and protect calls. Detectable via WPM into RX cross-process. Fully code-generated.",
	},
	{
		ID: "pe11", Name: "APC Injection", Category: CatAPC, Subtech: "T1055.004",
		Tags:        []string{"apc", "queue", "thread"},
		Implemented: true,
		Summary:     "Queue a shellcode address as an APC onto a target thread's APC queue; it runs when the thread enters an alertable wait.",
		Flow: []string{
			"OpenProcess + threadIDByPID (TH32CS_SNAPTHREAD)",
			"VirtualAllocEx + WriteProcessMemory shellcode",
			"OpenThread + QueueUserAPC(shellcode, thread)",
		},
		Notes: "Needs an alertable thread. See pe12 (Early Bird) for the lifecycle-start variant. Fully code-generated.",
	},
	{
		ID: "pe12", Name: "Early Bird APC Injection", Category: CatAPC, Subtech: "T1055.004",
		Tags:        []string{"apc", "suspended", "lifecycle"},
		Implemented: true,
		Summary:     "Queue the APC before the process initialises: create suspended, QueueUserAPC on its main thread, resume — payload runs before main.",
		Flow: []string{
			"CreateProcess(suspended)",
			"QueueUserAPC(shellcode, main thread)",
			"ResumeThread -> APC fires before the image entry",
		},
		Notes: "Runs earlier than hollowing, often before EDR hooks initialise in-process. Template scaffold.",
	},
	{
		ID: "pe13", Name: "RWX Hunting + Injection", Category: CatMemory, Subtech: "T1055.011",
		Tags:        []string{"rwx-hunt", "reuse"},
		Implemented: true,
		Summary:     "Scan the target's address space for an already-RWX region and write shellcode there — no fresh RWX allocation requested.",
		Flow: []string{
			"OpenProcess(target)",
			"VirtualQueryEx walk target VA space",
			"Locate a committed PAGE_EXECUTE_READWRITE region",
			"WriteProcessMemory shellcode into it",
			"CreateRemoteThread at the reused region",
		},
		Notes: "Defeats the 'new RWX allocation' heuristic. Fully code-generated.",
	},
	{
		ID: "pe14", Name: "Process Ghosting", Category: CatGhosting, Subtech: "T1055",
		Tags:        []string{"fileless", "pending-delete", "section"},
		Implemented: true,
		Summary:     "Create a file, mark it for deletion, map it as a section, close the handle (file vanishes), spawn a process from the fileless image section, run shellcode in it.",
		Flow: []string{
			"Read a sacrificial PE from disk for the image section",
			"NtCreateFile(temp) + NtWriteFile(PE) + NtSetInformationFile(FileDispositionInfo=DeletePending)",
			"NtCreateSection(SEC_IMAGE, temp file)",
			"Close file handle -> file deleted (never persisted on disk)",
			"NtCreateProcessEx from the fileless image section",
			"Stage shellcode (VirtualAllocEx+WPM+RX) + NtCreateThreadEx in the ghosted process",
		},
		Notes: "Image never exists on disk in a scannable state. Code-generated (EXPERIMENTAL: NT file-I/O struct layouts + NtCreateProcessEx PEB init require Windows on-target verification).",
	},
	{
		ID: "pe15", Name: "Remote Thread Hijacking", Category: CatHijack, Subtech: "T1055",
		Tags:        []string{"hijack", "context", "suspend"},
		Implemented: true,
		Summary:     "Suspend an existing remote thread, rewrite its context (Rip) to point at shellcode, resume — no new thread created.",
		Flow: []string{
			"OpenProcess + threadIDByPID (TH32CS_SNAPTHREAD)",
			"VirtualAllocEx + WriteProcessMemory shellcode",
			"OpenThread + SuspendThread + Get/SetThreadContext (Rip = shellcode) + ResumeThread",
		},
		Notes: "No CreateRemoteThread telemetry. Fully code-generated.",
	},
	{
		ID: "pe16", Name: "Module Stomping", Category: CatStomp, Subtech: "T1055.002",
		Tags:        []string{"module", "stomp", "legit"},
		Implemented: true,
		Summary:     "Load a legitimate DLL into the target, overwrite its .text with shellcode — execution appears to come from a trusted, signed module.",
		Flow: []string{
			"OpenProcess(target) + force-load a legit DLL (CreateRemoteThread LoadLibraryA)",
			"moduleBaseByPID -> DLL base; read .text bounds from remote PE headers",
			"VirtualProtectEx(.text -> RW) and WriteProcessMemory shellcode",
			"VirtualProtectEx back to RX, CreateRemoteThread at the stomped .text",
		},
		Notes: "Remote variant: the stomped region is backed by a legit, signed module — defeats 'unbacked executable memory' checks. Supply the stomp-target DLL path via --dll (default C:\\Windows\\System32\\wbemcomn.dll). Fully code-generated.",
	},
	{
		ID: "pe17", Name: "PEB Walk Injection", Category: CatPEB, Subtech: "T1055",
		Tags:        []string{"peb", "dynamic-resolve"},
		Implemented: true,
		Summary:     "Walk the PEB to find kernel32 and resolve VirtualAllocEx/WPM/CreateRemoteThread at runtime — no static imports to suspicious APIs.",
		Flow: []string{
			"PEB -> Ldr -> InLoadOrderModuleList -> find kernel32 base",
			"Walk export table, resolve each API by name",
			"Run the PE02 flow through the resolved pointers",
		},
		Notes: "ALIAS (via layer) — every Go-rewrite technique already resolves APIs via a PEB walk + DJB2 hash, so pe17 is the pe02 body. Generate `pe17 -e dynamic-api` for the explicit dynamic-api layer (the IAT contains only the Go-runtime baseline). Equivalent to `pe02 -e dynamic-api`.",
	},
	{
		ID: "pe18", Name: "PEB Walk + API Obfuscation", Category: CatPEB, Subtech: "T1055",
		Tags:        []string{"peb", "dynamic-api", "layered"},
		Implemented: true,
		Summary:     "PE17 plus full call-site obfuscation — defeats both static import analysis and naive dynamic monitoring.",
		Flow: []string{
			"PEB walk to resolve APIs (pe17)",
			"Layer call-site obfuscation / indirect invocation",
			"Execute remote inject",
		},
		Notes: "ALIAS (via layer) — pe17 with the dynamic-api layer plus indirect invocation. Generate `pe18 -e dynamic-api` (every API is resolved by PEB walk + DJB2 hash and invoked through wincall's indirect path). Equivalent to `pe02 -e dynamic-api`.",
	},
	{
		ID: "pe19", Name: "NtCreateSection + NtMapViewOfSection", Category: CatNTAPI, Subtech: "T1055",
		Tags:        []string{"section", "ntapi", "shared-memory"},
		Implemented: true,
		Summary:     "Create a shared section, map it into both processes, write shellcode locally, execute remotely — no cross-process WriteProcessMemory.",
		Flow: []string{
			"NtOpenProcess(target)",
			"NtCreateSection(SEC_COMMIT, PAGE_EXECUTE_READWRITE) in self",
			"NtMapViewOfSection(self, RW) + NtMapViewOfSection(target, RX)",
			"memcpy shellcode into the local view (shared with target)",
			"NtCreateThreadEx on the remote view",
		},
		Notes: "No WPM call at all — a classic telemetry gap. Fully code-generated (NT APIs throughout).",
	},
	{
		ID: "pe20", Name: "Mokingjay", Category: CatAbuse, Subtech: "T1055",
		Tags:        []string{"rwx-abuse", "vulnerable-dll"},
		Implemented: true,
		Summary:     "Abuse an already-RWX region shipped inside a vulnerable DLL (e.g. msys-2.0.dll) to host shellcode — no suspicious allocation.",
		Flow: []string{
			"LoadLibraryA the vulnerable DLL in self",
			"VirtualQuery-scan the loaded image for a committed RWX region",
			"Write shellcode into the existing RWX region (no alloc, no protect)",
			"CreateThread at the hijacked RWX region",
		},
		Notes: "Local self-inject variant. Supply the vulnerable DLL name via --dll (default msys-2.0.dll). EXPERIMENTAL / target-specific: which DLLs ship RWX sections varies by Windows build and installed software; the default is only present with MSYS2 installed. On-target verification required.",
	},
	{
		ID: "pe21", Name: "Fork API Injection (Dirty Vanity)", Category: CatAbuse, Subtech: "T1055",
		Tags:        []string{"fork", "rtlcreateprocessreflection"},
		Implemented: true,
		Summary:     "Write shellcode into your own process, then fork it with RtlCreateProcessReflection — the forked copy runs your shellcode under a fresh PID.",
		Flow: []string{
			"Stage shellcode in self (local RW->RX or module-stomp)",
			"RtlCreateProcessReflection -> child is a copy with shellcode already resident at the same VA",
			"NtCreateThreadEx in the child at the inherited address -> no cross-process write",
		},
		Notes: "Evades injection-focused hooks because nothing is written cross-process. Code-generated (EXPERIMENTAL: RtlCreateProcessReflection is an undocumented ntdll export; struct layout + reflected-thread state require Windows on-target verification).",
	},
	{
		ID: "pe22", Name: "Injection via Fibers", Category: CatFibers, Subtech: "T1055",
		Tags:        []string{"fibers", "cooperative"},
		Implemented: true,
		Summary:     "Convert the thread to a fiber, create a fiber whose entry is shellcode, switch to it — no new OS thread created.",
		Flow: []string{
			"ConvertThreadToFiber",
			"CreateFiber(entry = shellcode)",
			"SwitchToFiber -> runs shellcode in user-mode cooperative context",
		},
		Notes: "No thread-creation event. Fully code-generated.",
	},
	{
		ID: "pe23", Name: "NT API Injection", Category: CatNTAPI, Subtech: "T1055.001",
		Tags:        []string{"ntapi", "undocumented", "ntcreateprocessex"},
		Implemented: true,
		Summary:     "Remote injection done entirely with undocumented ntdll APIs (NtOpenProcess / NtAllocateVirtualMemory / NtWriteVirtualMemory / NtCreateThreadEx).",
		Flow: []string{
			"NtOpenProcess(target)",
			"NtAllocateVirtualMemory(RW or RWX) in target",
			"NtWriteVirtualMemory(shellcode)",
			"NtProtectVirtualMemory(->RX) if needed",
			"NtCreateThreadEx(shellcode)",
			"NtWaitForSingleObject(thread)",
		},
		Notes: "Skips kernel32 entirely. Use pe24/pe25 for direct/indirect syscalls one layer deeper than even ntdll.",
	},
	{
		ID: "pe24", Name: "Direct Syscalls", Category: CatSyscalls, Subtech: "T1055.004",
		Tags:        []string{"direct-syscall", "hook-bypass", "kernel"},
		Implemented: true,
		Summary:     "Invoke the syscall instruction directly from a stub in your own module — transition to the kernel without entering ntdll's hooked stubs.",
		Flow: []string{
			"Resolve syscall SSN + numbers for the Nt* routines needed",
			"Stub: mov r10,rcx; mov eax,<ssn>; syscall; ret",
			"Drive the PE23 flow through the stubs",
		},
		Notes: "Bypasses all userland hooks but the 'syscall from non-ntdll memory' return address is itself a detection — see pe25.",
	},
	{
		ID: "pe25", Name: "Indirect Syscalls", Category: CatSyscalls, Subtech: "T1055.004",
		Tags:        []string{"indirect-syscall", "ntdll-origin", "hook-bypass"},
		Implemented: true,
		Summary:     "Like pe24, but jump to the literal `syscall` instruction inside ntdll.dll — return address and stack originate from ntdll.",
		Flow: []string{
			"Resolve SSNs (as pe24)",
			"Locate a `syscall; ret` gadget inside ntdll .text",
			"Stub: mov r10,rcx; mov eax,<ssn>; jmp <ntdll syscall gadget>",
			"Drive the PE23 flow; every transition originates in ntdll memory",
		},
		Notes: "Strongest userland evasion in the series. Still visible to kernel callbacks — pair with sleep + encryption for memory scanners.",
	},
	{
		ID: "pe26", Name: "Modern Implant Loader", Category: CatClassic, Subtech: "T1055",
		Tags:        []string{"implant", "aes", "stomp", "callbacks", "layered"},
		Implemented: true,
		Summary:     "shroud's purpose-built modern loader: decrypt-at-rest (AES-256-CBC), stage into backed memory via module stomping, execute through a callback API — on top of dynamic-API/DJB2 resolution, AMSI/ETW patching and KnownDlls unhooking.",
		Flow: []string{
			"evasion.init: resolve APIs via PEB/DJB2, patch AMSI/ETW, unhook ntdll (KnownDlls)",
			"AES-256-CBC decrypt the staged payload in place",
			"Stage: module-stomp into a legit DLL's .text (backed memory) [if -e stomp]",
			"Execute via CreateTimerQueueTimer (no CreateThread) [if -e callbacks]",
		},
		Notes: "The loader to test against a modern EDR. It is NOT a single injection trick — it is the composed stack. Add/remove layers with -e.",
	},
}

// ByID returns the technique for a canonical id (e.g. "pe08"), or nil.
func ByID(id string) *Technique {
	for i := range Techniques {
		if Techniques[i].ID == id {
			return &Techniques[i]
		}
	}
	return nil
}

// All returns every technique, in registry order.
func All() []Technique { return Techniques }

// Implemented returns the fully code-generated techniques.
func Implemented() []Technique {
	var out []Technique
	for _, t := range Techniques {
		if t.Implemented {
			out = append(out, t)
		}
	}
	return out
}

// ByCategory groups techniques by category in CategoryOrder.
func ByCategory() map[Category][]Technique {
	groups := make(map[Category][]Technique)
	for _, c := range CategoryOrder {
		groups[c] = nil
	}
	for _, t := range Techniques {
		groups[t.Category] = append(groups[t.Category], t)
	}
	return groups
}

// Resolve accepts "pe08", "PE 08", "8", "08", or a slug/name substring.
// Range is 1..26 (the Python tool capped at 25 — fixed here for pe26).
func Resolve(query string) (*Technique, error) {
	q := slugify(query)
	if t := ByID(q); t != nil {
		return t, nil
	}
	if n, err := parseInt(q); err == nil {
		if n >= 1 && n <= 26 {
			return ByID(fmt.Sprintf("pe%02d", n)), nil
		}
	}
	for i := range Techniques {
		t := &Techniques[i]
		slug := slugify(t.Name)
		if strings.Contains(slug, q) || strings.Contains(t.ID, q) {
			return t, nil
		}
	}
	return nil, fmt.Errorf("no technique matching %q (try: pe26, 8, hollowing)", query)
}

// slugify lowercases and strips spaces + dashes so multi-word queries match
// against multi-word technique names regardless of separator.
func slugify(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "-", "")
	return s
}

func parseInt(s string) (int, error) {
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("not a number")
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}