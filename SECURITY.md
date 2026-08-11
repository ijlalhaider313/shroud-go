# Security & Responsible Use

## Scope of authorization

shroud generates offensive code — Windows process-injection implants with EDR-evasion
layers — for **authorized red-team, penetration testing, and security-research use
only**. It is a dual-use tool: the same capability that lets a defender validate an
EDR deployment lets an attacker bypass it.

**You are responsible for engagement scope, written consent, and compliance with all
applicable law.** Use shroud only against systems you own or are explicitly and
documentedly authorized to test. Unauthorized use is illegal in most jurisdictions.

## Authorization gate

`generate` and `build` are gated behind a one-time, local authorization marker:

```bash
./shroud authorize        # interactive (prompts YES)
./shroud authorize --yes   # non-interactive (scripts)
```

This writes `~/.shroud_authorized`. It is a **speed-bump and statement of intent, not
a security control** — it never phones home, stores no identity, and can be trivially
created by hand. Its purpose is to ensure the operator has consciously acknowledged
the authorized-use terms on this machine before generating offensive code. Removing
the marker re-arms the gate.

The gate is implemented in `internal/authorize/auth.go`. It cannot be circumvented by
a flag; the only way past it is the marker file, which is the point.

## Web console

`shroud web` starts a **local-only** browser console (`internal/web/`). It is a
convenience front for the same generate/deliver pipeline, not a remote service:

- **Loopback only.** The server binds `127.0.0.1` and `New` refuses any non-loopback
  bind. There is no TLS, no remote listener, no exposed port.
- **Bearer token.** A crypto-random hex token is generated at startup and printed to
  the terminal. Every `/api/*` request requires `Authorization: Bearer <token>` or it
  is rejected with 401. The static frontend (the page itself, `/static/*`) is served
  without the token so the browser can load it; the token reaches the SPA via
  `?token=<hex>` (the `--browser` flag opens the URL with it) or operator paste.
- **Authorize gate still applies.** Browsing is fine, but the `/api/generate` endpoint
  additionally calls `authorize.Require()` and returns 403 until `shroud authorize`
  has been run. The web UI's `/api/authorize` endpoint can record the marker (the
  `--yes` path) as a local convenience; the shell command is equivalent.
- **Artifact download is path-traversal guarded.** Downloads are restricted to
  out-dirs a generate/deliver call registered *this session*; the cleaned absolute
  path must be inside a registered dir with no `..` escape, or the request is 403.
- **Same "never executes output" rule.** The web console calls the same
  `internal/ops` pipeline; it writes project files / artifacts to disk and reports
  paths — it never runs them.

The console is a local operator dashboard, never meant to be exposed to a network.

## The generator never executes output

A core safety property: shroud **compiles produced binaries but never runs them**, and
**writes delivery artifacts but never runs them either.** `internal/builder/build.go`
shells out `go build` (or `garble ... build`) and reports the artifact path and size —
it never invokes the resulting `.exe`/`.dll`. The delivery path (`internal/delivery`)
writes `.lnk`/`.hta`/`.ps1`/… files to disk and reports their paths — it never invokes
`mshta`, `cscript`, `regsvr32`, or any host program on them. Verification of an
artifact's behavior (e.g. "does it pop calc") is the operator's responsibility, to be
performed only against authorized targets (typically a local VM).

There is no code path in shroud that executes a produced artifact.

## What shroud is NOT

- **Not a weapon.** shroud does not include working exploits for unpatched
  vulnerabilities, credential-theft logic, or lateral-movement primitives. It generates
  loaders that wrap shellcode **you supply** (from your own tools — msfvenom, donut,
  Sliver, custom). The evasion layers defeat *detection*, not *authorization*.
- **Not anonymous.** The implant carries your shellcode and your C2 configuration.
  OPSEC measures (IAT hygiene, garble, AMSI/ETW patching, unhooking) raise the cost of
  detection; they do not provide anonymity or immunity from a competent defender.
- **Not a security boundary.** The authorization gate is voluntary and local.

## Delivery formats

In addition to compiled implants (`exe|dll|c`), `generate -f` emits **delivery
artifacts** — launchers/droppers (`lnk`, `hta`, `sct`, `vba`, `ps1`, `xsl`, `js`,
`jse`) and raw shellcode (`raw`) — for the same authorized-use scope. The same
responsible-use rules apply:

- They wrap shellcode **you supply** or fetch a stage-2 **you host**. They contain no
  exploit of their own.
- **Inline mode** (`-s`/`--c2`) embeds your shellcode; **remote mode** (`--url`)
  fetches a stage-2 from a URL — use `--url` only with **your own** staging
  infrastructure on systems you control or are authorized to test against.
- The delivery path is still gated behind `shroud authorize` and the generator still
  **never executes** the produced artifact. Verifying a delivery artifact (e.g. "does
  the `.lnk` pop calc on double-click") is the operator's responsibility, on
  authorized targets only.

### Evasion scope (be explicit, don't oversell)

The heavy Go-runtime evasion stack (`-e dynamic-api/unhook/stomp/callbacks/amsi/etw`)
applies **only to `exe|dll|c`** (the compiled implant). Delivery formats are
launchers/droppers and cannot host that stack; they use native tricks (base64 transport
encoding, an AMSI-bypass prologue in the PowerShell stager, LOLBin choice). `-e` is
ignored for delivery formats. This is documented, not silently dropped — we do not
imply a `.lnk` carries the full implant evasion stack.

### Delivery-format verification caveat

The SCRENC (`.jse`) encoder and the LNK binary writer are verified by internal tests
(SCRENC round-trip over all 128 byte values; LNK header parse-back against pylnk3's
layout). **Windows on-target execution is the final verification step.** If a generated
`.jse` does not run under `cscript`/`wscript`, or a `.lnk` does not resolve on the
engagement target, fall back to `-f js` / `-f hta` (plaintext) — documented in the
README per format. We do not ship a delivery artifact as "verified working" without an
on-target check.

## What the evasion layers defeat (and what they don't)

| Layer | Defeats | Does NOT defeat |
|-------|---------|-----------------|
| `dynamic-api` | static IAT analysis | dynamic API tracing, ETW TI, memory scanning |
| `aes/rc4/xor` | on-disk & static signatures | runtime memory inspection after decrypt |
| `amsi` | AMSI content scan at load | kernel-mode callbacks, ETW TI |
| `etw` | userland ETW telemetry | kernel ETW, ETW Threat Intelligence |
| `unhook` / `unhook-kd` | userland hooks (EDR `ntdll` trampolines) | kernel callbacks, minifilters |
| `stomp` | unbacked-memory checks | RO memory scans of the stomped region |
| `callbacks` | `CreateThread` telemetry | callback-origin analysis |
| `sleep` | memory scanners that scan during the sleep window (region is RW ciphertext while idle) | active real-time inspection, kernel callbacks; opaque shellcode (meterpreter) is not auto-instrumented — a cooperative beacon must call `sleepScramble` from its own sleep path |

`sleep` has two tiers, selected by `--sleep-scheme`: **tier-1 `xor`** (default, stable)
inline-scrambles the staged region on the calling thread; **tier-2 `ekko`**
(EXPERIMENTAL) drives the encrypt/sleep/decrypt off the beacon thread via
`CreateTimerQueueTimer` + `wincall.NewCallback` (the Ekko/Foliage self-modifying
property). Both encrypt the STAGED PAYLOAD region, not the Go runtime `.text` (Ekko
encrypts its own `.text` because it is PIC shellcode; a compiled Go binary's `.text`
is the running runtime and must not be touched). Tier-2's callback bridge + timer
timing need Windows on-target verification; tier-1 is the safe default.

### Experimental techniques — on-target verification required

Five techniques are **code-generated but EXPERIMENTAL** — their bodies are complete
(not silent stubs) and they compile cleanly to a Windows PE, but their runtime behavior
needs Windows on-target verification before use on an engagement. They are not "verified
working" until run on a target:

- **`pe14` Process Ghosting** — NT file-I/O struct layouts, `NtCreateProcessEx` PEB init.
- **`pe21` Dirty Vanity** — `RtlCreateProcessReflection` (an undocumented ntdll export)
  and the reflected-thread state.
- **`pe06` Reflective DLL** + **`pe09` Whole-PE** — the manual PE mapper resolves
  imports **locally in the injector** (`LoadLibraryA`/`GetProcAddress`), which is correct
  for system DLLs whose base is shared across processes via KnownDLLs but may not hold
  for non-system imports (an in-target resolver may be needed). `DllMain` is kicked via
  `CreateRemoteThread` with `hinstDLL=base`; the `fdwReason` is not set to
  `DLL_PROCESS_ATTACH` by this path.
- **`pe20` Mokingjay** — target-specific: which DLLs ship an existing `PAGE_EXECUTE_
  READWRITE` section varies by Windows build and installed software. The default
  (`msys-2.0.dll`) is only present with MSYS2 installed; on a target without a RWX-section
  DLL the operator must supply a known one via `--dll`.

Use `pe01`/`pe02`/`pe08`/`pe11`/`pe12`/`pe15`/`pe23`/`pe26` as the verified-technique
baseline; `pe10`/`pe13`/`pe16`/`pe19` are fully code-generated and not flagged
experimental, but as with all techniques, Windows on-target validation is the final
verification step.

The three "via layer" aliases — `pe07` (routes to `pe01` + `-e unhook`), `pe17`/`pe18`
(route to `pe02` + `-e dynamic-api`) — are not experimental; they reuse verified bodies
and are activated by their matching evasion layer.

Explicitly **out of scope** (stated in the plan): kernel-callback evasion (ETW Threat
Intelligence, minifilters, object-notify callbacks) — shroud is userland-only. There is
no packed-output mode; wrap with your own packer for static-AV avoidance.

## IAT hygiene

A plain Go binary imports the runtime's kernel32 baseline
(`GetProcAddress`, `LoadLibraryExW`, `VirtualAlloc`, `CreateThread`) — unavoidable for
any Go binary. With `dynamic-api`, all *offensive* Win32 APIs are resolved at runtime
via a PEB walk + DJB2 hash, so the IAT contains only that baseline. Verify with:

```bash
objdump -p out/<id>/implant.exe | grep -Ei 'CreateRemoteThread|WriteProcessMemory|OpenProcess|VirtualAllocEx|AmsiScanBuffer|EtwEventWrite'
```

This is a detection-cost measure, not an invisibility guarantee — a defender tracing
API resolution dynamically will still see the calls. Honest about this in the docs
rather than overselling "undetectable."

## Reporting issues

This is a private red-team tool. For responsible disclosure of *shroud's own* bugs
(that could cause unsafe behavior, not bypass its own gate — the gate is intentionally
local), contact the maintainer directly. Do not file public issues that disclose
detection-bypass techniques in a way that aids malicious use.

## Liability

The authors grant no authorization to attack any system and accept no liability for
misuse. Using shroud against a system you do not own or lack written authorization to
test is your crime, not the authors'.