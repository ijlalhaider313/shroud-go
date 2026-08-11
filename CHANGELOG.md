# Changelog

All notable changes to shroud-go. Dates are absolute. This project follows a phase-based
release model (see `../.claude/plans/lucky-noodling-twilight.md` for the full plan).

## [Phase K] — 2026-08-11 — final 7 techniques + 3 aliases: all 26 code-generated

Closes the catalog. The 7 distinct techniques that were still flagged "planned/scaffold"
are now real Go bodies, and the 3 "via layer" aliases are routed + documented so they no
longer show as unimplemented. **All 26 catalog entries now emit a complete body — none are
scaffolds.** Implemented count 16 → 26.

### Added — 7 distinct technique bodies (`internal/payload/remote.go`, `technique_bodies.go`)

- **pe13 RWX hunting** (`pe13Body`): OpenProcess + `VirtualQueryEx` scan of the remote
  address space for an existing `PAGE_EXECUTE_READWRITE` region (reuses a legit RWX
  section a DLL already mapped), `WriteProcessMemory` shellcode into it,
  `CreateRemoteThread`. Defeats the "new RWX allocation" heuristic — no VirtualAllocEx.
- **pe10 AddressOfEntryPoint overwrite** (`pe10Body`): OpenProcess + module enum
  (`moduleEnumHelper`: `CreateToolhelp32Snapshot` TH32CS_SNAPMODULE +
  `Module32FirstW/NextW` to find the target's main module base) + `ReadProcessMemory`
  e_lfanew → OptionalHeader → `AddressOfEntryPoint` (offset e_lfanew+0x28) +
  `WriteProcessMemory` the entry RVA to point at staged shellcode. No allocation, no new
  thread — the process's own entry is hijacked. `CreateRemoteThread` re-trigger optional.
- **pe16 module stomping (remote)** (`pe16Body`): force-load a legit signed DLL into the
  remote process (`CreateRemoteThread`→`LoadLibraryA` on the `--dll` stomp target, default
  `C:\Windows\System32\wbemcomn.dll`), locate its `.text` bounds by basename
  (`moduleEnumHelper`), `ReadProcessMemory` the original .text (save),
  `VirtualProtectEx` RW → `WriteProcessMemory` shellcode → `VirtualProtectEx` RX. The
  staged region is backed by a legit signed module — defeats "unbacked executable memory"
  checks. Uses `--dll` for the stomp target.
- **pe19 section mapping** (`pe19Body`): `NtCreateSection` (SEC_COMMIT, local) +
  `NtMapViewOfSection` into *both* self (RW) and the target (RX), copy shellcode into the
  local view (the remote view sees it — shared section backing), `NtCreateThreadEx` in the
  target at the remote view base. **No `WriteProcessMemory` at all** — the section is the
  cross-process write. NT APIs throughout (reuses the `ntStructs` clientId/objAttrs
  helper). `GetCurrentProcess` for the local map.
- **pe06 reflective DLL** + **pe09 whole-PE** (`peLoaderHelper` + `pe06Body`/`pe09Body`):
  a shared manual PE mapper (`manualMapPE`) — `rvaToOff` (section-table RVA→file-offset
  walk), copy headers + sections into a remote `VirtualAllocEx` (SizeOfImage) region,
  resolve imports **locally in the injector** (`LoadLibraryA`/`GetProcAddress` — correct
  for system DLLs whose base is shared across processes via KnownDLLs) and patch the
  remote IAT via `WriteProcessMemory`, apply `IMAGE_REL_BASED_DIR64` relocations (RPM read
  + WPM write), flip RX. pe06 kicks off `DllMain` (CreateRemoteThread with
  `hinstDLL=base`); pe09 kicks off the PE entry point. Both **EXPERIMENTAL**: the local
  import resolution holds for system DLLs but non-system imports may need an in-target
  resolver; `DllMain`'s `fdwReason` is not set to `DLL_PROCESS_ATTACH` by this path.
  pe09 composes with pe16 (stomp into a legit module). Supply the PE/DLL via `-s`.
- **pe20 Mokingjay** (`pe20Body`, local): `LoadLibraryA` a DLL that ships a RWX section
  (default `--dll msys-2.0.dll`), `VirtualQuery` walk self to find that section's RWX
  region, copy shellcode in, `CreateThread` locally. No VirtualProtect, no allocation —
  borrows an existing executable writable section. **EXPERIMENTAL / target-specific**:
  which DLLs ship RWX sections varies by Windows build and installed software; the default
  is only present with MSYS2 installed. Routed in the `localRun` family.

### Modified — 3 "via layer" aliases (`catalog/techniques.go`, dispatch)

- **pe07** (Local + API Obfuscation) → routes to the `pe01` local inject body; activated
  by `-e unhook` (the manual-ntdll-map + unhook layer). Without `-e unhook` it emits the
  plain local inject primitive.
- **pe17** (Remote + API Obfuscation) → routes to the `pe02` remote-thread body; every
  Go-rewrite technique already resolves APIs via PEB walk + DJB2, so pe17 is pe02 with
  `-e dynamic-api` (IAT shows only the Go-runtime baseline).
- **pe18** (Remote + Indirect API Obfuscation) → pe17's body; `-e dynamic-api` resolves
  each API by hash and invokes through wincall's indirect path.
- All three are marked `Implemented: true` with Notes explaining the alias relationship
  (`ALIAS (via layer) —`); `show`/`list` display the notes. No new `Alias` struct field —
  the Notes text carries the relationship (minimal surface change).

### Catalog + dispatch (`internal/catalog/techniques.go`, `internal/payload/technique_bodies.go`)

- `Implemented: true` flipped for pe06/pe07/pe09/pe10/pe13/pe16/pe17/pe18/pe19/pe20.
  Header comment rewritten: "all 26 techniques are code-generated", explains the alias
  set + the EXPERIMENTAL list (pe14/pe21/pe06/pe09/pe20). Flow arrays updated for the 7
  new bodies to reflect the actual code-generated steps.
- `techniqueBody()`: `localRun` family gains pe20; `remoteRun` family gains
  pe06/pe09/pe10/pe13/pe16/pe17/pe18/pe19. `localRun()` emits `pe20Mokingjay(payload)`
  (early return, like pe07/pe21/pe22). `remoteRun()` emits `moduleEnumHelper()` for
  pe10/pe16 and `peLoaderHelper()` for pe06/pe09. `scaffoldRun()` is now dead code (no
  technique hits the default) — left in place (unused methods are legal Go).
- `internal/ops/ops.go` — `--dll` flag help updated to cover pe16/pe20.

### Tests

- `internal/payload/technique_bodies_test.go` — `TestPe13Body`, `TestPe10Body`,
  `TestPe16Body`, `TestPe19Body` (asserts `hWriteProcessMemory` **absent** — section
  mapping writes via the shared section, not WPM), `TestPe06Body`, `TestPe09Body`,
  `TestPe20Body`, `TestPe07Alias`, `TestPe17Pe18Alias`. `TestNewTechniquesCrossCompile`
  list extended to all 10: pe06/pe09/pe10/pe13/pe16/pe19/pe20/pe07/pe17/pe18.
- `internal/catalog/techniques_test.go` — `TestImplementedCount` expects 26 (was 16);
  comment updated to name the alias + EXPERIMENTAL sets.

### Verified

- `go build ./...`, `go vet ./...`, `go test ./...` all green. `SHROUD_COMPILE_TEST=1`
  cross-compile (GOOS=windows) passes for all 10 new entries.
- `shroud list` → "26 techniques (26 code-generated)" — every entry marked `*`, none `.`.
- Generated all 10 end-to-end (`-f c` headers): pe06/pe09/pe10/pe13/pe16/pe19/pe20/pe07/
  pe17/pe18 — each produces a `payload.h`.
- pe13 built to a real Windows EXE: `generate pe13 -f exe -s /tmp/sc.bin -e dynamic-api
  -o out/pe13exe` → PE32+ x86-64, 8 sections.
- **IAT hygiene** on pe13exe: offensive APIs (`CreateRemoteThread`, `WriteProcessMemory`,
  `OpenProcess`, `VirtualQueryEx`, `VirtualAllocEx`, `VirtualProtectEx`) all **absent** —
  resolved at runtime via PEB walk + DJB2 hash (dynamic-api). Only the Go-runtime
  `VirtualQuery`/`VirtualAlloc` baseline appears (identical to the pe26 control binary —
  pe13 uses `VirtualQueryEx`, not `VirtualQuery`, so the baseline match is not the
  offensive API).
- `show pe07`/`pe17`/`pe18` display the "ALIAS (via layer) —" notes; `show pe13` displays
  the full technique.
- Docs: README status 16→26, techniques table expanded to all 26 with `†`/`~` legend,
  roadmap + `--dll` flag row; SECURITY experimental-techniques section adds pe06/pe09/pe20.

## [Phase J] — 2026-08-11 — stretch: pe14 ghosting + pe21 dirty vanity + msfrpc + Ekko tier-2

Builds the deferred stretch items from the approved plan (Phase E/F/G stretch).

- **Phase E stretch — pe14 Process Ghosting + pe21 Dirty Vanity** (`internal/payload/remote.go`,
  `technique_bodies.go`, `catalog/techniques.go`): two new code-generated injection
  techniques, bringing the implemented count 14 → 16. pe14 ghosts a sacrificial PE
  (NtCreateFile + NtWriteFile + NtSetInformationFile DeletePending + NtCreateSection
  SEC_IMAGE + NtClose + NtCreateProcessEx) then stages shellcode + NtCreateThreadEx in
  the fileless process. pe21 stages shellcode in self, forks via
  RtlCreateProcessReflection, and NtCreateThreadEx in the child at the inherited VA
  (no cross-process WriteProcessMemory). Both are **EXPERIMENTAL** — code-generated
  with the full NT API sequence, flagged for Windows on-target verification of the
  struct layouts / undocumented-export behavior (per the plan's "no broken bodies"
  caveat). Compile-correctness + GOOS=windows cross-compile gates pass.
- **Phase F stretch — msfrpc C2 provider** (`internal/c2/msfrpc/`): a MessagePack-RPC
  client (`github.com/vmihailenco/msgpack/v5`) driving a LIVE msfrpcd — `auth.login`
  → token, `module.execute` on a payload module → raw shellcode bytes. Flat-array wire
  form `["method",args...]` + map responses per the official Metasploit RPC API, with
  array-unwrap + error-map handling for version variance. Self-signed-cert tolerant
  (`--msfrpc-insecure`, default true). Preflight contacts the daemon (auth.login) so
  `c2 preflight msfrpc` is a real reachability check. httptest-mock tests cover
  login/generate/error/missing-flags/Fetch end-to-end with no live msfrpcd. Runtime
  verification of the module.execute result shape across versions is the operator's step.
- **Phase G stretch — Ekko/Foliage sleep tier-2** (`internal/payload/sleep.go`): a new
  `--sleep-scheme ekko` selection (default `xor` = tier-1) implementing timer-driven
  self-modifying sleep. The beacon thread parks in WaitForSingleObject on an event while
  a `CreateTimerQueueTimer` callback (bridged via `wincall.NewCallback`) runs
  encrypt→sleep→decrypt→wake on a TIMER THREAD — the self-modification runs OFF the
  beacon thread (the Ekko/Foliage property). shroud encrypts the STAGED PAYLOAD region
  (not the Go runtime .text, which Ekko does because it is PIC shellcode). **EXPERIMENTAL**
  — the NewCallback bridge + timer timing need Windows on-target verification; tier-1
  `sleepScramble` remains the stable default. Cross-compiles to a Windows EXE.
- Tests: `TestPe14Body`, `TestPe21Body`, `TestEkkoSleepBody` + `TestEkkoSleepCrossCompile`
  (all behind `SHROUD_COMPILE_TEST=1` for the Windows build); `internal/c2/msfrpc`
  httptest suite; `catalog` implemented-count 14 → 16.
- Docs: README status/C2-table/evasion-table/roadmap updated; SECURITY unchanged.

## [Phase I] — 2026-08-10 — local web console + ops factoring

Adds a local-only browser console (`shroud web`) that surfaces the catalog, generate
and deliver forms, the C2 providers, and artifact download — calling the *same*
`internal/*` packages the CLI does, so there is one implementation of generate/deliver
behind two fronts.

### Added

- `internal/ops/ops.go` — the factored generate/deliver pipeline. `Generate(cmd, args)`
  and `Deliver(cmd, args, format)` take a `*cobra.Command` whose flags are already set
  (the CLI passes its real command; the web layer builds one from JSON) and return a
  structured `GenerateResult`/`DeliverResult` + error. They do NOT `os.Exit`, do NOT
  print, and do NOT call `authorize.Require` — that's the caller's job. This is the
  key move: keeping the providers cobra-coupled (`Fetch(cmd *cobra.Command)` reads flags
  off the command) while giving us "one implementation, two fronts". Also exports
  `AddGenerateFlags(fs)` (the single source of truth for the generate flag surface,
  shared by the CLI and the web handler), `FlagValue(fs, name, v)` (set a flag from a
  JSON-decoded value), and `ProviderFlags(p)` (reflect a provider's flag schema via
  pflag for the web UI's dynamic C2 forms — no `Provider` interface change).
- `internal/web/` — stdlib `net/http` + `//go:embed` SPA, zero new deps:
  - `server.go` — `Server{New, ListenAndServe, Handler}`. Bound to 127.0.0.1 only
    (`New` refuses non-loopback binds); crypto-random hex bearer token (printed at
    startup); `requireBearer` middleware (401 without a valid `Authorization: Bearer
    <token>`); `requireAuthz` middleware (additionally `authorize.Require()` → 403 on
    generate/deliver); session-scoped out-dir allowlist with a path-traversal guard
    (`safePath`: the cleaned absolute path must be inside a registered dir, no `..`
    escape). Static frontend (`, /static/*`) is served ungated so the browser can load
    the page; only `/api/*` is gated.
  - `handlers.go` — JSON API: `GET /api/status` (authorized? + c2 + formats + technique
    count), `GET /api/catalog`, `GET /api/evasion`, `GET /api/formats`, `GET /api/c2`
    (+ per-provider flag schema), `GET /api/c2/{name}/flags`, `POST /api/generate`
    (builds a cobra command from the JSON `flags` map, dispatches to `ops.Generate`
    or `ops.Deliver` by format, returns technique/format/evasion/outdir/built info +
    per-artifact `download_url`s), `GET /api/artifact?path=` (guarded download,
    `Content-Disposition: attachment`), `POST /api/authorize` (the `--yes` path).
  - `frontend/{index.html,app.js,style.css}` — vanilla-JS SPA (no npm, no CDN,
    CSP `default-src 'self'`). Tabs: Catalog / Generate / Deliver / C2 / Evasion.
    Generate + Deliver forms render per-provider C2 flag fields dynamically from
    `/api/c2`. The bearer token is read from `?token=<hex>` (the CLI's `--browser`
    flag opens the URL with it) or pasted by the operator; kept in `sessionStorage`.
  - `internal/web/web_test.go` — httptest-based: 401 without token, catalog count ==
    `catalog.All()`, formats + c2 shape, generate 403 when unauthorized + 200 after
    the authorize endpoint, delivery emit + artifact download (same-session) +
    traversal-escape 403, implant source-only (`pe26 -f c` writes `payload.h`),
    non-loopback bind refusal, static index/app.js served.
- `cmd/shroud/main.go` — `web` subcommand: `shroud web [--addr 127.0.0.1:7780]
  [--token <hex>] [--browser]`. Prints URL + token; `--browser` opens the default
  browser to the URL with the token appended (best-effort). Browsing is ungated; the
  generate/deliver *endpoints* are gated.

### Modified

- `cmd/shroud/main.go` — `runGenerate`/`runDeliver` rewritten as thin wrappers that
  call `ops.Generate`/`ops.Deliver` (keeping authorize, the banner, the `-e list`
  shortcut, printing, and `os.Exit` in the CLI layer). The inline flag registration in
  `cmdGenerate` is replaced by `ops.AddGenerateFlags(c.Flags())` (single source of
  truth; the web handler calls the same function). Removed the now-dead
  `loadShellcode`/`encryptPayload`/`dropCryptoConflict`/`removeLayer` helpers (their
  logic lives in `ops`; `cmdSliver`/`cmdC2*` were verified not to call them). Dropped
  the now-unused `payload`/`shellcode` imports. Added `web` + `ops` imports.

### Behavior changes (minor)

- The CLI no longer prints the `c2: <source> — <bytes> (built in <time>)` line when a
  `--c2` provider supplies shellcode; it prints the standard `shellcode: <source>`
  line instead (the provider source label is still shown). Cosmetic only.

### Verified

- `go build ./...`, `go vet ./...`, `go test ./...` all green (including the new
  `internal/web` tests and the unaffected cached suites).
- CLI regression: `shroud generate -f vbs` / `-f hta --url` / `generate pe26 -f c` /
  `-f exe -e ...` behave as before (delivery + implant paths both confirmed).
- Live web: `shroud web` → `http://127.0.0.1:7781/?token=…`; `curl` without token →
  401; with token → `/api/status` (authorized, c2=[donut,metasploit,sliver], 26
  techniques), `/api/catalog` (26, 14 implemented), `/api/c2` (3 providers + flag
  schemas); `POST /api/generate` delivery (vbs) → artifact + download_url; same-session
  `GET /api/artifact` → 200 (2054 bytes), `/etc/passwd` + `../`-escape → 403; implant
  `pe26 -f c` → `payload.h` written; unknown flag → 400.

## [Phase H] — 2026-08-10 — vbs + wsf delivery formats

Adds two more delivery-format emitters, mirroring the existing `js`/`sct`/`hta`
thin-emitter pattern. The delivery vocabulary goes 9 → 11 formats.

### Added

- `internal/delivery/vbs.go` — `vbsEmitter` (`.vbs`): VBScript run via
  `cscript //nologo payload.vbs`. `WScript.Shell.Run "<cmd>", 0, False` (0 = hidden
  window, False = don't wait). Inline mode launches the embedded-shellcode powershell
  stager (`powershell -w hidden -enc <ps1InlineEnc>`); remote mode runs the launcher's
  LOLBin fetch primitive. Reuses `launcherInlineCmd`/`lolbinRemote` + the existing
  `vbsEscape` (quote-doubling) from `escapers.go`.
- `internal/delivery/wsf.go` — `wsfEmitter` (`.wsf`): a Windows Script File — an XML
  container (`<package><job><script language="JScript">…</script></job></package>`)
  wrapping the same JScript body `js.go` emits (CDATA-escaped, `WScript.Shell.Run`).
  Run via `cscript //nologo payload.wsf`. Inline + remote mirror `jsEmitter`. The XML
  schema mirrors `sct.go`'s structure but uses the WSF `<package><job>` schema instead
  of a scriptlet `<registration>` block.
- Both registered in `delivery.init()`; `delivery.IsDelivery` / `Formats()` pick them
  up automatically (registry-driven — no hardcoded format list).

### Modified

- `internal/delivery/emitters_test.go` — `vbs`/`wsf` added to the
  `TestEmitterOutputShape` table (inline + remote, `WScript.Shell` marker, raw
  shellcode absent) and `TestEmitMissingPayloadErrors`.
- `cmd/shroud/main.go` — `-f` vocabulary + the `generate` Long help text list the two
  new formats. (Delivery dispatch is registry-driven, so this is descriptive only.)

### Verified

- `go build ./...`, `go vet ./...`, `go test ./...` all green.
- `TestEmitterOutputShape/vbs_{inline,remote}` + `wsf_{inline,remote}` pass: one
  artifact with the right extension, `WScript.Shell` present, raw shellcode absent.
- `shroud generate -f vbs` → `payload.vbs` (VBScript + `powershell -enc` stager, raw
  shellcode base64-encoded). `shroud generate -f wsf --url <url>` → `payload.wsf`
  (WSF XML wrapper + JScript fetch). Both structurally valid.

## [Phase G] — 2026-08-10 — sleep evasion layer (tier-1; Ekko deferred)

Implements the last unimplemented evasion layer — `sleep` — as a working tier-1
scheme: while the beacon sleeps, the staged payload region is flipped to
PAGE_READWRITE and XOR-scrambled so a memory scanner sees no executable plaintext;
on wake the region is restored to RX and the I-cache is flushed. XOR is symmetric,
so the same routine decrypts. This mirrors the original Python tool's
`shroud_sleep_xor` primitive (VirtualProtect → xor_scramble → Sleep → xor_unscramble
→ restore → FlushInstructionCache), including the deterministic 16-byte sleep key
(`g_skey`). The evasion model now has all 11 layers implemented.

### Added

- `internal/payload/sleep.go` — the sleep-evasion body:
  - `sleepHelper()` emits the `sleepScramble(addr, n, ms)` primitive + the
    numeric-encoded `sleepKey` (16 bytes, no plaintext string in the binary), armed
    whenever `-e sleep` is active. Registers `VirtualProtect`, `Sleep`,
    `FlushInstructionCache` via `b.api()` (DJB2 hash, PEB-walk resolved — IAT clean).
    The helper is available for a cooperative beacon to call from its own sleep
    path; it is a legal unused package-level func when `--sleep` is not set.
  - `sleepRun()` / `sleepLoopBody()` — the self-contained demo path, armed by
    `--sleep <dur>`: stages the payload (RW->RX or module-stomp) and loops
    `sleepScramble` on the region (encrypt-RW → sleep → decrypt-RX), exercising the
    scanner-defeat primitive in isolation **without executing the shellcode**. A real
    beacon calls `sleepScramble` from its own sleep path instead of this loop.
- `internal/payload/technique_bodies.go` — `techniqueBody()` gains a sleep demo
  override: when `-e sleep` is active AND `--sleep > 0`, the technique's normal
  `run()` is replaced by `sleepRun()` (bypasses the technique body). Without
  `--sleep`, only the helper is emitted (the technique runs normally; a custom beacon
  calls `sleepScramble` itself).
- `Spec.SleepMS uint32` field in `internal/payload/assemble.go`; `renderMain` emits
  `sleepHelper()` after the execution helpers.
- `internal/evasion/layers.go` — `Implemented[LayerSleep] = true`; Help text updated
  to describe the tier-1 scheme (was "Ekko/Foliage timer/APC scheme (Phase 2)").
- `cmd/shroud/main.go` — `--sleep <duration>` flag (Go duration syntax: `30s`,
  `2m`, …; default 0=off) on `generate`, parsed into `Spec.SleepMS` (ms, clamped to
  uint32); `mustDuration` helper; a `sleep demo` status line in the generate output.

### Modified

- `internal/evasion/layers_test.go` — `TestParseUnimplemented` (which asserted
  `Parse("sleep")` errors) → `TestParseSleepAccepted` (now asserts it parses cleanly).
- `internal/payload/technique_bodies_test.go` — `TestSleepBody` (sleepScramble +
  sleepLoop markers, the sleep-key bytes, the VirtualProtect/Sleep/
  FlushInstructionCache const declarations, valid-Go parse),
  `TestSleepHelperOnlyArmedWithLayer` (no sleepScramble/hSleep emitted without
  `-e sleep`), `TestSleepCrossCompile` (gated `SHROUD_COMPILE_TEST=1`).

### Deferred (tier-2)

- **Full Ekko/Foliage** (CreateTimerQueueTimer + RtlCreateTimer + QueueUserAPC +
  CreateEvent self-modifying .text encrypt/decrypt via two timers + an APC on a decoy
  thread) — research-grade and fragile in pure-Go-via-wincall without Windows
  on-target iteration. Tier-1 ships as the working `sleep` body; Ekko is the
  documented stretch. **Either way `sleep` is now usable, not a stub.**

### Verified

- `go build ./...`, `go vet ./...`, `go test ./...` all green.
- `evasion.Parse("sleep")` succeeds (was an error); `TestAllImplementedHaveHelp`
  covers the updated Help text.
- `shroud generate pe26 -f exe -e dynamic-api,sleep --sleep 30s` → builds
  `implant.exe` (1714176 bytes); emitted `main.go` contains `sleepScramble` +
  `sleepLoop` + the `hVirtualProtect`/`hSleep`/`hFlushInstructionCache` consts.
- `shroud generate pe26 -f exe -e dynamic-api,sleep` (no `--sleep`) → emits
  `sleepScramble` (helper available for a beacon) but NOT `sleepLoop` (no demo loop).
- **IAT hygiene confirmed** for the sleep-armed build: `VirtualProtect`, `Sleep`,
  `FlushInstructionCache` are all ABSENT from the import table (resolved at runtime
  via PEB walk + DJB2 hash). Only the Go-runtime `VirtualAlloc` baseline appears.
- `TestSleepCrossCompile` (SHROUD_COMPILE_TEST=1) confirms the sleep-armed project
  builds to a Windows EXE.

## [Phase F] — 2026-08-10 — donut C2 provider (msfrpc deferred)

Adds a third C2 / shellcode-source provider — **donut** — mirroring the metasploit
CLI shell-out pattern. donut converts a PE / DLL / .NET assembly / VBS / JS file into
position-independent shellcode, the natural "I have a PE/DLL, I need shellcode" path
that pairs with shroud's wrapping. The registry now lists donut, metasploit, sliver.

### Added

- `internal/c2/donut/donut.go` — `c2.Provider` backed by the `donut` binary
  (TheWover/Odzhan v1, verified against `/usr/bin/donut` v1.1).
  - Flags: `--donut-file` (required input), `--donut-arch` (1=x86, 2=amd64,
    3=x86+amd64; default 2), `--donut-format` (1=Binary default), `--donut-args`,
    `--donut-method`, `--donut-class`, `--donut-entropy` (1/2/3, 0=donut default),
    `--donut-exit` (1/2/3, 0=donut default), `--donut-bypass` (1/2/3, 0=donut default),
    `--donut-bin` (binary path override), `--donut-extra` (passthrough).
  - `Preflight`: `--donut-file` required + binary located (`--donut-bin` override or
    `exec.LookPath("donut")`).
  - `Fetch`: builds argv (`-i file -a arch -f format … -o tmpfile`), runs donut via
    `exec.Command` writing to a temp file with `-o` (so stdout/banner never
    contaminates the bytes — same pattern as metasploit), reads `loader.bin`.
  - `init() { c2.Register(provider{}) }`; wired in via blank import in main.go.
- `internal/c2/donut/donut_test.go` — `buildArgs` per arch/optional/passthrough,
  missing-file error, preflight missing-file + bad-bin-override errors, registration.

### Deferred

- **msfrpc** (msgpack-rpc-over-HTTPS to a running `msfrpcd`) — intentionally NOT
  shipped this phase. It pulls in a msgpack dependency (`github.com/vmihailenco/msgpack`)
  and needs a running msfrpcd to verify the exact call set for raw-shellcode generation
  (auth.login → module.execute/generate), which isn't available on this host. Per the
  plan's contingency, donut + msfvenom already cover the common "generate a PIC blob"
  need; msfrpc is added when a live msfrpcd is available to verify against. The
  `c2.Provider` seam is open for it (new subpackage + `init()` Register + blank import).

### Verified

- `go build ./...`, `go vet ./...`, `go test ./...` all green.
- `shroud c2 list` shows donut; `shroud c2 preflight donut` errors cleanly (no file).
- **donut byte-exact:** `shroud generate -f raw --c2 donut --donut-file x.exe
  --donut-arch 2 --donut-entropy 1` output (35436 bytes, SHA256
  `667c5b506568e32dd7e41809d4591e9afb5fcdfb4dad645c88342e8afb90438a`) == direct
  `donut -i x.exe -a 2 -f 1 -e 1 -o out.bin`. (Entropy pinned to 1=None on both
  sides for determinism; donut's default entropy=3 uses random names + a random
  symmetric key, so two runs are intentionally non-identical.)

## [Phase E] — 2026-08-10 — new injection techniques (pe11/12/15/22)

Builds out four Phase-2-roadmap techniques as real Go bodies (not `scaffoldRun`),
reusing the existing `b.api()` DJB2-const registration + `wincall.CallG0` pattern in
`internal/payload/`. Each technique is self-contained (its own structs/consts) — safe
because shroud emits one technique per build, so there is no double-emission concern.
The catalog's implemented count goes 10 → 14.

### Added

- **pe11 APC injection** (`remote.go`): OpenProcess + VirtualAllocEx +
  WriteProcessMemory + VirtualProtectEx (RW->RX) + `threadIDByPID` (TH32CS_SNAPTHREAD
  thread snapshot, first thread owned by the target) + OpenThread + QueueUserAPC.
  New `threadEnumHelper()` emits the `threadEntry32` struct (28B, 7 DWORDs) +
  `threadIDByPID`. Shared by pe11 and pe15.
- **pe12 Early Bird** (`remote.go`): CreateProcessW(suspended) a sacrificial process
  (numeric-encoded `--process`, default explorer.exe), stage shellcode RW->RX,
  QueueUserAPC(shellcode, main thread, 0), ResumeThread — APC fires before the image
  entry, sidestepping pe11's alertable-wait dependency. Self-contained
  `startupInfoW12`/`processInfoW12`/`stringToUTF16p12` structs. `pe12RunBody()` emits a
  self-contained run() (pe12 spawns its own process, so it bypasses the pidByName
  preamble the other remote techniques share).
- **pe15 remote thread hijack** (`remote.go`): OpenProcess + VirtualAllocEx + WPM +
  VirtualProtectEx + OpenThread + SuspendThread + GetThreadContext + rewrite Rip (offset
  0xF8) + SetThreadContext + ResumeThread — no CreateRemoteThread event. pe15-local
  CONTEXT consts (`ctx15Amd64Size=1232`, `ctx15Amd64Flags=0x100010`, `ctx15RipOffset=0xF8`).
- **pe22 fibers** (`technique_bodies.go`): local-stage payload (RW->RX or module-stomp) +
  ConvertThreadToFiber + CreateFiber(0, shellcodeAddr, 0) + SwitchToFiber — no new OS
  thread created (defeats thread-creation telemetry). Added a `pe22` case to the
  `localRun` family alongside pe01/pe04/pe26.

### Modified

- `internal/catalog/techniques.go` — `Implemented: true` for pe11/pe12/pe15/pe22;
  stale header comment fixed (was omitting pe03); count note updated to 14.
- `internal/catalog/techniques_test.go` — `TestImplementedCount` expects 14 (was 10).
- `internal/payload/technique_bodies.go` — `techniqueBody()` switch routes pe22 to
  `localRun`, pe11/pe12/pe15 to `remoteRun`; `localRun` gained a pe22 branch emitting
  `pe22Fibers(addr)` + `pe22Body()`; `remoteRun` emits `threadEnumHelper()` for pe11/pe15.
- `internal/payload/remote.go` — `remoteRunBody()` early-returns `pe12RunBody()` for
  pe12 (own process); pe11/pe15 cases in the switch + the four new body methods.

### Tests

- `internal/payload/technique_bodies_test.go` (NEW) — for each of pe11/pe12/pe15/pe22:
  `Assemble` a project with `dynamic-api`, assert the emitted `main.go` parses with
  `go/parser` and contains the expected API-call markers (`wincall.CallG0(hQueueUserAPC`,
  `hSuspendThread`, `ctx15RipOffset`, `hCreateFiber`, …) + DJB2 const declarations.
  `TestNewTechniquesCrossCompile` (gated behind `SHROUD_COMPILE_TEST=1`, runs `go mod
  tidy` + `GOOS=windows go build`) confirms all four build to a Windows EXE.

### Verified

- `go build ./...`, `go vet ./...`, `go test ./...` all green.
- All four techniques cross-compile to Windows EXE (~1.7MB each), e.g.
  `./shroud generate pe12 -f exe -o out` → `built -> out/implant.exe (1715200 bytes)`.
- **IAT hygiene confirmed** across pe11/pe12/pe15/pe22 and the pe01 baseline: the
  offensive-only APIs (`CreateRemoteThread`, `WriteProcessMemory`, `OpenProcess`,
  `VirtualAllocEx`, `QueueUserAPC`, `CreateProcessW`, `VirtualProtectEx`, `CreateFiber`,
  `SwitchToFiber`, `ConvertThreadToFiber`, `Thread32First/Next`,
  `CreateToolhelp32Snapshot`, `Process32FirstW/NextW`, `NtCreateThreadEx`, `AmsiScanBuffer`,
  `EtwEventWrite`) are all **absent** from the import table — resolved at runtime via
  PEB walk + DJB2 hash. (`SuspendThread`/`ResumeThread`/`Get/SetThreadContext` appear in
  the IAT, but those are Go-runtime scheduler imports present in every Go binary,
  including the pe01 baseline — not attributable to the offensive code.)

## [Phase A–D] — 2026-08-10 — pluggable C2 providers + multi-format delivery

Reframes shroud-go as a **payload-evasion / delivery kit**: generate shellcode from
any framework (Sliver, Metasploit, or future ones) and emit it as **any** delivery
format — with both inline-embed and `--url` remote-fetch modes. The implant pipeline
(`exe|dll|c`) is unchanged; delivery runs alongside it as a separate path.

### Added

- **Pluggable C2 provider framework** (`internal/c2`): `Provider` interface +
  registry (`Register`/`Resolve`/`Names`/`AddAllFlags`). Providers self-register in
  `init()` via a blank import — adding Mythic/Havoc/BRc/msfrpc is a new subpackage,
  no CLI changes.
  - `internal/c2/provider.go` — the seam (`ShellcodeResult`, `Provider`, registry).
  - `internal/c2/sliver/provider.go` — adapter wrapping the existing sliver engine
    (engine + tests untouched); owns `--sliver-config`/`--lhost`/`--lport`/`--transport`.
  - `internal/c2/metasploit/metasploit.go` — `msfvenom` CLI shell-out provider
    (`--msf-payload`/`--msf-lhost`/`--msf-lport`/`--msf-encoder`/`--msf-iterations`/
    `--msf-arch`/`--msf-format`/`--msf-platform`/`--msf-extra`); writes via `-o` to a
    temp file so msfvenom's stdout banner can never contaminate the shellcode bytes.
- **Delivery package** (`internal/delivery`): one emitter per format, shared stagers,
  and the two non-trivial binary/text encoders. `delivery.Spec{Format,Shellcode,URL,
  OutDir,Launcher,Arch,Technique}`, `Emitter` interface + registry, `Emit` writes
  artifacts with absolute resolved paths.
  - `stagers.go` — `ps1StagerBody`/`ps1StagerOneLine` (AMSI-bypass prologue + Add-Type
    P/Invoke VirtualAlloc/CreateThread/WaitForSingleObject + base64-decode),
    `ps1InlineEnc` (UTF-16LE base64 for `-enc`), `ps1Fetch`/`ps1FetchEnc`, `lolbinRemote`
    (per-launcher LOLBin primitives), `launcherInlineCmd`, `b64Std`, `utf16LE`.
  - `escapers.go` — vbs/js/vba string escapers for embedded command literals.
  - `screnc.go` — Microsoft Script Encoder (`.jse`) encoder: the exact inverse of the
    field-proven `scrdec.py` decoder (ReactOS `decode.c` dictionary + pick_encoding,
    encode table built by inversion). Round-trip test covers all 128 byte values.
  - `lnkbin.go` — minimal MS-SHLLINK (`.lnk`) binary writer: 1:1 port of pylnk3's
    serialization (ShellLinkHeader + LinkTargetIDList [RootEntry + DriveEntry +
    PathSegmentEntry with BEEF0004 block] + StringData ARGUMENTS [unicode] +
    ExtraData terminator). Targets limited to 8.3-clean System32 paths so
    `short_name == full_name` and the BEEF block size formula is byte-exact.
  - Emitters: `raw`, `ps1`, `hta`, `sct`, `vba`, `xsl`, `js`, `jse`, `lnk`.
- **CLI wiring** (`cmd/shroud/main.go`):
  - `generate` → `MaximumNArgs(1)` (id optional for delivery, required for implant);
    delivery branch (`runDeliver`) bypasses `Assemble`/`Build`.
  - `loadShellcode` is registry-driven via `c2.Resolve` (hardcoded sliver branch removed);
    provider flags registered via `c2.AddAllFlags`.
  - New flags: `--url`, `--launcher`; `-f` vocabulary expanded to the 8 delivery formats;
    new `c2` subcommand (`list` + `preflight <name>`).
  - Mutual-exclusivity: `--url` vs (`-s`/`--c2`) errors clearly; id-required rule for
    implant formats; metasploit provider registered via blank import.

### Verified

- `go build ./...`, `go vet ./...`, `go test ./...` all green (existing + new).
- **Metasploit provider byte-exact:** `shroud generate -f raw --c2 metasploit
  --msf-payload windows/x64/exec --msf-extra "CMD=calc.exe"` output (276 bytes,
  `fc48 83e4 f0e8…`) == direct `msfvenom -p windows/x64/exec CMD=calc.exe -f raw`.
- **LNK header byte-exact:** emitted `.lnk` parses back to `HeaderSize=0x4C`, shortcut
  CLSID, `LinkFlags=0xA1` (HasIDList|HasArguments|IsUnicode), `ShowCommand=7`
  (SW_SHOWMINNOACTIVE), RootEntry `1F50 E04F D020…`, correct IDListSize + ARGUMENTS.
- **Full user workflow:** `msfvenom` shellcode → `shroud generate -f lnk --c2 metasploit`
  → structurally-correct `.lnk`; implant regression (`generate pe26 -f c`) intact.

### Notes / contingencies

- **Delivery evasion scope** — the Go-runtime evasion stack (`-e dynamic-api/unhook/
  stomp/callbacks/amsi/etw`) applies only to `exe|dll|c`; delivery formats use native
  tricks (base64 transport, AMSI-bypass PS1 prologue, LOLBin choice). `-e` is ignored
  for delivery. Documented in README, not silently dropped.
- **Windows on-target execution is the final verification** for `.lnk` and `.jse`;
  fall back to `-f hta` / `-f js` (plaintext) if a generated file does not run on the
  engagement target. SCRENC correctness is proven by the all-bytes round-trip; LNK
  header by parse-back against pylnk3's layout.
- `msfrpc` (msgpack-over-HTTPS, session-aware) deferred as a future `c2.Provider`
  variant; `msfvenom` covers the common "generate a PIC blob from the framework" need
  with zero server state.

## [Phase 1] — 2026-08-09 — MVP: pure-Go end-to-end pipeline + parity techniques

First shippable release. Pure-Go end-to-end parity with the original Python+mingw tool
for the implemented techniques, emitting Windows implants cross-compiled with
`GOOS=windows` (no mingw on the EXE path).

### Added

- **CLI** (`cmd/shroud`): cobra subcommands `authorize`, `list`, `show`, `evasion`,
  `generate`, `build`. Ported from the Python `shroud` CLI with the same flag surface
  plus new `--garble`, `--tiny`, `--aes-iv`, and `-e list` shortcut.
- **Catalog** (`internal/catalog`): all 26 Offensive-Panda technique entries ported
  from `~/shroud/lib/registry.py` with metadata, MITRE mappings, flow, and notes.
  `Resolve()` accepts `pe08` / `8` / name-substring / slug-substring (case-insensitive,
  dash/space normalized via `slugify`).
- **Evasion model** (`internal/evasion`): composable layer model ported from
  `~/shroud/lib/evasion.py`, emitting Go fragments on go-wincall instead of C stubs.
  10 of 11 layers implemented (`sleep` → Phase 2). Crypto precedence `aes > rc4 > xor`
  and `unhook-kd`-supersedes-`unhook` enforced in `runGenerate`.
- **Shellcode ingest** (`internal/shellcode`): `Load(file|demo)`, AES-256-CBC
  (`crypto/aes` + PKCS7), internal RC4, XOR, `ParseHexKey`, plus `AESDecrypt` for
  round-trip verification.
- **Payload assembler** (`internal/payload`):
  - `assemble.go` — two-pass `renderMain` (body rendered first to register DJB2 hash
    constants, then `emitConsts`) writes the implant `main.go`.
  - `cformat.go` — `-f c` emits a standalone `payload.h` (byte array + crypto material
    + inline RC4/XOR decrypt C functions); AES emits key/iv with a usage note.
  - `projectfiles.go` — implant `go.mod`/`build.sh`/`README.md`; `build.sh` branches
    EXE (pure-Go, `CGO_ENABLED=0`) vs DLL (c-shared, `CGO_ENABLED=1` + mingw `CC`),
    runs `go mod tidy`, and uses the correct garble v0.17 syntax (garble flags before
    `build`, go-build flags after).
  - `technique_bodies.go`, `remote.go`, `apis.go` — the 10 technique bodies + shared
    NT-structs helper + DJB2 const emission.
- **Builder** (`internal/builder`): shells out `go mod tidy` + `build.sh` with
  `CGO_ENABLED=0 GOOS=windows GOARCH=amd64`. **Never executes the output.**
- **Authorize gate** (`internal/authorize`): `~/.shroud_authorized` marker ported
  unchanged in spirit from the Python tool.
- **winhash** (`internal/winhash`): DJB2-with-lowercase-folding hash matching
  go-wincall's `pkg/obf.hashString` exactly (Python cross-checked).

### Implemented techniques (10/26)

`pe01` local shellcode · `pe02` remote thread · `pe03` classic + dynamic-api (routes to
pe02 body) · `pe04` VirtualProtect RW→RX · `pe05` DLL injection (LoadLibrary) · `pe08`
process hollowing · `pe23` NT API injection · `pe24` direct syscalls · `pe25` indirect
syscalls · `pe26` modern implant loader (composed full stack).

### Tests

- `internal/shellcode/shellcode_test.go` — AES/RC4/XOR round-trips, `ParseHexKey`,
  `Load` (demo + file).
- `internal/catalog/techniques_test.go` — all 26 present, 10 implemented,
  `Resolve` across `pe08`/`PE08`/`8`/`hollowing`/`processhollowing`/`directsyscalls`,
  miss cases, `ByID`, `ByCategory` coverage.
- `internal/evasion/layers_test.go` — `Parse` (order/whitespace/dedup/empty/unknown/
  unimplemented), `Has`, crypto precedence, `AnyCrypto`, all-implemented-have-help.
- `internal/winhash/winhash_test.go` — known DJB2 vectors (`AmsiScanBuffer`,
  `VirtualProtect`, `EtwEventWrite`, `kernel32.dll`, `ntdll.dll`, …), lowercase folding,
  `Hex`.

### Verified

- `go test ./...` green; `go build ./...` green.
- All 10 techniques cross-compile to Windows EXE (pe26 also DLL) with the full stack.
- **Real-shellcode round-trip byte-exact:** 276-byte msfvenom `windows/x64/exec`
  shellcode → AES-256-CBC encrypt → emitted `encPayload` array → decrypt == original
  (verified with the stdlib `AESDecrypt` and an independent pycryptodome cross-check).
- **IAT hygiene:** `objdump -p` shows only the Go-runtime kernel32 baseline
  (`GetProcAddress`, `LoadLibraryExW`, `VirtualAlloc`, `CreateThread`); all offensive
  APIs are absent (resolved at runtime via PEB walk + DJB2 hash).

### Dependencies

- Generator: `github.com/spf13/cobra v1.10.2` (CLI).
- Implant: `github.com/carved4/go-wincall v1.3.2` (PEB walk, syscalls, unhook, callbacks),
  stdlib `crypto/aes`, `crypto/cipher`.
- Optional: `mvdan.cc/garble v0.17.0` (OPSC), `mingw-w64` (DLL only).

### Gotchas resolved (worth recording for Phase 2)

- `go.sum` has **no comment syntax** (unlike `go.mod`); a `#` seed line is malformed.
  Seeds are empty; `build.sh` runs `go mod tidy` to populate real hashes.
- `renderMain` is **two-pass**: the body must render first (helpers call `b.api()` to
  register DJB2 hash constants) before `emitConsts`, or the `const ()` block is blank
  and all `hXxx` symbols are undefined.
- **garble v0.17 syntax:** `garble <garble-flags> build <go-build-flags> [args]` —
  `-literals`/`-tiny` go before `build`; `-ldflags`/`-buildmode`/`-o` go after.
- **DLL c-shared** requires CGO + mingw and a `func main(){}` stub alongside
  `func init(){ run() }` (linker requirement). EXE stays pure-Go (`CGO_ENABLED=0`).
- `stomp`/`unhook` helpers must not re-register an already-emitted hash const
  (e.g. `b.api("ntdll.dll","ntdll.dll")` collides with the module const) — caused
  redeclaration errors, fixed by removing the redundant calls.
- go-wincall **only builds on GOOS=windows** (plan9 asm + windows build constraints),
  so its hash correctness was cross-checked against the algorithm source + Python,
  not by compiling go-wincall on Linux.

## [Pre-1] — 2026-07-18 — original Python tool

The predecessor `~/shroud` (Python + C/mingw) is the porting reference. shroud-go
reuses its technique metadata, evasion composition model, crypto/ingest, and
authorization gate — reimplemented in Go on top of go-wincall. See
[shroud-payload-generator](../.claude/projects/-home-kali/memory/shroud-payload-generator.md).

## Upcoming

- **Phase 2 remainder** — anti-debug, PPID spoof + blockdlls, x86. (All 26 techniques are
  now built; the 5 EXPERIMENTAL — pe06/pe09/pe14/pe20/pe21 — need Windows on-target
  verification. `sleep` tier-2 Ekko/Foliage is built — EXPERIMENTAL.)
- **More C2 providers** — Mythic, Havoc, Brute Ratel (implement `c2.Provider`
  + `init()` `Register`; no CLI changes).
- **Phase 5** — CI, integration tests, reproducible builds, beacon profiles.