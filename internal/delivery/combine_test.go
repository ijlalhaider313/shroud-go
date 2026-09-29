package delivery

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// isoHasPVD reports whether img has a valid ISO 9660 Primary Volume Descriptor
// at sector 16 (type 0x01, "CD001", version 0x01) and a set terminator at 17.
func isoHasPVD(img []byte) bool {
	if len(img) < (isoTermLBA+1)*isoSectorSize {
		return false
	}
	pvd := img[isoPvdLBA*isoSectorSize : (isoPvdLBA+1)*isoSectorSize]
	if pvd[0] != 0x01 || string(pvd[1:6]) != "CD001" || pvd[6] != 0x01 {
		return false
	}
	term := img[isoTermLBA*isoSectorSize : (isoTermLBA+1)*isoSectorSize]
	return term[0] == 0xFF && string(term[1:6]) == "CD001" && term[6] == 0x01
}

// TestZipReadBack builds a zip from known shellcode and reads it back with
// archive/zip, asserting both packaged files are present with the right shape:
// the .lnk is a valid LNK (header byte 0x4C) and the .bat is a batch dropper
// ("@echo off"), and the raw shellcode does not appear in either.
func TestZipReadBack(t *testing.T) {
	sc := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE}
	arts, err := emitForTest("zip", &Spec{Format: "zip", Shellcode: sc})
	if err != nil {
		t.Fatalf("zip emit: %v", err)
	}
	zr, err := zip.NewReader(bytes.NewReader(arts[0].Bytes), int64(len(arts[0].Bytes)))
	if err != nil {
		t.Fatalf("zip read: %v", err)
	}
	want := map[string]bool{"payload.lnk": false, "payload.bat": false}
	for _, f := range zr.File {
		if _, ok := want[f.Name]; !ok {
			t.Errorf("zip: unexpected entry %q", f.Name)
			continue
		}
		want[f.Name] = true
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("zip: open %s: %v", f.Name, err)
		}
		var buf bytes.Buffer
		if _, err := buf.ReadFrom(rc); err != nil {
			t.Fatalf("zip: read %s: %v", f.Name, err)
		}
		rc.Close()
		body := buf.Bytes()
		switch f.Name {
		case "payload.lnk":
			if len(body) == 0 || body[0] != 0x4C {
				t.Errorf("zip payload.lnk: first byte 0x%02X, want 0x4C", safeByte(body))
			}
		case "payload.bat":
			if !strings.HasPrefix(string(body), "@echo off") {
				t.Errorf("zip payload.bat: no @echo off prologue")
			}
		}
		if contains(string(body), string(sc)) {
			t.Errorf("zip %s: raw shellcode leaked", f.Name)
		}
	}
	for name, seen := range want {
		if !seen {
			t.Errorf("zip: missing entry %q", name)
		}
	}
}

// TestISOParseBack builds an ISO from known shellcode, then parses the root
// directory extent back out (PVD root record -> "." / ".." / file records) and
// verifies the two packaged files (PAYLOAD.LNK;1, PAYLOAD.BAT;1) have extents
// whose bytes exactly match the inner artifacts comboInner would produce.
func TestISOParseBack(t *testing.T) {
	sc := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x01, 0x02, 0x03}
	arts, err := emitForTest("iso", &Spec{Format: "iso", Shellcode: sc})
	if err != nil {
		t.Fatalf("iso emit: %v", err)
	}
	img := arts[0].Bytes
	if !isoHasPVD(img) {
		t.Fatal("iso: bad PVD/terminator")
	}

	// Expected inner artifacts (same Spec).
	inner, err := comboInner(&Spec{Format: "iso", Shellcode: sc})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]byte{}
	for _, a := range inner {
		want[isoName(a.Path)] = a.Bytes
	}

	// Root directory record is embedded in the PVD at offset 156 (34 bytes).
	pvd := img[isoPvdLBA*isoSectorSize : (isoPvdLBA+1)*isoSectorSize]
	rootRec := pvd[156 : 156+34]
	rootLBA := binary.LittleEndian.Uint32(rootRec[2:6])
	rootSize := binary.LittleEndian.Uint32(rootRec[10:14])
	if rootLBA != uint32(isoRootLBA) {
		t.Errorf("iso: root LBA %d, want %d", rootLBA, isoRootLBA)
	}
	if rootSize != uint32(isoSectorSize) {
		t.Errorf("iso: root size %d, want %d", rootSize, isoSectorSize)
	}

	// Walk the root directory extent, collecting non-self/parent file records.
	rootStart := int(rootLBA) * isoSectorSize
	got := map[string][]byte{}
	for off := 0; off < int(rootSize); {
		recLen := int(img[rootStart+off])
		if recLen == 0 {
			break // remaining bytes in the sector are padding
		}
		rec := img[rootStart+off : rootStart+off+recLen]
		nameLen := int(rec[32])
		name := string(rec[33 : 33+nameLen])
		// skip "." (0x00) and ".." (0x01)
		if name != "\x00" && name != "\x01" {
			fLBA := binary.LittleEndian.Uint32(rec[2:6])
			fSize := binary.LittleEndian.Uint32(rec[10:14])
			ext := img[int(fLBA)*isoSectorSize : int(fLBA)*isoSectorSize+int(fSize)]
			got[name] = ext
		}
		off += recLen
	}

	if len(got) != len(want) {
		t.Errorf("iso: %d file records, want %d", len(got), len(want))
	}
	for name, ext := range got {
		exp, ok := want[name]
		if !ok {
			t.Errorf("iso: unexpected file %q", name)
			continue
		}
		if !bytes.Equal(ext, exp) {
			t.Errorf("iso: extent %q = %d bytes, want %d bytes (mismatch)", name, len(ext), len(exp))
		}
		if contains(string(ext), string(sc)) {
			t.Errorf("iso: raw shellcode leaked in %q", name)
		}
	}
	for name := range want {
		if _, ok := got[name]; !ok {
			t.Errorf("iso: missing file %q", name)
		}
	}
}

// TestISO7zListsFiles is an out-of-band structural check: if 7z is on PATH,
// `7z l` on the generated ISO must list both packaged files. Skipped otherwise.
func TestISO7zListsFiles(t *testing.T) {
	if _, err := exec.LookPath("7z"); err != nil {
		t.Skip("7z not on PATH")
	}
	sc := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE}
	arts, err := emitForTest("iso", &Spec{Format: "iso", Shellcode: sc})
	if err != nil {
		t.Fatalf("iso emit: %v", err)
	}
	tmp := t.TempDir() + "/payload.iso"
	if err := os.WriteFile(tmp, arts[0].Bytes, 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("7z", "l", tmp).CombinedOutput()
	if err != nil {
		t.Fatalf("7z l: %v\n%s", err, out)
	}
	listing := string(out)
	for _, needle := range []string{"PAYLOAD.LNK", "PAYLOAD.BAT"} {
		if !contains(listing, needle) {
			t.Errorf("7z listing missing %q\n%s", needle, listing)
		}
	}
}
