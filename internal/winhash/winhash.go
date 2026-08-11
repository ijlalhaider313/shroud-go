// Package winhash computes the DJB2-with-lowercase-folding hash that go-wincall
// uses (pkg/obf) for API-name resolution. The generator precomputes these so the
// emitted implant references only numeric hash constants and keeps plaintext
// Win32 API-name strings out of the binary (beyond the Go-runtime baseline).
//
// Algorithm (must match github.com/carved4/go-wincall/pkg/obf.Hash):
//
//	hash = 5381
//	for each byte b (skipping NUL):
//	    if 'A' <= b <= 'Z': b += 0x20
//	    hash = hash*33 + b
package winhash

// Hash returns the DJB2 (lowercase-folded) hash of s.
func Hash(s string) uint32 {
	var h uint32 = 5381
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b == 0 {
			continue
		}
		if b >= 'A' && b <= 'Z' {
			b += 0x20
		}
		h = (h << 5) + h + uint32(b) // h*33 + b
	}
	return h
}

// Hex returns the hash formatted as a Go unsigned-integer hex literal "0x…".
func Hex(s string) string {
	const hexd = "0123456789abcdef"
	v := Hash(s)
	// 8 nibbles, fixed width
	var out [10]byte
	out[0] = '0'
	out[1] = 'x'
	for i := 7; i >= 0; i-- {
		out[2+i] = hexd[v&0xf]
		v >>= 4
	}
	return string(out[:])
}