// Package shellcode handles payload ingestion, at-rest encryption, and Go
// byte-array formatting. Ported from ~/shroud/lib/shellcode.py.
//
// The generator ships no operational shellcode of its own. It reads raw bytes
// you supply (msfvenom / donut / sliver / havoc / custom), or uses a tiny
// non-destructive DEMO stub (xor rax,rax; ret) so a build can be smoke-tested
// end-to-end without any offensive payload present.
//
// Encryption here defeats *static* signatures and on-disk scans. It is NOT a
// substitute for runtime opsec (sleep obfuscation, syscalls, etc.).
package shellcode

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
)

// DemoShellcode is a benign x86_64 Windows stub that returns cleanly:
//
//	48 31 c0   xor rax, rax
//	c3         ret
//
// Build smoke-test only — no operational effect.
var DemoShellcode = []byte{0x48, 0x31, 0xc0, 0xc3}

// ErrShellcode is returned for ingest/format failures.
var ErrShellcode = errors.New("shellcode error")

// Load returns the raw payload bytes from a file, or the demo stub when no
// path is given. The generator never executes these bytes.
func Load(path string) ([]byte, error) {
	if path == "" {
		return DemoShellcode, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrShellcode, err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: shellcode file is empty: %s", ErrShellcode, path)
	}
	return data, nil
}

// ParseHexKey parses a user-supplied hex key, or generates a random one of
// defaultLen bytes when keyHex is empty.
func ParseHexKey(keyHex string, defaultLen int) ([]byte, error) {
	if keyHex == "" {
		k := make([]byte, defaultLen)
		if _, err := rand.Read(k); err != nil {
			return nil, fmt.Errorf("%w: rand: %v", ErrShellcode, err)
		}
		return k, nil
	}
	cleaned := hexStr(keyHex)
	if len(cleaned)%2 != 0 {
		return nil, fmt.Errorf("%w: hex key has an odd number of nibbles", ErrShellcode)
	}
	k, err := hex.DecodeString(cleaned)
	if err != nil {
		return nil, fmt.Errorf("%w: bad hex key: %v", ErrShellcode, err)
	}
	return k, nil
}

func hexStr(s string) string {
	s = trimSpace(s)
	if len(s) >= 2 && (s[:2] == "0x" || s[:2] == "0X") {
		s = s[2:]
	}
	return s
}

func trimSpace(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}

// XOR encrypts/decrypts data with the repeating XOR key.
func XOR(data, key []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("%w: xor key is empty", ErrShellcode)
	}
	out := make([]byte, len(data))
	for i, b := range data {
		out[i] = b ^ key[i%len(key)]
	}
	return out, nil
}

// RC4 encrypts/decrypts data with the RC4 stream cipher (symmetric).
func RC4(data, key []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("%w: rc4 key is empty", ErrShellcode)
	}
	s := ksa(key)
	out := make([]byte, len(data))
	var i, j byte
	for n, b := range data {
		i++
		j += s[i]
		s[i], s[j] = s[j], s[i]
		out[n] = b ^ s[(s[i]+s[j])&0xff]
	}
	return out, nil
}

func ksa(key []byte) [256]byte {
	var s [256]byte
	for i := 0; i < 256; i++ {
		s[i] = byte(i)
	}
	var j byte
	for i := 0; i < 256; i++ {
		j += s[i] + key[i%len(key)]
		s[i], s[j] = s[j], s[i]
	}
	return s
}

// AESEncrypt encrypts data with AES-256-CBC and PKCS7 padding. The implant
// reverses this with stdlib crypto/aes+crypto/cipher — both stdlib, so the
// round-trip is guaranteed identical (no pycryptodome dependency anymore).
func AESEncrypt(data, key32, iv16 []byte) ([]byte, error) {
	if len(key32) != 32 {
		return nil, fmt.Errorf("%w: AES key must be 32 bytes", ErrShellcode)
	}
	if len(iv16) != 16 {
		return nil, fmt.Errorf("%w: AES IV must be 16 bytes", ErrShellcode)
	}
	block, err := aes.NewCipher(key32)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrShellcode, err)
	}
	padLen := 16 - len(data)%16
	padded := make([]byte, len(data)+padLen)
	copy(padded, data)
	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(padLen)
	}
	out := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv16).CryptBlocks(out, padded)
	return out, nil
}

// AESDecrypt reverses AESEncrypt (AES-256-CBC + PKCS7 strip). This mirrors the
// runtime decrypt the emitted implant performs, so the generator (and tests)
// can verify an encrypt round-trip. Not used by the implant itself.
func AESDecrypt(ct, key32, iv16 []byte) ([]byte, error) {
	if len(key32) != 32 {
		return nil, fmt.Errorf("%w: AES key must be 32 bytes", ErrShellcode)
	}
	if len(iv16) != 16 {
		return nil, fmt.Errorf("%w: AES IV must be 16 bytes", ErrShellcode)
	}
	if len(ct) == 0 || len(ct)%16 != 0 {
		return nil, fmt.Errorf("%w: ciphertext not block-aligned", ErrShellcode)
	}
	block, err := aes.NewCipher(key32)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrShellcode, err)
	}
	pt := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv16).CryptBlocks(pt, ct)
	if len(pt) > 0 {
		n := int(pt[len(pt)-1])
		if n > 0 && n <= 16 && n <= len(pt) {
			pt = pt[:len(pt)-n]
		}
	}
	return pt, nil
}

// GoArray formats data as a Go byte slice literal, perLine bytes per line.
func GoArray(data []byte, name string, perLine int) string {
	var b []byte
	b = append(b, "var "...)
	b = append(b, name...)
	b = append(b, " = []byte{\n"...)
	if len(data) == 0 {
		b = append(b, "\t0x00,\n"...)
	}
	for i := 0; i < len(data); i += perLine {
		end := i + perLine
		if end > len(data) {
			end = len(data)
		}
		b = append(b, '\t')
		for j := i; j < end; j++ {
			b = append(b, fmt.Sprintf("0x%02x, ", data[j])...)
		}
		b = append(b, '\n')
	}
	b = append(b, "}\n"...)
	return string(b)
}

// HexStr returns data as a lowercase hex string.
func HexStr(data []byte) string { return hex.EncodeToString(data) }