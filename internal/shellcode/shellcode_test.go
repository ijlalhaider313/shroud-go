package shellcode

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestAESRoundTrip verifies the generator's AES-256-CBC+PKCS7 encryption is
// reversible by the same stdlib path the implant uses (aesDecrypt-equivalent).
func TestAESRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	iv := make([]byte, 16)
	for i := range key {
		key[i] = byte(i)
	}
	for i := range iv {
		iv[i] = byte(0x10 + i)
	}
	plain := []byte("the quick brown fox jumps over the lazy dog 1234567890")
	ct, err := AESEncrypt(plain, key, iv)
	if err != nil {
		t.Fatalf("AESEncrypt: %v", err)
	}
	if bytes.Equal(ct, plain) {
		t.Fatal("ciphertext equals plaintext")
	}
	if len(ct)%16 != 0 {
		t.Fatalf("ciphertext not block-aligned: %d", len(ct))
	}
	// decrypt (mirror the implant's aesDecrypt logic)
	pt, err := AESDecrypt(ct, key, iv)
	if err != nil {
		t.Fatalf("aesDecrypt: %v", err)
	}
	if !bytes.Equal(pt, plain) {
		t.Errorf("round-trip mismatch:\n got  %q\n want %q", pt, plain)
	}
}

func TestRC4RoundTrip(t *testing.T) {
	key := []byte("shroud-test-key")
	plain := []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03}
	ct, err := RC4(plain, key)
	if err != nil {
		t.Fatalf("RC4: %v", err)
	}
	pt, err := RC4(ct, key) // RC4 is symmetric
	if err != nil {
		t.Fatalf("RC4 decrypt: %v", err)
	}
	if !bytes.Equal(pt, plain) {
		t.Errorf("RC4 round-trip: got %x want %x", pt, plain)
	}
}

func TestXORRoundTrip(t *testing.T) {
	key := []byte{0xAA, 0xBB, 0xCC}
	plain := []byte("hello world")
	ct, err := XOR(plain, key)
	if err != nil {
		t.Fatalf("XOR: %v", err)
	}
	pt, err := XOR(ct, key)
	if err != nil {
		t.Fatalf("XOR decrypt: %v", err)
	}
	if !bytes.Equal(pt, plain) {
		t.Errorf("XOR round-trip: got %q want %q", pt, plain)
	}
}

func TestParseHexKey(t *testing.T) {
	k, err := ParseHexKey("0x0102030405", 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !bytes.Equal(k, []byte{1, 2, 3, 4, 5}) {
		t.Errorf("parsed key = %x", k)
	}
	// empty -> random of defaultLen
	r, err := ParseHexKey("", 32)
	if err != nil || len(r) != 32 {
		t.Errorf("random key len = %d err=%v", len(r), err)
	}
	// odd nibbles -> error
	if _, err := ParseHexKey("abc", 0); err == nil {
		t.Error("odd nibbles accepted")
	}
}

func TestLoadDemoAndFile(t *testing.T) {
	// no path -> demo stub
	d, err := Load("")
	if err != nil || !bytes.Equal(d, DemoShellcode) {
		t.Errorf("Load(\"\") = %x err=%v", d, err)
	}
	// file path -> file bytes
	dir := t.TempDir()
	p := filepath.Join(dir, "sc.bin")
	want := []byte{0x90, 0x90, 0xc3}
	if err := os.WriteFile(p, want, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := Load(p)
	if err != nil || !bytes.Equal(got, want) {
		t.Errorf("Load(file) = %x err=%v", got, err)
	}
	// empty file -> error
	empty := filepath.Join(dir, "empty.bin")
	_ = os.WriteFile(empty, nil, 0o644)
	if _, err := Load(empty); err == nil {
		t.Error("empty file accepted")
	}
}

// (AESDecrypt is tested directly — no wrapper needed.)