package winhash

import "testing"

// Vectors below are independently computed with a reference Python DJB2
// (lowercase-folded) implementation — NOT shroud's own — so this is a real
// cross-check, not a circular one.

func TestHashKnownVectors(t *testing.T) {
	cases := []struct {
		name string
		want uint32
	}{
		{"abc", 0x0b885c8b},
		{"AmsiScanBuffer", 0x5dfb3dee},
		{"VirtualProtect", 0x8b9ebdcd},
		{"EtwEventWrite", 0x941f3482},
		{"kernel32.dll", 0x7040ee75},
		{"ntdll.dll", 0x22d3b5ed},
		{"CreateTimerQueue", 0x101bb45f},
		{"CreateTimerQueueTimer", 0x1f94d320},
		{"NtOpenProcess", 0x86c330b8},
		{"OpenProcess", 0xbc153e16},
	}
	for _, c := range cases {
		got := Hash(c.name)
		if got != c.want {
			t.Errorf("Hash(%q) = %#08x, want %#08x", c.name, got, c.want)
		}
	}
}

// TestHashLowercaseFolding verifies the A->0x20 fold: uppercase and lowercase
// inputs must hash identically (go-wincall resolves with the same folding).
func TestHashLowercaseFolding(t *testing.T) {
	if Hash("ABC") != Hash("abc") {
		t.Errorf("uppercase not folded: Hash(ABC)=%#08x Hash(abc)=%#08x", Hash("ABC"), Hash("abc"))
	}
	if Hash("AMSISCANBUFFER") != Hash("AmsiScanBuffer") {
		t.Error("mixed-case folding mismatch")
	}
}

func TestHex(t *testing.T) {
	if Hex("abc") != "0x0b885c8b" {
		t.Errorf("Hex(abc)=%q want 0x0b885c8b", Hex("abc"))
	}
}