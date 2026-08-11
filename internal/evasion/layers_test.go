package evasion

import "testing"

func TestParse(t *testing.T) {
	l, err := Parse("aes, dynamic-api ,rc4")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(l) != 3 {
		t.Fatalf("got %d layers: %v", len(l), l)
	}
	if l[0] != LayerAES || l[1] != LayerDynamicAPI || l[2] != LayerRC4 {
		t.Errorf("order/whitespace wrong: %v", l)
	}
}

func TestParseDedup(t *testing.T) {
	l, _ := Parse("aes,aes,aes")
	if len(l) != 1 {
		t.Errorf("dedup failed: %v", l)
	}
}

func TestParseEmpty(t *testing.T) {
	l, err := Parse("")
	if err != nil || l != nil {
		t.Errorf("Parse(\"\") = %v err=%v", l, err)
	}
}

func TestParseUnknown(t *testing.T) {
	if _, err := Parse("nonsense"); err == nil {
		t.Error("unknown layer accepted")
	}
}

func TestParseSleepAccepted(t *testing.T) {
	// sleep is now implemented (tier-1 memory-encrypt-during-sleep). It must
	// parse cleanly; the previous "not implemented" error is gone.
	l, err := Parse("sleep")
	if err != nil {
		t.Fatalf("Parse(sleep) error: %v", err)
	}
	if len(l) != 1 || l[0] != LayerSleep {
		t.Errorf("Parse(sleep) = %v, want [sleep]", l)
	}
}

func TestHas(t *testing.T) {
	l := []Layer{LayerAES, LayerStomp}
	if !Has(l, LayerAES) || !Has(l, LayerStomp) {
		t.Error("Has false negative")
	}
	if Has(l, LayerRC4) {
		t.Error("Has false positive")
	}
}

func TestCryptoLayerPrecedence(t *testing.T) {
	// AES > RC4 > XOR
	if CryptoLayer([]Layer{LayerXOR, LayerRC4, LayerAES}) != LayerAES {
		t.Error("AES should win")
	}
	if CryptoLayer([]Layer{LayerXOR, LayerRC4}) != LayerRC4 {
		t.Error("RC4 should beat XOR")
	}
	if CryptoLayer([]Layer{LayerXOR}) != LayerXOR {
		t.Error("XOR alone should win")
	}
	if CryptoLayer([]Layer{LayerAMSI, LayerETW}) != "" {
		t.Error("non-crypto layers should yield empty")
	}
}

func TestAnyCrypto(t *testing.T) {
	if !AnyCrypto([]Layer{LayerAES}) {
		t.Error("AnyCrypto(aes) false")
	}
	if AnyCrypto([]Layer{LayerAMSI}) {
		t.Error("AnyCrypto(amsi) true")
	}
}

func TestAllImplementedHaveHelp(t *testing.T) {
	for _, l := range All {
		if _, ok := Help[l]; !ok {
			t.Errorf("layer %q missing Help text", l)
		}
	}
}