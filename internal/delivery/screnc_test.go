package delivery

import (
	"strings"
	"testing"
)

// TestScrencRoundTripAllBytes proves the SCRENC encoder is the exact inverse of
// the field-proven scrdec.py decoder for every ASCII byte value. JScript bodies
// are ASCII, so we sweep 0x00..0x7F. This validates the pickEncoding + decodeDict
// tables and the escape handling (@# @& @! @* @$ for \r \n < > @).
func TestScrencRoundTripAllBytes(t *testing.T) {
	for c := 0; c < 128; c++ {
		plain := []byte{byte(c)}
		enc, err := ScrencEncode(plain)
		if err != nil {
			t.Errorf("byte 0x%02x: encode error: %v", c, err)
			continue
		}
		if !strings.HasPrefix(enc, "#@~^") || !strings.HasSuffix(enc, "^#~@") {
			t.Errorf("byte 0x%02x: bad envelope %q", c, enc)
			continue
		}
		// extract body (between the two == markers)
		body, err := screncBody(enc)
		if err != nil {
			t.Errorf("byte 0x%02x: %v", c, err)
			continue
		}
		dec, err := screncDecodeBody(body)
		if err != nil {
			t.Errorf("byte 0x%02x: decode error: %v", c, err)
			continue
		}
		if dec[0] != byte(c) {
			t.Errorf("byte 0x%02x: round-trip got 0x%02x (enc=%q)", c, dec[0], enc)
		}
	}
}

// TestScrencRoundTripScript sweeps a realistic multi-line JScript body so the
// position-dependent pickEncoding (j % 64) wraps and the \r\n escapes fire.
func TestScrencRoundTripScript(t *testing.T) {
	plain := []byte(jsBody("powershell -w hidden -enc Zm9v"))
	enc, err := ScrencEncode(plain)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	body, err := screncBody(enc)
	if err != nil {
		t.Fatalf("body: %v", err)
	}
	dec, err := screncDecodeBody(body)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if string(dec) != string(plain) {
		t.Errorf("round-trip mismatch\nin : %q\nout: %q", plain, dec)
	}
}

// screncBody extracts the encoded body between the len6== and csum6== markers of
// a full #@~^...^#~@ envelope. Used by the round-trip tests to feed screncDecodeBody.
func screncBody(enc string) ([]byte, error) {
	const prefix = "#@~^"
	const suffix = "^#~@"
	if !strings.HasPrefix(enc, prefix) || !strings.HasSuffix(enc, suffix) {
		return nil, nil
	}
	inner := enc[len(prefix) : len(enc)-len(suffix)]
	// inner = <len6>==<body><csum6>== ; len6 and csum6 are 8-char base64 (4 bytes).
	if len(inner) < 8+8 {
		return nil, nil
	}
	body := inner[8 : len(inner)-8]
	return []byte(body), nil
}