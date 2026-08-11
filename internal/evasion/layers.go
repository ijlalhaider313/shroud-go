// Package evasion defines the composable evasion-layer model for the Go
// rewrite, ported from ~/shroud/lib/evasion.py. Layers are toggled by the
// `-e` CSV flag and compose into the emitted implant.
//
// In the Go port the layers map onto github.com/carved4/go-wincall primitives
// (PEB-walk API resolution, KnownDlls unhook, indirect syscalls, callback
// bridge) rather than hand-rolled C stubs.
//
// The `dynamic-api` layer is the go-wincall default: every offensive Win32 API
// is resolved at runtime via a PEB walk + DJB2 hash, so the implant's IAT
// contains only the unavoidable Go-runtime baseline (GetProcAddress,
// LoadLibraryExW, VirtualAlloc, CreateThread). With it OFF, the implant uses
// plaintext wincall.Call for educational comparison (more indicators).
package evasion

import (
	"fmt"
	"strings"
)

// Layer is a composable evasion layer identifier.
type Layer string

const (
	LayerDynamicAPI Layer = "dynamic-api" // PEB-walk + DJB2 hash resolution (clean IAT)
	LayerAES        Layer = "aes"         // AES-256-CBC decrypt-at-rest
	LayerRC4        Layer = "rc4"         // RC4 decrypt-at-rest
	LayerXOR        Layer = "xor"         // XOR decrypt-at-rest
	LayerAMSI       Layer = "amsi"        // patch AmsiScanBuffer (C3-free 58 FF E0)
	LayerETW        Layer = "etw"         // patch ntdll!EtwEventWrite
	LayerUnhook     Layer = "unhook"      // restore ntdll .text from a fresh disk copy
	LayerUnhookKD   Layer = "unhook-kd"   // restore ntdll .text from \KnownDlls (no disk read)
	LayerStomp      Layer = "stomp"       // module-stomp payload into a legit DLL's .text
	LayerCallbacks  Layer = "callbacks"   // execute via CreateTimerQueueTimer (no CreateThread)
	LayerSleep      Layer = "sleep"       // memory-encrypt-during-sleep (XOR-scramble payload while idle)
)

// All is every known layer, in display order.
var All = []Layer{
	LayerDynamicAPI, LayerAES, LayerRC4, LayerXOR, LayerAMSI, LayerETW,
	LayerUnhook, LayerUnhookKD, LayerStomp, LayerCallbacks, LayerSleep,
}

// Help is a short description of what each layer defeats.
var Help = map[Layer]string{
	LayerDynamicAPI: "static IAT analysis — all Win32 APIs resolved via PEB walk + DJB2 hash",
	LayerAES:        "on-disk & static signatures — AES-256-CBC (stdlib crypto/aes)",
	LayerRC4:        "lighter encrypt-at-rest alternative (RC4)",
	LayerXOR:        "lightest encrypt-at-rest alternative (XOR)",
	LayerAMSI:       "content scanning — patches AmsiScanBuffer (C3-free 58 FF E0)",
	LayerETW:        "userland telemetry — patches ntdll!EtwEventWrite",
	LayerUnhook:     "userland hooks — restores ntdll .text from a fresh disk copy",
	LayerUnhookKD:   "same via \\KnownDlls\\ntdll.dll — no disk read, stealthier",
	LayerStomp:      "unbacked-memory checks — backs payload with a legit module's .text (--stomp-dll)",
	LayerCallbacks:  "thread telemetry — CreateTimerQueueTimer instead of CreateThread",
	LayerSleep:      "memory scanners during sleep — XOR-scramble the staged region (RW) while idle, restore to RX on wake (tier-1; Ekko/Foliage is the documented stretch)",
}

// Implemented reports whether a layer has a Go-fragment generator yet.
var Implemented = map[Layer]bool{
	LayerDynamicAPI: true,
	LayerAES:        true,
	LayerRC4:        true,
	LayerXOR:        true,
	LayerAMSI:       true,
	LayerETW:        true,
	LayerUnhook:     true,
	LayerUnhookKD:   true,
	LayerStomp:      true,
	LayerCallbacks:  true,
	LayerSleep:      true, // tier-1 memory-encrypt-during-sleep; Ekko/Foliage is the documented stretch
}

// Parse parses a CSV `-e` string into an ordered, deduped layer slice,
// validating each entry.
func Parse(csv string) ([]Layer, error) {
	if csv == "" {
		return nil, nil
	}
	var out []Layer
	seen := make(map[Layer]bool)
	for _, raw := range strings.Split(csv, ",") {
		l := Layer(strings.TrimSpace(raw))
		if l == "" {
			continue
		}
		if !known(l) {
			return nil, fmt.Errorf("unknown evasion layer %q (see: shroud generate -e list)", l)
		}
		if !Implemented[l] {
			return nil, fmt.Errorf("evasion layer %q is not implemented yet (planned: %s)", l, Help[l])
		}
		if seen[l] {
			continue
		}
		seen[l] = true
		out = append(out, l)
	}
	return out, nil
}

func known(l Layer) bool {
	for _, k := range All {
		if k == l {
			return true
		}
	}
	return false
}

// Has reports whether layers contains l.
func Has(layers []Layer, l Layer) bool {
	for _, x := range layers {
		if x == l {
			return true
		}
	}
	return false
}

// AnyCrypto reports whether any at-rest encryption layer is active.
func AnyCrypto(layers []Layer) bool {
	return Has(layers, LayerAES) || Has(layers, LayerRC4) || Has(layers, LayerXOR)
}

// CryptoLayer returns the active crypto layer, or "" if none. If multiple are
// set, AES wins, then RC4, then XOR (matching the Python tool's precedence).
func CryptoLayer(layers []Layer) Layer {
	if Has(layers, LayerAES) {
		return LayerAES
	}
	if Has(layers, LayerRC4) {
		return LayerRC4
	}
	if Has(layers, LayerXOR) {
		return LayerXOR
	}
	return ""
}