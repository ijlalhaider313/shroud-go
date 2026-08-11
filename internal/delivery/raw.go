// raw.go — emit the raw shellcode bytes as a .bin. Useful for staging into your
// own loader, WebDAV, SMB, or the launcher wrappers. No remote mode (raw has no
// fetch primitive — use a script format with --url for remote delivery).
package delivery

type rawEmitter struct{}

func (rawEmitter) Name() string { return "raw" }
func (rawEmitter) Ext() string  { return "bin" }

func (rawEmitter) Emit(s *Spec) ([]Artifact, error) {
	if s.Remote() {
		return nil, errPayloadRequired("raw")
	}
	if len(s.Shellcode) == 0 {
		return nil, errPayloadRequired("raw")
	}
	return []Artifact{writeFile("payload.bin", s.Shellcode)}, nil
}