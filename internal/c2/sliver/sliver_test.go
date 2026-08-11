package sliver

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBuildRCScriptMTLS(t *testing.T) {
	rc, err := buildRCScript(Options{
		Name:      "shroud-1",
		LHost:     "127.0.0.1",
		LPort:     8888,
		Transport: "mtls",
		OS:        "windows",
		Arch:      "amd64",
	}, "/tmp/out")
	if err != nil {
		t.Fatalf("buildRCScript: %v", err)
	}
	want := "generate --os windows --arch amd64 --mtls 127.0.0.1:8888 --format shellcode --save /tmp/out --name shroud-1"
	if !strings.Contains(rc, want) {
		t.Errorf("rc missing %q\ngot:\n%s", want, rc)
	}
	if !strings.Contains(rc, "exit") {
		t.Errorf("rc missing trailing exit (needed so console exits after generate):\n%s", rc)
	}
}

func TestBuildRCScriptTransports(t *testing.T) {
	for _, tc := range []struct {
		transport, flag string
	}{
		{"mtls", "--mtls 10.0.0.1:443"},
		{"https", "--https 10.0.0.1:443"},
		{"wg", "--wg 10.0.0.1:443"},
	} {
		rc, err := buildRCScript(Options{
			LHost: "10.0.0.1", LPort: 443, Transport: tc.transport,
			OS: "windows", Arch: "amd64", Name: "x",
		}, "/tmp/o")
		if err != nil {
			t.Fatalf("%s: %v", tc.transport, err)
		}
		if !strings.Contains(rc, tc.flag) {
			t.Errorf("%s: rc missing %q\n%s", tc.transport, tc.flag, rc)
		}
	}
}

func TestBuildRCScriptBadTransport(t *testing.T) {
	if _, err := buildRCScript(Options{
		Transport: "dns", LHost: "h", LPort: 1, OS: "windows", Arch: "amd64", Name: "x",
	}, "/tmp/o"); err == nil {
		t.Error("expected error for unknown transport")
	}
}

func TestBuildRCScriptDefaults(t *testing.T) {
	// Defaults (empty OS/Arch/Transport/Name) are applied in FetchShellcode, not
	// buildRCScript — buildRCScript gets the already-resolved values. Verify it
	// echoes whatever it's given for OS/Arch.
	rc, _ := buildRCScript(Options{
		LHost: "h", LPort: 1, Transport: "mtls",
		OS: "windows", Arch: "amd64", Name: "n",
	}, "/tmp/o")
	if !strings.Contains(rc, "--os windows --arch amd64") {
		t.Errorf("rc did not echo OS/Arch:\n%s", rc)
	}
}

func TestFindShellcodeNewest(t *testing.T) {
	dir := t.TempDir()
	// old bin (backdated) + newer bin -> newest wins
	_ = os.WriteFile(filepath.Join(dir, "old.bin"), []byte("old"), 0o644)
	old := filepath.Join(dir, "old.bin")
	backdate := time.Now().Add(-2 * time.Hour)
	_ = os.Chtimes(old, backdate, backdate)
	time.Sleep(15 * time.Millisecond) // ensure mtime differs
	_ = os.WriteFile(filepath.Join(dir, "new.bin"), []byte("new"), 0o644)

	got, err := findShellcode(dir)
	if err != nil {
		t.Fatalf("findShellcode: %v", err)
	}
	if filepath.Base(got) != "new.bin" {
		t.Errorf("findShellcode = %s, want new.bin (newest)", filepath.Base(got))
	}
}

func TestFindShellcodeIgnoresNonBin(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "shroud.rc"), []byte("rc"), 0o644)
	if _, err := findShellcode(dir); err == nil {
		t.Error("findShellcode matched a non-.bin file")
	}
}

func TestPreflightMissingConfig(t *testing.T) {
	// Preflight fails fast on missing config without contacting any server.
	err := Preflight(Options{Config: "/nonexistent/x.cfg", LHost: "h", LPort: 1})
	if err == nil {
		t.Fatal("Preflight accepted a nonexistent config")
	}
}

func TestPreflightMissingEndpoint(t *testing.T) {
	// A config that exists but no endpoint -> error (create a dummy so the config
	// check passes, then the endpoint check fails).
	f := filepath.Join(t.TempDir(), "dummy.cfg")
	_ = os.WriteFile(f, []byte("{}"), 0o644)
	if err := Preflight(Options{Config: f}); err == nil {
		t.Error("Preflight accepted missing LHost/LPort")
	}
}