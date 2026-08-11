// Package authorize implements the one-time authorized-use gate, ported
// unchanged in spirit from ~/shroud/shroud. `generate` and `build` are gated
// behind a local marker file at ~/.shroud_authorized.
//
// The gate is a speed-bump / statement of intent, not a security control:
// it records that the operator acknowledged authorized-use-only terms on this
// machine. It never phones home and stores no identity.
package authorize

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// MarkerFile is the path of the authorization marker.
var MarkerFile = func() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ".shroud_authorized"
	}
	return filepath.Join(home, ".shroud_authorized")
}()

const banner = `shroud generates offensive code for authorized red-team work only.

By authorizing you confirm you will use shroud ONLY against systems you own or
are explicitly authorized to test, and that you accept full responsibility for
engagement scope, consent, and compliance with all applicable law.

Unauthorized use is illegal. The authors grant no authorization to attack any
system and accept no liability for misuse.

Type YES (or pass --yes) to authorize this machine:
`

// Authorized reports whether the marker file exists.
func Authorized() bool {
	_, err := os.Stat(MarkerFile)
	return err == nil
}

// Authorize writes the marker after confirming interactive consent, unless
// `assumeYes` is true (the --yes flag). When stdin is non-interactive and
// assumeYes is false, it returns an error rather than silently authorizing.
func Authorize(stdin io.Reader, stdout io.Writer, assumeYes bool) error {
	if assumeYes {
		return writeMarker()
	}
	fmt.Fprint(stdout, banner)
	line, err := readLine(stdin)
	if err != nil {
		return fmt.Errorf("could not read response: %w", err)
	}
	if !strings.EqualFold(strings.TrimSpace(line), "YES") {
		return errors.New("authorization declined — re-run and type YES to continue")
	}
	return writeMarker()
}

func writeMarker() error {
	dir := filepath.Dir(MarkerFile)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("could not create marker directory: %w", err)
		}
	}
	content := "shroud authorized-use marker\n\nThis machine's operator acknowledged the authorized-use-only terms.\n"
	if err := os.WriteFile(MarkerFile, []byte(content), 0o600); err != nil {
		return fmt.Errorf("could not write marker %s: %w", MarkerFile, err)
	}
	return nil
}

// Require gates an action: returns nil if authorized, an error otherwise.
func Require() error {
	if Authorized() {
		return nil
	}
	return fmt.Errorf("not authorized — run `%s authorize` first (authorized use only)", progName())
}

func progName() string {
	if exe, err := os.Executable(); err == nil && exe != "" {
		return filepath.Base(exe)
	}
	return "shroud"
}

func readLine(r io.Reader) (string, error) {
	var buf [1024]byte
	n, err := r.Read(buf[:])
	if n > 0 {
		return string(buf[:n]), nil
	}
	return "", err
}