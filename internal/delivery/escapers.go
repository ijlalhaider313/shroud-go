// escapers.go — per-language string escape helpers so embedded command strings
// (which can contain quotes/backslashes from some LOLBin remote primitives) are
// safely inlined into script bodies. Inline-mode `powershell -enc <b64>` commands
// never contain quotes or backslashes, so these are mainly for the remote mode
// LOLBin primitives (e.g. wmic /format:"url").
package delivery

import "strings"

// vbsEscape escapes a string for a VBScript double-quoted literal: " -> "".
func vbsEscape(s string) string { return strings.ReplaceAll(s, `"`, `""`) }

// jsEscape escapes a string for a JScript/JavaScript double-quoted literal:
// backslash and double-quote are escaped. Newlines (none in our commands) are
// left as-is. Control chars are not expected in command strings.
func jsEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}

// vbaEscape escapes for a VBA double-quoted literal (same rule as VBScript).
func vbaEscape(s string) string { return vbsEscape(s) }