package msfrpc

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"shroud/internal/c2"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/vmihailenco/msgpack/v5"
)

// newCmd builds a cobra.Command with the provider's flags set to the given values.
func newCmd(t *testing.T, vals map[string]interface{}) *cobra.Command {
	t.Helper()
	c := &cobra.Command{}
	(provider{}).AddFlags(c.Flags())
	setFlags(t, c.Flags(), vals)
	return c
}

func setFlags(t *testing.T, fs *pflag.FlagSet, vals map[string]interface{}) {
	t.Helper()
	for k, v := range vals {
		switch x := v.(type) {
		case string:
			_ = fs.Set(k, x)
		case int:
			_ = fs.Set(k, itoa(x))
		case bool:
			_ = fs.Set(k, boolStr(x))
		}
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		return "-" + string(b)
	}
	return string(b)
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// mockServer returns an httptest server that speaks the msfrpcd flat-array wire
// format: it decodes the incoming ["method", args...] request, dispatches on the
// method name, and returns a canned msgpack map response. This lets the client's
// login + generatePayload paths be exercised end-to-end with no real msfrpcd.
func mockServer(t *testing.T, payload []byte) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req []interface{}
		body := new(bytes.Buffer)
		body.ReadFrom(r.Body)
		if err := msgpack.Unmarshal(body.Bytes(), &req); err != nil {
			t.Errorf("mock: decode request: %v", err)
			http.Error(w, "bad msgpack", 400)
			return
		}
		method, _ := req[0].(string)
		w.Header().Set("Content-Type", "binary/message-pack")
		switch method {
		case "auth.login":
			user, _ := req[1].(string)
			pass, _ := req[2].(string)
			if user == "msf" && pass == "secret" {
				_ = msgpack.NewEncoder(w).Encode(map[string]interface{}{
					"result": "success",
					"token":  "tok-abc123",
				})
				return
			}
			_ = msgpack.NewEncoder(w).Encode(map[string]interface{}{
				"result": "failure",
			})
		case "module.execute":
			// req = ["module.execute", token, "payload", payloadName, opts]
			_ = msgpack.NewEncoder(w).Encode(map[string]interface{}{
				"payload": payload,
			})
		default:
			_ = msgpack.NewEncoder(w).Encode(map[string]interface{}{
				"error":         true,
				"error_message": "unknown method " + method,
			})
		}
	}))
}

// TestParseExtra verifies the KEY=VAL parser.
func TestParseExtra(t *testing.T) {
	got := parseExtra("CMD=calc.exe EXITFUNC=thread")
	if got["CMD"] != "calc.exe" || got["EXITFUNC"] != "thread" {
		t.Errorf("parseExtra = %v", got)
	}
	if len(parseExtra("")) != 0 {
		t.Error("parseExtra(\"\") non-empty")
	}
	if len(parseExtra("noequals")) != 0 {
		t.Error("parseExtra(token without =) non-empty")
	}
}

// TestClientLogin verifies auth.login against the mock returns a token.
func TestClientLogin(t *testing.T) {
	srv := mockServer(t, nil)
	defer srv.Close()
	c := newClient(srv.URL, "msf", "secret", true)
	if err := c.login(); err != nil {
		t.Fatalf("login: %v", err)
	}
	if c.token != "tok-abc123" {
		t.Errorf("token = %q, want tok-abc123", c.token)
	}
}

// TestClientLoginBadPass verifies a failed auth.login surfaces an error.
func TestClientLoginBadPass(t *testing.T) {
	srv := mockServer(t, nil)
	defer srv.Close()
	c := newClient(srv.URL, "msf", "wrongpass", true)
	if err := c.login(); err == nil {
		t.Error("expected error on bad password")
	}
}

// TestClientGeneratePayload verifies module.execute returns the raw payload bytes.
func TestClientGeneratePayload(t *testing.T) {
	want := []byte{0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8}
	srv := mockServer(t, want)
	defer srv.Close()
	c := newClient(srv.URL, "msf", "secret", true)
	if err := c.login(); err != nil {
		t.Fatalf("login: %v", err)
	}
	got, err := c.generatePayload("windows/x64/exec", map[string]interface{}{"CMD": "calc.exe"})
	if err != nil {
		t.Fatalf("generatePayload: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("payload = % x, want % x", got, want)
	}
}

// TestClientGeneratePayloadEmpty verifies an empty payload is returned but not
// errored at the client layer (the Fetch layer checks len==0).
func TestClientGeneratePayloadEmpty(t *testing.T) {
	srv := mockServer(t, []byte{})
	defer srv.Close()
	c := newClient(srv.URL, "msf", "secret", true)
	_ = c.login()
	got, err := c.generatePayload("windows/x64/exec", nil)
	if err != nil {
		t.Fatalf("generatePayload: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty payload, got %d bytes", len(got))
	}
}

// TestCallErrorMap verifies the {"error":true,...} response is surfaced as an error.
func TestCallErrorMap(t *testing.T) {
	srv := mockServer(t, nil)
	defer srv.Close()
	c := newClient(srv.URL, "msf", "secret", true)
	// "bogus.method" hits the default branch -> error map
	if _, err := c.call("bogus.method", "tok"); err == nil {
		t.Error("expected error for unknown method")
	}
}

// TestPreflightMissingFlags verifies Preflight errors on missing required flags.
func TestPreflightMissingFlags(t *testing.T) {
	cases := []map[string]interface{}{
		{}, // all missing
		{"msfrpc-url": "https://x/api/"},                       // no pass, no payload
		{"msfrpc-url": "https://x/api/", "msfrpc-pass": "p"},   // no payload
		{"msfrpc-pass": "p", "msfrpc-payload": "windows/x64/exec"}, // no url
	}
	for i, vals := range cases {
		c := newCmd(t, vals)
		if err := (provider{}).Preflight(c); err == nil {
			t.Errorf("case %d: expected error for flags %v", i, vals)
		}
	}
}

// TestPreflightOK verifies Preflight succeeds against a reachable mock (auth.login OK).
func TestPreflightOK(t *testing.T) {
	srv := mockServer(t, nil)
	defer srv.Close()
	c := newCmd(t, map[string]interface{}{
		"msfrpc-url":     srv.URL,
		"msfrpc-pass":    "secret",
		"msfrpc-payload": "windows/x64/exec",
	})
	if err := (provider{}).Preflight(c); err != nil {
		t.Fatalf("Preflight: %v", err)
	}
}

// TestPreflightBadAuth verifies Preflight fails when auth.login rejects the creds.
func TestPreflightBadAuth(t *testing.T) {
	srv := mockServer(t, nil)
	defer srv.Close()
	c := newCmd(t, map[string]interface{}{
		"msfrpc-url":     srv.URL,
		"msfrpc-pass":    "wrongpass",
		"msfrpc-payload": "windows/x64/exec",
	})
	if err := (provider{}).Preflight(c); err == nil {
		t.Error("expected error on bad auth")
	}
}

// TestFetch verifies the full Fetch path: login + module.execute returns bytes,
// persisted to a temp file, with the expected ShellcodeResult fields.
func TestFetch(t *testing.T) {
	want := []byte{0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xcc, 0xc3}
	srv := mockServer(t, want)
	defer srv.Close()
	c := newCmd(t, map[string]interface{}{
		"msfrpc-url":     srv.URL,
		"msfrpc-pass":    "secret",
		"msfrpc-payload": "windows/x64/exec",
		"msfrpc-lhost":   "10.0.0.5",
		"msfrpc-lport":   4444,
		"msfrpc-extra":   "CMD=calc.exe EXITFUNC=thread",
	})
	res, err := (provider{}).Fetch(c)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !bytes.Equal(res.Bytes, want) {
		t.Errorf("Bytes = % x, want % x", res.Bytes, want)
	}
	if res.Name != "windows/x64/exec" {
		t.Errorf("Name = %q", res.Name)
	}
	if res.Source != "msfrpc:windows/x64/exec" {
		t.Errorf("Source = %q", res.Source)
	}
	if res.SavePath == "" {
		t.Error("SavePath empty")
	}
}

// TestProviderRegistered confirms init() registered the provider under "msfrpc".
func TestProviderRegistered(t *testing.T) {
	p, err := c2.Resolve("msfrpc")
	if err != nil {
		t.Fatal(err)
	}
	if p.Name() != "msfrpc" {
		t.Errorf("registered name = %q, want msfrpc", p.Name())
	}
}