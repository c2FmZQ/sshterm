// MIT License
//
// Copyright (c) 2026 TTBT Enterprises LLC
// Copyright (c) 2026 Robin Thellend <rthellend@rthellend.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package internal

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"

	"github.com/c2FmZQ/sshterm/config"
)

func generateTestSSHKey(t *testing.T) (ssh.PublicKey, ssh.Signer, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return sshPub, signer, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
}

func TestParseAuthorizedKeys(t *testing.T) {
	_, _, key1 := generateTestSSHKey(t)
	_, _, caKey := generateTestSSHKey(t)

	validContent := fmt.Sprintf(`
# Comment line
permitopen="host1.example.com:22",permitopen="*.internal:2222" %s user1
permitopen="10.0.0.0/8,192.168.1.10:2222,[2001:db8::/32]:22,[::1],2001:db8::1" %s user2
cert-authority,principals="foo@example.com,*@dev.example.com",permitopen="*:*" %s ca1
%s no-permitopen-key
restrict,port-forwarding,permitopen="allowed.example.com:22",no-port-forwarding %s restricted-key
permitopen="host.example.com:22",permitopen="none" %s cleared-key
permitopen="old.example.com:22",restrict,port-forwarding,permitopen="new.example.com:22" %s restrict-reset-key
`, key1, key1, caKey, key1, key1, key1, key1)

	rules, err := parseAuthorizedKeys([]byte(validContent))
	if err != nil {
		t.Fatalf("parseAuthorizedKeys unexpected error: %v", err)
	}
	if len(rules) != 7 {
		t.Fatalf("len(rules) = %d, want 7", len(rules))
	}
	if rules[0].isCA || len(rules[0].permitOpen) != 2 {
		t.Errorf("rules[0] = %+v", rules[0])
	}
	if len(rules[1].permitOpen) != 5 {
		t.Errorf("rules[1].permitOpen = %+v, want 5 entries", rules[1].permitOpen)
	}
	if !rules[2].isCA || len(rules[2].principals) != 2 || len(rules[2].permitOpen) != 1 || rules[2].permitOpen[0].port != 0 {
		t.Errorf("rules[2] = %+v", rules[2])
	}
	// Missing permitopen -> empty permitOpen (deny all).
	if len(rules[3].permitOpen) != 0 {
		t.Errorf("rules[3].permitOpen = %+v, want empty", rules[3].permitOpen)
	}
	// Trailing no-port-forwarding clears permitOpen.
	if len(rules[4].permitOpen) != 0 {
		t.Errorf("rules[4].permitOpen = %+v, want empty", rules[4].permitOpen)
	}
	// permitopen="none" clears previous permitOpen on the line.
	if len(rules[5].permitOpen) != 0 {
		t.Errorf("rules[5].permitOpen = %+v, want empty", rules[5].permitOpen)
	}
	// restrict clears previous permitOpen on the line, keeping only subsequent permitOpen.
	if len(rules[6].permitOpen) != 1 || rules[6].permitOpen[0].hostPattern != "new.example.com" {
		t.Errorf("rules[6].permitOpen = %+v, want [new.example.com:22]", rules[6].permitOpen)
	}

	invalidCases := []string{
		"not-a-valid-key",
		fmt.Sprintf(`unknown-opt="foo" %s`, key1),
		fmt.Sprintf(`principals="foo@example.com" %s`, key1),                    // principals without cert-authority
		fmt.Sprintf(`cert-authority,permitopen="*:22" %s`, caKey),               // cert-authority without principals
		fmt.Sprintf(`cert-authority,principals="" %s`, caKey),                   // empty principals
		fmt.Sprintf(`cert-authority,principals="a,,b" %s`, caKey),               // empty entry in principals
		fmt.Sprintf(`cert-authority="val" %s`, caKey),                           // cert-authority with value
		fmt.Sprintf(`cert-authority,principals="a"permitopen="none" %s`, caKey), // missing comma / unescaped internal quotes
		fmt.Sprintf(`permitopen=host.example.com:22 %s`, key1),                  // unquoted option value
		fmt.Sprintf(`permitopen="" %s`, key1),                                   // empty permitopen
		fmt.Sprintf(`permitopen="none,host.example.com:22" %s`, key1),           // none combined with other entry
		fmt.Sprintf(`permitopen="10.0.0.*:22" %s`, key1),                        // IP wildcard instead of CIDR
		fmt.Sprintf(`permitopen="192.168.*.*:22" %s`, key1),                     // IP wildcard instead of CIDR
		fmt.Sprintf(`permitopen="host.123:22" %s`, key1),                        // numeric TLD
		fmt.Sprintf(`permitopen="127.0.0.0x1:22" %s`, key1),                     // hex IPv4 TLD
		fmt.Sprintf(`permitopen="[host.example.com]:22" %s`, key1),              // bracketed non-IPv6
		fmt.Sprintf(`permitopen="[127.0.0.1]:22" %s`, key1),                     // bracketed IPv4
		fmt.Sprintf(`permitopen %s`, key1),
		fmt.Sprintf(`permitopen=":22" %s`, key1),
		fmt.Sprintf(`permitopen="host:" %s`, key1),
		fmt.Sprintf(`permitopen="host:99999" %s`, key1),
		fmt.Sprintf(`permitopen="10.0.0.0/99:22" %s`, key1),
		fmt.Sprintf(`permitopen="[::1:22" %s`, key1),
		fmt.Sprintf(`permitopen="2001:db8:1:2:3:4:5:6:22" %s`, key1), // unbracketed IPv6 with port
		fmt.Sprintf(`permitopen="bad[pattern.com:22" %s`, key1),
		fmt.Sprintf(`permitopen="app-[0-9].example.com:22" %s`, key1),
	}
	for _, tc := range invalidCases {
		if _, err := parseAuthorizedKeys([]byte(tc)); err == nil {
			t.Errorf("parseAuthorizedKeys(%q) succeeded, want error", tc)
		}
	}
}

func TestJumpHostConfigAndValidation(t *testing.T) {
	tmpDir := t.TempDir()
	_, _, pubKeyLine := generateTestSSHKey(t)
	akFile := filepath.Join(tmpDir, "authorized_keys")
	if err := os.WriteFile(akFile, []byte(`permitopen="*:22" `+pubKeyLine+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// 1. --host-key without --authorized-keys fails.
	if _, err := New(Options{HostKeyFile: "some-key"}); err == nil {
		t.Error("expected error when HostKeyFile is set without AuthorizedKeysFile")
	}

	// 2. Endpoint named "jump" conflicts when --authorized-keys is set.
	if _, err := New(Options{
		AuthorizedKeysFile: akFile,
		Endpoints:          []Endpoint{{Name: DefaultJumpEndpointName, Address: "127.0.0.1:22"}},
	}); err == nil {
		t.Error("expected error when endpoint name conflicts with built-in jump host")
	}

	// 3. Explicit --host-key is loaded and reflected in /config.json.
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pemBlock, err := ssh.MarshalPrivateKey(hostPriv, "")
	if err != nil {
		t.Fatal(err)
	}
	hkFile := filepath.Join(tmpDir, "host_key")
	if err := os.WriteFile(hkFile, pem.EncodeToMemory(pemBlock), 0o600); err != nil {
		t.Fatal(err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatal(err)
	}
	wantPubKey := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(hostSigner.PublicKey())))

	srv, err := New(Options{
		AuthorizedKeysFile: akFile,
		HostKeyFile:        hkFile,
		Endpoints:          []Endpoint{{Name: "direct-wss", Address: "10.0.0.1:22"}},
		Logger:             log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	for _, tc := range []struct {
		hostHeader string
		wantName   string
	}{
		{"", "127.0.0.1-wss"},
		{"SSH.Example.COM.:8443", "ssh.example.com-wss"},
		{"[::1]:8080", DefaultJumpEndpointName},
		{"direct", DefaultJumpEndpointName}, // "direct-wss" collides with configured endpoint
	} {
		req, err := http.NewRequest(http.MethodGet, ts.URL+"/config.json", nil)
		if err != nil {
			t.Fatal(err)
		}
		if tc.hostHeader != "" {
			req.Host = tc.hostHeader
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET /config.json (Host=%q): %v", tc.hostHeader, err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}

		var gotCfg config.Config
		if err := json.Unmarshal(body, &gotCfg); err != nil {
			t.Fatalf("Unmarshal (Host=%q): %v", tc.hostHeader, err)
		}
		if gotCfg.JumpHosts != tc.wantName {
			t.Errorf("Host=%q: JumpHosts = %q, want %q", tc.hostHeader, gotCfg.JumpHosts, tc.wantName)
		}
		if len(gotCfg.Endpoints) != 2 {
			t.Fatalf("Host=%q: len(Endpoints) = %d, want 2: %+v", tc.hostHeader, len(gotCfg.Endpoints), gotCfg.Endpoints)
		}
		if gotCfg.Endpoints[1].Name != tc.wantName || gotCfg.Endpoints[1].URL != "./_ws/"+DefaultJumpEndpointName {
			t.Errorf("Host=%q: jump endpoint = %+v, want Name=%q URL=%q", tc.hostHeader, gotCfg.Endpoints[1], tc.wantName, "./_ws/"+DefaultJumpEndpointName)
		}
		if len(gotCfg.Hosts) != 1 || gotCfg.Hosts[0].Name != tc.wantName || gotCfg.Hosts[0].Key != wantPubKey {
			t.Errorf("Host=%q: Hosts = %+v, want Name=%q Key=%q", tc.hostHeader, gotCfg.Hosts, tc.wantName, wantPubKey)
		}
	}
}

func startMockTargetSSHServer(t *testing.T, expectedUser string, allowedClientKey ssh.PublicKey) (string, ssh.PublicKey) {
	t.Helper()
	hostPub, hostSigner, _ := generateTestSSHKey(t)

	sshCfg := &ssh.ServerConfig{
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if c.User() == expectedUser && bytes.Equal(key.Marshal(), allowedClientKey.Marshal()) {
				return nil, nil
			}
			return nil, fmt.Errorf("target unauthorized user=%q", c.User())
		},
	}
	sshCfg.AddHostKey(hostSigner)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, chans, reqs, err := ssh.NewServerConn(c, sshCfg)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for newChan := range chans {
					if newChan.ChannelType() != "session" {
						_ = newChan.Reject(ssh.UnknownChannelType, "unsupported")
						continue
					}
					ch, chReqs, err := newChan.Accept()
					if err != nil {
						return
					}
					go func() {
						defer ch.Close()
						for req := range chReqs {
							if req.Type == "exec" && len(req.Payload) >= 4 {
								_ = req.Reply(true, nil)
								fmt.Fprintf(ch, "target-exec:%s", req.Payload[4:])
								_, _ = ch.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
								return
							}
							_ = req.Reply(false, nil)
						}
					}()
				}
			}(conn)
		}
	}()

	return l.Addr().String(), hostPub
}

func dialJumpSSHClient(t *testing.T, wsURL string, user string, hostKey ssh.PublicKey, authMethods ...ssh.AuthMethod) (*ssh.Client, error) {
	t.Helper()
	wsConn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		return nil, fmt.Errorf("websocket dial: %w", err)
	}
	clientCfg := &ssh.ClientConfig{
		User:            user,
		Auth:            authMethods,
		HostKeyCallback: ssh.FixedHostKey(hostKey),
		Timeout:         5 * time.Second,
	}
	c, chans, reqs, err := ssh.NewClientConn(&wsNetConn{conn: wsConn}, DefaultJumpEndpointName, clientCfg)
	if err != nil {
		wsConn.Close()
		return nil, err
	}
	return ssh.NewClient(c, chans, reqs), nil
}

func TestJumpHostPublicKeyAndCertAccessControl(t *testing.T) {
	// Keys and CAs
	allowedKeyPub, allowedKeySigner, allowedKeyLine := generateTestSSHKey(t)
	noPermitKeyPub, noPermitKeySigner, noPermitKeyLine := generateTestSSHKey(t)
	_, unknownKeySigner, _ := generateTestSSHKey(t)
	_, caSigner, caKeyLine := generateTestSSHKey(t)

	// Target SSH server
	targetAddr, targetHostPub := startMockTargetSSHServer(t, "targetuser", allowedKeyPub)

	// Authorized keys file
	akContent := fmt.Sprintf(`
# Key with specific permitopen
permitopen="internal.example.com:22",permitopen="127.0.0.0/8:2222" %s allowed-key
# Key without permitopen -> deny all
%s no-permitopen-key
# CA rule for all @example.com to *.dev.internal:22
cert-authority,principals="*@example.com",permitopen="*.dev.internal:22" %s corp-ca
# CA rule for sre@example.com to *.prod.internal:22
cert-authority,principals="sre@example.com",permitopen="*.prod.internal:22" %s corp-ca
`, allowedKeyLine, noPermitKeyLine, caKeyLine, caKeyLine)

	akFile := filepath.Join(t.TempDir(), "authorized_keys")
	if err := os.WriteFile(akFile, []byte(akContent), 0o600); err != nil {
		t.Fatal(err)
	}

	srv, err := New(Options{
		AuthorizedKeysFile: akFile,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			// Route allowed virtual hostnames to our mock target SSH server.
			switch address {
			case "internal.example.com:22", "app.dev.internal:22", "db.prod.internal:22", "127.0.0.1:2222":
				var d net.Dialer
				return d.DialContext(ctx, "tcp", targetAddr)
			default:
				return nil, fmt.Errorf("unexpected dial to %q", address)
			}
		},
		Logger: log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv.jumpHost.lookupIP = func(ctx context.Context, host string) ([]net.IPAddr, error) {
		switch host {
		case "resolved.example.com":
			return []net.IPAddr{
				{IP: net.ParseIP("10.0.0.99")},
				{IP: net.ParseIP("127.0.0.1")},
			}, nil
		case "forbidden.example.com":
			return []net.IPAddr{
				{IP: net.ParseIP("10.0.0.99")},
			}, nil
		default:
			return nil, fmt.Errorf("unknown host %q", host)
		}
	}
	jumpHostPub := srv.jumpHost.signer.PublicKey()

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	wsJumpURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/_ws/" + DefaultJumpEndpointName

	// 1. Unknown key is rejected.
	if _, err := dialJumpSSHClient(t, wsJumpURL, "anyuser", jumpHostPub, ssh.PublicKeys(unknownKeySigner)); err == nil {
		t.Fatal("expected unknown key to be rejected")
	}

	// 2. Key without permitopen is rejected (deny all).
	if _, err := dialJumpSSHClient(t, wsJumpURL, "anyuser", jumpHostPub, ssh.PublicKeys(noPermitKeySigner)); err == nil {
		t.Fatal("expected key without permitopen to be rejected")
	}
	_ = noPermitKeyPub

	// 3. Allowed public key can authenticate, open direct-tcpip to permitted hosts, and is denied others.
	jumpClient, err := dialJumpSSHClient(t, wsJumpURL, "arbitrary-jump-user", jumpHostPub, ssh.PublicKeys(allowedKeySigner))
	if err != nil {
		t.Fatalf("dialJumpSSHClient(allowedKey): %v", err)
	}
	defer jumpClient.Close()

	// Global keepalive request succeeds.
	ok, _, err := jumpClient.SendRequest("keepalive@openssh.com", true, nil)
	if err != nil || !ok {
		t.Errorf("keepalive request: ok=%v err=%v, want true, nil", ok, err)
	}

	// Opening a shell/exec session on the jump host itself is prohibited.
	if sess, err := jumpClient.NewSession(); err == nil {
		sess.Close()
		t.Fatal("expected NewSession on jump host to be rejected")
	}

	// Disallowed destination host or port is rejected.
	for _, badDest := range []string{"forbidden.example.com:22", "forbidden.example.com:2222", "internal.example.com:2222", "10.0.0.1:2222", "resolved.example.com:22"} {
		if c, err := jumpClient.Dial("tcp", badDest); err == nil {
			c.Close()
			t.Errorf("expected Dial(%q) to be rejected", badDest)
		}
	}

	// Permitted hostname ("internal.example.com:22"), literal CIDR ("127.0.0.1:2222"), and hostname resolving into CIDR ("resolved.example.com:2222" -> dials "127.0.0.1:2222") succeed end-to-end.
	for _, goodDest := range []string{"internal.example.com:22", "127.0.0.1:2222", "resolved.example.com:2222"} {
		tunConn, err := jumpClient.Dial("tcp", goodDest)
		if err != nil {
			t.Fatalf("jumpClient.Dial(%q): %v", goodDest, err)
		}
		tc, tchans, treqs, err := ssh.NewClientConn(tunConn, goodDest, &ssh.ClientConfig{
			User:            "targetuser",
			Auth:            []ssh.AuthMethod{ssh.PublicKeys(allowedKeySigner)},
			HostKeyCallback: ssh.FixedHostKey(targetHostPub),
		})
		if err != nil {
			tunConn.Close()
			t.Fatalf("NewClientConn over tunnel (%q): %v", goodDest, err)
		}
		targetClient := ssh.NewClient(tc, tchans, treqs)
		sess, err := targetClient.NewSession()
		if err != nil {
			targetClient.Close()
			t.Fatalf("targetClient.NewSession: %v", err)
		}
		out, err := sess.CombinedOutput("hello")
		sess.Close()
		targetClient.Close()
		if err != nil {
			t.Fatalf("CombinedOutput: %v", err)
		}
		if string(out) != "target-exec:hello" {
			t.Errorf("output = %q, want %q", out, "target-exec:hello")
		}
	}

	// 4. Certificate authentication with email principals (ignoring c.User()).
	mintCert := func(principals []string, validAfter, validBefore uint64, critOpts map[string]string) ssh.Signer {
		t.Helper()
		uPub, uSigner, _ := generateTestSSHKey(t)
		cert := &ssh.Certificate{
			Key:             uPub,
			CertType:        ssh.UserCert,
			KeyId:           strings.Join(principals, ","),
			ValidPrincipals: principals,
			ValidAfter:      validAfter,
			ValidBefore:     validBefore,
			Permissions: ssh.Permissions{
				CriticalOptions: critOpts,
				Extensions: map[string]string{
					"permit-X11-forwarding":   "",
					"permit-agent-forwarding": "",
					"permit-port-forwarding":  "",
					"permit-pty":              "",
					"permit-user-rc":          "",
				},
			},
		}
		if len(principals) == 0 {
			cert.ValidPrincipals = []string{"placeholder"}
			if err := cert.SignCert(rand.Reader, caSigner); err != nil {
				t.Fatal(err)
			}
			cert.ValidPrincipals = nil
			cert.Signature = nil
			raw := cert.Marshal()
			sig, err := caSigner.Sign(rand.Reader, raw[:len(raw)-4])
			if err != nil {
				t.Fatal(err)
			}
			cert.Signature = sig
		} else if err := cert.SignCert(rand.Reader, caSigner); err != nil {
			t.Fatal(err)
		}
		certSigner, err := ssh.NewCertSigner(cert, uSigner)
		if err != nil {
			t.Fatal(err)
		}
		return certSigner
	}

	now := uint64(time.Now().Unix())
	// 4a. Regular developer cert (alice@example.com) connecting as "root":
	// Allowed *.dev.internal:22, denied *.prod.internal:22.
	devCertSigner := mintCert([]string{"alice@example.com"}, now-60, now+600, nil)
	devJumpClient, err := dialJumpSSHClient(t, wsJumpURL, "root", jumpHostPub, ssh.PublicKeys(devCertSigner))
	if err != nil {
		t.Fatalf("dialJumpSSHClient(devCert): %v", err)
	}
	defer devJumpClient.Close()

	if c, err := devJumpClient.Dial("tcp", "app.dev.internal:22"); err != nil {
		t.Errorf("devCert Dial(app.dev.internal:22) failed: %v", err)
	} else {
		c.Close()
	}
	if c, err := devJumpClient.Dial("tcp", "db.prod.internal:22"); err == nil {
		c.Close()
		t.Error("expected devCert Dial(db.prod.internal:22) to be denied")
	}

	// 4b. SRE cert (sre@example.com) matches BOTH rules (*@example.com and sre@example.com):
	// Allowed both *.dev.internal:22 and *.prod.internal:22.
	sreCertSigner := mintCert([]string{"sre@example.com"}, now-60, now+600, nil)
	sreJumpClient, err := dialJumpSSHClient(t, wsJumpURL, "ubuntu", jumpHostPub, ssh.PublicKeys(sreCertSigner))
	if err != nil {
		t.Fatalf("dialJumpSSHClient(sreCert): %v", err)
	}
	defer sreJumpClient.Close()

	for _, dest := range []string{"app.dev.internal:22", "db.prod.internal:22"} {
		if c, err := sreJumpClient.Dial("tcp", dest); err != nil {
			t.Errorf("sreCert Dial(%s) failed: %v", dest, err)
		} else {
			c.Close()
		}
	}

	// 4c. Unmatched principal (user@other.org), expired cert, future cert, force-command cert, malformed source-address cert, and certs without permit-port-forwarding (including empty extensions) all fail auth.
	mintCertWithExts := func(exts map[string]string) ssh.Signer {
		uPub, uSigner, _ := generateTestSSHKey(t)
		cert := &ssh.Certificate{
			Key:             uPub,
			CertType:        ssh.UserCert,
			KeyId:           "alice@example.com",
			ValidPrincipals: []string{"alice@example.com"},
			ValidAfter:      now - 60,
			ValidBefore:     now + 600,
			Permissions: ssh.Permissions{
				Extensions: exts,
			},
		}
		if err := cert.SignCert(rand.Reader, caSigner); err != nil {
			t.Fatal(err)
		}
		cs, err := ssh.NewCertSigner(cert, uSigner)
		if err != nil {
			t.Fatal(err)
		}
		return cs
	}

	badCerts := []ssh.Signer{
		mintCert(nil, now-60, now+600, nil),
		mintCert([]string{"user@other.org"}, now-60, now+600, nil),
		mintCert([]string{"alice@example.com"}, now-600, now-10, nil),
		mintCert([]string{"alice@example.com"}, now+600, now+1200, nil),
		mintCert([]string{"alice@example.com"}, now-60, now+600, map[string]string{"force-command": "id"}),
		mintCert([]string{"alice@example.com"}, now-60, now+600, map[string]string{"source-address": "192.0.2.0/24"}),
		mintCert([]string{"alice@example.com"}, now-60, now+600, map[string]string{"source-address": "::/0"}),
		mintCert([]string{"alice@example.com"}, now-60, now+600, map[string]string{"source-address": "bad-entry,127.0.0.0/8"}),
		mintCert([]string{"alice@example.com"}, now-60, now+600, map[string]string{"source-address": "127.0.0.0/8,"}),
		mintCertWithExts(nil),
		mintCertWithExts(map[string]string{"permit-pty": ""}),
		mintCertWithExts(map[string]string{"permit-port-forwarding": "nonempty"}),
	}
	for i, badSigner := range badCerts {
		if c, err := dialJumpSSHClient(t, wsJumpURL, "root", jumpHostPub, ssh.PublicKeys(badSigner)); err == nil {
			c.Close()
			t.Errorf("badCerts[%d] unexpectedly succeeded authentication", i)
		}
	}

	// 4d. Cert with matching source-address (127.0.0.0/8) succeeds.
	goodSourceCert := mintCert([]string{"alice@example.com"}, now-60, now+600, map[string]string{"source-address": "127.0.0.0/8"})
	if c, err := dialJumpSSHClient(t, wsJumpURL, "root", jumpHostPub, ssh.PublicKeys(goodSourceCert)); err != nil {
		t.Errorf("goodSourceCert failed authentication: %v", err)
	} else {
		c.Close()
	}
}

// switchingPublicKey returns probePub.Marshal() on the first Marshal() call
// (used by validateKey with HasSig=false) and realPub.Marshal() on subsequent
// Marshal() calls (used when signing and sending HasSig=true).
type switchingPublicKey struct {
	probePub ssh.PublicKey
	realPub  ssh.PublicKey
	calls    int
}

func (k *switchingPublicKey) Type() string { return k.realPub.Type() }
func (k *switchingPublicKey) Marshal() []byte {
	k.calls++
	if k.calls <= 2 {
		return k.probePub.Marshal()
	}
	return k.realPub.Marshal()
}
func (k *switchingPublicKey) Verify(data []byte, sig *ssh.Signature) error {
	return k.realPub.Verify(data, sig)
}

type switchingSigner struct {
	pub        *switchingPublicKey
	realSigner ssh.Signer
}

func (s *switchingSigner) PublicKey() ssh.PublicKey {
	return s.pub
}

func (s *switchingSigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	return s.realSigner.Sign(rand, data)
}

func TestJumpHostKeyProbeIsolation(t *testing.T) {
	privKeyPub, _, privKeyLine := generateTestSSHKey(t)
	_, restrictedKeySigner, restrictedKeyLine := generateTestSSHKey(t)

	akContent := fmt.Sprintf(`
permitopen="secret.prod.internal:22" %s privileged-key
permitopen="sandbox.dev.internal:22" %s restricted-key
`, privKeyLine, restrictedKeyLine)

	akFile := filepath.Join(t.TempDir(), "authorized_keys")
	if err := os.WriteFile(akFile, []byte(akContent), 0o600); err != nil {
		t.Fatal(err)
	}

	srv, err := New(Options{
		AuthorizedKeysFile: akFile,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			c1, c2 := net.Pipe()
			_ = c2.Close()
			return c1, nil
		},
		Logger: log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	wsJumpURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/_ws/" + DefaultJumpEndpointName

	// Client probes privKeyPub (HasSig=false) and then signs with restrictedKeySigner (HasSig=true).
	jumpClient, err := dialJumpSSHClient(
		t,
		wsJumpURL,
		"user",
		srv.jumpHost.signer.PublicKey(),
		ssh.PublicKeys(&switchingSigner{
			pub:        &switchingPublicKey{probePub: privKeyPub, realPub: restrictedKeySigner.PublicKey()},
			realSigner: restrictedKeySigner,
		}),
	)
	if err != nil {
		t.Fatalf("dialJumpSSHClient: %v", err)
	}
	defer jumpClient.Close()

	// Must NOT have access to secret.prod.internal:22.
	if c, err := jumpClient.Dial("tcp", "secret.prod.internal:22"); err == nil {
		c.Close()
		t.Fatal("client gained privileged key's permitopen permissions via publickey probe!")
	}
	// Must have access to sandbox.dev.internal:22.
	if c, err := jumpClient.Dial("tcp", "sandbox.dev.internal:22"); err != nil {
		t.Fatalf("expected sandbox.dev.internal:22 to be allowed: %v", err)
	} else {
		c.Close()
	}
}

func TestValidateUserCertRejectsSHA1RSA(t *testing.T) {
	uPub, _, _ := generateTestSSHKey(t)
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaSigner, err := ssh.NewSignerFromKey(rsaPriv)
	if err != nil {
		t.Fatal(err)
	}
	algSigner := rsaSigner.(ssh.AlgorithmSigner)

	cert := &ssh.Certificate{
		Key:             uPub,
		CertType:        ssh.UserCert,
		ValidPrincipals: []string{"alice"},
		ValidBefore:     ssh.CertTimeInfinity,
		Permissions: ssh.Permissions{
			Extensions: map[string]string{"permit-port-forwarding": ""},
		},
	}
	if err := cert.SignCert(rand.Reader, &fixedAlgoTestSigner{AlgorithmSigner: algSigner, algo: ssh.KeyAlgoRSA}); err != nil {
		t.Fatal(err)
	}
	if err := validateUserCert(cert, "alice", nil); err == nil {
		t.Error("expected validateUserCert to reject ssh-rsa (SHA-1) signature")
	}

	if err := cert.SignCert(rand.Reader, &fixedAlgoTestSigner{AlgorithmSigner: algSigner, algo: ssh.KeyAlgoRSASHA512}); err != nil {
		t.Fatal(err)
	}
	if err := validateUserCert(cert, "alice", nil); err != nil {
		t.Errorf("expected validateUserCert to accept rsa-sha2-512 signature, got: %v", err)
	}
}

type fixedAlgoTestSigner struct {
	ssh.AlgorithmSigner
	algo string
}

func (s *fixedAlgoTestSigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	return s.AlgorithmSigner.SignWithAlgorithm(rand, data, s.algo)
}

func (s *fixedAlgoTestSigner) SignWithAlgorithm(rand io.Reader, data []byte, _ string) (*ssh.Signature, error) {
	return s.AlgorithmSigner.SignWithAlgorithm(rand, data, s.algo)
}

func TestAuthorizedKeysDocExamples(t *testing.T) {
	docBytes, err := os.ReadFile("../../../AUTHORIZED_KEYS.md")
	if err != nil {
		t.Fatalf("ReadFile(AUTHORIZED_KEYS.md): %v", err)
	}
	content := string(docBytes)
	const startFence = "```text\n"
	const endFence = "\n```"
	var blockCount int
	for {
		idx := strings.Index(content, startFence)
		if idx == -1 {
			break
		}
		content = content[idx+len(startFence):]
		endIdx := strings.Index(content, endFence)
		if endIdx == -1 {
			t.Fatal("unclosed ```text code block in AUTHORIZED_KEYS.md")
		}
		block := content[:endIdx]
		content = content[endIdx+len(endFence):]
		blockCount++

		rules, err := parseAuthorizedKeys([]byte(block))
		if err != nil {
			t.Errorf("AUTHORIZED_KEYS.md block #%d failed to parse: %v\nBlock:\n%s", blockCount, err, block)
		} else if len(rules) == 0 {
			t.Errorf("AUTHORIZED_KEYS.md block #%d parsed 0 rules", blockCount)
		}
		for i, r := range rules {
			if len(r.permitOpen) == 0 {
				t.Errorf("AUTHORIZED_KEYS.md block #%d rule #%d has empty permitOpen", blockCount, i+1)
			}
		}
	}
	if blockCount != 4 {
		t.Errorf("parsed %d ```text blocks from AUTHORIZED_KEYS.md, want 4", blockCount)
	}
}

func TestJumpHostAuthorizedKeysReload(t *testing.T) {
	_, key1Signer, key1Line := generateTestSSHKey(t)
	_, key2Signer, key2Line := generateTestSSHKey(t)

	akFile := filepath.Join(t.TempDir(), "authorized_keys")

	// 1. Error during initial load is fatal.
	if err := os.WriteFile(akFile, []byte("invalid-option "+key1Line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Options{AuthorizedKeysFile: akFile}); err == nil {
		t.Fatal("expected New to fail when initial authorized_keys file is invalid")
	}

	// 2. Initial valid load with key1 permitted to host1.example.com:22.
	if err := os.WriteFile(akFile, []byte(`permitopen="host1.example.com:22" `+key1Line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var logBuf bytes.Buffer
	var logMu sync.Mutex
	srv, err := New(Options{
		AuthorizedKeysFile: akFile,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			c1, c2 := net.Pipe()
			_ = c2.Close()
			return c1, nil
		},
		Logger: log.New(writerFunc(func(p []byte) (int, error) {
			logMu.Lock()
			defer logMu.Unlock()
			return logBuf.Write(p)
		}), "", 0),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	jumpHostPub := srv.jumpHost.signer.PublicKey()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	wsJumpURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/_ws/" + DefaultJumpEndpointName

	// key1 succeeds, key2 is rejected.
	c1, err := dialJumpSSHClient(t, wsJumpURL, "user", jumpHostPub, ssh.PublicKeys(key1Signer))
	if err != nil {
		t.Fatalf("dialJumpSSHClient(key1): %v", err)
	}
	if ch, err := c1.Dial("tcp", "host1.example.com:22"); err != nil {
		t.Fatalf("key1 Dial(host1.example.com:22): %v", err)
	} else {
		ch.Close()
	}
	c1.Close()

	if _, err := dialJumpSSHClient(t, wsJumpURL, "user", jumpHostPub, ssh.PublicKeys(key2Signer)); err == nil {
		t.Fatal("expected key2 to be rejected before reload")
	}

	// 3. Update authorized_keys to authorize key2 (for host2.example.com:22) and remove key1.
	if err := os.WriteFile(akFile, []byte(`permitopen="host2.example.com:22" `+key2Line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := dialJumpSSHClient(t, wsJumpURL, "user", jumpHostPub, ssh.PublicKeys(key1Signer)); err == nil {
		t.Fatal("expected key1 to be rejected after reload")
	}
	c2, err := dialJumpSSHClient(t, wsJumpURL, "user", jumpHostPub, ssh.PublicKeys(key2Signer))
	if err != nil {
		t.Fatalf("dialJumpSSHClient(key2) after reload: %v", err)
	}
	if ch, err := c2.Dial("tcp", "host2.example.com:22"); err != nil {
		t.Fatalf("key2 Dial(host2.example.com:22): %v", err)
	} else {
		ch.Close()
	}
	c2.Close()

	// 4. A reload with an invalid line fails closed: the bad line is
	// ignored, the valid lines take effect, and a removed key is revoked
	// even though the file has an error.
	if err := os.WriteFile(akFile, []byte("bad-option "+key2Line+"\n"+`permitopen="host1.example.com:22" `+key1Line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := dialJumpSSHClient(t, wsJumpURL, "user", jumpHostPub, ssh.PublicKeys(key2Signer)); err == nil {
		t.Fatal("expected key2 (on an invalid line) to be rejected after reload")
	}
	c1AfterBad, err := dialJumpSSHClient(t, wsJumpURL, "user", jumpHostPub, ssh.PublicKeys(key1Signer))
	if err != nil {
		t.Fatalf("expected key1 (on a valid line) to be authorized after partial reload, got: %v", err)
	}
	c1AfterBad.Close()

	logMu.Lock()
	logs := logBuf.String()
	logMu.Unlock()
	if !strings.Contains(logs, "error reloading authorized_keys") {
		t.Errorf("expected reload error in logs, got: %q", logs)
	}

	// 5. Removing the file denies everyone.
	if err := os.Remove(akFile); err != nil {
		t.Fatal(err)
	}
	if _, err := dialJumpSSHClient(t, wsJumpURL, "user", jumpHostPub, ssh.PublicKeys(key1Signer)); err == nil {
		t.Fatal("expected key1 to be rejected when authorized_keys is missing")
	}

	// 6. Restoring the file restores access.
	if err := os.WriteFile(akFile, []byte(`permitopen="host1.example.com:22" `+key1Line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c1Restored, err := dialJumpSSHClient(t, wsJumpURL, "user", jumpHostPub, ssh.PublicKeys(key1Signer))
	if err != nil {
		t.Fatalf("expected key1 to be authorized after authorized_keys is restored, got: %v", err)
	}
	c1Restored.Close()
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) {
	return f(p)
}

func TestJumpHostTrustedProxiesXForwardedFor(t *testing.T) {
	_, caSigner, caKeyLine := generateTestSSHKey(t)
	akFile := filepath.Join(t.TempDir(), "authorized_keys")
	if err := os.WriteFile(akFile, []byte(`cert-authority,principals="alice@example.com",permitopen="host.example.com:22" `+caKeyLine+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// 1. Invalid TrustedProxies entries fail startup.
	for _, badProxy := range []string{"not-an-ip", "10.0.0.0/99", ","} {
		if _, err := New(Options{
			AuthorizedKeysFile: akFile,
			TrustedProxies:     []string{badProxy},
		}); err == nil {
			t.Errorf("expected error for invalid TrustedProxies %q", badProxy)
		}
	}

	now := uint64(time.Now().Unix())
	mintSourceCert := func(sourceAddr string) ssh.Signer {
		t.Helper()
		uPub, uSigner, _ := generateTestSSHKey(t)
		cert := &ssh.Certificate{
			Key:             uPub,
			CertType:        ssh.UserCert,
			KeyId:           "alice@example.com",
			ValidPrincipals: []string{"alice@example.com"},
			ValidAfter:      now - 60,
			ValidBefore:     now + 600,
			Permissions: ssh.Permissions{
				CriticalOptions: map[string]string{"source-address": sourceAddr},
				Extensions:      map[string]string{"permit-port-forwarding": ""},
			},
		}
		if err := cert.SignCert(rand.Reader, caSigner); err != nil {
			t.Fatal(err)
		}
		cs, err := ssh.NewCertSigner(cert, uSigner)
		if err != nil {
			t.Fatal(err)
		}
		return cs
	}

	dialWithXFF := func(wsURL string, hostKey ssh.PublicKey, signer ssh.Signer, xff ...string) error {
		hdr := http.Header{}
		for _, v := range xff {
			hdr.Add("X-Forwarded-For", v)
		}
		wsConn, _, err := websocket.DefaultDialer.Dial(wsURL, hdr)
		if err != nil {
			return err
		}
		c, chans, reqs, err := ssh.NewClientConn(&wsNetConn{conn: wsConn}, DefaultJumpEndpointName, &ssh.ClientConfig{
			User:            "user",
			Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
			HostKeyCallback: ssh.FixedHostKey(hostKey),
			Timeout:         5 * time.Second,
		})
		if err != nil {
			wsConn.Close()
			return err
		}
		_ = ssh.NewClient(c, chans, reqs).Close()
		return nil
	}

	// 2. Without TrustedProxies, X-Forwarded-For is ignored.
	srvUntrusted, err := New(Options{
		AuthorizedKeysFile: akFile,
		Logger:             log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	tsUntrusted := httptest.NewServer(srvUntrusted.Handler())
	defer tsUntrusted.Close()
	wsUntrusted := "ws" + strings.TrimPrefix(tsUntrusted.URL, "http") + "/_ws/" + DefaultJumpEndpointName
	pubUntrusted := srvUntrusted.jumpHost.signer.PublicKey()

	if err := dialWithXFF(wsUntrusted, pubUntrusted, mintSourceCert("203.0.113.0/24"), "203.0.113.5"); err == nil {
		t.Error("expected X-Forwarded-For to be ignored when TrustedProxies is not configured")
	}
	if err := dialWithXFF(wsUntrusted, pubUntrusted, mintSourceCert("127.0.0.0/8"), "203.0.113.5"); err != nil {
		t.Errorf("expected direct peer 127.0.0.1 to match 127.0.0.0/8 when TrustedProxies is not configured: %v", err)
	}

	// 3. With TrustedProxies configured (127.0.0.1/32 and 10.10.0.0/16), X-Forwarded-For is evaluated right-to-left.
	srvTrusted, err := New(Options{
		AuthorizedKeysFile: akFile,
		TrustedProxies:     []string{"127.0.0.1/32,10.10.0.0/16"},
		Logger:             log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	tsTrusted := httptest.NewServer(srvTrusted.Handler())
	defer tsTrusted.Close()
	wsTrusted := "ws" + strings.TrimPrefix(tsTrusted.URL, "http") + "/_ws/" + DefaultJumpEndpointName
	pubTrusted := srvTrusted.jumpHost.signer.PublicKey()

	// Single XFF entry from trusted proxy: matches 203.0.113.0/24, does NOT match proxy's own 127.0.0.0/8.
	if err := dialWithXFF(wsTrusted, pubTrusted, mintSourceCert("203.0.113.0/24"), "203.0.113.5"); err != nil {
		t.Errorf("expected XFF 203.0.113.5 to match 203.0.113.0/24: %v", err)
	}
	if err := dialWithXFF(wsTrusted, pubTrusted, mintSourceCert("127.0.0.0/8"), "203.0.113.5"); err == nil {
		t.Error("expected XFF 203.0.113.5 not to match proxy's own 127.0.0.0/8")
	}

	// Client spoofs "198.51.100.99" in XFF; trusted proxy appends real client "203.0.113.5".
	if err := dialWithXFF(wsTrusted, pubTrusted, mintSourceCert("198.51.100.0/24"), "198.51.100.99, 203.0.113.5"); err == nil {
		t.Error("client-spoofed XFF prefix 198.51.100.99 should not be trusted")
	}
	if err := dialWithXFF(wsTrusted, pubTrusted, mintSourceCert("203.0.113.0/24"), "198.51.100.99, 203.0.113.5"); err != nil {
		t.Errorf("expected real client IP 203.0.113.5 to be selected: %v", err)
	}

	// Chained trusted proxies: client spoofs 198.51.100.99 -> outer proxy 10.10.1.2 sees 203.0.113.5 -> inner proxy 127.0.0.1 sees 10.10.1.2.
	if err := dialWithXFF(wsTrusted, pubTrusted, mintSourceCert("203.0.113.0/24"), "198.51.100.99, 203.0.113.5", "10.10.1.2"); err != nil {
		t.Errorf("expected chained XFF to resolve 203.0.113.5: %v", err)
	}

	// Malformed XFF fails closed and does NOT fall back to proxy's 127.0.0.1.
	if err := dialWithXFF(wsTrusted, pubTrusted, mintSourceCert("127.0.0.0/8"), "invalid-ip"); err == nil {
		t.Error("expected malformed XFF to fail closed")
	}
}
