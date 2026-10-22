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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"

	"github.com/c2FmZQ/sshterm/config"
)

func TestParseEndpoint(t *testing.T) {
	tests := []struct {
		spec    string
		want    Endpoint
		wantErr bool
	}{
		{
			spec: "myserver=192.168.1.100:2222",
			want: Endpoint{Name: "myserver", Address: "192.168.1.100:2222"},
		},
		{
			spec: "myserver=192.168.1.100",
			want: Endpoint{Name: "myserver", Address: "192.168.1.100:22"},
		},
		{
			spec: "host.example.com=ssh.internal.example.com",
			want: Endpoint{Name: "host.example.com", Address: "ssh.internal.example.com:22"},
		},
		{
			spec: "ipv6=[::1]:2222",
			want: Endpoint{Name: "ipv6", Address: "[::1]:2222"},
		},
		{
			spec: "ipv6=[::1]",
			want: Endpoint{Name: "ipv6", Address: "[::1]:22"},
		},
		{
			spec: "ipv6=::1",
			want: Endpoint{Name: "ipv6", Address: "[::1]:22"},
		},
		{
			spec:    "missing-equals",
			wantErr: true,
		},
		{
			spec:    "=192.168.1.1:22",
			wantErr: true,
		},
		{
			spec:    "bad:name=192.168.1.1:22",
			wantErr: true,
		},
		{
			spec:    "bad/name=192.168.1.1:22",
			wantErr: true,
		},
		{
			spec:    "..=192.168.1.1:22",
			wantErr: true,
		},
		{
			spec:    "myserver=",
			wantErr: true,
		},
		{
			spec:    "myserver=:22",
			wantErr: true,
		},
		{
			spec:    "myserver=192.168.1.1:0",
			wantErr: true,
		},
		{
			spec:    "myserver=192.168.1.1:70000",
			wantErr: true,
		},
		{
			spec:    "myserver=192.168.1.1:notaport",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		got, err := ParseEndpoint(tc.spec)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ParseEndpoint(%q) = %+v, want error", tc.spec, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseEndpoint(%q) unexpected error: %v", tc.spec, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseEndpoint(%q) = %+v, want %+v", tc.spec, got, tc.want)
		}
	}
}

func TestNewValidation(t *testing.T) {
	if _, err := New(Options{TLSCertFile: "cert.pem"}); err == nil {
		t.Error("expected error when only TLSCertFile is set")
	}
	if _, err := New(Options{TLSKeyFile: "key.pem"}); err == nil {
		t.Error("expected error when only TLSKeyFile is set")
	}
	if _, err := New(Options{ConfigFile: filepath.Join(t.TempDir(), "nonexistent.json")}); err == nil {
		t.Error("expected error for nonexistent config file")
	}
}

func TestEmbeddedStaticFilesAndHeaders(t *testing.T) {
	srv, err := New(Options{
		Logger: log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	for _, tc := range []struct {
		path     string
		wantType string
	}{
		{"/", "text/html; charset=utf-8"},
		{"/index.html", "text/html; charset=utf-8"},
		{"/ssh.wasm", "application/wasm"},
		{"/xterm.mjs", "text/javascript; charset=utf-8"},
		{"/stream-helper.js", "text/javascript; charset=utf-8"},
		{"/xterm.css", "text/css; charset=utf-8"},
		{"/ssh.png", "image/png"},
		{"/ssh.webmanifest", "application/manifest+json"},
		{"/LICENSE.xterm.txt", "text/plain; charset=utf-8"},
	} {
		resp, err := http.Get(ts.URL + tc.path)
		if err != nil {
			t.Fatalf("GET %s: %v", tc.path, err)
		}
		_, _ = io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s: status = %d, want 200", tc.path, resp.StatusCode)
		}
		if got := resp.Header.Get("Content-Type"); got != tc.wantType {
			t.Errorf("GET %s: Content-Type = %q, want %q", tc.path, got, tc.wantType)
		}
		if got := resp.Header.Get("X-Frame-Options"); got != "DENY" {
			t.Errorf("GET %s: X-Frame-Options = %q, want DENY", tc.path, got)
		}
		if got := resp.Header.Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("GET %s: X-Content-Type-Options = %q, want nosniff", tc.path, got)
		}
		if got := resp.Header.Get("Content-Security-Policy"); !strings.Contains(got, "frame-ancestors 'none'") {
			t.Errorf("GET %s: Content-Security-Policy = %q, want frame-ancestors 'none'", tc.path, got)
		}
	}

	// Ensure test artifacts and example config are not embedded.
	for _, excluded := range []string{"/tests.html", "/tests.wasm", "/config.json.example"} {
		resp, err := http.Get(ts.URL + excluded)
		if err != nil {
			t.Fatalf("GET %s: %v", excluded, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s: status = %d, want 404", excluded, resp.StatusCode)
		}
	}
}

func TestConfigJSONSynthesis(t *testing.T) {
	baseCfg := `{
  "persist": false,
  "theme": "dark",
  "endpoints": [
    {
      "name": "srv1",
      "url": "./old-url",
      "hostname": "srv1.internal.example.com"
    },
    {
      "name": "external",
      "url": "wss://other.example.com/ws"
    }
  ],
  "hosts": [
    {
      "name": "srv1",
      "key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINqyuT/sFvC37z1qMY0may2TMKqg2nxdjxBxyfXeieot"
    }
  ]
}`
	cfgPath := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(cfgPath, []byte(baseCfg), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	srv, err := New(Options{
		ConfigFile: cfgPath,
		Endpoints: []Endpoint{
			{Name: "srv1", Address: "10.0.0.10:22"},
			{Name: "srv2", Address: "10.0.0.20:2222"},
		},
		Logger: log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/config.json")
	if err != nil {
		t.Fatalf("GET /config.json: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /config.json: status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}

	// Ensure internal forwarding addresses are never exposed in config.json.
	if bytes.Contains(body, []byte("10.0.0.10")) || bytes.Contains(body, []byte("10.0.0.20")) {
		t.Fatalf("config.json leaked target forwarding address:\n%s", body)
	}

	var gotCfg config.Config
	if err := json.Unmarshal(body, &gotCfg); err != nil {
		t.Fatalf("Unmarshal config.json: %v", err)
	}
	if gotCfg.Theme != "dark" {
		t.Errorf("Theme = %q, want dark", gotCfg.Theme)
	}
	if gotCfg.Persist == nil || *gotCfg.Persist != false {
		t.Errorf("Persist = %v, want false", gotCfg.Persist)
	}
	if len(gotCfg.Endpoints) != 3 {
		t.Fatalf("len(Endpoints) = %d, want 3: %+v", len(gotCfg.Endpoints), gotCfg.Endpoints)
	}
	// srv1 should have updated URL and preserved Hostname.
	if gotCfg.Endpoints[0].Name != "srv1" || gotCfg.Endpoints[0].URL != "./_ws/srv1" || gotCfg.Endpoints[0].Hostname != "srv1.internal.example.com" {
		t.Errorf("Endpoints[0] = %+v", gotCfg.Endpoints[0])
	}
	// external should remain untouched.
	if gotCfg.Endpoints[1].Name != "external" || gotCfg.Endpoints[1].URL != "wss://other.example.com/ws" {
		t.Errorf("Endpoints[1] = %+v", gotCfg.Endpoints[1])
	}
	// srv2 should be appended.
	if gotCfg.Endpoints[2].Name != "srv2" || gotCfg.Endpoints[2].URL != "./_ws/srv2" {
		t.Errorf("Endpoints[2] = %+v", gotCfg.Endpoints[2])
	}

	// Verify HEAD /config.json.
	headResp, err := http.Head(ts.URL + "/config.json")
	if err != nil {
		t.Fatalf("HEAD /config.json: %v", err)
	}
	headResp.Body.Close()
	if headResp.StatusCode != http.StatusOK {
		t.Errorf("HEAD /config.json: status = %d, want 200", headResp.StatusCode)
	}
}

func TestWebSocketProxy(t *testing.T) {
	// Start a mock TCP echo/handshake server.
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer tcpListener.Close()

	go func() {
		for {
			conn, err := tcpListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				// Send SSH-like banner first.
				if _, err := c.Write([]byte("SSH-2.0-MockSSH\r\n")); err != nil {
					return
				}
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()

	srv, err := New(Options{
		Endpoints: []Endpoint{
			{Name: "mockssh", Address: tcpListener.Addr().String()},
		},
		Logger: log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	wsBaseURL := "ws" + strings.TrimPrefix(ts.URL, "http")

	// 1. Unknown endpoint should return 404.
	_, resp, err := websocket.DefaultDialer.Dial(wsBaseURL+"/_ws/unknown", nil)
	if err == nil {
		t.Fatal("expected error dialing unknown endpoint")
	}
	if resp == nil || resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown endpoint status = %v, want 404", resp)
	}

	// 2. Cross-origin request should be rejected with 403.
	badHeader := http.Header{"Origin": []string{"https://evil.example.com"}}
	_, resp, err = websocket.DefaultDialer.Dial(wsBaseURL+"/_ws/mockssh", badHeader)
	if err == nil {
		t.Fatal("expected error for cross-origin WebSocket")
	}
	if resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin status = %v, want 403", resp)
	}

	// 3. Valid binary proxy session.
	wsConn, _, err := websocket.DefaultDialer.Dial(wsBaseURL+"/_ws/mockssh", nil)
	if err != nil {
		t.Fatalf("Dial mockssh: %v", err)
	}
	defer wsConn.Close()

	msgType, banner, err := wsConn.ReadMessage()
	if err != nil {
		t.Fatalf("ReadMessage banner: %v", err)
	}
	if msgType != websocket.BinaryMessage || string(banner) != "SSH-2.0-MockSSH\r\n" {
		t.Fatalf("unexpected banner: type=%d data=%q", msgType, banner)
	}

	payload := []byte("hello over binary websocket")
	if err := wsConn.WriteMessage(websocket.BinaryMessage, payload); err != nil {
		t.Fatalf("WriteMessage: %v", err)
	}
	msgType, echoed, err := wsConn.ReadMessage()
	if err != nil {
		t.Fatalf("ReadMessage echo: %v", err)
	}
	if msgType != websocket.BinaryMessage || !bytes.Equal(echoed, payload) {
		t.Fatalf("unexpected echo: type=%d data=%q", msgType, echoed)
	}

	// 4. Text message should be rejected by server.
	if err := wsConn.WriteMessage(websocket.TextMessage, []byte("text not allowed")); err != nil {
		t.Fatalf("WriteMessage text: %v", err)
	}
	_, _, err = wsConn.ReadMessage()
	if err == nil {
		t.Fatal("expected connection close after sending text frame")
	}
}

func TestRunTLSAndShutdown(t *testing.T) {
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")
	keyFile := filepath.Join(tmpDir, "key.pem")
	generateSelfSignedCert(t, certFile, keyFile)

	srv, err := New(Options{
		Addr:        "127.0.0.1:0",
		TLSCertFile: certFile,
		TLSKeyFile:  keyFile,
		Endpoints: []Endpoint{
			{Name: "local", Address: "127.0.0.1:22"},
		},
		Logger: log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Run(ctx)
	}()

	// Wait for listener to be ready.
	var addr net.Addr
	for range 50 {
		if addr = srv.Addr(); addr != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if addr == nil {
		cancel()
		t.Fatal("server did not start listening in time")
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := client.Get("https://" + addr.String() + "/config.json")
	if err != nil {
		cancel()
		t.Fatalf("GET https config.json: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	cancel()
	if err := <-errCh; err != nil {
		t.Errorf("srv.Run returned error after cancel: %v", err)
	}
}

func generateSelfSignedCert(t *testing.T, certFile, keyFile string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes}), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestSSHOverWebSocketProxy(t *testing.T) {
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatal(err)
	}
	userPub, userPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshUserPub, err := ssh.NewPublicKey(userPub)
	if err != nil {
		t.Fatal(err)
	}
	userSigner, err := ssh.NewSignerFromKey(userPriv)
	if err != nil {
		t.Fatal(err)
	}

	sshCfg := &ssh.ServerConfig{
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if c.User() == "testuser" && bytes.Equal(key.Marshal(), sshUserPub.Marshal()) {
				return nil, nil
			}
			return nil, fmt.Errorf("unauthorized")
		},
	}
	sshCfg.AddHostKey(hostSigner)

	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpListener.Close()

	go func() {
		for {
			conn, err := tcpListener.Accept()
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
						newChan.Reject(ssh.UnknownChannelType, "unsupported")
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
								req.Reply(true, nil)
								fmt.Fprintf(ch, "ran:%s", req.Payload[4:])
								ch.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
								return
							}
							req.Reply(false, nil)
						}
					}()
				}
			}(conn)
		}
	}()

	srv, err := New(Options{
		Endpoints: []Endpoint{
			{Name: "testssh", Address: tcpListener.Addr().String()},
		},
		Logger: log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	wsBaseURL := "ws" + strings.TrimPrefix(ts.URL, "http")
	wsConn, _, err := websocket.DefaultDialer.Dial(wsBaseURL+"/_ws/testssh", nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer wsConn.Close()

	clientCfg := &ssh.ClientConfig{
		User:            "testuser",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(userSigner)},
		HostKeyCallback: ssh.FixedHostKey(hostSigner.PublicKey()),
	}
	c, chans, reqs, err := ssh.NewClientConn(&wsNetConn{conn: wsConn}, "testssh", clientCfg)
	if err != nil {
		t.Fatalf("ssh.NewClientConn: %v", err)
	}
	sshClient := ssh.NewClient(c, chans, reqs)
	defer sshClient.Close()

	sess, err := sshClient.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer sess.Close()

	out, err := sess.CombinedOutput("uname -a")
	if err != nil {
		t.Fatalf("CombinedOutput: %v", err)
	}
	if string(out) != "ran:uname -a" {
		t.Errorf("CombinedOutput = %q, want %q", out, "ran:uname -a")
	}
}

type wsNetConn struct {
	conn *websocket.Conn
	buf  []byte
}

func (c *wsNetConn) Read(b []byte) (int, error) {
	if len(c.buf) == 0 {
		_, p, err := c.conn.ReadMessage()
		if err != nil {
			return 0, err
		}
		c.buf = p
	}
	n := copy(b, c.buf)
	c.buf = c.buf[n:]
	return n, nil
}

func (c *wsNetConn) Write(b []byte) (int, error) {
	return len(b), c.conn.WriteMessage(websocket.BinaryMessage, b)
}

func (c *wsNetConn) Close() error                       { return c.conn.Close() }
func (c *wsNetConn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *wsNetConn) RemoteAddr() net.Addr               { return c.conn.RemoteAddr() }
func (c *wsNetConn) SetDeadline(t time.Time) error      { return nil }
func (c *wsNetConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *wsNetConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }
