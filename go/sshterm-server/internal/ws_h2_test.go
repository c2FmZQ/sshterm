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
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/net/http2/hpack"

	"github.com/c2FmZQ/websocket"
)

func buildClientWSFrame(fin bool, opcode byte, payload []byte) []byte {
	var b bytes.Buffer
	b0 := opcode
	if fin {
		b0 |= 0x80
	}
	b.WriteByte(b0)

	n := len(payload)
	switch {
	case n < 126:
		b.WriteByte(0x80 | byte(n))
	case n <= 65535:
		b.WriteByte(0x80 | 126)
		var ext [2]byte
		binary.BigEndian.PutUint16(ext[:], uint16(n))
		b.Write(ext[:])
	default:
		b.WriteByte(0x80 | 127)
		var ext [8]byte
		binary.BigEndian.PutUint64(ext[:], uint64(n))
		b.Write(ext[:])
	}

	mask := [4]byte{0x12, 0x34, 0x56, 0x78}
	b.Write(mask[:])
	maskedPayload := make([]byte, n)
	for i := range payload {
		maskedPayload[i] = payload[i] ^ mask[i&3]
	}
	b.Write(maskedPayload)
	return b.Bytes()
}

func readServerWSFrame(r io.Reader) (fin bool, opcode byte, payload []byte, err error) {
	var hdr [2]byte
	if _, err = io.ReadFull(r, hdr[:]); err != nil {
		return false, 0, nil, err
	}
	fin = hdr[0]&0x80 != 0
	opcode = hdr[0] & 0x0f
	if hdr[1]&0x80 != 0 {
		return false, 0, nil, errors.New("unexpected masked server frame")
	}
	n := int(hdr[1] & 0x7f)
	switch n {
	case 126:
		var ext [2]byte
		if _, err = io.ReadFull(r, ext[:]); err != nil {
			return false, 0, nil, err
		}
		n = int(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err = io.ReadFull(r, ext[:]); err != nil {
			return false, 0, nil, err
		}
		n = int(binary.BigEndian.Uint64(ext[:]))
	}
	payload = make([]byte, n)
	if _, err = io.ReadFull(r, payload); err != nil {
		return false, 0, nil, err
	}
	return fin, opcode, payload, nil
}

func TestRunH2CAndHTTP1(t *testing.T) {
	srv, err := New(Options{
		Addr:      "127.0.0.1:0",
		Endpoints: []Endpoint{{Name: "local", Address: "127.0.0.1:22"}},
		Logger:    log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Run(ctx)
	}()

	addr := waitServerAddr(t, srv, cancel)

	// HTTP/1.1 request
	h1Protos := &http.Protocols{}
	h1Protos.SetHTTP1(true)
	h1Client := &http.Client{Transport: &http.Transport{Protocols: h1Protos}}
	resp, err := h1Client.Get("http://" + addr.String() + "/config.json")
	if err != nil {
		cancel()
		t.Fatalf("HTTP/1.1 GET /config.json: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.ProtoMajor != 1 {
		t.Fatalf("HTTP/1.1 got status=%d proto=%d.%d", resp.StatusCode, resp.ProtoMajor, resp.ProtoMinor)
	}

	// Unencrypted HTTP/2 (h2c) request
	h2cProtos := &http.Protocols{}
	h2cProtos.SetUnencryptedHTTP2(true)
	h2cClient := &http.Client{Transport: &http.Transport{Protocols: h2cProtos}}
	resp, err = h2cClient.Get("http://" + addr.String() + "/config.json")
	if err != nil {
		cancel()
		t.Fatalf("h2c GET /config.json: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.ProtoMajor != 2 {
		t.Fatalf("h2c got status=%d proto=%d.%d", resp.StatusCode, resp.ProtoMajor, resp.ProtoMinor)
	}

	cancel()
	if err := <-errCh; err != nil {
		t.Fatalf("srv.Run: %v", err)
	}
}

func waitServerAddr(t *testing.T, srv *Server, cancel context.CancelFunc) net.Addr {
	t.Helper()
	for range 100 {
		if addr := srv.Addr(); addr != nil {
			return addr
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	t.Fatal("server did not start listening in time")
	return nil
}

const (
	h2ClientPreface                = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
	h2FrameData                    = 0x0
	h2FrameHeaders                 = 0x1
	h2FrameRSTStream               = 0x3
	h2FrameSettings                = 0x4
	h2FramePing                    = 0x6
	h2FrameWindowUpdate            = 0x8
	h2FlagAck                      = 0x1
	h2FlagEndStream                = 0x1
	h2FlagEndHeaders               = 0x4
	h2SettingEnableConnectProtocol = 0x8
)

type h2RawFrame struct {
	typ      byte
	flags    byte
	streamID uint32
	payload  []byte
}

func readH2Frame(r io.Reader) (h2RawFrame, error) {
	var hdr [9]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return h2RawFrame{}, err
	}
	n := int(hdr[0])<<16 | int(hdr[1])<<8 | int(hdr[2])
	payload := make([]byte, n)
	if n > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return h2RawFrame{}, err
		}
	}
	return h2RawFrame{
		typ:      hdr[3],
		flags:    hdr[4],
		streamID: binary.BigEndian.Uint32(hdr[5:9]) & 0x7fffffff,
		payload:  payload,
	}, nil
}

func writeH2Frame(w io.Writer, typ, flags byte, streamID uint32, payload []byte) error {
	var hdr [9]byte
	n := len(payload)
	hdr[0] = byte(n >> 16)
	hdr[1] = byte(n >> 8)
	hdr[2] = byte(n)
	hdr[3] = typ
	hdr[4] = flags
	binary.BigEndian.PutUint32(hdr[5:9], streamID&0x7fffffff)
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if n > 0 {
		_, err := w.Write(payload)
		return err
	}
	return nil
}

type h2TestSession struct {
	conn    net.Conn
	hdec    *hpack.Decoder
	writeMu sync.Mutex
	mu      sync.Mutex
	nextID  uint32
	streams map[uint32]*h2TestStream
}

type h2TestStream struct {
	sess   *h2TestSession
	id     uint32
	status chan string
	pr     *io.PipeReader
	pw     *io.PipeWriter
	buf    []byte
}

func dialH2Session(t *testing.T, addr string, useTLS bool) *h2TestSession {
	t.Helper()
	var (
		conn net.Conn
		err  error
	)
	if useTLS {
		tconn, err := tls.Dial("tcp", addr, &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"h2"},
		})
		if err != nil {
			t.Fatalf("tls.Dial: %v", err)
		}
		if proto := tconn.ConnectionState().NegotiatedProtocol; proto != "h2" {
			tconn.Close()
			t.Fatalf("NegotiatedProtocol = %q, want h2", proto)
		}
		conn = tconn
	} else {
		conn, err = net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("net.Dial: %v", err)
		}
	}

	if _, err := io.WriteString(conn, h2ClientPreface); err != nil {
		conn.Close()
		t.Fatalf("WriteString preface: %v", err)
	}
	if err := writeH2Frame(conn, h2FrameSettings, 0, 0, nil); err != nil {
		conn.Close()
		t.Fatalf("write SETTINGS: %v", err)
	}

	gotEnableConnect := false
	for {
		f, err := readH2Frame(conn)
		if err != nil {
			conn.Close()
			t.Fatalf("readH2Frame initial settings: %v", err)
		}
		if f.typ != h2FrameSettings || f.flags&h2FlagAck != 0 {
			continue
		}
		for i := 0; i+6 <= len(f.payload); i += 6 {
			id := binary.BigEndian.Uint16(f.payload[i : i+2])
			val := binary.BigEndian.Uint32(f.payload[i+2 : i+6])
			if id == h2SettingEnableConnectProtocol && val == 1 {
				gotEnableConnect = true
			}
		}
		if err := writeH2Frame(conn, h2FrameSettings, h2FlagAck, 0, nil); err != nil {
			conn.Close()
			t.Fatalf("write SETTINGS ACK: %v", err)
		}
		break
	}
	if !gotEnableConnect {
		conn.Close()
		t.Fatal("server did not advertise SETTINGS_ENABLE_CONNECT_PROTOCOL=1")
	}

	s := &h2TestSession{
		conn:    conn,
		hdec:    hpack.NewDecoder(4096, nil),
		nextID:  1,
		streams: make(map[uint32]*h2TestStream),
	}
	go s.readLoop()
	return s
}

func (s *h2TestSession) Close() error {
	s.mu.Lock()
	for _, st := range s.streams {
		_ = st.pw.Close()
	}
	s.mu.Unlock()
	return s.conn.Close()
}

func (s *h2TestSession) readLoop() {
	for {
		f, err := readH2Frame(s.conn)
		if err != nil {
			s.mu.Lock()
			for _, st := range s.streams {
				_ = st.pw.CloseWithError(err)
				select {
				case st.status <- "":
				default:
				}
			}
			s.mu.Unlock()
			return
		}

		switch f.typ {
		case h2FrameSettings:
			if f.flags&h2FlagAck == 0 {
				s.writeMu.Lock()
				_ = writeH2Frame(s.conn, h2FrameSettings, h2FlagAck, 0, nil)
				s.writeMu.Unlock()
			}
		case h2FramePing:
			if f.flags&h2FlagAck == 0 {
				s.writeMu.Lock()
				_ = writeH2Frame(s.conn, h2FramePing, h2FlagAck, 0, f.payload)
				s.writeMu.Unlock()
			}
		case h2FrameHeaders:
			var status string
			s.hdec.SetEmitFunc(func(hf hpack.HeaderField) {
				if hf.Name == ":status" {
					status = hf.Value
				}
			})
			_, _ = s.hdec.Write(f.payload)
			_ = s.hdec.Close()

			s.mu.Lock()
			st := s.streams[f.streamID]
			s.mu.Unlock()
			if st != nil {
				select {
				case st.status <- status:
				default:
				}
				if f.flags&h2FlagEndStream != 0 {
					_ = st.pw.Close()
				}
			}
		case h2FrameData:
			s.mu.Lock()
			st := s.streams[f.streamID]
			s.mu.Unlock()
			if st != nil {
				if len(f.payload) > 0 {
					_, _ = st.pw.Write(f.payload)
					var win [4]byte
					binary.BigEndian.PutUint32(win[:], uint32(len(f.payload)))
					s.writeMu.Lock()
					_ = writeH2Frame(s.conn, h2FrameWindowUpdate, 0, 0, win[:])
					_ = writeH2Frame(s.conn, h2FrameWindowUpdate, 0, f.streamID, win[:])
					s.writeMu.Unlock()
				}
				if f.flags&h2FlagEndStream != 0 {
					_ = st.pw.Close()
				}
			}
		case h2FrameRSTStream:
			var code uint32
			if len(f.payload) >= 4 {
				code = binary.BigEndian.Uint32(f.payload[:4])
			}
			s.mu.Lock()
			st := s.streams[f.streamID]
			s.mu.Unlock()
			if st != nil {
				_ = st.pw.CloseWithError(fmt.Errorf("stream reset: %d", code))
				select {
				case st.status <- "":
				default:
				}
			}
		}
	}
}

func (s *h2TestSession) dialWS(t *testing.T, scheme, authority, path string, extraHeaders http.Header) (*h2TestStream, string, error) {
	t.Helper()
	pr, pw := io.Pipe()

	s.mu.Lock()
	id := s.nextID
	s.nextID += 2
	st := &h2TestStream{
		sess:   s,
		id:     id,
		status: make(chan string, 1),
		pr:     pr,
		pw:     pw,
	}
	s.streams[id] = st
	s.mu.Unlock()

	var hbuf bytes.Buffer
	enc := hpack.NewEncoder(&hbuf)
	writeHdr := func(k, v string) {
		_ = enc.WriteField(hpack.HeaderField{Name: k, Value: v})
	}
	writeHdr(":method", http.MethodConnect)
	writeHdr(":protocol", "websocket")
	writeHdr(":scheme", scheme)
	writeHdr(":authority", authority)
	writeHdr(":path", path)
	writeHdr("sec-websocket-version", "13")
	for k, vs := range extraHeaders {
		lk := strings.ToLower(k)
		for _, v := range vs {
			writeHdr(lk, v)
		}
	}

	s.writeMu.Lock()
	err := writeH2Frame(s.conn, h2FrameHeaders, h2FlagEndHeaders, id, hbuf.Bytes())
	s.writeMu.Unlock()
	if err != nil {
		return nil, "", err
	}

	select {
	case status := <-st.status:
		if status != "200" {
			_ = pr.Close()
			return nil, status, fmt.Errorf("unexpected HTTP/2 status %q", status)
		}
		return st, status, nil
	case <-time.After(5 * time.Second):
		_ = pr.Close()
		return nil, "", errors.New("timed out waiting for HTTP/2 response headers")
	}
}

func (c *h2TestStream) WriteFrame(opcode byte, payload []byte) error {
	frame := buildClientWSFrame(true, opcode, payload)
	c.sess.writeMu.Lock()
	defer c.sess.writeMu.Unlock()
	return writeH2Frame(c.sess.conn, h2FrameData, 0, c.id, frame)
}

func (c *h2TestStream) ReadFrame() (byte, []byte, error) {
	_, op, payload, err := readServerWSFrame(c.pr)
	return op, payload, err
}

func (c *h2TestStream) Read(b []byte) (int, error) {
	for len(c.buf) == 0 {
		op, payload, err := c.ReadFrame()
		if err != nil {
			return 0, err
		}
		switch op {
		case websocket.BinaryMessage:
			c.buf = payload
		case websocket.PingMessage:
			_ = c.WriteFrame(websocket.PongMessage, payload)
		case websocket.CloseMessage:
			return 0, io.EOF
		default:
			return 0, fmt.Errorf("unexpected opcode %d", op)
		}
	}
	n := copy(b, c.buf)
	c.buf = c.buf[n:]
	return n, nil
}

func (c *h2TestStream) Write(b []byte) (int, error) {
	if err := c.WriteFrame(websocket.BinaryMessage, b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *h2TestStream) Close() error {
	_ = c.WriteFrame(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
	c.sess.writeMu.Lock()
	_ = writeH2Frame(c.sess.conn, h2FrameData, h2FlagEndStream, c.id, nil)
	c.sess.writeMu.Unlock()
	return c.pr.Close()
}

func (c *h2TestStream) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (c *h2TestStream) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (c *h2TestStream) SetDeadline(t time.Time) error      { return nil }
func (c *h2TestStream) SetReadDeadline(t time.Time) error  { return nil }
func (c *h2TestStream) SetWriteDeadline(t time.Time) error { return nil }

func hasGODEBUGSetting(godebug, want string) bool {
	for _, part := range strings.Split(godebug, ",") {
		if strings.TrimSpace(part) == want {
			return true
		}
	}
	return false
}

func envWithGODEBUG(environ []string, setting string) []string {
	out := make([]string, 0, len(environ)+1)
	found := false
	for _, kv := range environ {
		if strings.HasPrefix(kv, "GODEBUG=") {
			val := strings.TrimPrefix(kv, "GODEBUG=")
			if val == "" {
				out = append(out, "GODEBUG="+setting)
			} else {
				out = append(out, "GODEBUG="+val+","+setting)
			}
			found = true
			continue
		}
		out = append(out, kv)
	}
	if !found {
		out = append(out, "GODEBUG="+setting)
	}
	return out
}

// TestWebSocketOverHTTP2EndToEnd exercises real net/http HTTP/2 (TLS) and h2c
// Extended CONNECT WebSockets. Because net/http checks GODEBUG=http2xconnect=1
// during package init(), this test re-execs itself in a subprocess with
// GODEBUG=http2xconnect=1 when not already set.
func TestWebSocketOverHTTP2EndToEnd(t *testing.T) {
	if !hasGODEBUGSetting(os.Getenv("GODEBUG"), "http2xconnect=1") {
		cmd := exec.Command(os.Args[0], "-test.run=^TestWebSocketOverHTTP2EndToEnd$", "-test.v")
		cmd.Env = envWithGODEBUG(os.Environ(), "http2xconnect=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("subprocess with GODEBUG=http2xconnect=1 failed: %v\n%s", err, out)
		}
		return
	}

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

	sshListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer sshListener.Close()

	go func() {
		for {
			conn, err := sshListener.Accept()
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
								fmt.Fprintf(ch, "h2ran:%s", req.Payload[4:])
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

	t.Run("TLS_HTTP2_SSH", func(t *testing.T) {
		tmpDir := t.TempDir()
		certFile := filepath.Join(tmpDir, "cert.pem")
		keyFile := filepath.Join(tmpDir, "key.pem")
		generateSelfSignedCert(t, certFile, keyFile)

		srv, err := New(Options{
			Addr:        "127.0.0.1:0",
			TLSCertFile: certFile,
			TLSKeyFile:  keyFile,
			Endpoints:   []Endpoint{{Name: "testssh", Address: sshListener.Addr().String()}},
			Logger:      log.New(io.Discard, "", 0),
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		errCh := make(chan error, 1)
		go func() { errCh <- srv.Run(ctx) }()
		addr := waitServerAddr(t, srv, cancel)
		defer func() {
			cancel()
			if err := <-errCh; err != nil {
				t.Errorf("srv.Run: %v", err)
			}
		}()

		sessConn := dialH2Session(t, addr.String(), true)
		defer sessConn.Close()

		for _, p := range []string{"/", "/index.html"} {
			_, status, err := sessConn.dialWS(t, "https", addr.String(), p, nil)
			if err == nil || status != "405" {
				t.Fatalf("CONNECT %s = (%q, %v), want 405", p, status, err)
			}
		}

		_, status, err := sessConn.dialWS(t, "https", addr.String(), "/_ws/testssh", http.Header{
			"Origin": {"https://evil.example.com"},
		})
		if err == nil || status != "403" {
			t.Fatalf("cross-origin = (%q, %v), want 403", status, err)
		}

		wsClient, status, err := sessConn.dialWS(t, "https", addr.String(), "/_ws/testssh", nil)
		if err != nil {
			t.Fatalf("dialWS: %v", err)
		}
		defer wsClient.Close()
		if status != "200" {
			t.Fatalf("status = %q, want 200", status)
		}

		clientCfg := &ssh.ClientConfig{
			User:            "testuser",
			Auth:            []ssh.AuthMethod{ssh.PublicKeys(userSigner)},
			HostKeyCallback: ssh.FixedHostKey(hostSigner.PublicKey()),
		}
		c, chans, reqs, err := ssh.NewClientConn(wsClient, "testssh", clientCfg)
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

		out, err := sess.CombinedOutput("id")
		if err != nil {
			t.Fatalf("CombinedOutput: %v", err)
		}
		if string(out) != "h2ran:id" {
			t.Fatalf("CombinedOutput = %q, want %q", out, "h2ran:id")
		}
	})

	t.Run("H2C_WebSocket_JumpHost", func(t *testing.T) {
		tmpDir := t.TempDir()
		_, caSigner, caPubStr := generateTestSSHKey(t)
		akFile := filepath.Join(tmpDir, "authorized_keys")
		akLine := fmt.Sprintf("cert-authority,principals=\"alice\",permitopen=\"127.0.0.1:*\" %s ca\n", caPubStr)
		if err := os.WriteFile(akFile, []byte(akLine), 0o600); err != nil {
			t.Fatal(err)
		}

		srv, err := New(Options{
			Addr:               "127.0.0.1:0",
			AuthorizedKeysFile: akFile,
			TrustedProxies:     []string{"127.0.0.1/32"},
			Endpoints:          []Endpoint{{Name: "testssh", Address: sshListener.Addr().String()}},
			Logger:             log.New(io.Discard, "", 0),
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		errCh := make(chan error, 1)
		go func() { errCh <- srv.Run(ctx) }()
		addr := waitServerAddr(t, srv, cancel)
		defer func() {
			cancel()
			if err := <-errCh; err != nil {
				t.Errorf("srv.Run: %v", err)
			}
		}()

		sessConn := dialH2Session(t, addr.String(), false)
		defer sessConn.Close()

		cert := &ssh.Certificate{
			Key:             sshUserPub,
			Serial:          1,
			CertType:        ssh.UserCert,
			KeyId:           "alice-cert",
			ValidPrincipals: []string{"alice"},
			ValidAfter:      uint64(time.Now().Add(-time.Minute).Unix()),
			ValidBefore:     uint64(time.Now().Add(time.Hour).Unix()),
			Permissions: ssh.Permissions{
				CriticalOptions: map[string]string{"source-address": "203.0.113.0/24"},
				Extensions:      map[string]string{"permit-port-forwarding": ""},
			},
		}
		if err := cert.SignCert(rand.Reader, caSigner); err != nil {
			t.Fatal(err)
		}
		certSigner, err := ssh.NewCertSigner(cert, userSigner)
		if err != nil {
			t.Fatal(err)
		}

		wsClient, status, err := sessConn.dialWS(t, "http", addr.String(), "/_ws/testssh", nil)
		if err != nil {
			t.Fatalf("dialWS h2c: %v", err)
		}
		if status != "200" {
			t.Fatalf("h2c status = %q, want 200", status)
		}
		c, chans, reqs, err := ssh.NewClientConn(wsClient, "testssh", &ssh.ClientConfig{
			User:            "testuser",
			Auth:            []ssh.AuthMethod{ssh.PublicKeys(userSigner)},
			HostKeyCallback: ssh.FixedHostKey(hostSigner.PublicKey()),
		})
		if err != nil {
			t.Fatalf("h2c ssh.NewClientConn: %v", err)
		}
		sshClient := ssh.NewClient(c, chans, reqs)
		sess, err := sshClient.NewSession()
		if err != nil {
			t.Fatalf("h2c NewSession: %v", err)
		}
		out, err := sess.CombinedOutput("h2c")
		sess.Close()
		sshClient.Close()
		wsClient.Close()
		if err != nil || string(out) != "h2ran:h2c" {
			t.Fatalf("h2c CombinedOutput = (%q, %v), want %q", out, err, "h2ran:h2c")
		}

		jumpWS, _, err := sessConn.dialWS(t, "http", addr.String(), "/_ws/"+DefaultJumpEndpointName, http.Header{
			"X-Forwarded-For": {"203.0.113.42"},
		})
		if err != nil {
			t.Fatalf("dialWS jump: %v", err)
		}
		defer jumpWS.Close()

		jc, jchans, jreqs, err := ssh.NewClientConn(jumpWS, DefaultJumpEndpointName, &ssh.ClientConfig{
			User:            "alice",
			Auth:            []ssh.AuthMethod{ssh.PublicKeys(certSigner)},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		})
		if err != nil {
			t.Fatalf("jump ssh.NewClientConn: %v", err)
		}
		jumpClient := ssh.NewClient(jc, jchans, jreqs)
		defer jumpClient.Close()

		tunnelConn, err := jumpClient.Dial("tcp", sshListener.Addr().String())
		if err != nil {
			t.Fatalf("jumpClient.Dial: %v", err)
		}
		defer tunnelConn.Close()

		tc, tchans, treqs, err := ssh.NewClientConn(tunnelConn, "target", &ssh.ClientConfig{
			User:            "testuser",
			Auth:            []ssh.AuthMethod{ssh.PublicKeys(userSigner)},
			HostKeyCallback: ssh.FixedHostKey(hostSigner.PublicKey()),
		})
		if err != nil {
			t.Fatalf("target ssh.NewClientConn: %v", err)
		}
		targetClient := ssh.NewClient(tc, tchans, treqs)
		defer targetClient.Close()

		tsess, err := targetClient.NewSession()
		if err != nil {
			t.Fatalf("target NewSession: %v", err)
		}
		defer tsess.Close()
		tout, err := tsess.CombinedOutput("via-h2c-jump")
		if err != nil || string(tout) != "h2ran:via-h2c-jump" {
			t.Fatalf("target CombinedOutput = (%q, %v), want %q", tout, err, "h2ran:via-h2c-jump")
		}

		_, unauthSigner, _ := generateTestSSHKey(t)
		var unauthWG sync.WaitGroup
		for range 10 {
			unauthWG.Add(1)
			go func() {
				defer unauthWG.Done()
				uWS, _, dErr := sessConn.dialWS(t, "http", addr.String(), "/_ws/"+DefaultJumpEndpointName, nil)
				if dErr != nil {
					return
				}
				_, _, _, _ = ssh.NewClientConn(uWS, DefaultJumpEndpointName, &ssh.ClientConfig{
					User:            "intruder",
					Auth:            []ssh.AuthMethod{ssh.PublicKeys(unauthSigner)},
					HostKeyCallback: ssh.InsecureIgnoreHostKey(),
				})
				_ = uWS.WriteFrame(websocket.PingMessage, []byte("late-ping"))
				_ = uWS.WriteFrame(websocket.PongMessage, []byte("late-pong"))
				_ = uWS.Close()
			}()
		}
		unauthWG.Wait()
	})

	t.Run("H2C_JumpHost_UntrustedXFFIgnored", func(t *testing.T) {
		tmpDir := t.TempDir()
		_, caSigner, caPubStr := generateTestSSHKey(t)
		akFile := filepath.Join(tmpDir, "authorized_keys")
		akLine := fmt.Sprintf("cert-authority,principals=\"alice\",permitopen=\"127.0.0.1:*\" %s ca\n", caPubStr)
		if err := os.WriteFile(akFile, []byte(akLine), 0o600); err != nil {
			t.Fatal(err)
		}

		srv, err := New(Options{
			Addr:               "127.0.0.1:0",
			AuthorizedKeysFile: akFile,
			TrustedProxies:     []string{"192.0.2.1/32"},
			Logger:             log.New(io.Discard, "", 0),
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		errCh := make(chan error, 1)
		go func() { errCh <- srv.Run(ctx) }()
		addr := waitServerAddr(t, srv, cancel)
		defer func() {
			cancel()
			if err := <-errCh; err != nil {
				t.Errorf("srv.Run: %v", err)
			}
		}()

		sessConn := dialH2Session(t, addr.String(), false)
		defer sessConn.Close()

		cert := &ssh.Certificate{
			Key:             sshUserPub,
			Serial:          2,
			CertType:        ssh.UserCert,
			KeyId:           "alice-cert",
			ValidPrincipals: []string{"alice"},
			ValidAfter:      uint64(time.Now().Add(-time.Minute).Unix()),
			ValidBefore:     uint64(time.Now().Add(time.Hour).Unix()),
			Permissions: ssh.Permissions{
				CriticalOptions: map[string]string{"source-address": "203.0.113.0/24"},
				Extensions:      map[string]string{"permit-port-forwarding": ""},
			},
		}
		if err := cert.SignCert(rand.Reader, caSigner); err != nil {
			t.Fatal(err)
		}
		certSigner, err := ssh.NewCertSigner(cert, userSigner)
		if err != nil {
			t.Fatal(err)
		}

		jumpWS, _, err := sessConn.dialWS(t, "http", addr.String(), "/_ws/"+DefaultJumpEndpointName, http.Header{
			"X-Forwarded-For": {"203.0.113.42"},
		})
		if err != nil {
			t.Fatalf("dialWS jump: %v", err)
		}
		defer jumpWS.Close()

		if _, _, _, err := ssh.NewClientConn(jumpWS, DefaultJumpEndpointName, &ssh.ClientConfig{
			User:            "alice",
			Auth:            []ssh.AuthMethod{ssh.PublicKeys(certSigner)},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		}); err == nil {
			t.Fatal("expected SSH auth failure when X-Forwarded-For comes from untrusted peer")
		}
	})
}
