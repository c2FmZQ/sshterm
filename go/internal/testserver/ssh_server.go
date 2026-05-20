package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

type sshServer struct {
	t              *testing.T
	clientSequence uint16 // Tracks the client's request sequence number
	mu             sync.Mutex
	authorizedKeys map[string]bool
	config         *ssh.ServerConfig
	dir            string

	authority ssh.Signer
	signer    ssh.Signer
	pubKey    ssh.PublicKey

	x11SimDone chan struct{}

	resourceIdBase uint32
	resourceIdMask uint32
	rootWindowID   uint32
	rootVisualID   uint32
	x11ReplyTracker *wire.ReplyTracker
}

func newSSHServer(t *testing.T, dir string, hostCert bool) (*sshServer, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ed25519.GenerateKey: %w", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("ssh.NewPublicKey: %w", err)
	}
	authority, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, fmt.Errorf("ssh.NewSignerFromKey: %w", err)
	}
	signer := authority
	if hostCert {
		cert := &ssh.Certificate{
			Key:      sshPub,
			Serial:   0x12345,
			CertType: ssh.HostCert,
			KeyId:    "test-server",
			ValidPrincipals: []string{
				"test-server",
			},
		}
		if err := cert.SignCert(rand.Reader, authority); err != nil {
			t.Fatalf("unable to create signer cert: %v", err)
		}
		certSigner, err := ssh.NewCertSigner(cert, authority)
		if err != nil {
			return nil, fmt.Errorf("ssh.NewCertSigner: %w", err)
		}
		signer = certSigner
	}

	server := &sshServer{
		t:              t,
		authorizedKeys: make(map[string]bool),
		dir:            dir,
		authority:      authority,
		signer:         signer,
		pubKey:         sshPub,
		x11SimDone:     make(chan struct{}),
	}

	certChecker := &ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			return bytes.Equal(authority.PublicKey().Marshal(), auth.Marshal())
		},
		UserKeyFallback: func(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			server.mu.Lock()
			defer server.mu.Unlock()
			t.Logf("PublicKeyCallback: %q", pubKey.Marshal())
			if server.authorizedKeys[string(pubKey.Marshal())] {
				return &ssh.Permissions{
					Extensions: map[string]string{
						"pubkey-fp": ssh.FingerprintSHA256(pubKey),
					},
				}, nil
			}
			return nil, fmt.Errorf("unknown public key for %q", c.User())
		},
	}

	config := &ssh.ServerConfig{
		KeyboardInteractiveCallback: func(c ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			t.Logf("KeyboardInteractiveCallback")
			answers, err := client("", "", []string{"Password: "}, []bool{false})
			if err != nil {
				return nil, err
			}
			if len(answers) == 1 && c.User() == "testuser" && string(answers[0]) == "password" {
				return nil, nil
			}
			return nil, fmt.Errorf("keyboard interactive rejected for %q", c.User())
		},

		PublicKeyCallback: certChecker.Authenticate,
	}
	config.AddHostKey(signer)
	server.config = config
	return server, nil
}

func (s *sshServer) handle(nConn net.Conn) error {
	serverSSHConn, chans, reqs, err := ssh.NewServerConn(nConn, s.config)
	if err != nil {
		return err
	}

	var wg sync.WaitGroup
	defer wg.Wait()

	wg.Add(1)
	go func() {
		ssh.DiscardRequests(reqs)
		wg.Done()
	}()

	for newChannel := range chans {
		s.t.Logf("newChannel type: %s", newChannel.ChannelType())
		switch newChannel.ChannelType() {
		case "direct-tcpip":
			s.handleDirectTCPIP(&wg, newChannel)
		case "session":
			s.handleSession(&wg, newChannel, serverSSHConn)
		case "x11":
			s.handleX11Channel(&wg, newChannel)
		default:
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
		}
	}
	return nil
}

func (s *sshServer) handleDirectTCPIP(wg *sync.WaitGroup, newChannel ssh.NewChannel) {
	s.t.Logf("port-forward: %q", newChannel.ExtraData())
	channel, requests, err := newChannel.Accept()
	if err != nil {
		s.t.Errorf("Could not accept channel: %v", err)
		return
	}
	wg.Add(1)
	go func(in <-chan *ssh.Request) {
		ssh.DiscardRequests(in)
		wg.Done()
	}(requests)
	s.handle(fakeConn{channel})
}

func (s *sshServer) handleSession(wg *sync.WaitGroup, newChannel ssh.NewChannel, serverConn *ssh.ServerConn) {
	channel, requests, err := newChannel.Accept()
	if err != nil {
		s.t.Errorf("Could not accept channel: %v", err)
		return
	}
	wg.Add(1)
	go func(in <-chan *ssh.Request) {
		defer wg.Done()
		for req := range in {
			s.t.Logf("request type: %s", req.Type)
			switch req.Type {
			case "x11-req":
				s.t.Logf("X11 request received: %q", req.Payload)
				var x11req struct {
					SingleConnection       bool
					AuthenticationProtocol string
					AuthenticationCookie   string
					ScreenNumber           uint32
				}
				if err := ssh.Unmarshal(req.Payload, &x11req); err != nil {
					s.t.Errorf("ssh.Unmarshal x11-req: %v", err)
					req.Reply(false, nil)
					continue
				}
				req.Reply(true, nil)
				wg.Add(1)
				go func() {
					defer wg.Done()
					s.t.Log("Starting X11 simulation")
					authCookie, err := hex.DecodeString(x11req.AuthenticationCookie)
					if err != nil {
						s.t.Errorf("x11req.AuthenticationCookie: %v", err)
						return
					}
					s.simulateX11Application(serverConn, x11req.AuthenticationProtocol, authCookie)
					s.t.Log("X11 simulation finished")
				}()

			case "shell":
				req.Reply(true, nil)
				term := terminal.NewTerminal(channel, "remote> ")

				wg.Add(1)
				go func() {
					defer func() {
						channel.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
						channel.Close()
						wg.Done()
					}()
					for {
						line, err := term.ReadLine()
						if err != nil || line == "exit" {
							break
						}
					}
				}()

			case "exec":
				req.Reply(true, nil)
				if len(req.Payload) > 4 {
					fmt.Fprintf(channel, "exec: %s\n", req.Payload[4:])
				}
				channel.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
				channel.Close()

			case "subsystem":
				if len(req.Payload) < 4 || string(req.Payload[4:]) != "sftp" {
					req.Reply(false, nil)
					return
				}
				req.Reply(true, nil)
				wg.Add(1)
				go func() {
					defer wg.Done()
					server, err := sftp.NewServer(channel, sftp.WithServerWorkingDirectory(s.dir))
					if err != nil {
						s.t.Error(err)
						return
					}
					if err := server.Serve(); err != nil {
						if err != io.EOF {
							s.t.Error("sftp server completed with error:", err)
							return
						}
					}
					server.Close()
					s.t.Log("sftp client exited session.")
				}()

			default:
				req.Reply(false, nil)
			}
		}
	}(requests)
}

func (s *sshServer) handleX11Channel(wg *sync.WaitGroup, newChannel ssh.NewChannel) {
	s.t.Logf("X11 channel received: %q", newChannel.ExtraData())
	// Accept the channel and discard any requests on it.
	channel, requests, err := newChannel.Accept()
	if err != nil {
		s.t.Errorf("Could not accept X11 channel: %v", err)
		return
	}
	wg.Add(1)
	go func(in <-chan *ssh.Request) {
		ssh.DiscardRequests(in)
		wg.Done()
	}(requests)
	channel.Close() // Close the channel immediately as simulateX11Application will open a new one.
}

var _ net.Conn = (*netConn)(nil)

type netConn struct {
	conn *websocket.Conn
	buf  []byte
}

func (c *netConn) Close() error {
	return c.conn.Close()
}

func (c *netConn) Read(b []byte) (int, error) {
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

func (c *netConn) Write(b []byte) (int, error) {
	return len(b), c.conn.WriteMessage(websocket.BinaryMessage, b)
}

func (c *netConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *netConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

func (c *netConn) SetDeadline(t time.Time) error {
	c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}

func (c *netConn) LocalAddr() net.Addr {
	return c.conn.NetConn().LocalAddr()
}

func (c *netConn) RemoteAddr() net.Addr {
	return c.conn.NetConn().RemoteAddr()
}

type fakeConn struct {
	io.ReadWriteCloser
}

func (fakeConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (fakeConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func (fakeConn) SetDeadline(t time.Time) error {
	return nil
}

func (fakeConn) LocalAddr() net.Addr {
	return &net.TCPAddr{}
}

func (fakeConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{}
}
