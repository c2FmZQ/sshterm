// MIT License
//
// Copyright (c) 2024 TTBT Enterprises LLC
// Copyright (c) 2024 Robin Thellend <rthellend@rthellend.com>
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

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/chromedp/cdproto"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/cdproto/webauthn"
	"github.com/chromedp/chromedp"
	"github.com/gorilla/websocket"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

func main() {
	if _, err := os.Stat("/home"); err == nil {
		fmt.Fprintf(os.Stderr, "This tool is intended to run in a container.\n")
		os.Exit(1)
	}
	addr := flag.String("addr", ":8443", "The TCP address to listen to")
	docRoot := flag.String("document-root", "", "The document root directory")
	withChromeDP := flag.String("with-chromedp", "", "The url of the remote debugging port")

	tmpDir, err := os.MkdirTemp("", "sshterm-test")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	flag.Parse()
	if *docRoot == "" {
		log.Fatal("--document-root must be set")
	}

	upgrader := &websocket.Upgrader{
		ReadBufferSize:  8192,
		WriteBufferSize: 8192,
	}
	sshServer, err := newSSHServer(tmpDir, false)
	if err != nil {
		log.Fatalf("SSH Server: %v", err)
	}
	sshServerWithCert, err := newSSHServer(tmpDir, true)
	if err != nil {
		log.Fatalf("SSH Server: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/websocket", func(w http.ResponseWriter, req *http.Request) {
		conn, err := upgrader.Upgrade(w, req, nil)
		if err != nil {
			log.Printf("ERR %v", err)
			return
		}
		defer conn.Close()
		req.ParseForm()
		if req.Form.Get("cert") == "true" {
			sshServerWithCert.handle(&netConn{conn: conn})
			return
		}
		sshServer.handle(&netConn{conn: conn})
	})
	mux.HandleFunc("/reset", func(w http.ResponseWriter, req *http.Request) {
		os.RemoveAll(tmpDir)
		os.Mkdir(tmpDir, 0o755)
		fmt.Fprintln(w, "OK")
	})
	mux.HandleFunc("/addkey", func(w http.ResponseWriter, req *http.Request) {
		if req.Method != "POST" {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		b, _ := io.ReadAll(req.Body)
		log.Printf("/addkey %q", b)

		sshServer.mu.Lock()
		defer sshServer.mu.Unlock()
		sshServer.authorizedKeys[string(b)] = true

		sshServerWithCert.mu.Lock()
		defer sshServerWithCert.mu.Unlock()
		sshServerWithCert.authorizedKeys[string(b)] = true

		fmt.Fprintln(w, "OK")
	})
	mux.HandleFunc("/cakey", func(w http.ResponseWriter, req *http.Request) {
		k := ssh.MarshalAuthorizedKey(sshServerWithCert.pubKey)
		log.Printf("/cakey: %s", k)
		fmt.Fprintf(w, "%s\n", k)
	})
	mux.HandleFunc("/cert", func(w http.ResponseWriter, req *http.Request) {
		log.Print("/cert")
		if req.Method != "POST" {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		defer req.Body.Close()
		body, err := io.ReadAll(req.Body)
		if err != nil {
			log.Printf("/cert: ReadAll: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		pub, _, _, _, err := ssh.ParseAuthorizedKey(body)
		if err != nil {
			log.Printf("/cert: ParseAuthorizedKey: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		now := time.Now().UTC()
		cert := &ssh.Certificate{
			Key:         pub,
			CertType:    ssh.UserCert,
			KeyId:       "testuser",
			ValidAfter:  uint64(now.Add(-5 * time.Minute).Unix()),
			ValidBefore: uint64(now.Add(10 * time.Minute).Unix()),
		}
		if err := cert.SignCert(rand.Reader, sshServerWithCert.authority); err != nil {
			log.Printf("/cert: SignCert: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		out := ssh.MarshalAuthorizedKey(cert)
		w.Header().Set("content-type", "text/plain")
		w.Header().Set("content-length", fmt.Sprintf("%d", len(out)))
		w.Write(out)
	})
	fs := http.FileServer(http.Dir(*docRoot))
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		fs.ServeHTTP(w, req)
	})

	httpServer := http.Server{
		Handler: mux,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Generate self-signed certificate
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "devtest"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"devtest", "devtest.local"},
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		log.Fatalf("x509.CreateCertificate: %v", err)
	}
	certFile := filepath.Join(tmpDir, "cert.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes}), 0o600); err != nil {
		log.Fatalf("cert: %s", err)
	}
	b, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		log.Fatalf("x509.MarshalECPrivateKey: %v", err)
	}
	keyFile := filepath.Join(tmpDir, "key.pem")
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b}), 0o600); err != nil {
		log.Fatalf("key: %s", err)
	}

	go func() {
		l, err := net.Listen("tcp", *addr)
		if err != nil {
			log.Fatalf("listen: %v", err)
		}
		log.Printf("HTTPS Server listening on %s. Document root is %s\n", l.Addr(), *docRoot)
		if err := httpServer.ServeTLS(l, certFile, keyFile); err != nil && err != http.ErrServerClosed {
			log.Fatalf("http server: %v", err)
		}
	}()
	if *withChromeDP == "" {
		<-ctx.Done()
		httpServer.Shutdown(ctx)
		return
	}

	ctx, cancel = chromedp.NewRemoteAllocator(ctx, *withChromeDP)
	defer cancel()

	ctx, cancel = chromedp.NewContext(ctx,
		//chromedp.WithDebugf(log.Printf),
		chromedp.WithErrorf(log.Printf),
		chromedp.WithLogf(log.Printf),
	)
	defer cancel()

	gotException := make(chan bool, 1)
	chromedp.ListenTarget(ctx, func(ev any) {
		switch ev := ev.(type) {
		case *cdproto.Message:
		case *runtime.EventConsoleAPICalled:
			//log.Printf("* console.%s call:", ev.Type)
			//for _, arg := range ev.Args {
			//	log.Printf("   %s - %s", arg.Type, arg.Value)
			//}
		case *runtime.EventExceptionThrown:
			log.Printf("Exception: * %s", ev.ExceptionDetails.Error())
			gotException <- true
		case *webauthn.EventCredentialAdded, *webauthn.EventCredentialAsserted, *webauthn.EventCredentialDeleted, *webauthn.EventCredentialUpdated:
			log.Printf("WebAuthn event: %#v", ev)
		default:
			//log.Printf("Target event: %#v", ev)
		}
	})

	if err := chromedp.Run(ctx, webauthn.Enable().WithEnableUI(false)); err != nil {
		log.Fatalf("webauthn.Enable(): %v", err)
	}

	var authenticatorID webauthn.AuthenticatorID
	if err := chromedp.Run(ctx,
		chromedp.ActionFunc(func(ctx context.Context) error {
			authID, err := webauthn.AddVirtualAuthenticator(&webauthn.VirtualAuthenticatorOptions{
				Protocol:                    webauthn.AuthenticatorProtocolCtap2,
				Ctap2version:                webauthn.Ctap2versionCtap21,
				Transport:                   webauthn.AuthenticatorTransportInternal,
				HasResidentKey:              true,
				HasUserVerification:         true,
				AutomaticPresenceSimulation: true,
				IsUserVerified:              true,
			}).Do(ctx)
			authenticatorID = authID
			return err
		}),
	); err != nil {
		log.Fatalf("webauthn.AddVirtualAuthenticator(): %v", err)
	}
	log.Printf("AddVirtualAuthenticator: %q", authenticatorID)

	if err := chromedp.Run(ctx,
		webauthn.ClearCredentials(authenticatorID),
		webauthn.SetAutomaticPresenceSimulation(authenticatorID, true),
		chromedp.ActionFunc(func(ctx context.Context) error {
			creds, err := webauthn.GetCredentials(authenticatorID).Do(ctx)
			log.Printf("Credentials: %v", creds)
			return err
		}),
	); err != nil {
		log.Fatalf("webauthn.SetAutomaticPresenceSimulation(): %v", err)
	}

	var res, output string
	if err := chromedp.Run(ctx,
		chromedp.Navigate("https://devtest.local:8443/tests.html"),
		chromedp.WaitVisible("#done"),
		chromedp.Evaluate(`window.sshApp.exited`, &res),
		chromedp.Evaluate(`window.sshApp.term.selectAll(), window.sshApp.term.getSelection()`, &output),
	); err != nil {
		log.Printf("chromedp.Run: %v", err)
	}
	fmt.Println(output)
	fmt.Println(res)
	if res != "PASS" {
		os.Exit(1)
	}
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

type sshServer struct {
	mu             sync.Mutex
	authorizedKeys map[string]bool
	config         *ssh.ServerConfig
	dir            string

	authority ssh.Signer
	signer    ssh.Signer
	pubKey    ssh.PublicKey
}

func newSSHServer(dir string, hostCert bool) (*sshServer, error) {
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
			log.Fatalf("unable to create signer cert: %v", err)
		}
		certSigner, err := ssh.NewCertSigner(cert, authority)
		if err != nil {
			return nil, fmt.Errorf("ssh.NewCertSigner: %w", err)
		}
		signer = certSigner
	}

	server := &sshServer{
		authorizedKeys: make(map[string]bool),
		dir:            dir,
		authority:      authority,
		signer:         signer,
		pubKey:         sshPub,
	}

	certChecker := &ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			return bytes.Equal(authority.PublicKey().Marshal(), auth.Marshal())
		},
		UserKeyFallback: func(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			server.mu.Lock()
			defer server.mu.Unlock()
			log.Printf("PublicKeyCallback: %q", pubKey.Marshal())
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
			log.Print("KeyboardInteractiveCallback")
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
	_, chans, reqs, err := ssh.NewServerConn(nConn, s.config)
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
		log.Printf("newChannel type: %s", newChannel.ChannelType())
		switch newChannel.ChannelType() {
		case "direct-tcpip":
			s.handleDirectTCPIP(&wg, newChannel)
		case "session":
			s.handleSession(&wg, newChannel)
		default:
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
		}
	}
	return nil
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

func (s *sshServer) handleDirectTCPIP(wg *sync.WaitGroup, newChannel ssh.NewChannel) {
	log.Printf("port-forward: %q", newChannel.ExtraData())
	channel, requests, err := newChannel.Accept()
	if err != nil {
		log.Fatalf("Could not accept channel: %v", err)
	}
	wg.Add(1)
	go func(in <-chan *ssh.Request) {
		ssh.DiscardRequests(in)
		wg.Done()
	}(requests)
	s.handle(fakeConn{channel})
}

func (s *sshServer) handleSession(wg *sync.WaitGroup, newChannel ssh.NewChannel) {
	channel, requests, err := newChannel.Accept()
	if err != nil {
		log.Fatalf("Could not accept channel: %v", err)
	}
	wg.Add(1)
	go func(in <-chan *ssh.Request) {
		defer wg.Done()
		for req := range in {
			log.Printf("request type: %s", req.Type)
			switch req.Type {
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
						log.Fatal(err)
					}
					if err := server.Serve(); err != nil {
						if err != io.EOF {
							log.Fatal("sftp server completed with error:", err)
						}
					}
					server.Close()
					log.Print("sftp client exited session.")
				}()

			default:
				req.Reply(false, nil)
			}
		}
	}(requests)
}
