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
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/gorilla/websocket"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

func main() {
	addr := flag.String("addr", ":8880", "The TCP address to listen to")
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
	sshServer, err := newSSHServer(tmpDir)
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
		sshServer.mu.Lock()
		defer sshServer.mu.Unlock()
		log.Printf("/addkey %q", b)
		sshServer.authorizedKeys[string(b)] = true
		fmt.Fprintln(w, "OK")
	})
	mux.HandleFunc("/deletekey", func(w http.ResponseWriter, req *http.Request) {
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

	go func() {
		l, err := net.Listen("tcp", *addr)
		if err != nil {
			log.Fatalf("listen: %v", err)
		}
		log.Printf("HTTP Server listening on %s. Document root is %s\n", l.Addr(), *docRoot)
		if err := httpServer.Serve(l); err != nil && err != http.ErrServerClosed {
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
	ctx, cancel = chromedp.NewContext(ctx, chromedp.WithLogf(log.Printf))
	defer cancel()

	var res, output string
	if err := chromedp.Run(ctx,
		chromedp.Navigate("http://devtest:8880/tests.html"),
		chromedp.WaitVisible("#done"),
		chromedp.Evaluate(`window.sshApp.exited`, &res),
		chromedp.Evaluate(`window.sshApp.term.selectAll(), window.sshApp.term.getSelection()`, &output),
	); err != nil {
		log.Fatal(err)
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

	signer ssh.Signer
	pubKey ssh.PublicKey
}

func newSSHServer(dir string) (*sshServer, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ed25519.GenerateKey: %w", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("ssh.NewPublicKey: %w", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, fmt.Errorf("ssh.NewSignerFromKey: %w", err)
	}

	server := &sshServer{
		authorizedKeys: make(map[string]bool),
		dir:            dir,
		signer:         signer,
		pubKey:         sshPub,
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

		PublicKeyCallback: func(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
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
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}
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
	return nil
}
