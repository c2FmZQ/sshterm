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

//go:build docker

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
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
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/cdproto"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

var (
	addr         = flag.String("addr", ":8443", "The TCP address to listen to")
	docRoot      = flag.String("document-root", "", "The document root directory")
	withChromeDP = flag.String("with-chromedp", "", "The url of the remote debugging port")
	outputDir    = flag.String("output-dir", "", "Where the test output files are written")
)

func TestMain(m *testing.M) {
	flag.Parse()
	if _, err := os.Stat("/home"); err == nil {
		log.Fatalf("This test is intended to run in a container.\n")
	}
	if *docRoot == "" {
		log.Fatal("--document-root must be set")
	}
	os.Exit(m.Run())
}

func TestSSHTerm(t *testing.T) {
	tmpDir := t.TempDir()
	reset := func() {
		os.RemoveAll(tmpDir)
		os.Mkdir(tmpDir, 0o755)
	}
	upgrader := &websocket.Upgrader{
		ReadBufferSize:  8192,
		WriteBufferSize: 8192,
	}
	sshServer, err := newSSHServer(t, tmpDir, false)
	if err != nil {
		t.Fatalf("SSH Server: %v", err)
	}
	sshServerWithCert, err := newSSHServer(t, tmpDir, true)
	if err != nil {
		t.Fatalf("SSH Server: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/websocket", func(w http.ResponseWriter, req *http.Request) {
		conn, err := upgrader.Upgrade(w, req, nil)
		if err != nil {
			t.Logf("ERR %v", err)
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
		reset()
		fmt.Fprintln(w, "OK")
	})
	mux.HandleFunc("/addkey", func(w http.ResponseWriter, req *http.Request) {
		if req.Method != "POST" {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		b, _ := io.ReadAll(req.Body)
		t.Logf("/addkey %q", b)

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
		t.Logf("/cakey: %s", k)
		fmt.Fprintf(w, "%s\n", k)
	})
	mux.HandleFunc("/cert", func(w http.ResponseWriter, req *http.Request) {
		t.Logf("/cert")
		if req.Method != "POST" {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		defer req.Body.Close()
		body, err := io.ReadAll(req.Body)
		if err != nil {
			t.Logf("/cert: ReadAll: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		pub, _, _, _, err := ssh.ParseAuthorizedKey(body)
		if err != nil {
			t.Logf("/cert: ParseAuthorizedKey: %v", err)
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
			t.Logf("/cert: SignCert: %v", err)
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
		t.Logf("%s %s", req.Method, req.RequestURI)
		w.Header().Set("Cache-Control", "no-store")
		if req.URL.Path == "/tests.x11.config.json" || req.URL.Path == "/tests.real.config.json" {
			b, err := os.ReadFile(filepath.Join(*docRoot, "tests.x11.config.json"))
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if req.URL.Path == "/tests.real.config.json" {
				b = bytes.Replace(b, []byte(`"hostname": "test-server"`), []byte(`"hostname": "x11-apps.local"`), 1)
				b = bytes.Replace(b, []byte(`"hostnames": [ "test-server" ]`), []byte(`"hostnames": [ "x11-apps.local" ]`), 1)
			}
			key := bytes.TrimSpace(ssh.MarshalAuthorizedKey(sshServerWithCert.pubKey))
			w.Header().Set("content-type", "application/json")
			w.Write(bytes.Replace(b, []byte("===CAKEY==="), key, 1))
			return
		}
		fs.ServeHTTP(w, req)
	})

	httpServer := http.Server{
		Handler: mux,
	}

	ctx := t.Context()
	var cancel context.CancelFunc

	// Generate self-signed certificate
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
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
		t.Fatalf("x509.CreateCertificate: %v", err)
	}
	certFile := filepath.Join(tmpDir, "cert.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes}), 0o600); err != nil {
		t.Fatalf("cert: %s", err)
	}
	b, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("x509.MarshalECPrivateKey: %v", err)
	}
	keyFile := filepath.Join(tmpDir, "key.pem")
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b}), 0o600); err != nil {
		t.Fatalf("key: %s", err)
	}

	go func() {
		l, err := net.Listen("tcp", *addr)
		if err != nil {
			t.Errorf("listen: %v", err)
			return
		}
		t.Logf("HTTPS Server listening on %s. Document root is %s\n", l.Addr(), *docRoot)
		if err := httpServer.ServeTLS(l, certFile, keyFile); err != nil && err != http.ErrServerClosed {
			t.Errorf("http server: %v", err)
			return
		}
	}()
	if *withChromeDP == "" {
		<-ctx.Done()
		httpServer.Shutdown(ctx)
		return
	}

	logConsole := func(ev *runtime.EventConsoleAPICalled) {
		var parts []string
		for _, arg := range ev.Args {
			if strings.Contains(arg.Value.String(), "ForwardX11 requested, but X11 is not enabled") {
				t.Error("X11 not enabled")
				cancel()
			}
			if s, err := strconv.Unquote(arg.Value.String()); err == nil {
				parts = append(parts, s)
			} else {
				parts = append(parts, arg.Value.String())
			}
		}
		fmt.Fprintf(os.Stderr, "console.%s: %s\n", ev.Type, strings.Join(parts, " "))
	}

	t.Run("X11", func(t *testing.T) {
		ctx, cancel = context.WithTimeout(t.Context(), 5*time.Minute)
		defer cancel()
		ctx, cancel = chromedp.NewRemoteAllocator(ctx, *withChromeDP)
		defer cancel()

		ctx, cancel = chromedp.NewContext(ctx,
			chromedp.WithErrorf(t.Logf),
			chromedp.WithLogf(t.Logf),
		)
		defer cancel()

		chromedp.ListenTarget(ctx, func(ev any) {
			switch ev := ev.(type) {
			case *cdproto.Message:
			case *runtime.EventConsoleAPICalled:
				logConsole(ev)
			case *runtime.EventExceptionThrown:
				t.Logf("Exception: * %s", ev.ExceptionDetails.Error())
			default:
			}
		})
		clearX11Operations()
		// Navigate to the WASM app to display the X11 output
		var buf []byte
		var canvasOperationsJSON string

		if err := chromedp.Run(ctx,
			chromedp.Navigate("https://devtest.local:8443/tests.html?x11"),
			chromedp.WaitVisible(`div[id^="x11-window-"]`), // Wait for the X11 window to appear
			chromedp.MouseClickXY(100, 100),                // Set lastPointerID
		); err != nil {
			t.Fatalf("Failed to run chromedp actions: %v", err)
		}

		t.Log("Waiting for X11 Simulation to finish")
		<-sshServerWithCert.x11SimDone

		if err := chromedp.Run(ctx,
			chromedp.CaptureScreenshot(&buf),
			chromedp.Evaluate(`JSON.stringify(window.getCanvasOperations())`, &canvasOperationsJSON),
		); err != nil {
			t.Fatalf("Failed to run chromedp actions: %v", err)
		}
		x11Ops := GetX11Operations()
		var canvasOps []CanvasOperation
		if err := json.Unmarshal([]byte(canvasOperationsJSON), &canvasOps); err != nil {
			t.Fatalf("Failed to unmarshal canvas operations: %v", err)
		}

		compareOperations(t, x11Ops, canvasOps)

		if *outputDir != "" {
			screenshotPath := filepath.Join(*outputDir, "x11_screenshot.png")
			if err := os.WriteFile(screenshotPath, buf, 0o644); err != nil {
				t.Fatalf("Failed to save screenshot: %v", err)
			}
			t.Logf("X11 screenshot saved to %s", screenshotPath)
		}
		t.Log("X11 test completed")
	})

	t.Run("WASM X11 Tests", func(t *testing.T) {
		ctx, cancel = context.WithTimeout(t.Context(), 5*time.Minute)
		defer cancel()
		ctx, cancel = chromedp.NewRemoteAllocator(ctx, *withChromeDP)
		defer cancel()

		ctx, cancel = chromedp.NewContext(ctx,
			chromedp.WithErrorf(t.Logf),
			chromedp.WithLogf(t.Logf),
		)
		defer cancel()

		pass := make(chan bool, 1)
		sendPass := func(v bool) {
			select {
			case pass <- v:
			default:
			}
		}
		chromedp.ListenTarget(ctx, func(ev any) {
			switch ev := ev.(type) {
			case *cdproto.Message:
			case *runtime.EventConsoleAPICalled:
				logConsole(ev)
				if len(ev.Args) > 0 {
					if v := ev.Args[0].Value.String(); v == `"Exit status 0"` {
						sendPass(true)
					} else if strings.HasPrefix(v, `"Exit status`) {
						sendPass(false)
					}
				}
			case *runtime.EventExceptionThrown:
				t.Logf("Exception: * %s", ev.ExceptionDetails.Error())
			default:
			}
		})
		clearX11Operations()
		// Navigate to the WASM app to display the X11 output
		var buf []byte
		if err := chromedp.Run(ctx,
			chromedp.Navigate("https://devtest.local:8443/tests.x11.html"),
			chromedp.WaitVisible("#x11-wasm-tests-done"),
			chromedp.CaptureScreenshot(&buf),
		); err != nil {
			t.Fatalf("Failed to run chromedp actions: %v", err)
		}
		if *outputDir != "" {
			screenshotPath := filepath.Join(*outputDir, "x11_wasm_screenshot.png")
			if err := os.WriteFile(screenshotPath, buf, 0o644); err != nil {
				t.Fatalf("Failed to save screenshot: %v", err)
			}
			t.Logf("X11 screenshot saved to %s", screenshotPath)
		}
		t.Log("X11 WASM tests completed")
		cancel()
		if !<-pass {
			t.Error("Test failed")
		}
	})
}

// CanvasOperation represents a single canvas drawing operation captured from the frontend.
type CanvasOperation struct {
	Type        string `json:"type"`
	Args        []any  `json:"args"`
	FillStyle   string `json:"fillStyle"`
	StrokeStyle string `json:"strokeStyle"`
}

func parseColorString(colorStr string) uint32 {
	if strings.HasPrefix(colorStr, "#") {
		// Parse hex color
		color, err := strconv.ParseUint(colorStr[1:], 16, 32)
		if err != nil {
			return 0 // Should not happen in tests
		}
		return uint32(color)
	} else if strings.HasPrefix(colorStr, "rgb") {
		// Parse rgb(r, g, b) color
		rgb := strings.TrimPrefix(colorStr, "rgb(")
		rgb = strings.TrimSuffix(rgb, ")")
		parts := strings.Split(rgb, ", ")
		if len(parts) == 3 {
			r, _ := strconv.Atoi(parts[0])
			g, _ := strconv.Atoi(parts[1])
			b, _ := strconv.Atoi(parts[2])
			return uint32(r<<16 | g<<8 | b)
		}
	}
	return 0 // Default or error color
}

func compareOperations(t *testing.T, x11Ops []X11Operation, canvasOps []CanvasOperation) {
	count := make(map[string]int)
	for _, op := range x11Ops {
		count[op.Type]++
	}
	for _, op := range canvasOps {
		count[op.Type]--
	}
	var diff bool
	for k, v := range count {
		if v == 0 {
			continue
		}
		diff = true
		if v > 0 {
			t.Logf("X11 has %d more %s than Canvas", v, k)
		} else {
			t.Logf("Canvas has %d more %s than X11", -v, k)
		}
	}
	if diff {
		t.Fatalf("Operations mismatch: X11=%d, Canvas=%d", len(x11Ops), len(canvasOps))
	}
}
