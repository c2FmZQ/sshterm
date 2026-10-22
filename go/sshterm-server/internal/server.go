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
	"context"
	"crypto/tls"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"mime"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/c2FmZQ/sshterm/config"
)

//go:embed docroot
var embeddedDocroot embed.FS

func init() {
	for ext, typ := range map[string]string{
		".css":         "text/css; charset=utf-8",
		".html":        "text/html; charset=utf-8",
		".ico":         "image/x-icon",
		".js":          "text/javascript; charset=utf-8",
		".json":        "application/json",
		".mjs":         "text/javascript; charset=utf-8",
		".png":         "image/png",
		".svg":         "image/svg+xml",
		".txt":         "text/plain; charset=utf-8",
		".wasm":        "application/wasm",
		".webmanifest": "application/manifest+json",
	} {
		_ = mime.AddExtensionType(ext, typ)
	}
}

const (
	defaultCSP = "default-src 'self'; style-src 'unsafe-inline' 'self'; script-src 'wasm-unsafe-eval' 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none';"

	dialTimeout = 10 * time.Second
	writeWait   = 10 * time.Second
	pongWait    = 60 * time.Second
	pingPeriod  = (pongWait * 9) / 10
)

// Endpoint maps a logical sshterm endpoint name to a TCP host:port address.
type Endpoint struct {
	Name    string
	Address string
}

// ParseEndpoint parses an endpoint specification in the form "name=host[:port]".
// If no port is specified, port 22 is used.
func ParseEndpoint(spec string) (Endpoint, error) {
	name, addr, ok := strings.Cut(spec, "=")
	if !ok {
		return Endpoint{}, fmt.Errorf("invalid endpoint %q: expected name=host[:port]", spec)
	}
	name = strings.TrimSpace(name)
	addr = strings.TrimSpace(addr)
	if name == "" {
		return Endpoint{}, fmt.Errorf("invalid endpoint %q: name cannot be empty", spec)
	}
	if strings.ContainsAny(name, ":/\\ \t\r\n") || name == "." || name == ".." {
		return Endpoint{}, fmt.Errorf("invalid endpoint name %q", name)
	}
	if addr == "" {
		return Endpoint{}, fmt.Errorf("invalid endpoint %q: address cannot be empty", spec)
	}
	normalized, err := normalizeHostPort(addr)
	if err != nil {
		return Endpoint{}, fmt.Errorf("invalid endpoint %q: %w", spec, err)
	}
	return Endpoint{
		Name:    name,
		Address: normalized,
	}, nil
}

func normalizeHostPort(addr string) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		// If splitting failed, assume port 22 was omitted.
		h := strings.TrimPrefix(strings.TrimSuffix(addr, "]"), "[")
		if h == "" {
			return "", errors.New("host cannot be empty")
		}
		candidate := net.JoinHostPort(h, "22")
		host, port, err = net.SplitHostPort(candidate)
		if err != nil {
			return "", err
		}
	}
	if host == "" {
		return "", errors.New("host cannot be empty")
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return "", fmt.Errorf("invalid port %q", port)
	}
	return net.JoinHostPort(host, port), nil
}

// Options configures a Server instance.
type Options struct {
	Addr        string
	ConfigFile  string
	TLSCertFile string
	TLSKeyFile  string
	Endpoints   []Endpoint
	FS          fs.FS
	DialContext func(ctx context.Context, network, address string) (net.Conn, error)
	Logger      *log.Logger
}

// Server serves the sshterm web application and proxies WebSocket connections
// to configured SSH endpoints.
type Server struct {
	opts       Options
	endpoints  map[string]string
	configJSON []byte
	upgrader   websocket.Upgrader
	mux        *http.ServeMux
	logger     *log.Logger

	mu       sync.Mutex
	listener net.Listener
}

// New creates and initializes a new Server.
func New(opts Options) (*Server, error) {
	if (opts.TLSCertFile == "") != (opts.TLSKeyFile == "") {
		return nil, errors.New("--tls-cert and --tls-key must be specified together")
	}
	for _, ep := range opts.Endpoints {
		if ep.Name == "" || strings.ContainsAny(ep.Name, ":/\\ \t\r\n") || ep.Name == "." || ep.Name == ".." {
			return nil, fmt.Errorf("invalid endpoint name %q", ep.Name)
		}
		if _, err := normalizeHostPort(ep.Address); err != nil {
			return nil, fmt.Errorf("invalid address for endpoint %q: %w", ep.Name, err)
		}
	}

	docFS := opts.FS
	if docFS == nil {
		var err error
		docFS, err = fs.Sub(embeddedDocroot, "docroot")
		if err != nil {
			return nil, fmt.Errorf("embedded docroot: %w", err)
		}
	}

	if opts.DialContext == nil {
		dialer := &net.Dialer{
			Timeout:   dialTimeout,
			KeepAlive: 30 * time.Second,
		}
		opts.DialContext = dialer.DialContext
	}
	logger := opts.Logger
	if logger == nil {
		logger = log.Default()
	}

	cfgBytes, epMap, err := buildConfigJSON(opts.ConfigFile, opts.Endpoints)
	if err != nil {
		return nil, err
	}

	s := &Server{
		opts:       opts,
		endpoints:  epMap,
		configJSON: cfgBytes,
		upgrader: websocket.Upgrader{
			ReadBufferSize:  8192,
			WriteBufferSize: 8192,
		},
		mux:    http.NewServeMux(),
		logger: logger,
	}

	fileServer := http.FileServerFS(docFS)
	s.mux.HandleFunc("GET /config.json", s.handleConfigJSON)
	s.mux.HandleFunc("HEAD /config.json", s.handleConfigJSON)
	s.mux.HandleFunc("GET /_ws/{name}", s.handleWebSocket)
	s.mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Cache-Control", "no-cache")
		fileServer.ServeHTTP(w, req)
	})

	return s, nil
}

func buildConfigJSON(configFile string, endpoints []Endpoint) ([]byte, map[string]string, error) {
	var cfg config.Config
	if configFile != "" {
		b, err := os.ReadFile(configFile)
		if err != nil {
			return nil, nil, fmt.Errorf("reading config file: %w", err)
		}
		if err := json.Unmarshal(b, &cfg); err != nil {
			return nil, nil, fmt.Errorf("parsing config file: %w", err)
		}
	}

	epMap := make(map[string]string, len(endpoints))
	for _, ep := range endpoints {
		addr, err := normalizeHostPort(ep.Address)
		if err != nil {
			return nil, nil, err
		}
		epMap[ep.Name] = addr
		wsURL := "./_ws/" + ep.Name

		updated := false
		for i := range cfg.Endpoints {
			if cfg.Endpoints[i].Name == ep.Name {
				cfg.Endpoints[i].URL = wsURL
				updated = true
				break
			}
		}
		if !updated {
			cfg.Endpoints = append(cfg.Endpoints, struct {
				Name     string `json:"name"`
				URL      string `json:"url"`
				Hostname string `json:"hostname,omitempty"`
			}{
				Name: ep.Name,
				URL:  wsURL,
			})
		}
	}

	out, err := json.MarshalIndent(&cfg, "", "  ")
	if err != nil {
		return nil, nil, fmt.Errorf("marshaling config.json: %w", err)
	}
	out = append(out, '\n')
	return out, epMap, nil
}

// Handler returns the HTTP handler for the server.
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Security-Policy", defaultCSP)
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		s.mux.ServeHTTP(w, req)
	})
}

func (s *Server) handleConfigJSON(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Content-Length", strconv.Itoa(len(s.configJSON)))
	if req.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.Write(s.configJSON)
}

func (s *Server) handleWebSocket(w http.ResponseWriter, req *http.Request) {
	name := req.PathValue("name")
	targetAddr, exists := s.endpoints[name]
	if !exists {
		http.NotFound(w, req)
		return
	}

	wsConn, err := s.upgrader.Upgrade(w, req, nil)
	if err != nil {
		s.logger.Printf("websocket upgrade failed for %q: %v", name, err)
		return
	}
	defer wsConn.Close()

	dialCtx, cancel := context.WithTimeout(req.Context(), dialTimeout)
	tcpConn, err := s.opts.DialContext(dialCtx, "tcp", targetAddr)
	cancel()
	if err != nil {
		s.logger.Printf("dial %q (%s) failed: %v", name, targetAddr, err)
		_ = wsConn.WriteControl(
			websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseInternalServerErr, "upstream connection failed"),
			time.Now().Add(writeWait),
		)
		return
	}
	defer tcpConn.Close()

	s.proxyConn(wsConn, tcpConn)
}

func (s *Server) proxyConn(wsConn *websocket.Conn, tcpConn net.Conn) {
	done := make(chan struct{})
	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() {
			close(done)
			_ = wsConn.Close()
			_ = tcpConn.Close()
		})
	}

	_ = wsConn.SetReadDeadline(time.Now().Add(pongWait))
	wsConn.SetPongHandler(func(string) error {
		return wsConn.SetReadDeadline(time.Now().Add(pongWait))
	})

	var wg sync.WaitGroup
	wg.Add(3)

	// Periodic WebSocket ping goroutine.
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(pingPeriod)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				if err := wsConn.WriteControl(websocket.PingMessage, nil, time.Now().Add(writeWait)); err != nil {
					closeBoth()
					return
				}
			}
		}
	}()

	// WebSocket -> TCP
	go func() {
		defer wg.Done()
		defer closeBoth()
		for {
			msgType, r, err := wsConn.NextReader()
			if err != nil {
				return
			}
			_ = wsConn.SetReadDeadline(time.Now().Add(pongWait))
			if msgType != websocket.BinaryMessage {
				_ = wsConn.WriteControl(
					websocket.CloseMessage,
					websocket.FormatCloseMessage(websocket.CloseUnsupportedData, "binary messages only"),
					time.Now().Add(writeWait),
				)
				return
			}
			if _, err := io.Copy(tcpConn, r); err != nil {
				return
			}
		}
	}()

	// TCP -> WebSocket
	go func() {
		defer wg.Done()
		defer closeBoth()
		buf := make([]byte, 16384)
		for {
			n, err := tcpConn.Read(buf)
			if n > 0 {
				_ = wsConn.SetWriteDeadline(time.Now().Add(writeWait))
				if wErr := wsConn.WriteMessage(websocket.BinaryMessage, buf[:n]); wErr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	wg.Wait()
}

// Addr returns the network address the server is listening on, or nil if it has
// not started listening yet.
func (s *Server) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener == nil {
		return nil
	}
	return s.listener.Addr()
}

// Run starts the HTTP/HTTPS server and blocks until ctx is canceled or an
// unrecoverable server error occurs.
func (s *Server) Run(ctx context.Context) error {
	addr := s.opts.Addr
	if addr == "" {
		addr = "127.0.0.1:8080"
	}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.listener = l
	s.mu.Unlock()

	httpServer := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		if s.opts.TLSCertFile != "" && s.opts.TLSKeyFile != "" {
			httpServer.TLSConfig = &tls.Config{
				MinVersion: tls.VersionTLS12,
			}
			s.logger.Printf("HTTPS server listening on https://%s", l.Addr())
			errCh <- httpServer.ServeTLS(l, s.opts.TLSCertFile, s.opts.TLSKeyFile)
		} else {
			s.logger.Printf("HTTP server listening on http://%s", l.Addr())
			errCh <- httpServer.Serve(l)
		}
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
		err := <-errCh
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}
