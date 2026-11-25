// MIT License
//
// Copyright (c) 2026 TTBT Enterprises LLC
// Copyright (c) 2026 Robin Thellend <rthellend@gmail.com>
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
	"io"
	"log"
	"net"
	"net/http"
	"testing"
	"time"
)

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
