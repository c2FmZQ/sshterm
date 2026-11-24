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

package main

import (
	"context"
	"encoding/binary"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/c2FmZQ/sshterm/sshterm-server/internal"
)

func checkServerEnableConnectSetting(t *testing.T) bool {
	t.Helper()
	srv, err := internal.New(internal.Options{
		Addr:   "127.0.0.1:0",
		Logger: log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Run(ctx) }()
	defer func() {
		cancel()
		<-errCh
	}()

	var addr net.Addr
	for range 100 {
		if addr = srv.Addr(); addr != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if addr == nil {
		t.Fatal("server did not start listening")
	}

	conn, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	if _, err := io.WriteString(conn, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"); err != nil {
		t.Fatalf("WriteString preface: %v", err)
	}
	// Empty client SETTINGS frame.
	if _, err := conn.Write([]byte{0, 0, 0, 0x4, 0, 0, 0, 0, 0}); err != nil {
		t.Fatalf("Write client SETTINGS: %v", err)
	}

	for {
		var hdr [9]byte
		if _, err := io.ReadFull(conn, hdr[:]); err != nil {
			t.Fatalf("ReadFull frame header: %v", err)
		}
		n := int(hdr[0])<<16 | int(hdr[1])<<8 | int(hdr[2])
		payload := make([]byte, n)
		if _, err := io.ReadFull(conn, payload); err != nil {
			t.Fatalf("ReadFull payload: %v", err)
		}
		if hdr[3] != 0x4 || hdr[4]&0x1 != 0 {
			continue
		}
		for i := 0; i+6 <= len(payload); i += 6 {
			id := binary.BigEndian.Uint16(payload[i : i+2])
			val := binary.BigEndian.Uint32(payload[i+2 : i+6])
			if id == 0x8 && val == 1 {
				return true
			}
		}
		return false
	}
}

func stripGODEBUG(env []string) []string {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		if !strings.HasPrefix(kv, "GODEBUG=") {
			out = append(out, kv)
		}
	}
	return out
}

func TestStandaloneDefaultH2XConnect(t *testing.T) {
	switch os.Getenv("SSHTERM_H2XCONNECT_MODE") {
	case "default":
		if !checkServerEnableConnectSetting(t) {
			t.Fatal("expected SETTINGS_ENABLE_CONNECT_PROTOCOL=1 by default in sshterm-server")
		}
		return
	case "disabled":
		if checkServerEnableConnectSetting(t) {
			t.Fatal("expected SETTINGS_ENABLE_CONNECT_PROTOCOL to be omitted when GODEBUG=http2xconnect=0")
		}
		return
	}

	t.Run("enabled_by_default_without_GODEBUG", func(t *testing.T) {
		cmd := exec.Command(os.Args[0], "-test.run=^TestStandaloneDefaultH2XConnect$")
		cmd.Env = append(stripGODEBUG(os.Environ()), "SSHTERM_H2XCONNECT_MODE=default")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("default subprocess failed: %v\n%s", err, out)
		}
	})

	t.Run("explicit_opt_out_respected", func(t *testing.T) {
		cmd := exec.Command(os.Args[0], "-test.run=^TestStandaloneDefaultH2XConnect$")
		cmd.Env = append(stripGODEBUG(os.Environ()), "GODEBUG=http2xconnect=0", "SSHTERM_H2XCONNECT_MODE=disabled")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("opt-out subprocess failed: %v\n%s", err, out)
		}
	})
}
