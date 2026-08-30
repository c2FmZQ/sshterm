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

package zmodem

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
)

type mockTerminal struct {
	io.Reader
	out bytes.Buffer
}

func (m *mockTerminal) Write(p []byte) (n int, err error) {
	return m.out.Write(p)
}

func (m *mockTerminal) Printf(format string, args ...any) {
	fmt.Fprintf(&m.out, format, args...)
}

func TestZmodemFilterSplitSignature(t *testing.T) {
	term := &mockTerminal{Reader: bytes.NewReader(nil)}

	download := func(name string, size int64, r io.Reader) error {
		io.ReadAll(r)
		return nil
	}
	upload := func() ([]*File, error) {
		return nil, nil
	}

	filter := New(term, download, upload)

	// Write signature in tiny chunks to test sliding window
	sig := []byte{'*', '*', zDLE, zHEX, '0', '0'}

	prefix := []byte("hello ")
	filter.Write(prefix)

	for _, b := range sig {
		filter.Write([]byte{b})
	}

	suffix := []byte("world")
	filter.Write(suffix)

	// Wait a moment for async pipe copies
	time.Sleep(50 * time.Millisecond)

	out := term.out.String()
	// The prefix AND the signature itself should have been written to the terminal
	expectedTermOut := "hello **\x18B00\x1b[33m[ZMODEM] Intercepted receive request...\x1b[0m\r\n"
	if !strings.HasPrefix(out, expectedTermOut) {
		t.Fatalf("Terminal output mismatch.\nGot: %q\nExp prefix: %q", out, expectedTermOut)
	}
}

func TestZmodemFilterFallback(t *testing.T) {
	term := &mockTerminal{Reader: bytes.NewReader(nil)}

	download := func(name string, size int64, r io.Reader) error {
		io.ReadAll(r)
		return nil
	}

	filter := New(term, download, nil)

	sig := []byte{'*', '*', zDLE, zHEX, '0', '0'}

	// Write signature followed by shell prompt in a single burst
	burst := append(sig, []byte("\r\nuser@host:~$")...)
	filter.Write(burst)

	time.Sleep(50 * time.Millisecond)

	out := term.out.String()
	if !strings.Contains(out, "user@host:~$") {
		t.Fatalf("Expected shell prompt to fallback to terminal output. Got: %q", out)
	}
}
