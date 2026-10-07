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
	"sync"
	"testing"
	"time"
)

type mockTerminal struct {
	io.Reader
	// The filter writes to the terminal from both the caller's goroutine and
	// the transfer session goroutine.
	mu  sync.Mutex
	out bytes.Buffer
}

func (m *mockTerminal) Write(p []byte) (n int, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.out.Write(p)
}

func (m *mockTerminal) Printf(format string, args ...any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	fmt.Fprintf(&m.out, format, args...)
}

func (m *mockTerminal) String() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.out.String()
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

	out := term.String()
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

	out := term.String()
	if !strings.Contains(out, "user@host:~$") {
		t.Fatalf("Expected shell prompt to fallback to terminal output. Got: %q", out)
	}
}

func TestZmodemFilterConsent(t *testing.T) {
	sig := []byte{'*', '*', zDLE, zHEX, '0', '0'}
	for _, tc := range []struct {
		answer      string
		expectReply []byte
		expectOut   string
	}{
		{answer: "y", expectReply: []byte{'*', '*', zDLE, zHEX, '0', '1'}, expectOut: "Accept? [y/N] \x1b[0my\r\n"},
		{answer: "n", expectReply: cancelSeq, expectOut: "[ZMODEM] Receive canceled."},
		{answer: "\r", expectReply: cancelSeq, expectOut: "[ZMODEM] Receive canceled."},
	} {
		t.Run(fmt.Sprintf("%q", tc.answer), func(t *testing.T) {
			inR, inW := io.Pipe()
			defer inW.Close()
			term := &mockTerminal{Reader: inR}
			download := func(name string, size int64, r io.Reader) error {
				t.Errorf("download called")
				return nil
			}
			filter := New(term, download, nil)

			writeDone := make(chan struct{})
			go func() {
				filter.Write(append(sig, []byte("\r\nmore output")...))
				close(writeDone)
			}()

			// Nothing must be sent to the remote side before the user answers.
			replyCh := make(chan []byte, 1)
			go func() {
				buf := make([]byte, 1024)
				n, _ := filter.Read(buf)
				replyCh <- buf[:n]
			}()
			deadline := time.Now().Add(5 * time.Second)
			for !strings.Contains(term.String(), "[y/N]") {
				if time.Now().After(deadline) {
					t.Fatalf("no consent prompt. Got: %q", term.String())
				}
				time.Sleep(10 * time.Millisecond)
			}
			select {
			case r := <-replyCh:
				t.Fatalf("reply sent before consent: %q", r)
			case <-time.After(50 * time.Millisecond):
			}

			inW.Write([]byte(tc.answer))

			select {
			case r := <-replyCh:
				if !bytes.HasPrefix(r, tc.expectReply) {
					t.Errorf("reply = %q, want prefix %q", r, tc.expectReply)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("timed out waiting for reply")
			}
			if tc.answer != "y" {
				select {
				case <-writeDone:
				case <-time.After(5 * time.Second):
					t.Fatal("Write didn't return after decline")
				}
				if out := term.String(); !strings.Contains(out, "more output") {
					t.Errorf("remaining output not written to terminal. Got: %q", out)
				}
			}
			if out := term.String(); !strings.Contains(out, tc.expectOut) {
				t.Errorf("terminal output = %q, want %q", out, tc.expectOut)
			}
		})
	}
}

func TestZmodemFilterUploadConsent(t *testing.T) {
	inR, inW := io.Pipe()
	defer inW.Close()
	term := &mockTerminal{Reader: inR}
	uploadCalled := make(chan struct{}, 1)
	upload := func() ([]*File, error) {
		uploadCalled <- struct{}{}
		return nil, nil
	}
	filter := New(term, nil, upload)
	go filter.Write([]byte{'*', '*', zDLE, zHEX, '0', '1'})
	go io.Copy(io.Discard, filter)

	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(term.String(), "[y/N]") {
		if time.Now().After(deadline) {
			t.Fatalf("no consent prompt. Got: %q", term.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	inW.Write([]byte("n"))
	for !strings.Contains(term.String(), "Send canceled") {
		if time.Now().After(deadline) {
			t.Fatalf("send not canceled. Got: %q", term.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	select {
	case <-uploadCalled:
		t.Fatal("upload called after decline")
	default:
	}
}
