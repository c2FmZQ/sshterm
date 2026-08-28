package app

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/c2FmZQ/sshterm/internal/zmodem"
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

	receiveCalled := false
	sendCalled := false

	startRecv := func(f *zmodemFilter) {
		f.active = true
		f.resetPipe()
		receiveCalled = true
		go func() {
			io.ReadAll(f.zmodemPipeR)
			f.zmodemPipeR.Close()
		}()
	}
	startSend := func(f *zmodemFilter) {
		f.active = true
		f.resetPipe()
		sendCalled = true
	}

	filter, _ := newZmodemFilter(term, startRecv, startSend)

	// Write signature in tiny chunks to test sliding window
	sig := []byte{'*', '*', zmodem.ZDLE, zmodem.ZHEX, '0', '0'}

	prefix := []byte("hello ")
	filter.Write(prefix)

	for _, b := range sig {
		filter.Write([]byte{b})
	}

	suffix := []byte("world")
	filter.Write(suffix)

	// Wait a moment for async pipe copies
	time.Sleep(50 * time.Millisecond)

	if !receiveCalled {
		t.Fatal("Expected receive handler to be called")
	}
	if sendCalled {
		t.Fatal("Did not expect send handler to be called")
	}

	out := term.out.String()
	// The prefix AND the signature itself should have been written to the terminal
	expectedTermOut := "hello **\x18B00\x1b[33m[ZMODEM] Intercepted receive request...\x1b[0m\r\n"
	if out != expectedTermOut {
		t.Fatalf("Terminal output mismatch.\nGot: %q\nExp: %q", out, expectedTermOut)
	}
}

func TestZmodemFilterFallback(t *testing.T) {
	term := &mockTerminal{Reader: bytes.NewReader(nil)}

	startRecv := func(f *zmodemFilter) {
		f.active = true
		f.resetPipe()
		go func() {
			// Immediately close the reader to simulate ZMODEM abort or completion
			f.zmodemPipeR.Close()
			f.mu.Lock()
			f.active = false
			f.mu.Unlock()
		}()
	}

	filter, _ := newZmodemFilter(term, startRecv, nil)

	sig := []byte{'*', '*', zmodem.ZDLE, zmodem.ZHEX, '0', '0'}

	// Write signature followed by shell prompt in a single burst
	burst := append(sig, []byte("\r\nuser@host:~$")...)
	filter.Write(burst)

	time.Sleep(50 * time.Millisecond)

	out := term.out.String()
	if !strings.Contains(out, "user@host:~$") {
		t.Fatalf("Expected shell prompt to fallback to terminal output. Got: %q", out)
	}
}
