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

package depfix

import (
	"bytes"
	"io"
)

const (
	// maxTermEscapeChunk is the maximum number of bytes allowed in an
	// unterminated escape sequence before injecting a '~' terminator and
	// restarting '\x1b', keeping golang.org/x/term's 256-byte inBuf from
	// ever filling up.
	maxTermEscapeChunk = 64
)

// WrapTermReadWriter wraps an io.ReadWriter passed to golang.org/x/term's
// NewTerminal to prevent a 256-byte unterminated escape sequence from filling
// Terminal.inBuf and causing an infinite synchronous 0-byte Read busy loop.
func WrapTermReadWriter(rw io.ReadWriter) io.ReadWriter {
	return &termSafeReadWriter{rw: rw}
}

type termSafeReadWriter struct {
	rw     io.ReadWriter
	outBuf bytes.Buffer
	inEsc  bool
	escLen int
}

func (t *termSafeReadWriter) Write(p []byte) (int, error) {
	return t.rw.Write(p)
}

func isTermEscTerminator(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '~'
}

func (t *termSafeReadWriter) Read(p []byte) (int, error) {
	if !EnableTermEscapeGuard {
		return t.rw.Read(p)
	}
	if t.outBuf.Len() > 0 {
		return t.outBuf.Read(p)
	}
	raw := make([]byte, max(len(p), 64))
	n, err := t.rw.Read(raw)
	for i := 0; i < n; i++ {
		c := raw[i]
		if !t.inEsc {
			if c == 0x1b {
				t.inEsc = true
				t.escLen = 1
			}
			t.outBuf.WriteByte(c)
			continue
		}
		if c == 0x1b {
			// Terminate the previous unfinished escape sequence before
			// starting the new one.
			t.outBuf.WriteByte('~')
			t.outBuf.WriteByte(0x1b)
			t.escLen = 1
			continue
		}
		if c == '\r' || c == '\n' || c == 0x03 || c == 0x04 {
			// Terminate the unfinished escape sequence so line/control
			// keys are still processed by x/term.
			t.outBuf.WriteByte('~')
			t.outBuf.WriteByte(c)
			t.inEsc = false
			t.escLen = 0
			continue
		}
		if isTermEscTerminator(c) {
			t.outBuf.WriteByte(c)
			t.inEsc = false
			t.escLen = 0
			continue
		}
		if t.escLen >= maxTermEscapeChunk-1 {
			// Close the current chunk with '~' so x/term consumes it as
			// keyUnknown and clears t.remainder, then re-open '\x1b' so
			// subsequent bytes of the escape sequence remain inside an
			// escape sequence.
			t.outBuf.WriteByte('~')
			t.outBuf.WriteByte(0x1b)
			t.escLen = 1
		}
		t.outBuf.WriteByte(c)
		t.escLen++
	}
	if t.outBuf.Len() > 0 {
		nn, _ := t.outBuf.Read(p)
		return nn, err
	}
	return 0, err
}
