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
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/term"
)

type trackingTermIO struct {
	in            *bytes.Reader
	eofWithData   bool
	zeroReadCalls atomic.Int32
}

func (t *trackingTermIO) Read(p []byte) (int, error) {
	if len(p) == 0 {
		if t.zeroReadCalls.Add(1) >= 10 {
			return 0, errors.New("detected infinite 0-byte Read loop in golang.org/x/term")
		}
		return 0, nil
	}
	n, err := t.in.Read(p)
	if t.eofWithData && err == nil && t.in.Len() == 0 {
		err = io.EOF
	}
	return n, err
}

func (t *trackingTermIO) Write(p []byte) (int, error) {
	return len(p), nil
}

func TestTermEscapeGuard(t *testing.T) {
	// 260-byte unterminated escape sequence (exceeds x/term's 256-byte inBuf)
	// followed by a normal terminator 'm' and "hello\n".
	input := "\x1b[" + strings.Repeat("0", 260) + "mhello\n"

	t.Run("VulnerabilityWithoutRemediation", func(t *testing.T) {
		WithDisabled(&EnableTermEscapeGuard, func() {
			tio := &trackingTermIO{in: bytes.NewReader([]byte(input))}
			vt := term.NewTerminal(WrapTermReadWriter(tio), "> ")
			_, err := vt.ReadLine()
			if tio.zeroReadCalls.Load() == 0 {
				t.Fatalf("expected golang.org/x/term to call Read with len(p)==0 on 260-byte escape sequence (err=%v); if fixed upstream, remove WrapTermReadWriter", err)
			}
		})
	})

	t.Run("RemediationEnabled", func(t *testing.T) {
		tio := &trackingTermIO{in: bytes.NewReader([]byte(input))}
		vt := term.NewTerminal(WrapTermReadWriter(tio), "> ")
		line, err := vt.ReadLine()
		if err != nil && !errors.Is(err, io.EOF) {
			t.Fatalf("ReadLine: %v", err)
		}
		if tio.zeroReadCalls.Load() != 0 {
			t.Fatalf("unexpected 0-byte Read calls: %d", tio.zeroReadCalls.Load())
		}
		if line != "hello" {
			t.Fatalf("ReadLine() = %q, want %q", line, "hello")
		}
	})

	t.Run("SimultaneousDataAndEOF", func(t *testing.T) {
		// 256-byte input where injected chunk terminators expand outBuf past
		// 256 bytes while the underlying reader returns (256, io.EOF).
		eofInput := "\x1b[" + strings.Repeat("0", 247) + "mhello\n"
		tio := &trackingTermIO{
			in:          bytes.NewReader([]byte(eofInput)),
			eofWithData: true,
		}
		vt := term.NewTerminal(WrapTermReadWriter(tio), "> ")
		line, err := vt.ReadLine()
		if err != nil && !errors.Is(err, io.EOF) {
			t.Fatalf("ReadLine: %v", err)
		}
		if line != "hello" {
			t.Fatalf("ReadLine() = %q, want %q", line, "hello")
		}
	})
}
