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

package app

import (
	"bytes"
	"io"
	"sync"

	"github.com/c2FmZQ/sshterm/internal/zmodem"
)

type terminalPrinter interface {
	io.Reader
	io.Writer
	Printf(format string, args ...any)
}

type zmodemFilter struct {
	term   terminalPrinter
	stdinW *io.PipeWriter

	zmodemPipeR *io.PipeReader
	zmodemPipeW *io.PipeWriter

	active bool
	mu     sync.Mutex
	window [6]byte

	startReceive func(f *zmodemFilter)
	startSend    func(f *zmodemFilter)
}

func newZmodemFilter(term terminalPrinter, startReceive, startSend func(f *zmodemFilter)) (*zmodemFilter, io.Reader) {
	stdinR, stdinW := io.Pipe()
	f := &zmodemFilter{
		term:         term,
		stdinW:       stdinW,
		startReceive: startReceive,
		startSend:    startSend,
	}
	f.resetPipe()

	// Forward terminal input to the SSH session
	go func() {
		buf := make([]byte, 1024)
		warned := false
		for {
			n, err := term.Read(buf)
			if n > 0 {
				f.mu.Lock()
				active := f.active
				f.mu.Unlock()

				if active {
					if bytes.Contains(buf[:n], []byte{'\x03'}) { // Ctrl-C
						f.term.Printf("\x1b[31m[ZMODEM] Transfer aborted by user.\x1b[0m\r\n")
						f.mu.Lock()
						f.active = false
						// Send 5 ZCANs to remote to abort
						stdinW.Write([]byte{zmodem.ZCAN, zmodem.ZCAN, zmodem.ZCAN, zmodem.ZCAN, zmodem.ZCAN})
						// Close the write side of the pipe to interrupt the parser
						if f.zmodemPipeW != nil {
							f.zmodemPipeW.Close()
						}
						f.mu.Unlock()
					} else if !warned {
						f.term.Printf("\x1b[33m[ZMODEM] Keyboard input is ignored during file transfers. Press Ctrl-C to abort.\x1b[0m\r\n")
						warned = true
					}
				} else {
					warned = false
					stdinW.Write(buf[:n])
				}
			}
			if err != nil {
				stdinW.CloseWithError(err)
				break
			}
		}
	}()

	return f, stdinR
}

func (f *zmodemFilter) resetPipe() {
	if f.zmodemPipeR != nil {
		f.zmodemPipeR.Close()
	}
	if f.zmodemPipeW != nil {
		f.zmodemPipeW.Close()
	}
	f.zmodemPipeR, f.zmodemPipeW = io.Pipe()
}

func (f *zmodemFilter) Write(p []byte) (n int, err error) {
	f.mu.Lock()
	if f.active {
		w := f.zmodemPipeW
		f.mu.Unlock()
		n, err := w.Write(p)
		if err != nil {
			// If the ZMODEM pipe is closed (e.g. session finished), the remaining data
			// belongs to the terminal (e.g. the subsequent shell prompt).
			f.term.Write(p[n:])
			return len(p), nil
		}
		return n, nil
	}

	sigReceive := []byte{'*', '*', zmodem.ZDLE, zmodem.ZHEX, '0', '0'}
	sigSend := []byte{'*', '*', zmodem.ZDLE, zmodem.ZHEX, '0', '1'}

	for i, b := range p {
		f.window[0], f.window[1], f.window[2], f.window[3], f.window[4], f.window[5] = f.window[1], f.window[2], f.window[3], f.window[4], f.window[5], b

		if bytes.Equal(f.window[:], sigReceive) {
			f.term.Write(p[:i+1])
			f.term.Printf("\x1b[33m[ZMODEM] Intercepted receive request...\x1b[0m\r\n")
			f.startReceive(f)
			f.mu.Unlock()

			f.zmodemPipeW.Write(sigReceive)
			if i+1 < len(p) {
				n2, err := f.zmodemPipeW.Write(p[i+1:])
				if err != nil {
					f.term.Write(p[i+1+n2:])
				}
			}
			return len(p), nil
		}
		if bytes.Equal(f.window[:], sigSend) {
			f.term.Write(p[:i+1])
			f.term.Printf("\x1b[33m[ZMODEM] Intercepted send request...\x1b[0m\r\n")
			f.startSend(f)
			f.mu.Unlock()

			f.zmodemPipeW.Write(sigSend)
			if i+1 < len(p) {
				n2, err := f.zmodemPipeW.Write(p[i+1:])
				if err != nil {
					f.term.Write(p[i+1+n2:])
				}
			}
			return len(p), nil
		}
	}

	f.term.Write(p)
	f.mu.Unlock()
	return len(p), nil
}
