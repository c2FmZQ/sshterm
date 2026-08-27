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

//go:build wasm

package app

import (
	"bytes"
	"io"
	"sync"

	"github.com/c2FmZQ/sshterm/internal/jsutil"
	"github.com/c2FmZQ/sshterm/internal/terminal"
	"github.com/c2FmZQ/sshterm/internal/zmodem"
)

type zmodemFilter struct {
	term   *terminal.Terminal
	stdinW *io.PipeWriter

	zmodemPipeR *io.PipeReader
	zmodemPipeW *io.PipeWriter

	active bool
	mu     sync.Mutex
}

func newZmodemFilter(term *terminal.Terminal) (*zmodemFilter, io.Reader) {
	stdinR, stdinW := io.Pipe()
	f := &zmodemFilter{
		term:   term,
		stdinW: stdinW,
	}
	f.resetPipe()

	// Forward terminal input to the SSH session
	go func() {
		io.Copy(stdinW, term)
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
	defer f.mu.Unlock()

	if f.active {
		return f.zmodemPipeW.Write(p)
	}

	// Check for ZRQINIT (sz) or ZRINIT (rz)
	// ZRQINIT: **\x18B00
	// ZRINIT:  **\x18B01
	if bytes.Contains(p, []byte{'*', '*', zmodem.ZDLE, zmodem.ZHEX, '0', '0'}) {
		f.term.Printf("\r\n\x1b[33m[ZMODEM] Intercepted receive request...\x1b[0m\r\n")
		f.startReceive(p)
		return len(p), nil
	}
	if bytes.Contains(p, []byte{'*', '*', zmodem.ZDLE, zmodem.ZHEX, '0', '1'}) {
		f.term.Printf("\r\n\x1b[33m[ZMODEM] Intercepted send request...\x1b[0m\r\n")
		f.startSend(p)
		return len(p), nil
	}

	return f.term.Write(p)
}

func (f *zmodemFilter) startReceive(p []byte) {
	f.active = true
	f.resetPipe()

	go func() {
		// Feed the initial buffer into the ZMODEM pipe
		f.zmodemPipeW.Write(p)
	}()

	go func() {
		rw := struct {
			io.Reader
			io.Writer
		}{f.zmodemPipeR, f.stdinW}

		helper := jsutil.NewStreamHelper()
		var numFiles int
		err := zmodem.Receive(rw, func(name string, size int64, rc io.Reader) error {
			numFiles++
			f.term.Printf("\r\n\x1b[36m[ZMODEM] Receiving %s (%d bytes)...\x1b[0m\r\n", name, size)
			if helper == nil {
				data, err := io.ReadAll(rc)
				if err == nil {
					jsutil.ExportFile(data, name, "application/octet-stream")
				}
				return err
			}
			return helper.Download(io.NopCloser(rc), name, size, nil, nil)
		})

		f.mu.Lock()
		f.active = false
		f.mu.Unlock()

		if err == nil {
			f.term.Printf("\r\n\x1b[32m[ZMODEM] Received %d files successfully.\x1b[0m\r\n", numFiles)
		} else {
			f.term.Printf("\r\n\x1b[31m[ZMODEM] Receive Error: %v\x1b[0m\r\n", err)
		}
	}()
}

func (f *zmodemFilter) startSend(p []byte) {
	f.active = true
	f.resetPipe()

	go func() {
		f.zmodemPipeW.Write(p)
	}()

	go func() {
		imported := jsutil.ImportFiles("", true)
		var files []*zmodem.File
		for _, imp := range imported {
			data, err := imp.ReadAll()
			if err == nil {
				files = append(files, &zmodem.File{Name: imp.Name, Data: data})
			}
		}

		if len(files) == 0 {
			f.term.Printf("\r\n\x1b[33m[ZMODEM] Send canceled (no files selected).\x1b[0m\r\n")
			// We should abort the session
			f.stdinW.Write([]byte{zmodem.ZCAN, zmodem.ZCAN, zmodem.ZCAN, zmodem.ZCAN, zmodem.ZCAN})
			f.mu.Lock()
			f.active = false
			f.mu.Unlock()
			return
		}

		f.term.Printf("\r\n\x1b[33m[ZMODEM] Sending %d files...\x1b[0m\r\n", len(files))

		rw := struct {
			io.Reader
			io.Writer
		}{f.zmodemPipeR, f.stdinW}

		err := zmodem.Send(rw, files)

		f.mu.Lock()
		f.active = false
		f.mu.Unlock()

		if err != nil {
			f.term.Printf("\r\n\x1b[31m[ZMODEM] Send Error: %v\x1b[0m\r\n", err)
		} else {
			f.term.Printf("\r\n\x1b[32m[ZMODEM] Send completed successfully.\x1b[0m\r\n")
		}
	}()
}
