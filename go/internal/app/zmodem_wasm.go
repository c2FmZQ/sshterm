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

//go:build wasm

package app

import (
	"io"

	"github.com/c2FmZQ/sshterm/internal/jsutil"
	"github.com/c2FmZQ/sshterm/internal/terminal"
	"github.com/c2FmZQ/sshterm/internal/zmodem"
)

func newZmodemFilterWasm(term *terminal.Terminal) (io.Writer, io.Reader) {
	return newZmodemFilter(term, startReceiveAction, startSendAction)
}

func startReceiveAction(f *zmodemFilter) {
	f.active = true
	f.resetPipe()

	go func() {
		defer f.zmodemPipeR.Close()
		rw := struct {
			io.Reader
			io.Writer
		}{f.zmodemPipeR, f.stdinW}

		helper := jsutil.NewStreamHelper()
		var numFiles int
		err := zmodem.Receive(rw, func(name string, size int64, rc io.Reader) error {
			numFiles++
			s := "s"
			if size == 1 {
				s = ""
			}
			f.term.Printf("\x1b[36m[ZMODEM] Receiving %s (%d byte%s)...\x1b[0m\r\n", name, size, s)
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

		s := "s"
		if numFiles == 1 {
			s = ""
		}
		if err == nil {
			f.term.Printf("\x1b[32m[ZMODEM] Received %d file%s successfully.\x1b[0m\r\n", numFiles, s)
		} else {
			f.term.Printf("\x1b[31m[ZMODEM] Receive Error: %v\x1b[0m\r\n", err)
		}
	}()
}

func startSendAction(f *zmodemFilter) {
	f.active = true
	f.resetPipe()

	go func() {
		defer f.zmodemPipeR.Close()
		imported := jsutil.ImportFiles("", true)
		var files []*zmodem.File
		for _, imp := range imported {
			data, err := imp.ReadAll()
			if err == nil {
				files = append(files, &zmodem.File{Name: imp.Name, Data: data})
			}
		}

		if len(files) == 0 {
			f.term.Printf("\x1b[33m[ZMODEM] Send canceled (no files selected).\x1b[0m\r\n")
			// Send standard ZMODEM cancel sequence to abort remote rz
			f.stdinW.Write(zmodem.CancelSeq)
			f.mu.Lock()
			f.active = false
			f.window = [6]byte{}
			f.mu.Unlock()
			return
		}

		s := "s"
		if len(files) == 1 {
			s = ""
		}
		f.term.Printf("\x1b[33m[ZMODEM] Sending %d file%s...\x1b[0m\r\n", len(files), s)

		rw := struct {
			io.Reader
			io.Writer
		}{f.zmodemPipeR, f.stdinW}

		err := zmodem.Send(rw, files)

		f.mu.Lock()
		f.active = false
		f.mu.Unlock()

		if err != nil {
			f.term.Printf("\x1b[31m[ZMODEM] Send Error: %v\x1b[0m\r\n", err)
		} else {
			f.term.Printf("\x1b[32m[ZMODEM] Send completed successfully.\x1b[0m\r\n")
		}
	}()
}
