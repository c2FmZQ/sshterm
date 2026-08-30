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
	"io"
	"sync"
)

// TerminalPrinter is the interface that the terminal must implement.
type TerminalPrinter interface {
	io.Reader
	io.Writer
	Printf(format string, args ...any)
}

// DownloadFunc is called for each file received during a ZMODEM download.
// name is the filename, size is the file size in bytes, and r provides the
// file content.
type DownloadFunc func(name string, size int64, r io.Reader) error

// UploadFunc is called when a ZMODEM upload request is detected.
// It should return the files to send, or nil to cancel the upload.
type UploadFunc func() ([]*File, error)

// Filter intercepts ZMODEM signatures in the SSH output stream and
// handles file transfers using the provided callbacks.
type Filter struct {
	term   TerminalPrinter
	stdinW *io.PipeWriter

	pipeR *io.PipeReader
	pipeW *io.PipeWriter

	active bool
	mu     sync.Mutex
	window [6]byte

	download DownloadFunc
	upload   UploadFunc
}

// New creates a Filter. It returns the Filter (an io.Writer for session
// stdout) and an io.Reader to use as session stdin.
//
// download is called for each file received during a ZMODEM download.
// upload is called when a ZMODEM upload request is detected; it should
// return the files to send, or nil to cancel.
func New(term TerminalPrinter, download DownloadFunc, upload UploadFunc) (*Filter, io.Reader) {
	stdinR, stdinW := io.Pipe()
	f := &Filter{
		term:     term,
		stdinW:   stdinW,
		download: download,
		upload:   upload,
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
						f.window = [6]byte{}
						// Send standard ZMODEM cancel sequence to remote
						stdinW.Write(cancelSeq)
						// Close the write side of the pipe to interrupt the parser
						if f.pipeW != nil {
							f.pipeW.Close()
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

func (f *Filter) resetPipe() {
	if f.pipeR != nil {
		f.pipeR.Close()
	}
	if f.pipeW != nil {
		f.pipeW.Close()
	}
	f.pipeR, f.pipeW = io.Pipe()
}

// Write implements io.Writer. It scans for ZMODEM signatures in the
// data stream and triggers file transfer sessions.
func (f *Filter) Write(p []byte) (n int, err error) {
	f.mu.Lock()
	if f.active {
		w := f.pipeW
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

	sigReceive := []byte{'*', '*', zDLE, zHEX, '0', '0'}
	sigSend := []byte{'*', '*', zDLE, zHEX, '0', '1'}

	for i, b := range p {
		f.window[0], f.window[1], f.window[2], f.window[3], f.window[4], f.window[5] = f.window[1], f.window[2], f.window[3], f.window[4], f.window[5], b

		if bytes.Equal(f.window[:], sigReceive) {
			f.term.Write(p[:i+1])
			f.term.Printf("\x1b[33m[ZMODEM] Intercepted receive request...\x1b[0m\r\n")
			f.handleReceive()
			f.mu.Unlock()

			f.pipeW.Write(sigReceive)
			if i+1 < len(p) {
				n2, err := f.pipeW.Write(p[i+1:])
				if err != nil {
					f.term.Write(p[i+1+n2:])
				}
			}
			return len(p), nil
		}
		if bytes.Equal(f.window[:], sigSend) {
			f.term.Write(p[:i+1])
			f.term.Printf("\x1b[33m[ZMODEM] Intercepted send request...\x1b[0m\r\n")
			f.handleSend()
			f.mu.Unlock()

			f.pipeW.Write(sigSend)
			if i+1 < len(p) {
				n2, err := f.pipeW.Write(p[i+1:])
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

// handleReceive orchestrates a complete ZMODEM receive session.
// Called with f.mu held.
func (f *Filter) handleReceive() {
	f.active = true
	f.resetPipe()

	go func() {
		defer f.pipeR.Close()
		rw := struct {
			io.Reader
			io.Writer
		}{f.pipeR, f.stdinW}

		var numFiles int
		err := receive(rw, func(name string, size int64, rc io.Reader) error {
			numFiles++
			s := "s"
			if size == 1 {
				s = ""
			}
			f.term.Printf("\x1b[36m[ZMODEM] Receiving %s (%d byte%s)...\x1b[0m\r\n", name, size, s)
			return f.download(name, size, rc)
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

// handleSend orchestrates a complete ZMODEM send session.
// Called with f.mu held.
func (f *Filter) handleSend() {
	f.active = true
	f.resetPipe()

	go func() {
		defer f.pipeR.Close()

		files, err := f.upload()
		if err != nil || len(files) == 0 {
			if err != nil {
				f.term.Printf("\x1b[31m[ZMODEM] Upload error: %v\x1b[0m\r\n", err)
			} else {
				f.term.Printf("\x1b[33m[ZMODEM] Send canceled (no files selected).\x1b[0m\r\n")
			}
			// Send standard ZMODEM cancel sequence to abort remote rz
			f.stdinW.Write(cancelSeq)
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
		}{f.pipeR, f.stdinW}

		err = send(rw, files)

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
