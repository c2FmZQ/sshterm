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
)

// File represents a file for ZMODEM transfer.
type File struct {
	Name string
	Size int64
	R    io.ReadCloser
}

// receive performs a ZMODEM receive session, downloading all sent files.
// For each file, onFile is called with the filename, size, and an io.Reader
// that will stream the file contents.
func receive(rw io.ReadWriter, onFile func(name string, size int64, rc io.Reader) error) error {
	zr := newReader(rw)

	// 1. Send ZRINIT to start
	err := writeHexHeader(rw, header{Type: zRINIT})
	if err != nil {
		return err
	}

	for {
		h, err := zr.readHeader()
		if err != nil {
			return err
		}

		switch h.Type {
		case zFILE:
			useCrc32 := (h.Format == formatBin32)
			data, _, err := zr.readDataBlock(useCrc32)
			if err != nil {
				return err
			}

			parts := bytes.SplitN(data, []byte{0}, 2)
			name := string(parts[0])

			// Parse size (simplified: size is space-separated after name)
			// e.g. "filename\0 1234 0 0 0"
			var size int64
			if len(parts) > 1 {
				fmt.Sscanf(string(parts[1]), "%d", &size)
			}

			// We received ZFILE. We send ZRPOS to accept it.
			if err := writeHexHeader(rw, header{Type: zRPOS}); err != nil {
				return err
			}

			// Wait for ZDATA header
			dataStarted := false
			for !dataStarted {
				h2, err := zr.readHeader()
				if err != nil {
					return err
				}
				switch h2.Type {
				case zDATA:
					dataStarted = true
					useCrc32 = (h2.Format == formatBin32)
				case zEOF:
					// Empty file or sender skipped data
					if err := writeHexHeader(rw, header{Type: zRINIT}); err != nil {
						return err
					}
					// Return empty reader
					if err := onFile(name, size, bytes.NewReader(nil)); err != nil {
						return err
					}
					continue // wait for next file or ZFIN
				default:
					return fmt.Errorf("unexpected header before ZDATA: %d", h2.Type)
				}
			}

			// We are now at the start of ZDATA.
			// Pass a custom io.Reader to onFile that pulls chunks directly from the network.
			r := &dataReader{
				zr:       zr,
				rw:       rw,
				useCrc32: useCrc32,
			}

			if err := onFile(name, size, r); err != nil {
				return err
			}

			// If the reader didn't consume until EOF, we must drain it to stay in sync
			if !r.eof && r.err == nil {
				io.Copy(io.Discard, r)
			}

			if r.err != nil && r.err != io.EOF {
				return r.err
			}

			// Wait for ZEOF header (might have already been read if readDataBlock returned it,
			// but ZMODEM sends ZEOF as a separate header after the last data block)
			h2, err := zr.readHeader()
			if err != nil {
				return err
			}
			if h2.Type != zEOF {
				return fmt.Errorf("expected ZEOF after data, got %d", h2.Type)
			}
			if err := writeHexHeader(rw, header{Type: zRINIT}); err != nil {
				return err
			}

		case zFIN:
			writeHexHeader(rw, header{Type: zFIN})
			return nil

		case zABORT, zCAN, zFERR:
			return fmt.Errorf("transfer aborted by sender")
		}
	}
}

type dataReader struct {
	zr       *reader
	rw       io.ReadWriter
	useCrc32 bool
	buf      []byte
	offset   uint32
	eof      bool
	err      error
}

func (r *dataReader) Read(p []byte) (n int, err error) {
	if r.err != nil {
		return 0, r.err
	}
	if len(r.buf) > 0 {
		n = copy(p, r.buf)
		r.buf = r.buf[n:]
		return n, nil
	}
	if r.eof {
		return 0, io.EOF
	}

	chunk, endType, err := r.zr.readDataBlock(r.useCrc32)
	if err != nil {
		r.err = err
		return 0, err
	}

	r.offset += uint32(len(chunk))

	if endType == zCRCQ || endType == zCRCW {
		flags := [4]byte{byte(r.offset), byte(r.offset >> 8), byte(r.offset >> 16), byte(r.offset >> 24)}
		writeHexHeader(r.rw, header{Type: zACK, Flags: flags})
	}

	if endType == zCRCE || endType == zCRCW {
		r.eof = true
	}

	if len(chunk) > 0 {
		n = copy(p, chunk)
		if n < len(chunk) {
			r.buf = chunk[n:]
		}
	} else if r.eof {
		return 0, io.EOF
	}

	return n, nil
}
