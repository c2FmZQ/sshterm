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
	R    io.Reader
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

			if err := writeHexHeader(rw, header{Type: zRPOS}); err != nil {
				return err
			}

			pr, pw := io.Pipe()

			// Run callback in background to consume the reader
			callbackErr := make(chan error, 1)
			go func() {
				callbackErr <- onFile(name, size, pr)
			}()

			fileDone := false
			var fileErr error

			for !fileDone {
				h2, err := zr.readHeader()
				if err != nil {
					fileErr = err
					break
				}

				switch h2.Type {
				case zEOF:
					if err := writeHexHeader(rw, header{Type: zRINIT}); err != nil {
						fileErr = err
					}
					fileDone = true

				case zDATA:
					useCrc32 = (h2.Format == formatBin32)
					var offset uint32
					for {
						chunk, endType, err := zr.readDataBlock(useCrc32)
						if err != nil {
							fileErr = err
							break
						}

						pw.Write(chunk)
						offset += uint32(len(chunk))

						if endType == zCRCQ || endType == zCRCW {
							flags := [4]byte{byte(offset), byte(offset >> 8), byte(offset >> 16), byte(offset >> 24)}
							writeHexHeader(rw, header{Type: zACK, Flags: flags})
						}

						if endType == zCRCE || endType == zCRCW {
							break
						}
					}
				default:
					fileErr = fmt.Errorf("unexpected header during ZDATA: %d", h2.Type)
					fileDone = true
				}

				if fileErr != nil {
					break
				}
			}

			pw.CloseWithError(fileErr)

			// Wait for the onFile callback to finish processing.
			if cbErr := <-callbackErr; cbErr != nil && fileErr == nil {
				fileErr = cbErr
			}

			if fileErr != nil {
				return fileErr
			}

		case zFIN:
			writeHexHeader(rw, header{Type: zFIN})
			return nil

		case zABORT, zCAN, zFERR:
			return fmt.Errorf("transfer aborted by sender")
		}
	}
}
