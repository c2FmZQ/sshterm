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

// File represents a ZMODEM transmitted file.
type File struct {
	Name string
	Data []byte
}

// Receive performs a ZMODEM receive session, downloading all sent files.
// For each file, onFile is called with the filename, size, and an io.Reader
// that will stream the file contents.
func Receive(rw io.ReadWriter, onFile func(name string, size int64, rc io.Reader) error) error {
	zr := NewReader(rw)

	// 1. Send ZRINIT to start
	err := WriteHexHeader(rw, Header{Type: ZRINIT})
	if err != nil {
		return err
	}

	for {
		h, err := zr.ReadHeader()
		if err != nil {
			return err
		}

		switch h.Type {
		case ZFILE:
			useCrc32 := (h.Format == FormatBin32)
			data, _, err := zr.ReadDataBlock(useCrc32)
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

			if err := WriteHexHeader(rw, Header{Type: ZRPOS}); err != nil {
				return err
			}

			pr, pw := io.Pipe()

			// Run callback in background to consume the reader
			go func() {
				// The consumer handles the streaming download
				onFile(name, size, pr)
			}()

			fileDone := false
			var fileErr error

			for !fileDone {
				h2, err := zr.ReadHeader()
				if err != nil {
					fileErr = err
					break
				}

				switch h2.Type {
				case ZEOF:
					if err := WriteHexHeader(rw, Header{Type: ZRINIT}); err != nil {
						fileErr = err
					}
					fileDone = true

				case ZDATA:
					useCrc32 = (h2.Format == FormatBin32)
					offset := 0
					for {
						chunk, endType, err := zr.ReadDataBlock(useCrc32)
						if err != nil {
							fileErr = err
							break
						}

						pw.Write(chunk)
						offset += len(chunk)

						if endType == ZCRCQ || endType == ZCRCW {
							flags := [4]byte{byte(offset), byte(offset >> 8), byte(offset >> 16), byte(offset >> 24)}
							WriteHexHeader(rw, Header{Type: ZACK, Flags: flags})
						}

						if endType == ZCRCE || endType == ZCRCW {
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
			if fileErr != nil {
				return fileErr
			}

		case ZFIN:
			WriteHexHeader(rw, Header{Type: ZFIN})
			return nil

		case ZABORT, ZCAN, ZFERR:
			return fmt.Errorf("transfer aborted by sender")
		}
	}
}
