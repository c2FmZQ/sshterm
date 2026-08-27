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
	"fmt"
	"io"
)

// Send performs a ZMODEM send session, uploading the provided files.
// Note: This relies on a reliable underlying stream (e.g. SSH).
func Send(rw io.ReadWriter, files []*File) error {
	zr := NewReader(rw)

	// 1. Send ZRQINIT
	if err := WriteHexHeader(rw, Header{Type: ZRQINIT}); err != nil {
		return err
	}

	var currentFile *File

	for {
		h, err := zr.ReadHeader()
		if err != nil {
			return err
		}

		switch h.Type {
		case ZRINIT:
			if len(files) == 0 {
				// 4. No more files, send ZFIN
				if err := WriteHexHeader(rw, Header{Type: ZFIN}); err != nil {
					return err
				}
				// Wait for ZFIN reply
				reply, err := zr.ReadHeader()
				if err == nil && reply.Type == ZFIN {
					rw.Write([]byte("OO"))
				}
				return nil
			}

			// 2. Send ZFILE for the next file
			currentFile = files[0]
			files = files[1:]

			// Build file info: "name\0size"
			info := []byte(fmt.Sprintf("%s\x00%d 0 0 0 %d %d", currentFile.Name, len(currentFile.Data), len(files), 0))

			if err := WriteBinaryHeader(rw, Header{Type: ZFILE}); err != nil {
				return err
			}
			if err := WriteDataBlock(rw, info, ZCRCW, false); err != nil {
				return err
			}

		case ZRPOS:
			// Receiver accepted ZFILE. Send ZDATA.
			if err := WriteBinaryHeader(rw, Header{Type: ZDATA}); err != nil {
				return err
			}

			// Send file data
			if err := WriteDataBlock(rw, currentFile.Data, ZCRCE, false); err != nil {
				return err
			}

			// Send ZEOF
			offset := uint32(len(currentFile.Data))
			flags := [4]byte{byte(offset), byte(offset >> 8), byte(offset >> 16), byte(offset >> 24)}
			if err := WriteHexHeader(rw, Header{Type: ZEOF, Flags: flags}); err != nil {
				return err
			}

		case ZABORT, ZCAN, ZFERR:
			return fmt.Errorf("transfer aborted by receiver")

		default:
			// Ignore other headers
		}
	}
}
