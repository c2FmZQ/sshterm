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
	"math"
)

// send performs a ZMODEM send session, uploading the provided files.
// Note: This relies on a reliable underlying stream (e.g. SSH).
func send(rw io.ReadWriter, files []*File) error {
	for _, f := range files {
		if f.Size < 0 || f.Size > math.MaxUint32 {
			return fmt.Errorf("file %q: size %d exceeds ZMODEM 32-bit limit (%d)",
				f.Name, f.Size, uint32(math.MaxUint32))
		}
	}

	zr := newReader(rw)

	var currentFile *File

	for {
		h, err := zr.readHeader()
		if err != nil {
			return err
		}

		switch h.Type {
		case zRINIT:
			if currentFile != nil {
				// We already sent ZFILE and are waiting for ZRPOS.
				// This is a duplicate ZRINIT from the receiver, ignore it.
				continue
			}

			if len(files) == 0 {
				// 4. No more files, send ZFIN
				if err := writeHexHeader(rw, header{Type: zFIN}); err != nil {
					return err
				}
				// Wait for ZFIN reply
				reply, err := zr.readHeader()
				if err == nil && reply.Type == zFIN {
					rw.Write([]byte("OO"))
				}
				return nil
			}

			// 2. Send ZFILE for the next file
			currentFile = files[0]
			files = files[1:]

			// Build file info: "name\0size"
			info := []byte(fmt.Sprintf("%s\x00%d 0 0 0 %d %d", currentFile.Name, currentFile.Size, len(files), 0))

			if err := writeBinaryHeader(rw, header{Type: zFILE}); err != nil {
				return err
			}
			if err := writeDataBlock(rw, info, zCRCW, false); err != nil {
				return err
			}

		case zRPOS:
			// Receiver accepted ZFILE and requested to resume from an offset.
			requestedOffset := uint32(h.Flags[0]) | uint32(h.Flags[1])<<8 | uint32(h.Flags[2])<<16 | uint32(h.Flags[3])<<24
			if requestedOffset > 0 {
				if seeker, ok := currentFile.R.(io.Seeker); ok {
					if _, err := seeker.Seek(int64(requestedOffset), io.SeekStart); err != nil {
						return err
					}
				} else {
					if _, err := io.CopyN(io.Discard, currentFile.R, int64(requestedOffset)); err != nil {
						return err
					}
				}
			}

			if err := writeBinaryHeader(rw, header{Type: zDATA}); err != nil {
				return err
			}

			// Stream file data in chunks
			buf := make([]byte, 8192)
			offset := requestedOffset
			for {
				n, readErr := currentFile.R.Read(buf)
				if n > 0 || (offset == 0 && readErr == io.EOF) {
					// Use zCRCG for intermediate chunks, zCRCE for the last
					endType := byte(zCRCG)
					if readErr != nil || offset+uint32(n) >= uint32(currentFile.Size) {
						endType = zCRCE
					}
					if err := writeDataBlock(rw, buf[:n], endType, false); err != nil {
						return err
					}
					offset += uint32(n)
				}
				if readErr != nil {
					if readErr != io.EOF {
						return readErr
					}
					break
				}
			}

			// Send ZEOF
			flags := [4]byte{byte(offset), byte(offset >> 8), byte(offset >> 16), byte(offset >> 24)}
			if err := writeHexHeader(rw, header{Type: zEOF, Flags: flags}); err != nil {
				return err
			}
			currentFile = nil // Reset state, waiting for next ZRINIT

		case zSKIP:
			currentFile = nil // Receiver skipped this file, wait for next ZRINIT

		case zABORT, zCAN, zFERR:
			return fmt.Errorf("transfer aborted by receiver")

		default:
			// Ignore other headers
		}
	}
}
