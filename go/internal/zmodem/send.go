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
func send(rw io.ReadWriter, files []*File, onStart func(name string, size int64)) error {
	for _, f := range files {
		if f.Size < 0 || f.Size > math.MaxUint32 {
			return fmt.Errorf("file %q: size %d exceeds ZMODEM 32-bit limit (%d)",
				f.Name, f.Size, uint32(math.MaxUint32))
		}
	}

	zr := newReader(rw)

	var currentFile *File

	defer func() {
		if currentFile != nil && currentFile.R != nil {
			currentFile.R.Close()
		}
		for _, f := range files {
			if f != nil && f.R != nil {
				f.R.Close()
			}
		}
	}()

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

			if onStart != nil {
				onStart(currentFile.Name, currentFile.Size)
			}

			// Build file info: "name\0size"
			info := []byte(fmt.Sprintf("%s\x00%d 0 0 0 %d %d", currentFile.Name, currentFile.Size, len(files), 0))

			if err := writeBinaryHeader(rw, header{Type: zFILE}); err != nil {
				return err
			}
			if err := writeDataBlock(rw, info, zCRCW, false); err != nil {
				return err
			}

		case zRPOS:
			if currentFile == nil || currentFile.R == nil {
				// ZRPOS outside of the ZFILE -> ZRPOS window, e.g. a
				// retransmission request arriving after we already sent ZEOF,
				// or one following a ZSKIP. There is nothing to send.
				continue
			}

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

			// Stream file data in chunks. The last subpacket must end the
			// frame with zCRCE, so a chunk is held back until the next read
			// says whether more data follows. Relying on the declared size
			// instead would desynchronize the receiver whenever the reader
			// yields a different number of bytes than File.Size advertises.
			cur, next := make([]byte, 8192), make([]byte, 8192)
			pending := 0
			offset := requestedOffset
			for {
				n, readErr := currentFile.R.Read(next)
				if readErr != nil && readErr != io.EOF {
					return readErr
				}
				if n > 0 {
					if pending > 0 {
						if err := writeDataBlock(rw, cur[:pending], zCRCG, false); err != nil {
							return err
						}
						offset += uint32(pending)
					}
					cur, next = next, cur
					pending = n
				}
				if readErr == io.EOF {
					break
				}
			}
			// Always emit a final subpacket, even for an empty file, so the
			// receiver sees a complete ZDATA frame before the ZEOF header.
			if err := writeDataBlock(rw, cur[:pending], zCRCE, false); err != nil {
				return err
			}
			offset += uint32(pending)

			// Send ZEOF
			flags := [4]byte{byte(offset), byte(offset >> 8), byte(offset >> 16), byte(offset >> 24)}
			if err := writeHexHeader(rw, header{Type: zEOF, Flags: flags}); err != nil {
				return err
			}
			if currentFile.R != nil {
				currentFile.R.Close()
			}
			currentFile = nil // Reset state, waiting for next ZRINIT

		case zSKIP:
			if currentFile != nil && currentFile.R != nil {
				currentFile.R.Close()
			}
			currentFile = nil // Receiver skipped this file, wait for next ZRINIT

		case zABORT, zCAN, zFERR:
			return fmt.Errorf("transfer aborted by receiver")

		default:
			// Ignore other headers
		}
	}
}
