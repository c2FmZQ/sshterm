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

// readDataBlock reads a single subpacket of data up to a zDLE frame-end marker.
// Returns the unescaped data, the frame end type (e.g., zCRCE, zCRCG, zCRCQ, zCRCW), and any error.
func (zr *reader) readDataBlock(useCrc32 bool) ([]byte, byte, error) {
	var buf bytes.Buffer
	var endType byte

	// Start calculating CRC on the unescaped bytes
	var crc16 uint16
	var crc32Val uint32 = 0xFFFFFFFF

	for {
		b, err := zr.r.ReadByte()
		if err != nil {
			return nil, 0, err
		}

		// Handle escaping manually inline for performance and to catch zDLE frame endings
		if b == xON || b == xOFF || b == xON|0x80 || b == xOFF|0x80 {
			continue // ignore flow control
		}

		if b == zDLE {
			next, err := zr.r.ReadByte()
			if err != nil {
				return nil, 0, err
			}

			switch next {
			case zCRCE, zCRCG, zCRCQ, zCRCW:
				endType = next
				if useCrc32 {
					crc32Val = updcrc32(next, crc32Val)
				} else {
					crc16 = updcrc16(next, crc16)
				}
				goto ReadCRC
			case zRUB0:
				b = 0x7F
			case zRUB1:
				b = 0xFF
			case zCAN:
				return nil, 0, errCanceled
			default:
				b = next ^ 0x40
			}
		}

		if useCrc32 {
			crc32Val = updcrc32(b, crc32Val)
		} else {
			crc16 = updcrc16(b, crc16)
		}
		buf.WriteByte(b)
	}

ReadCRC:
	if useCrc32 {
		crcBytes := make([]byte, 4)
		for i := 0; i < 4; i++ {
			b, err := zr.readByteUnescaped()
			if err != nil {
				return nil, 0, err
			}
			crcBytes[i] = b
		}
		expectedCRC := uint32(crcBytes[0]) | (uint32(crcBytes[1]) << 8) | (uint32(crcBytes[2]) << 16) | (uint32(crcBytes[3]) << 24)
		if ^crc32Val != expectedCRC {
			return nil, 0, fmt.Errorf("%w: ZDATA CRC32 mismatch", errInvalidHeader)
		}
	} else {
		crc1, err := zr.readByteUnescaped()
		if err != nil {
			return nil, 0, err
		}
		crc2, err := zr.readByteUnescaped()
		if err != nil {
			return nil, 0, err
		}
		expectedCRC := (uint16(crc1) << 8) | uint16(crc2)
		if crc16 != expectedCRC {
			return nil, 0, fmt.Errorf("%w: ZDATA CRC16 mismatch", errInvalidHeader)
		}
	}

	return buf.Bytes(), endType, nil
}

// writeDataBlock writes a ZMODEM data subpacket to the writer.
func writeDataBlock(w io.Writer, data []byte, endType byte, useCrc32 bool) error {
	var buf bytes.Buffer

	var crc16 uint16
	var crc32Val uint32 = 0xFFFFFFFF

	// Write and compute CRC for data payload
	for _, b := range data {
		if useCrc32 {
			crc32Val = updcrc32(b, crc32Val)
		} else {
			crc16 = updcrc16(b, crc16)
		}
		escapeByte(b, &buf)
	}

	// The zDLE frame end type is ALSO included in the CRC calculation
	buf.WriteByte(zDLE)
	buf.WriteByte(endType)

	if useCrc32 {
		crc32Val = updcrc32(endType, crc32Val)
		crc32Val = ^crc32Val
		escapeByte(byte(crc32Val), &buf)
		escapeByte(byte(crc32Val>>8), &buf)
		escapeByte(byte(crc32Val>>16), &buf)
		escapeByte(byte(crc32Val>>24), &buf)
	} else {
		crc16 = updcrc16(endType, crc16)
		escapeByte(byte(crc16>>8), &buf)
		escapeByte(byte(crc16&0xFF), &buf)
	}

	_, err := w.Write(buf.Bytes())
	return err
}
