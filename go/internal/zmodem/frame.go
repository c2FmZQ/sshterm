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
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
)

var errCanceled = errors.New("zmodem transfer canceled")

// Subpacket endings
const (
	zCRCE = 'h' // CRC next, frame ends, header (ZACK) follows
	zCRCG = 'i' // CRC next, frame continues non-stop
	zCRCQ = 'j' // CRC next, frame continues, ZACK expected
	zCRCW = 'k' // CRC next, frame ends, wait for ZACK
	zRUB0 = 'l' // Translate to rubout 0177
	zRUB1 = 'm' // Translate to rubout 0377
)

// updcrc32 computes the Zmodem CRC32 (which matches the IEEE standard CRC32).
func updcrc32(cp uint8, crc uint32) uint32 {
	return crc32.Update(crc, crc32.IEEETable, []byte{cp})
}

// Escape handles ZMODEM character escaping.
// zDLE, xON, xOFF, and their 8th bit set variants must be escaped.
func needsEscape(b byte) bool {
	switch b & 0x7F {
	case zDLE, xON, xOFF, 0x0D, 0x10: // CR, DLE, XON, XOFF
		return true
	}
	return false
}

func escapeByte(b byte, out *bytes.Buffer) {
	if needsEscape(b) {
		out.WriteByte(zDLE)
		out.WriteByte(b ^ 0x40)
	} else {
		out.WriteByte(b)
	}
}

// writeBinaryHeader writes a ZBIN header to the writer.
func writeBinaryHeader(w io.Writer, h header) error {
	var buf bytes.Buffer
	buf.WriteByte(zPAD)
	buf.WriteByte(zDLE)
	buf.WriteByte(zBIN)

	data := []byte{h.Type, h.Flags[0], h.Flags[1], h.Flags[2], h.Flags[3]}
	var crc uint16
	for _, b := range data {
		crc = updcrc16(b, crc)
		escapeByte(b, &buf)
	}
	escapeByte(byte(crc>>8), &buf)
	escapeByte(byte(crc&0xFF), &buf)

	_, err := w.Write(buf.Bytes())
	return err
}

// writeBinary32Header writes a ZBIN32 header to the writer.
func writeBinary32Header(w io.Writer, h header) error {
	var buf bytes.Buffer
	buf.WriteByte(zPAD)
	buf.WriteByte(zDLE)
	buf.WriteByte(zBIN32)

	data := []byte{h.Type, h.Flags[0], h.Flags[1], h.Flags[2], h.Flags[3]}
	var crc uint32 = 0xFFFFFFFF
	for _, b := range data {
		crc = updcrc32(b, crc)
		escapeByte(b, &buf)
	}
	crc = ^crc
	escapeByte(byte(crc), &buf)
	escapeByte(byte(crc>>8), &buf)
	escapeByte(byte(crc>>16), &buf)
	escapeByte(byte(crc>>24), &buf)

	_, err := w.Write(buf.Bytes())
	return err
}

// reader provides robust reading of ZMODEM frames from an underlying stream.
type reader struct {
	r *bufio.Reader
}

func newReader(r io.Reader) *reader {
	return &reader{r: bufio.NewReader(r)}
}

// readByteUnescaped reads one byte, handling zDLE escaping.
func (zr *reader) readByteUnescaped() (byte, error) {
	for {
		b, err := zr.r.ReadByte()
		if err != nil {
			return 0, err
		}
		if b == xON || b == xOFF || b == xON|0x80 || b == xOFF|0x80 {
			continue // ignore flow control
		}
		if b == zDLE {
			next, err := zr.r.ReadByte()
			if err != nil {
				return 0, err
			}
			if next == zRUB0 {
				return 0x7F, nil
			}
			if next == zRUB1 {
				return 0xFF, nil
			}
			// Cancel sequence: zDLE followed by CAN, then 4 more CANs (5 total).
			if next == zCAN {
				canCount := 1
				for canCount < 5 {
					peek, err := zr.r.ReadByte()
					if err != nil {
						return 0, errCanceled
					}
					if peek == zCAN || peek == zDLE {
						canCount++
					} else {
						break
					}
				}
				if canCount >= 5 {
					return 0, errCanceled
				}
				// Not a real cancel sequence; treat as escaped byte.
				return next ^ 0x40, nil
			}
			return next ^ 0x40, nil
		}
		return b, nil
	}
}

// readHeader scans for the next valid ZMODEM header.
func (zr *reader) readHeader() (header, error) {
	for {
		// Scan for zPAD
		b, err := zr.r.ReadByte()
		if err != nil {
			return header{}, err
		}
		if b != zPAD {
			continue
		}

		// Wait for zDLE
		b, err = zr.r.ReadByte()
		if err != nil {
			return header{}, err
		}
		if b == zPAD {
			// Might be multiple zPADs
			b, err = zr.r.ReadByte()
			if err != nil {
				return header{}, err
			}
		}
		if b != zDLE {
			continue
		}

		// Read header type
		b, err = zr.r.ReadByte()
		if err != nil {
			return header{}, err
		}

		switch b {
		case zHEX:
			return zr.readHexHeader()
		case zBIN:
			return zr.readBinHeader()
		case zBIN32:
			return zr.readBin32Header()
		}
	}
}

func (zr *reader) readHexHeader() (header, error) {
	hexBuf := make([]byte, 14)
	if _, err := io.ReadFull(zr.r, hexBuf); err != nil {
		return header{}, err
	}

	// Consume trailing \r\n and XON if present, but we can also just ignore them
	// because readHeader scans for the next zPAD anyway.

	return parseHexHeader(hexBuf)
}

func (zr *reader) readBinHeader() (header, error) {
	data := make([]byte, 5)
	var crc uint16
	for i := 0; i < 5; i++ {
		b, err := zr.readByteUnescaped()
		if err != nil {
			return header{}, err
		}
		data[i] = b
		crc = updcrc16(b, crc)
	}

	crc1, err := zr.readByteUnescaped()
	if err != nil {
		return header{}, err
	}
	crc2, err := zr.readByteUnescaped()
	if err != nil {
		return header{}, err
	}

	expectedCRC := (uint16(crc1) << 8) | uint16(crc2)
	if crc != expectedCRC {
		return header{}, fmt.Errorf("%w: ZBIN CRC mismatch", errInvalidHeader)
	}

	h := header{Type: data[0], Format: formatBin}
	copy(h.Flags[:], data[1:5])
	return h, nil
}

func (zr *reader) readBin32Header() (header, error) {
	data := make([]byte, 5)
	var crc uint32 = 0xFFFFFFFF
	for i := 0; i < 5; i++ {
		b, err := zr.readByteUnescaped()
		if err != nil {
			return header{}, err
		}
		data[i] = b
		crc = updcrc32(b, crc)
	}

	crcBytes := make([]byte, 4)
	for i := 0; i < 4; i++ {
		b, err := zr.readByteUnescaped()
		if err != nil {
			return header{}, err
		}
		crcBytes[i] = b
	}

	expectedCRC := uint32(crcBytes[0]) | (uint32(crcBytes[1]) << 8) | (uint32(crcBytes[2]) << 16) | (uint32(crcBytes[3]) << 24)
	if ^crc != expectedCRC {
		return header{}, fmt.Errorf("%w: ZBIN32 CRC mismatch", errInvalidHeader)
	}

	h := header{Type: data[0], Format: formatBin32}
	copy(h.Flags[:], data[1:5])
	return h, nil
}
