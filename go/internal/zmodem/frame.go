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

var ErrCanceled = errors.New("zmodem transfer canceled")

// Subpacket endings
const (
	ZCRCE = 'h' // CRC next, frame ends, header (ZACK) follows
	ZCRCG = 'i' // CRC next, frame continues non-stop
	ZCRCQ = 'j' // CRC next, frame continues, ZACK expected
	ZCRCW = 'k' // CRC next, frame ends, wait for ZACK
	ZRUB0 = 'l' // Translate to rubout 0177
	ZRUB1 = 'm' // Translate to rubout 0377
)

// updcrc32 computes the Zmodem CRC32 (which matches the IEEE standard CRC32).
func updcrc32(cp uint8, crc uint32) uint32 {
	return crc32.Update(crc, crc32.IEEETable, []byte{cp})
}

// Escape handles ZMODEM character escaping.
// ZDLE, XON, XOFF, and their 8th bit set variants must be escaped.
func needsEscape(b byte) bool {
	switch b & 0x7F {
	case ZDLE, XON, XOFF, 0x0D, 0x10: // CR, DLE, XON, XOFF
		return true
	}
	return false
}

func escapeByte(b byte, out *bytes.Buffer) {
	if needsEscape(b) {
		out.WriteByte(ZDLE)
		out.WriteByte(b ^ 0x40)
	} else {
		out.WriteByte(b)
	}
}

// WriteBinaryHeader writes a ZBIN header to the writer.
func WriteBinaryHeader(w io.Writer, h Header) error {
	var buf bytes.Buffer
	buf.WriteByte(ZPAD)
	buf.WriteByte(ZDLE)
	buf.WriteByte(ZBIN)

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

// WriteBinary32Header writes a ZBIN32 header to the writer.
func WriteBinary32Header(w io.Writer, h Header) error {
	var buf bytes.Buffer
	buf.WriteByte(ZPAD)
	buf.WriteByte(ZDLE)
	buf.WriteByte(ZBIN32)

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

// Reader provides robust reading of ZMODEM frames from an underlying stream.
type Reader struct {
	r *bufio.Reader
}

func NewReader(r io.Reader) *Reader {
	return &Reader{r: bufio.NewReader(r)}
}

// ReadByteUnescaped reads one byte, handling ZDLE escaping.
func (zr *Reader) ReadByteUnescaped() (byte, error) {
	for {
		b, err := zr.r.ReadByte()
		if err != nil {
			return 0, err
		}
		if b == XON || b == XOFF || b == XON|0x80 || b == XOFF|0x80 {
			continue // ignore flow control
		}
		if b == ZDLE {
			next, err := zr.r.ReadByte()
			if err != nil {
				return 0, err
			}
			if next == ZRUB0 {
				return 0x7F, nil
			}
			if next == ZRUB1 {
				return 0xFF, nil
			}
			// Cancel sequence: ZDLE followed by CAN, then 4 more CANs (5 total).
			if next == ZCAN {
				canCount := 1
				for canCount < 5 {
					peek, err := zr.r.ReadByte()
					if err != nil {
						return 0, ErrCanceled
					}
					if peek == ZCAN || peek == ZDLE {
						canCount++
					} else {
						break
					}
				}
				if canCount >= 5 {
					return 0, ErrCanceled
				}
				// Not a real cancel sequence; treat as escaped byte.
				return next ^ 0x40, nil
			}
			return next ^ 0x40, nil
		}
		return b, nil
	}
}

// ReadHeader scans for the next valid ZMODEM header.
func (zr *Reader) ReadHeader() (Header, error) {
	for {
		// Scan for ZPAD
		b, err := zr.r.ReadByte()
		if err != nil {
			return Header{}, err
		}
		if b != ZPAD {
			continue
		}

		// Wait for ZDLE
		b, err = zr.r.ReadByte()
		if err != nil {
			return Header{}, err
		}
		if b == ZPAD {
			// Might be multiple ZPADs
			b, err = zr.r.ReadByte()
			if err != nil {
				return Header{}, err
			}
		}
		if b != ZDLE {
			continue
		}

		// Read header type
		b, err = zr.r.ReadByte()
		if err != nil {
			return Header{}, err
		}

		switch b {
		case ZHEX:
			return zr.readHexHeader()
		case ZBIN:
			return zr.readBinHeader()
		case ZBIN32:
			return zr.readBin32Header()
		}
	}
}

func (zr *Reader) readHexHeader() (Header, error) {
	hexBuf := make([]byte, 14)
	if _, err := io.ReadFull(zr.r, hexBuf); err != nil {
		return Header{}, err
	}

	// Consume trailing \r\n and XON if present, but we can also just ignore them
	// because ReadHeader scans for the next ZPAD anyway.

	return ParseHexHeader(hexBuf)
}

func (zr *Reader) readBinHeader() (Header, error) {
	data := make([]byte, 5)
	var crc uint16
	for i := 0; i < 5; i++ {
		b, err := zr.ReadByteUnescaped()
		if err != nil {
			return Header{}, err
		}
		data[i] = b
		crc = updcrc16(b, crc)
	}

	crc1, err := zr.ReadByteUnescaped()
	if err != nil {
		return Header{}, err
	}
	crc2, err := zr.ReadByteUnescaped()
	if err != nil {
		return Header{}, err
	}

	expectedCRC := (uint16(crc1) << 8) | uint16(crc2)
	if crc != expectedCRC {
		return Header{}, fmt.Errorf("%w: ZBIN CRC mismatch", ErrInvalidHeader)
	}

	h := Header{Type: data[0], Format: FormatBin}
	copy(h.Flags[:], data[1:5])
	return h, nil
}

func (zr *Reader) readBin32Header() (Header, error) {
	data := make([]byte, 5)
	var crc uint32 = 0xFFFFFFFF
	for i := 0; i < 5; i++ {
		b, err := zr.ReadByteUnescaped()
		if err != nil {
			return Header{}, err
		}
		data[i] = b
		crc = updcrc32(b, crc)
	}

	crcBytes := make([]byte, 4)
	for i := 0; i < 4; i++ {
		b, err := zr.ReadByteUnescaped()
		if err != nil {
			return Header{}, err
		}
		crcBytes[i] = b
	}

	expectedCRC := uint32(crcBytes[0]) | (uint32(crcBytes[1]) << 8) | (uint32(crcBytes[2]) << 16) | (uint32(crcBytes[3]) << 24)
	if ^crc != expectedCRC {
		return Header{}, fmt.Errorf("%w: ZBIN32 CRC mismatch", ErrInvalidHeader)
	}

	h := Header{Type: data[0], Format: FormatBin32}
	copy(h.Flags[:], data[1:5])
	return h, nil
}
