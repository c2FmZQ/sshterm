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
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

// Constants for Zmodem protocol characters.
const (
	zPAD   = '*'
	zDLE   = 0x18
	zDLEE  = 0x58 // zDLE ^ 0x40
	zHEX   = 'B'
	zBIN   = 'A'
	zBIN32 = 'C'
	xON    = 0x11
	xOFF   = 0x13
	can    = 0x18 // ASCII CAN, same as zDLE
)

// cancelSeq is the standard ZMODEM cancel sequence: 8 CAN bytes + 8 backspaces.
var cancelSeq = []byte{
	can, can, can, can, can, can, can, can,
	0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
}

// Zmodem frame types.
const (
	zRQINIT    = 0  // Request receive init
	zRINIT     = 1  // Receive init
	zSINIT     = 2  // Send init sequence
	zACK       = 3  // Acknowledge
	zFILE      = 4  // File name from sender
	zSKIP      = 5  // To sender: skip this file
	zNAK       = 6  // Last packet was garbled
	zABORT     = 7  // Abort batch transfers
	zFIN       = 8  // Finish session
	zRPOS      = 9  // Resume data trans at this position
	zDATA      = 10 // Data packet(s) follow
	zEOF       = 11 // End of file
	zFERR      = 12 // Fatal Read or Write error detected
	zCRC       = 13 // Request for file CRC and response
	zCHALLENGE = 14 // Receiver's Challenge
	zCOMPL     = 15 // Request is complete
	zCAN       = 16 // Other end canned session with CAN*5
	zFREECNT   = 17 // Request for free bytes on filesystem
	zCOMMAND   = 18 // Command from sending program
	zSTDERR    = 19 // Output to standard error, data follows
)

// Format types
const (
	formatHex = iota
	formatBin
	formatBin32
)

// header represents a Zmodem frame header.
type header struct {
	Type   uint8
	Flags  [4]byte // Or payload/position bytes
	Format int
}

// errInvalidHeader is returned when a header is malformed.
var errInvalidHeader = errors.New("invalid zmodem header")

// updcrc16 calculates the ZMODEM CRC-16 (XMODEM CRC).
func updcrc16(cp uint8, crc uint16) uint16 {
	crc = crc ^ (uint16(cp) << 8)
	for i := 0; i < 8; i++ {
		if crc&0x8000 != 0 {
			crc = (crc << 1) ^ 0x1021
		} else {
			crc = crc << 1
		}
	}
	return crc
}

// writeHexHeader writes a HEX header to the given writer.
// Hex headers are used to start sessions and for other control messages
// that need to survive character translation.
func writeHexHeader(w io.Writer, h header) error {
	buf := make([]byte, 21) // **\x18B + 14 hex + \r\n\x11
	buf[0] = zPAD
	buf[1] = zPAD
	buf[2] = zDLE
	buf[3] = zHEX

	data := []byte{h.Type, h.Flags[0], h.Flags[1], h.Flags[2], h.Flags[3]}

	crc := uint16(0)
	for _, b := range data {
		crc = updcrc16(b, crc)
	}

	hexBuf := make([]byte, 14)
	hex.Encode(hexBuf[0:2], []byte{h.Type})
	hex.Encode(hexBuf[2:10], h.Flags[:])
	hex.Encode(hexBuf[10:12], []byte{byte(crc >> 8)})
	hex.Encode(hexBuf[12:14], []byte{byte(crc & 0xFF)})

	copy(buf[4:18], hexBuf)
	buf[18] = '\r'
	buf[19] = '\n'
	if h.Type != zFIN && h.Type != zACK {
		buf[20] = xON
	} else {
		buf = buf[:20] // ZFIN/ZACK don't require XON
	}

	_, err := w.Write(buf)
	return err
}

// parseHexHeader parses a HEX header from the provided 14 bytes of hex data.
func parseHexHeader(hexData []byte) (header, error) {
	if len(hexData) != 14 {
		return header{}, fmt.Errorf("%w: expected 14 hex bytes, got %d", errInvalidHeader, len(hexData))
	}

	decoded := make([]byte, 7)
	if _, err := hex.Decode(decoded, hexData); err != nil {
		return header{}, fmt.Errorf("%w: invalid hex: %v", errInvalidHeader, err)
	}

	h := header{
		Type:   decoded[0],
		Format: formatHex,
	}
	copy(h.Flags[:], decoded[1:5])

	crc := uint16(0)
	for i := 0; i < 5; i++ {
		crc = updcrc16(decoded[i], crc)
	}

	expectedCRC := (uint16(decoded[5]) << 8) | uint16(decoded[6])
	if crc != expectedCRC {
		return header{}, fmt.Errorf("%w: CRC mismatch, expected %04x, got %04x", errInvalidHeader, expectedCRC, crc)
	}

	return h, nil
}
