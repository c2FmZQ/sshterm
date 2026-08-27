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
	"testing"
)

func TestHexHeaderWriteParse(t *testing.T) {
	tests := []struct {
		name   string
		header Header
	}{
		{
			name: "ZRQINIT",
			header: Header{
				Type:  ZRQINIT,
				Flags: [4]byte{0, 0, 0, 0},
			},
		},
		{
			name: "ZFILE",
			header: Header{
				Type:  ZFILE,
				Flags: [4]byte{0, 0, 0, 1}, // Conversion options
			},
		},
		{
			name: "ZFIN",
			header: Header{
				Type:  ZFIN,
				Flags: [4]byte{0, 0, 0, 0},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := WriteHexHeader(&buf, tc.header); err != nil {
				t.Fatalf("WriteHexHeader failed: %v", err)
			}

			out := buf.Bytes()
			// Must start with **\x18B
			if !bytes.HasPrefix(out, []byte{ZPAD, ZPAD, ZDLE, ZHEX}) {
				t.Fatalf("Missing hex header prefix: %x", out)
			}

			// Extract the 14 hex bytes
			hexData := out[4 : 4+14]
			parsed, err := ParseHexHeader(hexData)
			if err != nil {
				t.Fatalf("ParseHexHeader failed: %v", err)
			}

			if parsed.Type != tc.header.Type {
				t.Errorf("Type mismatch: expected %d, got %d", tc.header.Type, parsed.Type)
			}
			if parsed.Flags != tc.header.Flags {
				t.Errorf("Flags mismatch: expected %v, got %v", tc.header.Flags, parsed.Flags)
			}
		})
	}
}

func TestParseHexHeader_InvalidCRC(t *testing.T) {
	// A valid hex string but we will flip a byte to invalidate the CRC
	hexData := []byte("00000000000000")
	// The CRC for 5 zeros is 0000
	_, err := ParseHexHeader(hexData)
	if err != nil {
		t.Fatalf("Expected valid all zeros to parse, got %v", err)
	}

	// Invalidate the type byte but keep CRC the same
	hexData[1] = '1'
	_, err = ParseHexHeader(hexData)
	if err == nil {
		t.Fatal("Expected error due to CRC mismatch")
	}
}
