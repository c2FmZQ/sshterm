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

func TestBinaryHeaderWriteParse(t *testing.T) {
	tests := []struct {
		name   string
		header header
	}{
		{
			name: "ZDATA",
			header: header{
				Type:  zDATA,
				Flags: [4]byte{1, 2, 3, 4},
			},
		},
		{
			name: "ZACK",
			header: header{
				Type:  zACK,
				Flags: [4]byte{0xFF, 0x18, 0x0D, 0x0A}, // Bytes that need escaping
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name+"_ZBIN", func(t *testing.T) {
			var buf bytes.Buffer
			if err := writeBinaryHeader(&buf, tc.header); err != nil {
				t.Fatalf("WriteBinaryHeader failed: %v", err)
			}

			zr := newReader(&buf)
			parsed, err := zr.readHeader()
			if err != nil {
				t.Fatalf("ReadHeader failed: %v", err)
			}

			if parsed.Type != tc.header.Type || parsed.Flags != tc.header.Flags {
				t.Errorf("Mismatch: expected %+v, got %+v", tc.header, parsed)
			}
		})

		t.Run(tc.name+"_ZBIN32", func(t *testing.T) {
			var buf bytes.Buffer
			if err := writeBinary32Header(&buf, tc.header); err != nil {
				t.Fatalf("WriteBinary32Header failed: %v", err)
			}

			zr := newReader(&buf)
			parsed, err := zr.readHeader()
			if err != nil {
				t.Fatalf("ReadHeader failed: %v", err)
			}

			if parsed.Type != tc.header.Type || parsed.Flags != tc.header.Flags {
				t.Errorf("Mismatch: expected %+v, got %+v", tc.header, parsed)
			}
		})
	}
}

func TestEscaping(t *testing.T) {
	var buf bytes.Buffer
	h := header{Type: zFILE, Flags: [4]byte{zDLE, xON, xOFF, 0x0D}}
	writeBinary32Header(&buf, h)

	// Check that none of the restricted bytes appear unescaped after ZDLE
	out := buf.Bytes()
	for i, b := range out {
		if i > 2 { // Skip ZPAD ZDLE ZBIN32
			if b == zDLE && i < len(out)-1 {
				// The next byte must be XOR'd with 0x40
				next := out[i+1]
				if next == zDLE || next == xON || next == xOFF || next == 0x0D {
					t.Errorf("Found unescaped control character after ZDLE: %x", next)
				}
			}
		}
	}
}

func TestReadByteUnescaped_Cancel(t *testing.T) {
	zr := newReader(bytes.NewReader(cancelSeq))
	if _, err := zr.readByteUnescaped(); err != errCanceled {
		t.Fatalf("Expected errCanceled, got %v", err)
	}
}

func TestReadByteUnescaped_ShortCanRun(t *testing.T) {
	// Fewer than five CANs is not a cancel sequence.
	zr := newReader(bytes.NewReader([]byte{zDLE, can, 'A', 'B'}))
	b, err := zr.readByteUnescaped()
	if err != nil {
		t.Fatalf("readByteUnescaped failed: %v", err)
	}
	if want := byte(can ^ 0x40); b != want {
		t.Errorf("Expected escaped byte %#x, got %#x", want, b)
	}
	// The byte that ended the CAN run must not have been swallowed.
	if b, err = zr.readByteUnescaped(); err != nil || b != 'A' {
		t.Errorf("Expected 'A', nil; got %q, %v", b, err)
	}
}
