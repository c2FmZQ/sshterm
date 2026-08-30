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

func TestDataBlockWriteParse(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		endType  byte
		useCrc32 bool
	}{
		{
			name:     "Small Payload CRC16 ZCRCE",
			data:     []byte("hello world"),
			endType:  zCRCE,
			useCrc32: false,
		},
		{
			name:     "Small Payload CRC32 ZCRCG",
			data:     []byte("hello world with more text"),
			endType:  zCRCG,
			useCrc32: true,
		},
		{
			name:     "Escaped Payload CRC16 ZCRCW",
			data:     []byte{0x0D, 0x18, 0x11, 0x13, 0x18, 'A', 'B', 'C'}, // Needs escaping
			endType:  zCRCW,
			useCrc32: false,
		},
		{
			name:     "Empty Payload CRC32 ZCRCQ",
			data:     []byte{},
			endType:  zCRCQ,
			useCrc32: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := writeDataBlock(&buf, tc.data, tc.endType, tc.useCrc32); err != nil {
				t.Fatalf("WriteDataBlock failed: %v", err)
			}

			zr := newReader(&buf)
			parsedData, parsedEndType, err := zr.readDataBlock(tc.useCrc32)
			if err != nil {
				t.Fatalf("ReadDataBlock failed: %v", err)
			}

			if parsedEndType != tc.endType {
				t.Errorf("EndType mismatch: expected %x, got %x", tc.endType, parsedEndType)
			}
			if !bytes.Equal(parsedData, tc.data) {
				t.Errorf("Data mismatch: expected %x, got %x", tc.data, parsedData)
			}
		})
	}
}

func TestDataBlock_CorruptedCRC(t *testing.T) {
	var buf bytes.Buffer
	err := writeDataBlock(&buf, []byte("good data"), zCRCE, false)
	if err != nil {
		t.Fatal(err)
	}

	// Corrupt the CRC by changing the last byte
	out := buf.Bytes()
	out[len(out)-1] ^= 0xFF

	zr := newReader(bytes.NewReader(out))
	_, _, err = zr.readDataBlock(false)
	if err == nil {
		t.Fatal("Expected CRC mismatch error, but got nil")
	}
}
