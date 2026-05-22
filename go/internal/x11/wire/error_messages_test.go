//go:build x11 && !wasm

package wire

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestErrors(t *testing.T) {
	testCases := []struct {
		name      string
		errorCode byte
		expected  Error
	}{
		{"Request", 1, &RequestError{}},
		{"Value", ValueErrorCode, &ValueError{}},
		{"Window", WindowErrorCode, &WindowError{}},
		{"Pixmap", PixmapErrorCode, &PixmapError{}},
		{"Atom", 5, &AtomError{}},
		{"Cursor", CursorErrorCode, &CursorError{}},
		{"Font", 7, &FontError{}},
		{"Match", 8, &MatchError{}},
		{"Drawable", 9, &DrawableError{}},
		{"Access", 10, &AccessError{}},
		{"Alloc", 11, &AllocError{}},
		{"Colormap", ColormapErrorCode, &ColormapError{}},
		{"GContext", GContextErrorCode, &GContextError{}},
		{"IDChoice", IDChoiceErrorCode, &IDChoiceError{}},
		{"Name", 15, &NameError{}},
		{"Length", 16, &LengthError{}},
		{"Implementation", 17, &ImplementationError{}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := NewError(tc.errorCode, 1, 2, Opcodes{Major: 4, Minor: 3})
			if err.Code() != tc.errorCode {
				t.Errorf("expected error code %d, got %d", tc.errorCode, err.Code())
			}

			encoded := err.EncodeMessage(binary.LittleEndian)
			expected := make([]byte, 32)
			expected[0] = 0
			expected[1] = tc.errorCode
			binary.LittleEndian.PutUint16(expected[2:4], 1)
			binary.LittleEndian.PutUint32(expected[4:8], 2)
			binary.LittleEndian.PutUint16(expected[8:10], 3)
			expected[10] = 4
			if !bytes.Equal(encoded, expected) {
				t.Errorf("error encoding failed. Got %v, want %v", encoded, expected)
			}

			decoded, err2 := ParseError(encoded, binary.LittleEndian)
			if err2 != nil {
				t.Fatal(err2)
			}
			if decoded.Code() != tc.errorCode {
				t.Errorf("expected error code %d, got %d", tc.errorCode, decoded.Code())
			}
			if decoded.Sequence() != 1 {
				t.Errorf("expected sequence 1, got %d", decoded.Sequence())
			}
			if decoded.BadValue() != 2 {
				t.Errorf("expected bad value 2, got %d", decoded.BadValue())
			}
			if decoded.MinorOp() != 3 {
				t.Errorf("expected minor op 3, got %d", decoded.MinorOp())
			}
			if decoded.MajorOp() != 4 {
				t.Errorf("expected major op 4, got %d", decoded.MajorOp())
			}
		})
	}

	t.Run("GenericError", func(t *testing.T) {
		err := NewError(99, 1, 2, Opcodes{Major: 4, Minor: 3})
		if _, ok := err.(*GenericError); !ok {
			t.Errorf("expected GenericError, got %T", err)
		}
	})
}
