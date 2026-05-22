//go:build x11 && !wasm

package wire

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"testing"
)

func TestReadServerMessages(t *testing.T) {
	order := binary.LittleEndian
	buf := new(bytes.Buffer)
	// Write an error
	err := NewError(RequestErrorCode, 2, 3, Opcodes{Major: 5, Minor: 4})
	buf.Write(err.EncodeMessage(order))
	// Write a reply
	reply := &GetGeometryReply{
		Sequence: 1,
		Depth:    2,
		Root:     3,
	}
	tracker := NewReplyTracker()
	tracker.Expect(1, Opcodes{Major: GetGeometry})
	buf.Write(reply.EncodeMessage(order))
	// Write an event
	event := &KeyEvent{
		Opcode:     KeyPress,
		Detail:     1,
		Sequence:   2,
		Time:       3,
		Root:       4,
		Event:      5,
		Child:      6,
		RootX:      7,
		RootY:      8,
		EventX:     9,
		EventY:     10,
		State:      11,
		SameScreen: true,
	}
	buf.Write(event.EncodeMessage(order))

	ch := ReadServerMessagesWithTracker(buf, order, tracker)
	msg1 := <-ch
	if _, ok := msg1.(Error); !ok {
		t.Errorf("expected Error, got %T", msg1)
	}
	msg2 := <-ch
	if _, ok := msg2.(*GetGeometryReply); !ok {
		t.Errorf("expected GetGeometryReply, got %T", msg2)
	}
	msg3 := <-ch
	if _, ok := msg3.(*KeyEvent); !ok {
		t.Errorf("expected KeyEvent, got %T", msg3)
	}
}

func TestReplyMessages(t *testing.T) {
	t.Run("GetKeyboardControl", func(t *testing.T) {
		reply := &GetKeyboardControlReply{
			Sequence:         9,
			KeyClickPercent:  1,
			BellPercent:      2,
			BellPitch:        3,
			BellDuration:     4,
			LedMask:          5,
			GlobalAutoRepeat: 1,
			AutoRepeats:      [32]byte{1, 2, 3},
		}
		encoded := reply.EncodeMessage(binary.LittleEndian)
		expected := make([]byte, 52)
		expected[0] = 1
		expected[1] = 1
		binary.LittleEndian.PutUint16(expected[2:4], 9)
		binary.LittleEndian.PutUint32(expected[4:8], 5)
		binary.LittleEndian.PutUint32(expected[8:12], 5)
		expected[12] = 1
		expected[13] = 2
		binary.LittleEndian.PutUint16(expected[14:16], 3)
		binary.LittleEndian.PutUint16(expected[16:18], 4)
		expected[20] = 1
		expected[21] = 2
		expected[22] = 3
		if !bytes.Equal(encoded, expected) {
			t.Errorf("GetKeyboardControlReply encoding failed. Got %v, want %v", encoded, expected)
		}
	})

	t.Run("QueryTree", func(t *testing.T) {
		reply := &QueryTreeReply{
			Sequence:    5,
			Root:        1,
			Parent:      2,
			NumChildren: 1,
			Children:    []uint32{3},
		}
		encoded := reply.EncodeMessage(binary.LittleEndian)
		expected := make([]byte, 36)
		expected[0] = 1
		binary.LittleEndian.PutUint16(expected[2:4], 5)
		binary.LittleEndian.PutUint32(expected[4:8], 1)
		binary.LittleEndian.PutUint32(expected[8:12], 1)
		binary.LittleEndian.PutUint32(expected[12:16], 2)
		binary.LittleEndian.PutUint16(expected[16:18], 1)
		binary.LittleEndian.PutUint32(expected[32:36], 3)
		if !bytes.Equal(encoded, expected) {
			t.Errorf("QueryTreeReply encoding failed. Got %v, want %v", encoded, expected)
		}
	})

	t.Run("ListFontsWithInfo", func(t *testing.T) {
		reply := &ListFontsWithInfoReply{
			Sequence:   6,
			NameLength: 4,
			FontName:   "test",
		}
		encoded := reply.EncodeMessage(binary.LittleEndian)
		expected := make([]byte, 64)
		expected[0] = 1
		expected[1] = 4
		binary.LittleEndian.PutUint16(expected[2:4], 6)
		binary.LittleEndian.PutUint32(expected[4:8], 8)
		copy(expected[60:], "test")
		if !bytes.Equal(encoded, expected) {
			t.Errorf("ListFontsWithInfoReply encoding failed. Got %v, want %v", encoded, expected)
		}
	})

	t.Run("GetFontPath", func(t *testing.T) {
		reply := &GetFontPathReply{
			Sequence: 7,
			NPaths:   1,
			Paths:    []string{"/usr/share/fonts"},
		}
		encoded := reply.EncodeMessage(binary.LittleEndian)
		expected := make([]byte, 52)
		expected[0] = 1
		binary.LittleEndian.PutUint16(expected[2:4], 7)
		binary.LittleEndian.PutUint32(expected[4:8], 5)
		binary.LittleEndian.PutUint16(expected[8:10], 1)
		expected[32] = 16
		copy(expected[33:], "/usr/share/fonts")
		if !bytes.Equal(encoded, expected) {
			t.Errorf("GetFontPathReply encoding failed. Got %v, want %v", encoded, expected)
		}
	})

	t.Run("QueryKeymap", func(t *testing.T) {
		reply := &QueryKeymapReply{
			Sequence: 8,
			Keys:     [32]byte{1, 2, 3},
		}
		encoded := reply.EncodeMessage(binary.LittleEndian)
		expected := make([]byte, 40)
		expected[0] = 1
		binary.LittleEndian.PutUint16(expected[2:4], 8)
		binary.LittleEndian.PutUint32(expected[4:8], 2)
		expected[8] = 1
		expected[9] = 2
		expected[10] = 3
		if !bytes.Equal(encoded, expected) {
			t.Errorf("QueryKeymapReply encoding failed. Got %v, want %v", encoded, expected)
		}
	})

	t.Run("GetMotionEvents", func(t *testing.T) {
		reply := &GetMotionEventsReply{
			Sequence: 2,
			NEvents:  1,
			Events: []TimeCoord{
				{
					Time: 123,
					X:    10,
					Y:    20,
				},
			},
		}
		encoded := reply.EncodeMessage(binary.LittleEndian)
		expected := make([]byte, 40)
		expected[0] = 1
		binary.LittleEndian.PutUint16(expected[2:4], 2)
		binary.LittleEndian.PutUint32(expected[4:8], 2)
		binary.LittleEndian.PutUint32(expected[8:12], 1)
		binary.LittleEndian.PutUint32(expected[32:36], 123)
		binary.LittleEndian.PutUint16(expected[36:38], 10)
		binary.LittleEndian.PutUint16(expected[38:40], 20)
		if !bytes.Equal(encoded, expected) {
			t.Errorf("GetMotionEventsReply encoding failed. Got %v, want %v", encoded, expected)
		}
	})

	t.Run("QueryTextExtents", func(t *testing.T) {
		reply := &QueryTextExtentsReply{
			Sequence:       3,
			DrawDirection:  0,
			FontAscent:     10,
			FontDescent:    2,
			OverallAscent:  11,
			OverallDescent: 3,
			OverallWidth:   100,
			OverallLeft:    -5,
			OverallRight:   95,
		}
		encoded := reply.EncodeMessage(binary.LittleEndian)
		expected := make([]byte, 32)
		expected[0] = 1
		expected[1] = 0
		binary.LittleEndian.PutUint16(expected[2:4], 3)
		binary.LittleEndian.PutUint32(expected[4:8], 0)
		binary.LittleEndian.PutUint16(expected[8:10], uint16(10))
		binary.LittleEndian.PutUint16(expected[10:12], uint16(2))
		binary.LittleEndian.PutUint16(expected[12:14], uint16(11))
		binary.LittleEndian.PutUint16(expected[14:16], uint16(3))
		binary.LittleEndian.PutUint32(expected[16:20], uint32(100))
		binary.LittleEndian.PutUint32(expected[20:24], int32ToUint32(-5))
		binary.LittleEndian.PutUint32(expected[24:28], int32ToUint32(95))
		if !bytes.Equal(encoded, expected) {
			t.Errorf("QueryTextExtentsReply encoding failed. Got %v, want %v", encoded, expected)
		}
	})

	t.Run("ListExtensions", func(t *testing.T) {
		reply := &ListExtensionsReply{
			Sequence: 4,
			NNames:   2,
			Names:    []string{"ext1", "ext2"},
		}
		encoded := reply.EncodeMessage(binary.LittleEndian)

		var data []byte
		data = append(data, 4, 'e', 'x', 't', '1')
		data = append(data, 4, 'e', 'x', 't', '2')

		expected := make([]byte, 32+len(data)+PadLen(len(data)))
		expected[0] = 1
		expected[1] = 2
		binary.LittleEndian.PutUint16(expected[2:4], 4)
		binary.LittleEndian.PutUint32(expected[4:8], uint32((len(data)+3)/4))
		copy(expected[32:], data)

		if !bytes.Equal(encoded, expected) {
			t.Errorf("ListExtensionsReply encoding failed. Got %v, want %v", encoded, expected)
		}
	})

	t.Run("GetWindowAttributes", func(t *testing.T) {
		reply := &GetWindowAttributesReply{
			Sequence:           10,
			BackingStore:       1,
			VisualID:           2,
			Class:              3,
			BitGravity:         4,
			WinGravity:         5,
			BackingPlanes:      6,
			BackingPixel:       7,
			SaveUnder:          1,
			MapIsInstalled:     1,
			MapState:           2,
			OverrideRedirect:   1,
			Colormap:           8,
			AllEventMasks:      9,
			YourEventMask:      10,
			DoNotPropagateMask: 11,
		}
		encoded := reply.EncodeMessage(binary.LittleEndian)
		expected := make([]byte, 44)
		expected[0] = 1
		expected[1] = 1
		binary.LittleEndian.PutUint16(expected[2:4], 10)
		binary.LittleEndian.PutUint32(expected[4:8], 3)
		binary.LittleEndian.PutUint32(expected[8:12], 2)
		binary.LittleEndian.PutUint16(expected[12:14], 3)
		expected[14] = 4
		expected[15] = 5
		binary.LittleEndian.PutUint32(expected[16:20], 6)
		binary.LittleEndian.PutUint32(expected[20:24], 7)
		expected[24] = 1
		expected[25] = 1
		expected[26] = 2
		expected[27] = 1
		binary.LittleEndian.PutUint32(expected[28:32], 8)
		binary.LittleEndian.PutUint32(expected[32:36], 9)
		binary.LittleEndian.PutUint32(expected[36:40], 10)
		binary.LittleEndian.PutUint16(expected[40:42], 11)
		if !bytes.Equal(encoded, expected) {
			t.Errorf("GetWindowAttributesReply encoding failed. Got %v, want %v", encoded, expected)
		}
	})

	t.Run("GetGeometry", func(t *testing.T) {
		reply := &GetGeometryReply{
			Sequence:    11,
			Depth:       1,
			Root:        2,
			X:           3,
			Y:           4,
			Width:       5,
			Height:      6,
			BorderWidth: 7,
		}
		encoded := reply.EncodeMessage(binary.LittleEndian)
		expected := make([]byte, 32)
		expected[0] = 1
		expected[1] = 1
		binary.LittleEndian.PutUint16(expected[2:4], 11)
		binary.LittleEndian.PutUint32(expected[8:12], 2)
		binary.LittleEndian.PutUint16(expected[12:14], 3)
		binary.LittleEndian.PutUint16(expected[14:16], 4)
		binary.LittleEndian.PutUint16(expected[16:18], 5)
		binary.LittleEndian.PutUint16(expected[18:20], 6)
		binary.LittleEndian.PutUint16(expected[20:22], 7)
		if !bytes.Equal(encoded, expected) {
			t.Errorf("GetGeometryReply encoding failed. Got %v, want %v", encoded, expected)
		}
	})

	t.Run("InternAtom", func(t *testing.T) {
		reply := &InternAtomReply{
			Sequence: 12,
			Atom:     1,
		}
		encoded := reply.EncodeMessage(binary.LittleEndian)
		expected := make([]byte, 32)
		expected[0] = 1
		binary.LittleEndian.PutUint16(expected[2:4], 12)
		binary.LittleEndian.PutUint32(expected[8:12], 1)
		if !bytes.Equal(encoded, expected) {
			t.Errorf("InternAtomReply encoding failed. Got %v, want %v", encoded, expected)
		}
	})

	t.Run("GetAtomName", func(t *testing.T) {
		reply := &GetAtomNameReply{
			Sequence:   13,
			NameLength: 4,
			Name:       "test",
		}
		encoded := reply.EncodeMessage(binary.LittleEndian)
		expected := make([]byte, 36)
		expected[0] = 1
		binary.LittleEndian.PutUint16(expected[2:4], 13)
		binary.LittleEndian.PutUint32(expected[4:8], 1)
		binary.LittleEndian.PutUint16(expected[8:10], 4)
		copy(expected[32:], "test")
		if !bytes.Equal(encoded, expected) {
			t.Errorf("GetAtomNameReply encoding failed. Got %v, want %v", encoded, expected)
		}
	})

	t.Run("GetProperty", func(t *testing.T) {
		reply := &GetPropertyReply{
			Sequence:              14,
			Format:                8,
			PropertyType:          1,
			BytesAfter:            2,
			ValueLenInFormatUnits: 4,
			Value:                 []byte{1, 2, 3, 4},
		}
		encoded := reply.EncodeMessage(binary.LittleEndian)
		expected := make([]byte, 36)
		expected[0] = 1
		expected[1] = 8
		binary.LittleEndian.PutUint16(expected[2:4], 14)
		binary.LittleEndian.PutUint32(expected[4:8], 1)
		binary.LittleEndian.PutUint32(expected[8:12], 1)
		binary.LittleEndian.PutUint32(expected[12:16], 2)
		binary.LittleEndian.PutUint32(expected[16:20], 4)
		copy(expected[32:], []byte{1, 2, 3, 4})
		if !bytes.Equal(encoded, expected) {
			t.Errorf("GetPropertyReply encoding failed. Got %v, want %v", encoded, expected)
		}
	})

	t.Run("ListProperties", func(t *testing.T) {
		reply := &ListPropertiesReply{
			Sequence:      15,
			NumProperties: 3,
			Atoms:         []uint32{1, 2, 3},
		}
		encoded := reply.EncodeMessage(binary.LittleEndian)
		expected := make([]byte, 44)
		expected[0] = 1
		binary.LittleEndian.PutUint16(expected[2:4], 15)
		binary.LittleEndian.PutUint32(expected[4:8], 3)
		binary.LittleEndian.PutUint16(expected[8:10], 3)
		binary.LittleEndian.PutUint32(expected[32:36], 1)
		binary.LittleEndian.PutUint32(expected[36:40], 2)
		binary.LittleEndian.PutUint32(expected[40:44], 3)
		if !bytes.Equal(encoded, expected) {
			t.Errorf("ListPropertiesReply encoding failed. Got %v, want %v", encoded, expected)
		}
	})

	t.Run("GetSelectionOwner", func(t *testing.T) {
		reply := &GetSelectionOwnerReply{
			Sequence: 16,
			Owner:    1,
		}
		encoded := reply.EncodeMessage(binary.LittleEndian)
		expected := make([]byte, 32)
		expected[0] = 1
		binary.LittleEndian.PutUint16(expected[2:4], 16)
		binary.LittleEndian.PutUint32(expected[8:12], 1)
		if !bytes.Equal(encoded, expected) {
			t.Errorf("GetSelectionOwnerReply encoding failed. Got %v, want %v", encoded, expected)
		}
	})

	t.Run("GrabPointer", func(t *testing.T) {
		reply := &GrabPointerReply{
			Sequence: 17,
			Status:   1,
		}
		encoded := reply.EncodeMessage(binary.LittleEndian)
		expected := make([]byte, 32)
		expected[0] = 1
		expected[1] = 1
		binary.LittleEndian.PutUint16(expected[2:4], 17)
		if !bytes.Equal(encoded, expected) {
			t.Errorf("GrabPointerReply encoding failed. Got %v, want %v", encoded, expected)
		}
	})

	t.Run("GrabKeyboard", func(t *testing.T) {
		reply := &GrabKeyboardReply{
			Sequence: 18,
			Status:   1,
		}
		encoded := reply.EncodeMessage(binary.LittleEndian)
		expected := make([]byte, 32)
		expected[0] = 1
		expected[1] = 1
		binary.LittleEndian.PutUint16(expected[2:4], 18)
		if !bytes.Equal(encoded, expected) {
			t.Errorf("GrabKeyboardReply encoding failed. Got %v, want %v", encoded, expected)
		}
	})

	t.Run("QueryPointer", func(t *testing.T) {
		reply := &QueryPointerReply{
			Sequence:   19,
			SameScreen: true,
			Root:       1,
			Child:      2,
			RootX:      3,
			RootY:      4,
			WinX:       5,
			WinY:       6,
			Mask:       7,
		}
		encoded := reply.EncodeMessage(binary.LittleEndian)
		expected := make([]byte, 32)
		expected[0] = 1
		expected[1] = 1
		binary.LittleEndian.PutUint16(expected[2:4], 19)
		binary.LittleEndian.PutUint32(expected[8:12], 1)
		binary.LittleEndian.PutUint32(expected[12:16], 2)
		binary.LittleEndian.PutUint16(expected[16:18], 3)
		binary.LittleEndian.PutUint16(expected[18:20], 4)
		binary.LittleEndian.PutUint16(expected[20:22], 5)
		binary.LittleEndian.PutUint16(expected[22:24], 6)
		binary.LittleEndian.PutUint16(expected[24:26], 7)
		if !bytes.Equal(encoded, expected) {
			t.Errorf("QueryPointerReply encoding failed. Got %v, want %v", encoded, expected)
		}
	})

	t.Run("TranslateCoords", func(t *testing.T) {
		reply := &TranslateCoordsReply{
			Sequence:   20,
			SameScreen: true,
			Child:      1,
			DstX:       2,
			DstY:       3,
		}
		encoded := reply.EncodeMessage(binary.LittleEndian)
		expected := make([]byte, 32)
		expected[0] = 1
		expected[1] = 1
		binary.LittleEndian.PutUint16(expected[2:4], 20)
		binary.LittleEndian.PutUint32(expected[8:12], 1)
		binary.LittleEndian.PutUint16(expected[12:14], 2)
		binary.LittleEndian.PutUint16(expected[14:16], 3)
		if !bytes.Equal(encoded, expected) {
			t.Errorf("TranslateCoordsReply encoding failed. Got %v, want %v", encoded, expected)
		}
	})

	t.Run("GetInputFocus", func(t *testing.T) {
		reply := &GetInputFocusReply{
			Sequence: 21,
			RevertTo: 1,
			Focus:    2,
		}
		encoded := reply.EncodeMessage(binary.LittleEndian)
		expected := make([]byte, 32)
		expected[0] = 1
		expected[1] = 1
		binary.LittleEndian.PutUint16(expected[2:4], 21)
		binary.LittleEndian.PutUint32(expected[8:12], 2)
		if !bytes.Equal(encoded, expected) {
			t.Errorf("GetInputFocusReply encoding failed. Got %v, want %v", encoded, expected)
		}
	})

	t.Run("QueryFont", func(t *testing.T) {
		reply := &QueryFontReply{
			Sequence:       22,
			MinCharOrByte2: 1,
			MaxCharOrByte2: 2,
			DefaultChar:    3,
			DrawDirection:  1,
			MinByte1:       1,
			MaxByte1:       2,
			AllCharsExist:  true,
			FontAscent:     10,
			FontDescent:    2,
		NumCharInfos:   1,
			CharInfos: []XCharInfo{
				{1, 2, 3, 4, 5, 6},
			},
		}
		encoded := reply.EncodeMessage(binary.LittleEndian)
		expected := make([]byte, 72)
		expected[0] = 1
		expected[1] = 1
		binary.LittleEndian.PutUint16(expected[2:4], 22)
		binary.LittleEndian.PutUint32(expected[4:8], 10)
		binary.LittleEndian.PutUint16(expected[40:42], 1)
		binary.LittleEndian.PutUint16(expected[42:44], 2)
		binary.LittleEndian.PutUint16(expected[44:46], 3)
		expected[48] = 1
		expected[49] = 1
		expected[50] = 2
		expected[51] = 1
		binary.LittleEndian.PutUint16(expected[52:54], uint16(10))
		binary.LittleEndian.PutUint16(expected[54:56], uint16(2))
		binary.LittleEndian.PutUint32(expected[56:60], 1)
		binary.LittleEndian.PutUint16(expected[60:62], 1)
		binary.LittleEndian.PutUint16(expected[62:64], 2)
		binary.LittleEndian.PutUint16(expected[64:66], 3)
		binary.LittleEndian.PutUint16(expected[66:68], 4)
		binary.LittleEndian.PutUint16(expected[68:70], 5)
		binary.LittleEndian.PutUint16(expected[70:72], 6)
		if !bytes.Equal(encoded, expected) {
			t.Errorf("QueryFontReply encoding failed. Got %v, want %v", encoded, expected)
		}
	})

	t.Run("ListFonts", func(t *testing.T) {
		reply := &ListFontsReply{
			Sequence:  23,
			FontNames: []string{"test", "test2"},
		}
		encoded := reply.EncodeMessage(binary.LittleEndian)
		expected := make([]byte, 44)
		expected[0] = 1
		binary.LittleEndian.PutUint16(expected[2:4], 23)
		binary.LittleEndian.PutUint32(expected[4:8], 3)
		binary.LittleEndian.PutUint16(expected[8:10], 2)
		expected[32] = 4
		copy(expected[33:37], "test")
		expected[37] = 5
		copy(expected[38:43], "test2")
		if !bytes.Equal(encoded, expected) {
			t.Errorf("ListFontsReply encoding failed. Got %v, want %v", encoded, expected)
		}
	})

	t.Run("GetImage", func(t *testing.T) {
		reply := &GetImageReply{
			Sequence:  24,
			Depth:     24,
			VisualID:  1,
			ImageData: []byte{1, 2, 3, 4},
		}
		encoded := reply.EncodeMessage(binary.LittleEndian)
		expected := make([]byte, 36)
		expected[0] = 1
		expected[1] = 24
		binary.LittleEndian.PutUint16(expected[2:4], 24)
		binary.LittleEndian.PutUint32(expected[4:8], 1)
		binary.LittleEndian.PutUint32(expected[8:12], 1)
		copy(expected[32:], []byte{1, 2, 3, 4})
		if !bytes.Equal(encoded, expected) {
			t.Errorf("GetImageReply encoding failed. Got %v, want %v", encoded, expected)
		}
	})

	t.Run("AllocColor", func(t *testing.T) {
		reply := &AllocColorReply{
			Sequence: 25,
			Red:      1,
			Green:    2,
			Blue:     3,
			Pixel:    4,
		}
		encoded := reply.EncodeMessage(binary.LittleEndian)
		expected := make([]byte, 32)
		expected[0] = 1
		binary.LittleEndian.PutUint16(expected[2:4], 25)
		binary.LittleEndian.PutUint16(expected[8:10], 1)
		binary.LittleEndian.PutUint16(expected[10:12], 2)
		binary.LittleEndian.PutUint16(expected[12:14], 3)
		binary.LittleEndian.PutUint32(expected[16:20], 4)
		if !bytes.Equal(encoded, expected) {
			t.Errorf("AllocColorReply encoding failed. Got %v, want %v", encoded, expected)
		}
	})

	t.Run("ListInstalledColormaps", func(t *testing.T) {
		reply := &ListInstalledColormapsReply{
			Sequence:     26,
			NumColormaps: 3,
			Colormaps:    []uint32{1, 2, 3},
		}
		encoded := reply.EncodeMessage(binary.LittleEndian)
		expected := make([]byte, 44)
		expected[0] = 1
		binary.LittleEndian.PutUint16(expected[2:4], 26)
		binary.LittleEndian.PutUint32(expected[4:8], 3)
		binary.LittleEndian.PutUint16(expected[8:10], 3)
		binary.LittleEndian.PutUint32(expected[32:36], 1)
		binary.LittleEndian.PutUint32(expected[36:40], 2)
		binary.LittleEndian.PutUint32(expected[40:44], 3)
		if !bytes.Equal(encoded, expected) {
			t.Errorf("ListInstalledColormapsReply encoding failed. Got %v, want %v", encoded, expected)
		}
	})

	t.Run("QueryColors", func(t *testing.T) {
		reply := &QueryColorsReply{
			Sequence: 27,
			Colors: []XColorItem{
				{Pixel: 0, Red: 1, Green: 2, Blue: 3, Flags: 0},
				{Pixel: 0, Red: 4, Green: 5, Blue: 6, Flags: 0},
			},
		}
		encoded := reply.EncodeMessage(binary.LittleEndian)
		expected := make([]byte, 48)
		expected[0] = 1
		binary.LittleEndian.PutUint16(expected[2:4], 27)
		binary.LittleEndian.PutUint32(expected[4:8], 4)
		binary.LittleEndian.PutUint16(expected[8:10], 2)
		binary.LittleEndian.PutUint16(expected[32:34], 1)
		binary.LittleEndian.PutUint16(expected[34:36], 2)
		binary.LittleEndian.PutUint16(expected[36:38], 3)
		binary.LittleEndian.PutUint16(expected[40:42], 4)
		binary.LittleEndian.PutUint16(expected[42:44], 5)
		binary.LittleEndian.PutUint16(expected[44:46], 6)
		if !bytes.Equal(encoded, expected) {
			t.Errorf("QueryColorsReply encoding failed. Got %v, want %v", encoded, expected)
		}
	})

	t.Run("LookupColor", func(t *testing.T) {
		reply := &LookupColorReply{
			Sequence:   28,
			Red:        1,
			Green:      2,
			Blue:       3,
			ExactRed:   4,
			ExactGreen: 5,
			ExactBlue:  6,
		}
		encoded := reply.EncodeMessage(binary.LittleEndian)
		expected := make([]byte, 32)
		expected[0] = 1
		binary.LittleEndian.PutUint16(expected[2:4], 28)
		binary.LittleEndian.PutUint16(expected[8:10], 1)
		binary.LittleEndian.PutUint16(expected[10:12], 2)
		binary.LittleEndian.PutUint16(expected[12:14], 3)
		binary.LittleEndian.PutUint16(expected[14:16], 4)
		binary.LittleEndian.PutUint16(expected[16:18], 5)
		binary.LittleEndian.PutUint16(expected[18:20], 6)
		if !bytes.Equal(encoded, expected) {
			t.Errorf("LookupColorReply encoding failed. Got %v, want %v", encoded, expected)
		}
	})

	t.Run("QueryBestSize", func(t *testing.T) {
		reply := &QueryBestSizeReply{
			Sequence: 29,
			Width:    1,
			Height:   2,
		}
		encoded := reply.EncodeMessage(binary.LittleEndian)
		expected := make([]byte, 32)
		expected[0] = 1
		binary.LittleEndian.PutUint16(expected[2:4], 29)
		binary.LittleEndian.PutUint16(expected[8:10], 1)
		binary.LittleEndian.PutUint16(expected[10:12], 2)
		if !bytes.Equal(encoded, expected) {
			t.Errorf("QueryBestSizeReply encoding failed. Got %v, want %v", encoded, expected)
		}
	})

	t.Run("QueryExtension", func(t *testing.T) {
		reply := &QueryExtensionReply{
			Sequence:    30,
			Present:     true,
			MajorOpcode: 1,
			FirstEvent:  2,
			FirstError:  3,
		}
		encoded := reply.EncodeMessage(binary.LittleEndian)
		expected := make([]byte, 32)
		expected[0] = 1
		binary.LittleEndian.PutUint16(expected[2:4], 30)
		expected[8] = 1
		expected[9] = 1
		expected[10] = 2
		expected[11] = 3
		if !bytes.Equal(encoded, expected) {
			t.Errorf("QueryExtensionReply encoding failed. Got %v, want %v", encoded, expected)
		}
	})

	t.Run("SetPointerMapping", func(t *testing.T) {
		reply := &SetPointerMappingReply{
			Sequence: 31,
		}
		encoded := reply.EncodeMessage(binary.LittleEndian)
		expected := make([]byte, 32)
		expected[0] = 1
		binary.LittleEndian.PutUint16(expected[2:4], 31)
		if !bytes.Equal(encoded, expected) {
			t.Errorf("SetPointerMappingReply encoding failed. Got %v, want %v", encoded, expected)
		}
	})

	t.Run("GetPointerMapping", func(t *testing.T) {
		reply := &GetPointerMappingReply{
			Sequence: 32,
			Length:   4,
			PMap:     []byte{1, 2, 3, 4},
		}
		encoded := reply.EncodeMessage(binary.LittleEndian)
		expected := make([]byte, 36)
		expected[0] = 1
		expected[1] = 4
		binary.LittleEndian.PutUint16(expected[2:4], 32)
		binary.LittleEndian.PutUint32(expected[4:8], 1)
		copy(expected[32:], []byte{1, 2, 3, 4})
		if !bytes.Equal(encoded, expected) {
			t.Errorf("GetPointerMappingReply encoding failed. Got %v, want %v", encoded, expected)
		}
	})

	t.Run("GetKeyboardMapping", func(t *testing.T) {
		reply := &GetKeyboardMappingReply{
			Sequence:          33,
			KeySymsPerKeycode: 1,
			KeySyms:           []uint32{1, 2, 3},
		}
		encoded := reply.EncodeMessage(binary.LittleEndian)
		expected := make([]byte, 44)
		expected[0] = 1
		expected[1] = 1
		binary.LittleEndian.PutUint16(expected[2:4], 33)
		binary.LittleEndian.PutUint32(expected[4:8], 3)
		binary.LittleEndian.PutUint32(expected[32:36], 1)
		binary.LittleEndian.PutUint32(expected[36:40], 2)
		binary.LittleEndian.PutUint32(expected[40:44], 3)
		if !bytes.Equal(encoded, expected) {
			t.Errorf("GetKeyboardMappingReply encoding failed. Got %v, want %v", encoded, expected)
		}
	})

	t.Run("GetScreenSaver", func(t *testing.T) {
		reply := &GetScreenSaverReply{
			Sequence:    34,
			Timeout:     1,
			Interval:    2,
			PreferBlank: 1,
			AllowExpose: 1,
		}
		encoded := reply.EncodeMessage(binary.LittleEndian)
		expected := make([]byte, 32)
		expected[0] = 1
		binary.LittleEndian.PutUint16(expected[2:4], 34)
		binary.LittleEndian.PutUint16(expected[8:10], 1)
		binary.LittleEndian.PutUint16(expected[10:12], 2)
		expected[12] = 1
		expected[13] = 1
		if !bytes.Equal(encoded, expected) {
			t.Errorf("GetScreenSaverReply encoding failed. Got %v, want %v", encoded, expected)
		}
	})

	t.Run("ListHosts", func(t *testing.T) {
		reply := &ListHostsReply{
			Sequence: 35,
			NumHosts: 1,
			Hosts: []Host{
				{
					Family: 1,
					Data:   []byte{1, 2, 3, 4},
				},
			},
		}
		encoded := reply.EncodeMessage(binary.LittleEndian)
		expected := make([]byte, 40)
		expected[0] = 1
		binary.LittleEndian.PutUint16(expected[2:4], 35)
		binary.LittleEndian.PutUint32(expected[4:8], 2)
		binary.LittleEndian.PutUint16(expected[8:10], 1)
		expected[32] = 1
		binary.LittleEndian.PutUint16(expected[34:36], 4)
		copy(expected[36:], []byte{1, 2, 3, 4})
		if !bytes.Equal(encoded, expected) {
			t.Errorf("ListHostsReply encoding failed. Got %v, want %v", encoded, expected)
		}
	})

	t.Run("SetModifierMapping", func(t *testing.T) {
		reply := &SetModifierMappingReply{
			Sequence: 36,
		}
		encoded := reply.EncodeMessage(binary.LittleEndian)
		expected := make([]byte, 32)
		expected[0] = 1
		binary.LittleEndian.PutUint16(expected[2:4], 36)
		if !bytes.Equal(encoded, expected) {
			t.Errorf("SetModifierMappingReply encoding failed. Got %v, want %v", encoded, expected)
		}
	})

	t.Run("GetModifierMapping", func(t *testing.T) {
		reply := &GetModifierMappingReply{
			Sequence: 37,
			KeyCodes: []KeyCode{1, 2, 3, 4},
		}
		encoded := reply.EncodeMessage(binary.LittleEndian)
		expected := make([]byte, 36)
		expected[0] = 1
		binary.LittleEndian.PutUint16(expected[2:4], 37)
		binary.LittleEndian.PutUint32(expected[4:8], 1)
		copy(expected[32:], []byte{1, 2, 3, 4})
		if !bytes.Equal(encoded, expected) {
			t.Errorf("GetModifierMappingReply encoding failed. Got %v, want %v", encoded, expected)
		}
	})

	t.Run("SetPointerMapping", func(t *testing.T) {
		reply := &SetPointerMappingReply{
			Sequence: 31,
			Status:   1,
		}
		encoded := reply.EncodeMessage(binary.LittleEndian)
		expected := make([]byte, 32)
		expected[0] = 1
		expected[1] = 1
		binary.LittleEndian.PutUint16(expected[2:4], 31)
		if !bytes.Equal(encoded, expected) {
			t.Errorf("SetPointerMappingReply encoding failed. Got %v, want %v", encoded, expected)
		}
	})

	t.Run("SetModifierMapping", func(t *testing.T) {
		reply := &SetModifierMappingReply{
			Sequence: 36,
			Status:   1,
		}
		encoded := reply.EncodeMessage(binary.LittleEndian)
		expected := make([]byte, 32)
		expected[0] = 1
		expected[1] = 1
		binary.LittleEndian.PutUint16(expected[2:4], 36)
		if !bytes.Equal(encoded, expected) {
			t.Errorf("SetModifierMappingReply encoding failed. Got %v, want %v", encoded, expected)
		}
	})

	t.Run("GetPointerControl", func(t *testing.T) {
		reply := &GetPointerControlReply{
			Sequence:         1,
			AccelNumerator:   2,
			AccelDenominator: 3,
			Threshold:        4,
		}
		encoded := reply.EncodeMessage(binary.LittleEndian)
		expected := make([]byte, 32)
		expected[0] = 1
		binary.LittleEndian.PutUint16(expected[2:4], 1)
		binary.LittleEndian.PutUint32(expected[4:8], 0)
		binary.LittleEndian.PutUint16(expected[8:10], 2)
		binary.LittleEndian.PutUint16(expected[10:12], 3)
		binary.LittleEndian.PutUint16(expected[12:14], 4)
		if !bytes.Equal(encoded, expected) {
			t.Errorf("GetPointerControlReply encoding failed. Got %v, want %v", encoded, expected)
		}
	})
}

func int32ToUint32(i int32) uint32 {
	return uint32(i)
}

func TestGetWindowAttributesReply(t *testing.T) {
	order := binary.LittleEndian
	reply := &GetWindowAttributesReply{
		ReplyType:          1,
		BackingStore:       2,
		Sequence:           3,
		Length:             3,
		VisualID:           5,
		Class:              6,
		BitGravity:         7,
		WinGravity:         8,
		BackingPlanes:      9,
		BackingPixel:       10,
		SaveUnder:          1,
		MapIsInstalled:     1,
		MapState:           2,
		OverrideRedirect:   1,
		Colormap:           11,
		AllEventMasks:      12,
		YourEventMask:      13,
		DoNotPropagateMask: 14,
	}

	encoded := reply.EncodeMessage(order)
	decoded, err := ParseGetWindowAttributesReply(order, encoded)
	if err != nil {
		t.Fatalf("ParseGetWindowAttributesReply failed: %v", err)
	}

	if !reflect.DeepEqual(reply, decoded) {
		t.Errorf("expected %#v, got %#v", reply, decoded)
	}
}

func TestGetGeometryReply(t *testing.T) {
	order := binary.LittleEndian
	reply := &GetGeometryReply{
		Sequence:    1,
		Depth:       2,
		Root:        3,
		X:           4,
		Y:           5,
		Width:       6,
		Height:      7,
		BorderWidth: 8,
	}

	encoded := reply.EncodeMessage(order)
	decoded, err := ParseGetGeometryReply(order, encoded)
	if err != nil {
		t.Fatalf("ParseGetGeometryReply failed: %v", err)
	}

	if !reflect.DeepEqual(reply, decoded) {
		t.Errorf("expected %+v, got %+v", reply, decoded)
	}
}

func TestBigRequestsEnableReply(t *testing.T) {
	order := binary.LittleEndian
	reply := &BigRequestsEnableReply{
		Sequence:         1,
		MaxRequestLength: 1234,
	}

	encoded := reply.EncodeMessage(order)
	decoded, err := ParseReply(Opcodes{Major: BigRequestsOpcode}, encoded, order)
	if err != nil {
		t.Fatalf("ParseBigRequestsEnableReply failed: %v", err)
	}

	if !reflect.DeepEqual(reply, decoded) {
		t.Errorf("expected %+v, got %+v", reply, decoded)
	}
}

func TestParseGetDeviceMotionEventsReply(t *testing.T) {
	order := binary.LittleEndian
	reply := &GetDeviceMotionEventsReply{
		Sequence: 1,
		NEvents:  2,
		Events: []TimeCoord{
			{Time: 1, X: 2, Y: 3},
			{Time: 4, X: 5, Y: 6},
		},
	}

	encoded := reply.EncodeMessage(order)
	decoded, err := ParseGetDeviceMotionEventsReply(order, encoded)
	if err != nil {
		t.Fatalf("ParseGetDeviceMotionEventsReply failed: %v", err)
	}

	if !reflect.DeepEqual(reply, decoded) {
		t.Errorf("expected %+v, got %+v", reply, decoded)
	}
}

func TestParseChangeKeyboardDeviceReply(t *testing.T) {
	order := binary.LittleEndian
	reply := &ChangeKeyboardDeviceReply{
		Sequence: 1,
		Status:   2,
	}

	encoded := reply.EncodeMessage(order)
	decoded, err := ParseChangeKeyboardDeviceReply(order, encoded)
	if err != nil {
		t.Fatalf("ParseChangeKeyboardDeviceReply failed: %v", err)
	}

	if !reflect.DeepEqual(reply, decoded) {
		t.Errorf("expected %+v, got %+v", reply, decoded)
	}
}

func TestParseChangePointerDeviceReply(t *testing.T) {
	order := binary.LittleEndian
	reply := &ChangePointerDeviceReply{
		Sequence: 1,
		Status:   2,
	}

	encoded := reply.EncodeMessage(order)
	decoded, err := ParseChangePointerDeviceReply(order, encoded)
	if err != nil {
		t.Fatalf("ParseChangePointerDeviceReply failed: %v", err)
	}

	if !reflect.DeepEqual(reply, decoded) {
		t.Errorf("expected %+v, got %+v", reply, decoded)
	}
}

func TestInternAtomReply(t *testing.T) {
	order := binary.LittleEndian
	reply := &InternAtomReply{
		Sequence: 1,
		Atom:     2,
	}

	encoded := reply.EncodeMessage(order)
	decoded, err := ParseInternAtomReply(order, encoded)
	if err != nil {
		t.Fatalf("ParseInternAtomReply failed: %v", err)
	}

	if !reflect.DeepEqual(reply, decoded) {
		t.Errorf("expected %+v, got %+v", reply, decoded)
	}
}

func TestGetAtomNameReply(t *testing.T) {
	order := binary.LittleEndian
	reply := &GetAtomNameReply{
		Sequence:   1,
		NameLength: 4,
		Name:       "ATOM",
	}

	encoded := reply.EncodeMessage(order)
	decoded, err := ParseGetAtomNameReply(order, encoded)
	if err != nil {
		t.Fatalf("ParseGetAtomNameReply failed: %v", err)
	}

	if !reflect.DeepEqual(reply, decoded) {
		t.Errorf("expected %+v, got %+v", reply, decoded)
	}
}

func TestGetPropertyReply(t *testing.T) {
	order := binary.LittleEndian
	reply := &GetPropertyReply{
		Sequence:              1,
		Format:                8,
		PropertyType:          2,
		BytesAfter:            3,
		ValueLenInFormatUnits: 4,
		Value:                 []byte{1, 2, 3, 4},
	}

	encoded := reply.EncodeMessage(order)
	decoded, err := ParseGetPropertyReply(order, encoded)
	if err != nil {
		t.Fatalf("ParseGetPropertyReply failed: %v", err)
	}

	if !reflect.DeepEqual(reply, decoded) {
		t.Errorf("expected %+v, got %+v", reply, decoded)
	}
}

func TestListPropertiesReply(t *testing.T) {
	order := binary.LittleEndian
	reply := &ListPropertiesReply{
		Sequence:      1,
		NumProperties: 2,
		Atoms:         []uint32{1, 2},
	}

	encoded := reply.EncodeMessage(order)
	decoded, err := ParseListPropertiesReply(order, encoded)
	if err != nil {
		t.Fatalf("ParseListPropertiesReply failed: %v", err)
	}

	if !reflect.DeepEqual(reply, decoded) {
		t.Errorf("expected %+v, got %+v", reply, decoded)
	}
}

func TestQueryTextExtentsReply(t *testing.T) {
	order := binary.LittleEndian
	reply := &QueryTextExtentsReply{
		Sequence:       1,
		DrawDirection:  2,
		FontAscent:     3,
		FontDescent:    4,
		OverallAscent:  5,
		OverallDescent: 6,
		OverallWidth:   7,
		OverallLeft:    8,
		OverallRight:   9,
	}

	encoded := reply.EncodeMessage(order)
	decoded, err := ParseQueryTextExtentsReply(order, encoded)
	if err != nil {
		t.Fatalf("ParseQueryTextExtentsReply failed: %v", err)
	}

	if !reflect.DeepEqual(reply, decoded) {
		t.Errorf("expected %+v, got %+v", reply, decoded)
	}
}

func TestGetMotionEventsReply(t *testing.T) {
	order := binary.LittleEndian
	reply := &GetMotionEventsReply{
		Sequence: 1,
		NEvents:  2,
		Events: []TimeCoord{
			{Time: 1, X: 2, Y: 3},
			{Time: 4, X: 5, Y: 6},
		},
	}

	encoded := reply.EncodeMessage(order)
	decoded, err := ParseGetMotionEventsReply(order, encoded)
	if err != nil {
		t.Fatalf("ParseGetMotionEventsReply failed: %v", err)
	}

	if !reflect.DeepEqual(reply, decoded) {
		t.Errorf("expected %+v, got %+v", reply, decoded)
	}
}

func TestGetSelectionOwnerReply(t *testing.T) {
	order := binary.LittleEndian
	reply := &GetSelectionOwnerReply{
		Sequence: 1,
		Owner:    2,
	}

	encoded := reply.EncodeMessage(order)
	decoded, err := ParseGetSelectionOwnerReply(order, encoded)
	if err != nil {
		t.Fatalf("ParseGetSelectionOwnerReply failed: %v", err)
	}

	if !reflect.DeepEqual(reply, decoded) {
		t.Errorf("expected %+v, got %+v", reply, decoded)
	}
}

func TestGrabPointerReply(t *testing.T) {
	order := binary.LittleEndian
	reply := &GrabPointerReply{
		Sequence: 1,
		Status:   2,
	}

	encoded := reply.EncodeMessage(order)
	decoded, err := ParseGrabPointerReply(order, encoded)
	if err != nil {
		t.Fatalf("ParseGrabPointerReply failed: %v", err)
	}

	if !reflect.DeepEqual(reply, decoded) {
		t.Errorf("expected %+v, got %+v", reply, decoded)
	}
}

func TestGrabKeyboardReply(t *testing.T) {
	order := binary.LittleEndian
	reply := &GrabKeyboardReply{
		Sequence: 1,
		Status:   2,
	}

	encoded := reply.EncodeMessage(order)
	decoded, err := ParseGrabKeyboardReply(order, encoded)
	if err != nil {
		t.Fatalf("ParseGrabKeyboardReply failed: %v", err)
	}

	if !reflect.DeepEqual(reply, decoded) {
		t.Errorf("expected %+v, got %+v", reply, decoded)
	}
}

func TestQueryPointerReply(t *testing.T) {
	order := binary.LittleEndian
	reply := &QueryPointerReply{
		Sequence:   1,
		SameScreen: true,
		Root:       2,
		Child:      3,
		RootX:      4,
		RootY:      5,
		WinX:       6,
		WinY:       7,
		Mask:       8,
	}

	encoded := reply.EncodeMessage(order)
	decoded, err := ParseQueryPointerReply(order, encoded)
	if err != nil {
		t.Fatalf("ParseQueryPointerReply failed: %v", err)
	}

	if !reflect.DeepEqual(reply, decoded) {
		t.Errorf("expected %+v, got %+v", reply, decoded)
	}
}

func TestTranslateCoordsReply(t *testing.T) {
	order := binary.LittleEndian
	reply := &TranslateCoordsReply{
		Sequence:   1,
		SameScreen: true,
		Child:      2,
		DstX:       3,
		DstY:       4,
	}

	encoded := reply.EncodeMessage(order)
	decoded, err := ParseTranslateCoordsReply(order, encoded)
	if err != nil {
		t.Fatalf("ParseTranslateCoordsReply failed: %v", err)
	}

	if !reflect.DeepEqual(reply, decoded) {
		t.Errorf("expected %+v, got %+v", reply, decoded)
	}
}

func TestGetInputFocusReply(t *testing.T) {
	order := binary.LittleEndian
	reply := &GetInputFocusReply{
		Sequence: 1,
		RevertTo: 2,
		Focus:    3,
	}

	encoded := reply.EncodeMessage(order)
	decoded, err := ParseGetInputFocusReply(order, encoded)
	if err != nil {
		t.Fatalf("ParseGetInputFocusReply failed: %v", err)
	}

	if !reflect.DeepEqual(reply, decoded) {
		t.Errorf("expected %+v, got %+v", reply, decoded)
	}
}

func TestListFontsReply(t *testing.T) {
	order := binary.LittleEndian
	reply := &ListFontsReply{
		Sequence:  1,
		FontNames: []string{"font1", "font2"},
	}

	encoded := reply.EncodeMessage(order)
	decoded, err := ParseListFontsReply(order, encoded)
	if err != nil {
		t.Fatalf("ParseListFontsReply failed: %v", err)
	}

	if !reflect.DeepEqual(reply, decoded) {
		t.Errorf("expected %+v, got %+v", reply, decoded)
	}
}

func TestGetImageReply(t *testing.T) {
	order := binary.LittleEndian
	reply := &GetImageReply{
		Sequence:  1,
		Depth:     2,
		VisualID:  3,
		ImageData: []byte{1, 2, 3, 4},
	}

	encoded := reply.EncodeMessage(order)
	decoded, err := ParseGetImageReply(order, encoded)
	if err != nil {
		t.Fatalf("ParseGetImageReply failed: %v", err)
	}

	if !reflect.DeepEqual(reply, decoded) {
		t.Errorf("expected %+v, got %+v", reply, decoded)
	}
}

func TestAllocColorReply(t *testing.T) {
	order := binary.LittleEndian
	reply := &AllocColorReply{
		Sequence: 1,
		Red:      2,
		Green:    3,
		Blue:     4,
		Pixel:    5,
	}

	encoded := reply.EncodeMessage(order)
	decoded, err := ParseAllocColorReply(order, encoded)
	if err != nil {
		t.Fatalf("ParseAllocColorReply failed: %v", err)
	}

	if !reflect.DeepEqual(reply, decoded) {
		t.Errorf("expected %+v, got %+v", reply, decoded)
	}
}

func TestAllocNamedColorReply(t *testing.T) {
	order := binary.LittleEndian
	reply := &AllocNamedColorReply{
		Sequence: 1,
		Red:      2,
		Green:    3,
		Blue:     4,
		Pixel:    5,
	}

	encoded := reply.EncodeMessage(order)
	decoded, err := ParseAllocNamedColorReply(order, encoded)
	if err != nil {
		t.Fatalf("ParseAllocNamedColorReply failed: %v", err)
	}

	if !reflect.DeepEqual(reply, decoded) {
		t.Errorf("expected %+v, got %+v", reply, decoded)
	}
}

func TestListInstalledColormapsReply(t *testing.T) {
	order := binary.LittleEndian
	reply := &ListInstalledColormapsReply{
		Sequence:     1,
		NumColormaps: 2,
		Colormaps:    []uint32{1, 2},
	}

	encoded := reply.EncodeMessage(order)
	decoded, err := ParseListInstalledColormapsReply(order, encoded)
	if err != nil {
		t.Fatalf("ParseListInstalledColormapsReply failed: %v", err)
	}

	if !reflect.DeepEqual(reply, decoded) {
		t.Errorf("expected %+v, got %+v", reply, decoded)
	}
}

func TestQueryColorsReply(t *testing.T) {
	order := binary.LittleEndian
	reply := &QueryColorsReply{
		Sequence: 1,
		Colors: []XColorItem{
			{Red: 2, Green: 3, Blue: 4},
			{Red: 7, Green: 8, Blue: 9},
		},
	}

	encoded := reply.EncodeMessage(order)
	decoded, err := ParseQueryColorsReply(order, encoded)
	if err != nil {
		t.Fatalf("ParseQueryColorsReply failed: %v", err)
	}

	if !reflect.DeepEqual(reply, decoded) {
		t.Errorf("expected %+v, got %+v", reply, decoded)
	}
}

func TestLookupColorReply(t *testing.T) {
	order := binary.LittleEndian
	reply := &LookupColorReply{
		Sequence:   1,
		Red:        2,
		Green:      3,
		Blue:       4,
		ExactRed:   5,
		ExactGreen: 6,
		ExactBlue:  7,
	}

	encoded := reply.EncodeMessage(order)
	decoded, err := ParseLookupColorReply(order, encoded)
	if err != nil {
		t.Fatalf("ParseLookupColorReply failed: %v", err)
	}

	if !reflect.DeepEqual(reply, decoded) {
		t.Errorf("expected %+v, got %+v", reply, decoded)
	}
}

func TestQueryBestSizeReply(t *testing.T) {
	order := binary.LittleEndian
	reply := &QueryBestSizeReply{
		Sequence: 1,
		Width:    2,
		Height:   3,
	}

	encoded := reply.EncodeMessage(order)
	decoded, err := ParseQueryBestSizeReply(order, encoded)
	if err != nil {
		t.Fatalf("ParseQueryBestSizeReply failed: %v", err)
	}

	if !reflect.DeepEqual(reply, decoded) {
		t.Errorf("expected %+v, got %+v", reply, decoded)
	}
}

func TestQueryExtensionReply(t *testing.T) {
	order := binary.LittleEndian
	reply := &QueryExtensionReply{
		Sequence:    1,
		Present:     true,
		MajorOpcode: 2,
		FirstEvent:  3,
		FirstError:  4,
	}

	encoded := reply.EncodeMessage(order)
	decoded, err := ParseQueryExtensionReply(order, encoded)
	if err != nil {
		t.Fatalf("ParseQueryExtensionReply failed: %v", err)
	}

	if !reflect.DeepEqual(reply, decoded) {
		t.Errorf("expected %+v, got %+v", reply, decoded)
	}
}

func TestSetPointerMappingReply(t *testing.T) {
	order := binary.LittleEndian
	reply := &SetPointerMappingReply{
		Sequence: 1,
		Status:   2,
	}

	encoded := reply.EncodeMessage(order)
	decoded, err := ParseSetPointerMappingReply(order, encoded)
	if err != nil {
		t.Fatalf("ParseSetPointerMappingReply failed: %v", err)
	}

	if !reflect.DeepEqual(reply, decoded) {
		t.Errorf("expected %+v, got %+v", reply, decoded)
	}
}

func TestGetPointerMappingReply(t *testing.T) {
	order := binary.LittleEndian
	reply := &GetPointerMappingReply{
		Sequence: 1,
		Length:   4,
		PMap:     []byte{1, 2, 3, 4},
	}

	encoded := reply.EncodeMessage(order)
	decoded, err := ParseGetPointerMappingReply(order, encoded)
	if err != nil {
		t.Fatalf("ParseGetPointerMappingReply failed: %v", err)
	}

	if !reflect.DeepEqual(reply, decoded) {
		t.Errorf("expected %+v, got %+v", reply, decoded)
	}
}

func TestGetKeyboardMappingReply(t *testing.T) {
	order := binary.LittleEndian
	reply := &GetKeyboardMappingReply{
		Sequence:          1,
		KeySymsPerKeycode: 1,
		KeySyms:           []uint32{1, 2},
	}

	encoded := reply.EncodeMessage(order)
	decoded, err := ParseGetKeyboardMappingReply(order, encoded)
	if err != nil {
		t.Fatalf("ParseGetKeyboardMappingReply failed: %v", err)
	}

	if !reflect.DeepEqual(reply, decoded) {
		t.Errorf("expected %+v, got %+v", reply, decoded)
	}
}

func TestGetKeyboardControlReply(t *testing.T) {
	order := binary.LittleEndian
	reply := &GetKeyboardControlReply{
		Sequence:         1,
		KeyClickPercent:  2,
		BellPercent:      3,
		BellPitch:        4,
		BellDuration:     5,
		LedMask:          6,
		GlobalAutoRepeat: 1,
		AutoRepeats:      [32]byte{1, 2, 3},
	}

	encoded := reply.EncodeMessage(order)
	decoded, err := ParseGetKeyboardControlReply(order, encoded)
	if err != nil {
		t.Fatalf("ParseGetKeyboardControlReply failed: %v", err)
	}

	if !reflect.DeepEqual(reply, decoded) {
		t.Errorf("expected %+v, got %+v", reply, decoded)
	}
}

func TestGetScreenSaverReply(t *testing.T) {
	order := binary.LittleEndian
	reply := &GetScreenSaverReply{
		Sequence:    1,
		Timeout:     2,
		Interval:    3,
		PreferBlank: 4,
		AllowExpose: 5,
	}

	encoded := reply.EncodeMessage(order)
	decoded, err := ParseGetScreenSaverReply(order, encoded)
	if err != nil {
		t.Fatalf("ParseGetScreenSaverReply failed: %v", err)
	}

	if !reflect.DeepEqual(reply, decoded) {
		t.Errorf("expected %+v, got %+v", reply, decoded)
	}
}

func TestListHostsReply(t *testing.T) {
	order := binary.LittleEndian
	reply := &ListHostsReply{
		Sequence: 1,
		NumHosts: 1,
		Hosts: []Host{
			{Family: 1, Data: []byte{1, 2, 3, 4}},
		},
	}

	encoded := reply.EncodeMessage(order)
	decoded, err := ParseListHostsReply(order, encoded)
	if err != nil {
		t.Fatalf("ParseListHostsReply failed: %v", err)
	}

	if !reflect.DeepEqual(reply, decoded) {
		t.Errorf("expected %+v, got %+v", reply, decoded)
	}
}

func TestSetModifierMappingReply(t *testing.T) {
	order := binary.LittleEndian
	reply := &SetModifierMappingReply{
		Sequence: 1,
		Status:   2,
	}

	encoded := reply.EncodeMessage(order)
	decoded, err := ParseSetModifierMappingReply(order, encoded)
	if err != nil {
		t.Fatalf("ParseSetModifierMappingReply failed: %v", err)
	}

	if !reflect.DeepEqual(reply, decoded) {
		t.Errorf("expected %+v, got %+v", reply, decoded)
	}
}

func TestGetModifierMappingReply(t *testing.T) {
	order := binary.LittleEndian
	reply := &GetModifierMappingReply{
		Sequence:            1,
		KeyCodesPerModifier: 2,
		KeyCodes:            []KeyCode{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
	}

	encoded := reply.EncodeMessage(order)
	decoded, err := ParseGetModifierMappingReply(order, encoded)
	if err != nil {
		t.Fatalf("ParseGetModifierMappingReply failed: %v", err)
	}

	if !reflect.DeepEqual(reply, decoded) {
		t.Errorf("expected %+v, got %+v", reply, decoded)
	}
}

func TestQueryKeymapReply(t *testing.T) {
	order := binary.LittleEndian
	reply := &QueryKeymapReply{
		Sequence: 1,
		Keys:     [32]byte{1, 2, 3},
	}

	encoded := reply.EncodeMessage(order)
	decoded, err := ParseQueryKeymapReply(order, encoded)
	if err != nil {
		t.Fatalf("ParseQueryKeymapReply failed: %v", err)
	}

	if !reflect.DeepEqual(reply, decoded) {
		t.Errorf("expected %+v, got %+v", reply, decoded)
	}
}

func TestGetFontPathReply(t *testing.T) {
	order := binary.LittleEndian
	reply := &GetFontPathReply{
		Sequence: 1,
		NPaths:   2,
		Paths:    []string{"path1", "path2"},
	}

	encoded := reply.EncodeMessage(order)
	decoded, err := ParseGetFontPathReply(order, encoded)
	if err != nil {
		t.Fatalf("ParseGetFontPathReply failed: %v", err)
	}

	if !reflect.DeepEqual(reply, decoded) {
		t.Errorf("expected %+v, got %+v", reply, decoded)
	}
}

func TestQueryTreeReply(t *testing.T) {
	order := binary.LittleEndian
	reply := &QueryTreeReply{
		Sequence:    1,
		Root:        2,
		Parent:      3,
		NumChildren: 2,
		Children:    []uint32{4, 5},
	}

	encoded := reply.EncodeMessage(order)
	decoded, err := ParseQueryTreeReply(order, encoded)
	if err != nil {
		t.Fatalf("ParseQueryTreeReply failed: %v", err)
	}

	if !reflect.DeepEqual(reply, decoded) {
		t.Errorf("expected %+v, got %+v", reply, decoded)
	}
}

func TestAllocColorCellsReply(t *testing.T) {
	order := binary.LittleEndian
	reply := &AllocColorCellsReply{
		Sequence: 1,
		NPixels:  2,
		NMasks:   2,
		Pixels:   []uint32{1, 2},
		Masks:    []uint32{3, 4},
	}

	encoded := reply.EncodeMessage(order)
	decoded, err := ParseAllocColorCellsReply(order, encoded)
	if err != nil {
		t.Fatalf("ParseAllocColorCellsReply failed: %v", err)
	}

	if !reflect.DeepEqual(reply, decoded) {
		t.Errorf("expected %+v, got %+v", reply, decoded)
	}
}

func TestAllocColorPlanesReply(t *testing.T) {
	order := binary.LittleEndian
	reply := &AllocColorPlanesReply{
		Sequence:  1,
		NPixels:   2,
		RedMask:   3,
		GreenMask: 4,
		BlueMask:  5,
		Pixels:    []uint32{1, 2},
	}

	encoded := reply.EncodeMessage(order)
	decoded, err := ParseAllocColorPlanesReply(order, encoded)
	if err != nil {
		t.Fatalf("ParseAllocColorPlanesReply failed: %v", err)
	}

	if !reflect.DeepEqual(reply, decoded) {
		t.Errorf("expected %+v, got %+v", reply, decoded)
	}
}

func TestGetPointerControlReply(t *testing.T) {
	order := binary.LittleEndian
	reply := &GetPointerControlReply{
		Sequence:         1,
		AccelNumerator:   2,
		AccelDenominator: 3,
		Threshold:        4,
	}

	encoded := reply.EncodeMessage(order)
	decoded, err := ParseGetPointerControlReply(order, encoded)
	if err != nil {
		t.Fatalf("ParseGetPointerControlReply failed: %v", err)
	}

	if !reflect.DeepEqual(reply, decoded) {
		t.Errorf("expected %+v, got %+v", reply, decoded)
	}
}

func TestQueryFontReply(t *testing.T) {
	order := binary.LittleEndian
	reply := &QueryFontReply{
		Sequence:       1,
		MinCharOrByte2: 1,
		MaxCharOrByte2: 2,
		DefaultChar:    3,
		DrawDirection:  1,
		MinByte1:       1,
		MaxByte1:       2,
		AllCharsExist:  true,
		FontAscent:     10,
		FontDescent:    2,
		NumFontProps:   2,
		NumCharInfos:   1,
		CharInfos: []XCharInfo{
			{1, 2, 3, 4, 5, 6},
		},
		FontProps: []FontProp{
			{Name: 100, Value: 200},
			{Name: 300, Value: 400},
		},
	}

	encoded := reply.EncodeMessage(order)
	decoded, err := ParseQueryFontReply(order, encoded)
	if err != nil {
		t.Fatalf("ParseQueryFontReply failed: %v", err)
	}

	if !reflect.DeepEqual(reply, decoded) {
		t.Errorf("expected %+v, got %+v", reply, decoded)
	}
}

func TestListExtensionsReply(t *testing.T) {
	order := binary.LittleEndian
	reply := &ListExtensionsReply{
		Sequence: 1,
		NNames:   2,
		Names:    []string{"ext1", "ext2"},
	}

	encoded := reply.EncodeMessage(order)
	decoded, err := ParseListExtensionsReply(order, encoded)
	if err != nil {
		t.Fatalf("ParseListExtensionsReply failed: %v", err)
	}

	if !reflect.DeepEqual(reply, decoded) {
		t.Errorf("expected %+v, got %+v", reply, decoded)
	}
}
