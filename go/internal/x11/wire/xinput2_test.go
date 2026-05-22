//go:build x11

package wire

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetExtensionVersionRequest_EncodeDecode(t *testing.T) {
	order := binary.LittleEndian
	req := &GetExtensionVersionRequest{
		Name: "XInputExtension",
	}

	encoded := req.EncodeMessage(order)

	parsed, err := ParseRequest(order, encoded, 1, false)
	assert.NoError(t, err)

	assert.Equal(t, req, parsed)
}

func TestXIBarrierReleasePointerRequest_EncodeDecode(t *testing.T) {
	order := binary.LittleEndian
	req := &XIBarrierReleasePointerRequest{
		NumBarriers: 1,
		Barriers: []XIBarrier{
			{
				Barrier: 1,
				EventID: 2,
			},
		},
	}

	encoded := req.EncodeMessage(order)

	parsed, err := ParseRequest(order, encoded, 1, false)
	assert.NoError(t, err)

	assert.Equal(t, req, parsed)
}

func TestXIGetSelectedEventsRequest_EncodeDecode(t *testing.T) {
	order := binary.LittleEndian
	req := &XIGetSelectedEventsRequest{
		Window: Window(1),
	}

	encoded := req.EncodeMessage(order)

	parsed, err := ParseRequest(order, encoded, 1, false)
	assert.NoError(t, err)

	assert.Equal(t, req, parsed)
}

func TestXIGetPropertyRequest_EncodeDecode(t *testing.T) {
	order := binary.LittleEndian
	req := &XIGetPropertyRequest{
		DeviceID: 2,
		Delete:   true,
		Property: 3,
		Type:     4,
		Offset:   5,
		Len:      6,
	}

	encoded := req.EncodeMessage(order)

	parsed, err := ParseRequest(order, encoded, 1, false)
	assert.NoError(t, err)

	assert.Equal(t, req, parsed)
}

func TestXIDeletePropertyRequest_EncodeDecode(t *testing.T) {
	order := binary.LittleEndian
	req := &XIDeletePropertyRequest{
		DeviceID: 2,
		Property: 3,
	}

	encoded := req.EncodeMessage(order)

	parsed, err := ParseRequest(order, encoded, 1, false)
	assert.NoError(t, err)

	assert.Equal(t, req, parsed)
}

func TestXIChangePropertyRequest_EncodeDecode(t *testing.T) {
	order := binary.LittleEndian
	req := &XIChangePropertyRequest{
		DeviceID: 2,
		Mode:     1,
		Format:   8,
		Property: 3,
		Type:     4,
		NumItems: 4,
		Data:     []byte{1, 2, 3, 4},
	}

	encoded := req.EncodeMessage(order)

	parsed, err := ParseRequest(order, encoded, 1, false)
	assert.NoError(t, err)

	assert.Equal(t, req, parsed)
}

func TestXIListPropertiesRequest_EncodeDecode(t *testing.T) {
	order := binary.LittleEndian
	req := &XIListPropertiesRequest{
		DeviceID: 2,
	}

	encoded := req.EncodeMessage(order)

	parsed, err := ParseRequest(order, encoded, 1, false)
	assert.NoError(t, err)

	assert.Equal(t, req, parsed)
}

func TestXIPassiveUngrabDeviceRequest_EncodeDecode(t *testing.T) {
	order := binary.LittleEndian
	req := &XIPassiveUngrabDeviceRequest{
		DeviceID:     2,
		GrabWindow:   Window(1),
		Detail:       5,
		NumModifiers: 1,
		GrabType:     1,
		Modifiers:    []byte{1, 2, 3, 4},
	}

	encoded := req.EncodeMessage(order)

	parsed, err := ParseRequest(order, encoded, 1, false)
	assert.NoError(t, err)

	assert.Equal(t, req, parsed)
}

func TestXIPassiveGrabDeviceRequest_EncodeDecode(t *testing.T) {
	order := binary.LittleEndian
	req := &XIPassiveGrabDeviceRequest{
		DeviceID:         2,
		GrabWindow:       Window(1),
		Time:             3,
		Cursor:           4,
		Detail:           5,
		NumModifiers:     1,
		MaskLen:          1,
		GrabType:         1,
		GrabMode:         2,
		PairedDeviceMode: 3,
		OwnerEvents:      true,
		Mask:             []byte{5, 6, 7, 8},
		Modifiers:        []byte{1, 2, 3, 4},
	}

	encoded := req.EncodeMessage(order)

	parsed, err := ParseRequest(order, encoded, 1, false)
	assert.NoError(t, err)

	assert.Equal(t, req, parsed)
}

func TestXIAllowEventsRequest_EncodeDecode(t *testing.T) {
	order := binary.LittleEndian
	req := &XIAllowEventsRequest{
		DeviceID:   2,
		EventMode:  1,
		Time:       3,
		TouchID:    4,
		GrabWindow: Window(5),
	}

	encoded := req.EncodeMessage(order)

	parsed, err := ParseRequest(order, encoded, 1, false)
	assert.NoError(t, err)

	assert.Equal(t, req, parsed)
}

func TestXIUngrabDeviceRequest_EncodeDecode(t *testing.T) {
	order := binary.LittleEndian
	req := &XIUngrabDeviceRequest{
		DeviceID: 2,
		Time:     3,
	}

	encoded := req.EncodeMessage(order)

	parsed, err := ParseRequest(order, encoded, 1, false)
	assert.NoError(t, err)

	assert.Equal(t, req, parsed)
}

func TestXIGrabDeviceRequest_EncodeDecode(t *testing.T) {
	order := binary.LittleEndian
	req := &XIGrabDeviceRequest{
		DeviceID:         2,
		GrabWindow:       Window(1),
		Time:             3,
		Cursor:           4,
		GrabMode:         1,
		PairedDeviceMode: 2,
		OwnerEvents:      true,
		MaskLen:          1,
		Mask:             []byte{1, 2, 3, 4},
	}

	encoded := req.EncodeMessage(order)

	parsed, err := ParseRequest(order, encoded, 1, false)
	assert.NoError(t, err)

	assert.Equal(t, req, parsed)
}

func TestXIGetFocusRequest_EncodeDecode(t *testing.T) {
	order := binary.LittleEndian
	req := &XIGetFocusRequest{
		DeviceID: 2,
	}

	encoded := req.EncodeMessage(order)

	parsed, err := ParseRequest(order, encoded, 1, false)
	assert.NoError(t, err)

	assert.Equal(t, req, parsed)
}

func TestXISetFocusRequest_EncodeDecode(t *testing.T) {
	order := binary.LittleEndian
	req := &XISetFocusRequest{
		DeviceID: 2,
		Focus:    Window(1),
		Time:     3,
	}

	encoded := req.EncodeMessage(order)

	parsed, err := ParseRequest(order, encoded, 1, false)
	assert.NoError(t, err)

	assert.Equal(t, req, parsed)
}

func TestXIQueryDeviceRequest_EncodeDecode(t *testing.T) {
	order := binary.LittleEndian
	req := &XIQueryDeviceRequest{
		DeviceID: 2,
	}

	encoded := req.EncodeMessage(order)

	parsed, err := ParseRequest(order, encoded, 1, false)
	assert.NoError(t, err)

	assert.Equal(t, req, parsed)
}

func TestXISelectEventsRequest_EncodeDecode(t *testing.T) {
	order := binary.LittleEndian
	req := &XISelectEventsRequest{
		Window:   Window(1),
		NumMasks: 1,
		Masks: []XIEventMask{
			{
				DeviceID: 2,
				MaskLen:  1,
				Mask:     []uint32{0x04030201},
			},
		},
	}

	encoded := req.EncodeMessage(order)

	parsed, err := ParseRequest(order, encoded, 1, false)
	assert.NoError(t, err)

	assert.Equal(t, req, parsed)
}

func TestXIGetClientPointerRequest_EncodeDecode(t *testing.T) {
	order := binary.LittleEndian
	req := &XIGetClientPointerRequest{
		Window: Window(1),
	}

	encoded := req.EncodeMessage(order)

	parsed, err := ParseRequest(order, encoded, 1, false)
	assert.NoError(t, err)

	assert.Equal(t, req, parsed)
}

func TestXISetClientPointerRequest_EncodeDecode(t *testing.T) {
	order := binary.LittleEndian
	req := &XISetClientPointerRequest{
		DeviceID: 2,
		Window:   Window(1),
	}

	encoded := req.EncodeMessage(order)

	parsed, err := ParseRequest(order, encoded, 1, false)
	assert.NoError(t, err)

	assert.Equal(t, req, parsed)
}

func TestXIChangeHierarchyRequest_EncodeDecode(t *testing.T) {
	order := binary.LittleEndian
	req := &XIChangeHierarchyRequest{
		NumChanges: 1,
		Changes: []XIChangeHierarchyChange{
			&XIDetachSlave{
				Type:     4,
				Length:   8,
				DeviceID: 5,
			},
		},
	}

	encoded := req.EncodeMessage(order)

	parsed, err := ParseRequest(order, encoded, 1, false)
	assert.NoError(t, err)

	assert.Equal(t, req, parsed)
}

func TestXIChangeCursorRequest_EncodeDecode(t *testing.T) {
	order := binary.LittleEndian
	req := &XIChangeCursorRequest{
		DeviceID: 2,
		Window:   Window(1),
		Cursor:   3,
	}

	encoded := req.EncodeMessage(order)

	parsed, err := ParseRequest(order, encoded, 1, false)
	assert.NoError(t, err)

	assert.Equal(t, req, parsed)
}

func TestXIWarpPointerRequest_EncodeDecode(t *testing.T) {
	order := binary.LittleEndian
	req := &XIWarpPointerRequest{
		DeviceID:  2,
		SrcWindow: Window(1),
		DstWindow: Window(2),
		SrcX:      10,
		SrcY:      20,
		SrcW:      100,
		SrcH:      200,
		DstX:      30,
		DstY:      40,
	}

	encoded := req.EncodeMessage(order)

	parsed, err := ParseRequest(order, encoded, 1, false)
	assert.NoError(t, err)

	assert.Equal(t, req, parsed)
}
func TestListInputDevicesRequest(t *testing.T) {
	order := binary.LittleEndian
	request := &ListInputDevicesRequest{}

	encoded := request.EncodeMessage(order)
	decoded, err := ParseListInputDevicesRequest(order, encoded[4:], 1)
	if err != nil {
		t.Fatalf("ParseListInputDevicesRequest failed: %v", err)
	}

	assert.Equal(t, request, decoded)
}
func TestOpenDeviceRequest(t *testing.T) {
	order := binary.LittleEndian
	request := &OpenDeviceRequest{
		DeviceID: 5,
	}

	encoded := request.EncodeMessage(order)
	decoded, err := ParseOpenDeviceRequest(order, encoded[4:], 1)
	if err != nil {
		t.Fatalf("ParseOpenDeviceRequest failed: %v", err)
	}

	assert.Equal(t, request, decoded)
}
func TestSelectExtensionEventRequest(t *testing.T) {
	order := binary.LittleEndian
	request := &SelectExtensionEventRequest{
		Window:  123,
		Classes: []uint32{10, 20},
	}

	encoded := request.EncodeMessage(order)
	decoded, err := ParseSelectExtensionEventRequest(order, encoded[4:], 1)
	if err != nil {
		t.Fatalf("ParseSelectExtensionEventRequest failed: %v", err)
	}

	assert.Equal(t, request, decoded)
}
func TestGetDeviceMotionEventsRequest(t *testing.T) {
	order := binary.LittleEndian
	request := &GetDeviceMotionEventsRequest{
		Start:    100,
		Stop:     200,
		DeviceID: 5,
	}

	encoded := request.EncodeMessage(order)
	decoded, err := ParseGetDeviceMotionEventsRequest(order, encoded[4:], 1)
	if err != nil {
		t.Fatalf("ParseGetDeviceMotionEventsRequest failed: %v", err)
	}

	assert.Equal(t, request, decoded)
}
func TestChangeKeyboardDeviceRequest(t *testing.T) {
	order := binary.LittleEndian
	request := &ChangeKeyboardDeviceRequest{
		DeviceID: 5,
	}

	encoded := request.EncodeMessage(order)
	decoded, err := ParseChangeKeyboardDeviceRequest(order, encoded[4:], 1)
	if err != nil {
		t.Fatalf("ParseChangeKeyboardDeviceRequest failed: %v", err)
	}

	assert.Equal(t, request, decoded)
}
func TestChangePointerDeviceRequest(t *testing.T) {
	order := binary.LittleEndian
	request := &ChangePointerDeviceRequest{
		XAxis:    1,
		YAxis:    2,
		DeviceID: 5,
	}

	encoded := request.EncodeMessage(order)
	decoded, err := ParseChangePointerDeviceRequest(order, encoded[4:], 1)
	if err != nil {
		t.Fatalf("ParseChangePointerDeviceRequest failed: %v", err)
	}

	assert.Equal(t, request, decoded)
}
func TestGrabDeviceKeyRequest(t *testing.T) {
	order := binary.LittleEndian
	request := &GrabDeviceKeyRequest{
		GrabWindow:      123,
		Modifiers:       1,
		Key:             10,
		DeviceID:        5,
		OwnerEvents:     true,
		ThisDeviceMode:  1,
		OtherDeviceMode: 0,
		NumClasses:      0,
		Classes:         []uint32{},
	}

	encoded := request.EncodeMessage(order)
	decoded, err := ParseGrabDeviceKeyRequest(order, encoded[4:], 1)
	if err != nil {
		t.Fatalf("ParseGrabDeviceKeyRequest failed: %v", err)
	}

	assert.Equal(t, request, decoded)
}
func TestUngrabDeviceKeyRequest(t *testing.T) {
	order := binary.LittleEndian
	request := &UngrabDeviceKeyRequest{
		GrabWindow: 123,
		Modifiers:  1,
		Key:        10,
		DeviceID:   5,
	}

	encoded := request.EncodeMessage(order)
	decoded, err := ParseUngrabDeviceKeyRequest(order, encoded[4:], 1)
	if err != nil {
		t.Fatalf("ParseUngrabDeviceKeyRequest failed: %v", err)
	}

	assert.Equal(t, request, decoded)
}
func TestGrabDeviceButtonRequest(t *testing.T) {
	order := binary.LittleEndian
	request := &GrabDeviceButtonRequest{
		GrabWindow:      123,
		Modifiers:       1,
		Button:          10,
		DeviceID:        5,
		OwnerEvents:     true,
		ThisDeviceMode:  1,
		OtherDeviceMode: 0,
		NumClasses:      0,
		Classes:         []uint32{},
	}

	encoded := request.EncodeMessage(order)
	decoded, err := ParseGrabDeviceButtonRequest(order, encoded[4:], 1)
	if err != nil {
		t.Fatalf("ParseGrabDeviceButtonRequest failed: %v", err)
	}

	assert.Equal(t, request, decoded)
}
func TestUngrabDeviceButtonRequest(t *testing.T) {
	order := binary.LittleEndian
	request := &UngrabDeviceButtonRequest{
		GrabWindow: 123,
		Modifiers:  1,
		Button:     10,
		DeviceID:   5,
	}

	encoded := request.EncodeMessage(order)
	decoded, err := ParseUngrabDeviceButtonRequest(order, encoded[4:], 1)
	if err != nil {
		t.Fatalf("ParseUngrabDeviceButtonRequest failed: %v", err)
	}

	assert.Equal(t, request, decoded)
}
func TestAllowDeviceEventsRequest(t *testing.T) {
	order := binary.LittleEndian
	request := &AllowDeviceEventsRequest{
		Time:     0,
		DeviceID: 5,
		Mode:     1,
	}

	encoded := request.EncodeMessage(order)
	decoded, err := ParseAllowDeviceEventsRequest(order, encoded[4:], 1)
	if err != nil {
		t.Fatalf("ParseAllowDeviceEventsRequest failed: %v", err)
	}

	assert.Equal(t, request, decoded)
}
func TestGetDeviceFocusRequest(t *testing.T) {
	order := binary.LittleEndian
	request := &GetDeviceFocusRequest{
		DeviceID: 5,
	}

	encoded := request.EncodeMessage(order)
	decoded, err := ParseGetDeviceFocusRequest(order, encoded[4:], 1)
	if err != nil {
		t.Fatalf("ParseGetDeviceFocusRequest failed: %v", err)
	}

	assert.Equal(t, request, decoded)
}
func TestSetDeviceFocusRequest(t *testing.T) {
	order := binary.LittleEndian
	request := &SetDeviceFocusRequest{
		Focus:    123,
		Time:     0,
		RevertTo: 1,
		DeviceID: 5,
	}

	encoded := request.EncodeMessage(order)
	decoded, err := ParseSetDeviceFocusRequest(order, encoded[4:], 1)
	if err != nil {
		t.Fatalf("ParseSetDeviceFocusRequest failed: %v", err)
	}

	assert.Equal(t, request, decoded)
}
func TestGetFeedbackControlRequest(t *testing.T) {
	order := binary.LittleEndian
	request := &GetFeedbackControlRequest{
		DeviceID: 5,
	}

	encoded := request.EncodeMessage(order)
	decoded, err := ParseGetFeedbackControlRequest(order, encoded[4:], 1)
	if err != nil {
		t.Fatalf("ParseGetFeedbackControlRequest failed: %v", err)
	}

	assert.Equal(t, request, decoded)
}
func TestChangeFeedbackControlRequest(t *testing.T) {
	order := binary.LittleEndian
	request := &ChangeFeedbackControlRequest{
		Mask:      1,
		DeviceID:  5,
		ControlID: 10,
		Control:   []byte{1, 2, 3, 4},
	}

	encoded := request.EncodeMessage(order)
	decoded, err := ParseChangeFeedbackControlRequest(order, encoded[4:], 1)
	if err != nil {
		t.Fatalf("ParseChangeFeedbackControlRequest failed: %v", err)
	}

	assert.Equal(t, request, decoded)
}
func TestGetDeviceKeyMappingRequest(t *testing.T) {
	order := binary.LittleEndian
	request := &GetDeviceKeyMappingRequest{
		DeviceID: 5,
		FirstKey: 10,
		Count:    2,
	}

	encoded := request.EncodeMessage(order)
	decoded, err := ParseGetDeviceKeyMappingRequest(order, encoded[4:], 1)
	if err != nil {
		t.Fatalf("ParseGetDeviceKeyMappingRequest failed: %v", err)
	}

	assert.Equal(t, request, decoded)
}
func TestChangeDeviceKeyMappingRequest(t *testing.T) {
	order := binary.LittleEndian
	request := &ChangeDeviceKeyMappingRequest{
		DeviceID:          5,
		FirstKey:          10,
		KeysymsPerKeycode: 2,
		KeycodeCount:      2,
		Keysyms:           []uint32{1, 2, 3, 4},
	}

	encoded := request.EncodeMessage(order)
	decoded, err := ParseChangeDeviceKeyMappingRequest(order, encoded[4:], 1)
	if err != nil {
		t.Fatalf("ParseChangeDeviceKeyMappingRequest failed: %v", err)
	}

	assert.Equal(t, request, decoded)
}
func TestGetDeviceModifierMappingRequest(t *testing.T) {
	order := binary.LittleEndian
	request := &GetDeviceModifierMappingRequest{
		DeviceID: 5,
	}

	encoded := request.EncodeMessage(order)
	decoded, err := ParseGetDeviceModifierMappingRequest(order, encoded[4:], 1)
	if err != nil {
		t.Fatalf("ParseGetDeviceModifierMappingRequest failed: %v", err)
	}

	assert.Equal(t, request, decoded)
}
func TestSetDeviceModifierMappingRequest(t *testing.T) {
	order := binary.LittleEndian
	request := &SetDeviceModifierMappingRequest{
		DeviceID: 5,
		Keycodes: []byte{1, 2, 3, 4, 5, 6, 7, 8},
	}

	encoded := request.EncodeMessage(order)
	decoded, err := ParseSetDeviceModifierMappingRequest(order, encoded[4:], 1)
	if err != nil {
		t.Fatalf("ParseSetDeviceModifierMappingRequest failed: %v", err)
	}

	assert.Equal(t, request, decoded)
}
func TestGetDeviceButtonMappingRequest(t *testing.T) {
	order := binary.LittleEndian
	request := &GetDeviceButtonMappingRequest{
		DeviceID: 5,
	}

	encoded := request.EncodeMessage(order)
	decoded, err := ParseGetDeviceButtonMappingRequest(order, encoded[4:], 1)
	if err != nil {
		t.Fatalf("ParseGetDeviceButtonMappingRequest failed: %v", err)
	}

	assert.Equal(t, request, decoded)
}
func TestSetDeviceButtonMappingRequest(t *testing.T) {
	order := binary.LittleEndian
	request := &SetDeviceButtonMappingRequest{
		DeviceID: 5,
		Map:      []byte{1, 3, 2},
	}

	encoded := request.EncodeMessage(order)
	decoded, err := ParseSetDeviceButtonMappingRequest(order, encoded[4:], 1)
	if err != nil {
		t.Fatalf("ParseSetDeviceButtonMappingRequest failed: %v", err)
	}

	assert.Equal(t, request, decoded)
}
func TestQueryDeviceStateRequest(t *testing.T) {
	order := binary.LittleEndian
	request := &QueryDeviceStateRequest{
		DeviceID: 5,
	}

	encoded := request.EncodeMessage(order)
	decoded, err := ParseQueryDeviceStateRequest(order, encoded[4:], 1)
	if err != nil {
		t.Fatalf("ParseQueryDeviceStateRequest failed: %v", err)
	}

	assert.Equal(t, request, decoded)
}
func TestSendExtensionEventRequest(t *testing.T) {
	order := binary.LittleEndian
	request := &SendExtensionEventRequest{
		Destination: 123,
		DeviceID:    5,
		Propagate:   true,
		NumClasses:  0,
		NumEvents:   1,
		Events:      []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
		Classes:     []uint32{},
	}

	encoded := request.EncodeMessage(order)
	decoded, err := ParseSendExtensionEventRequest(order, encoded[4:], 1)
	if err != nil {
		t.Fatalf("ParseSendExtensionEventRequest failed: %v", err)
	}

	assert.Equal(t, request, decoded)
}
func TestDeviceBellRequest(t *testing.T) {
	order := binary.LittleEndian
	request := &DeviceBellRequest{
		DeviceID:      5,
		FeedbackID:    10,
		FeedbackClass: 1,
		Percent:       50,
	}

	encoded := request.EncodeMessage(order)
	decoded, err := ParseDeviceBellRequest(order, encoded[4:], 1)
	if err != nil {
		t.Fatalf("ParseDeviceBellRequest failed: %v", err)
	}

	assert.Equal(t, request, decoded)
}

func TestXIQueryPointerRequest_EncodeDecode(t *testing.T) {
	order := binary.LittleEndian
	req := &XIQueryPointerRequest{
		Window:   Window(1),
		DeviceID: 2,
	}

	encoded := req.EncodeMessage(order)

	parsed, err := ParseRequest(order, encoded, 1, false)
	assert.NoError(t, err)

	assert.Equal(t, req, parsed)
}

func TestXIDeviceEvent_Encode(t *testing.T) {
	order := binary.LittleEndian
	event := &XIDeviceEvent{
		Sequence:  10,
		EventType: 6, // Motion
		DeviceID:  2,
		Time:      12345,
		Detail:    0,
		Root:      1,
		Event:     2,
		Child:     3,
		RootX:     10 << 16,
		RootY:     20 << 16,
		EventX:    10 << 16,
		EventY:    20 << 16,
		SourceID:  5,
		Buttons:   []uint32{0xCAFEBABE},
		Mods: ModifierInfo{
			Base:      1,
			Latched:   2,
			Locked:    3,
			Effective: 4,
		},
		Group: GroupInfo{
			Base:      5,
			Latched:   6,
			Locked:    7,
			Effective: 8,
		},
	}

	encoded := event.EncodeMessage(order)

	// Fixed length 76 + buttons (4) = 80 bytes.
	assert.Equal(t, 80, len(encoded))

	// Check GenericEvent header
	assert.Equal(t, byte(35), encoded[0])
	assert.Equal(t, byte(XInputOpcode), encoded[1])
	assert.Equal(t, uint16(10), order.Uint16(encoded[2:4]))
	// Length field: (80 - 32) / 4 = 12
	assert.Equal(t, uint32(12), order.Uint32(encoded[4:8]))

	// Check buttons_len at 48
	assert.Equal(t, uint16(1), order.Uint16(encoded[48:50])) // 1 unit of 4 bytes

	// Check sourceid at 52
	assert.Equal(t, uint16(5), order.Uint16(encoded[52:54]))

	// Check Mods (offset 56)
	assert.Equal(t, uint32(1), order.Uint32(encoded[56:60]))
	assert.Equal(t, uint32(2), order.Uint32(encoded[60:64]))
	assert.Equal(t, uint32(3), order.Uint32(encoded[64:68]))
	assert.Equal(t, uint32(4), order.Uint32(encoded[68:72]))

	// Check Group (offset 72)
	assert.Equal(t, byte(5), encoded[72])
	assert.Equal(t, byte(6), encoded[73])
	assert.Equal(t, byte(7), encoded[74])
	assert.Equal(t, byte(8), encoded[75])

	// Check Buttons (offset 76)
	assert.Equal(t, uint32(0xCAFEBABE), order.Uint32(encoded[76:80]))
}

func TestXIQueryPointerReply_Encode(t *testing.T) {
	order := binary.LittleEndian
	reply := &XIQueryPointerReply{
		Sequence:   10,
		Root:       1,
		Child:      2,
		RootX:      10 << 16,
		RootY:      20 << 16,
		WinX:       30 << 16,
		WinY:       40 << 16,
		SameScreen: true,
		Mods: ModifierInfo{
			Base:      1,
			Latched:   2,
			Locked:    3,
			Effective: 4,
		},
		Group: GroupInfo{
			Base:      5,
			Latched:   6,
			Locked:    7,
			Effective: 8,
		},
		Buttons: []uint32{0xDEADBEEF},
	}

	encoded := reply.EncodeMessage(order)

	// Fixed length 56 + buttons (4) = 60 bytes.
	assert.Equal(t, 60, len(encoded))

	// Header checks
	assert.Equal(t, byte(1), encoded[0])
	assert.Equal(t, uint16(10), order.Uint16(encoded[2:4]))
	// Length: (60 - 32) / 4 = 7
	assert.Equal(t, uint32(7), order.Uint32(encoded[4:8]))

	// Check same_screen at 32
	assert.Equal(t, byte(1), encoded[32])

	// Check buttons_len at 34
	assert.Equal(t, uint16(1), order.Uint16(encoded[34:36]))

	// Check Mods (offset 36)
	assert.Equal(t, uint32(1), order.Uint32(encoded[36:40]))
	assert.Equal(t, uint32(2), order.Uint32(encoded[40:44]))
	assert.Equal(t, uint32(3), order.Uint32(encoded[44:48]))
	assert.Equal(t, uint32(4), order.Uint32(encoded[48:52]))

	// Check Group (offset 52)
	assert.Equal(t, byte(5), encoded[52])
	assert.Equal(t, byte(6), encoded[53])
	assert.Equal(t, byte(7), encoded[54])
	assert.Equal(t, byte(8), encoded[55])

	// Check Buttons (offset 56)
	assert.Equal(t, uint32(0xDEADBEEF), order.Uint32(encoded[56:60]))
}
