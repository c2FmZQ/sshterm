//go:build x11 && !wasm

package x11

import (
	"encoding/binary"
	"testing"

	"github.com/c2FmZQ/sshterm/internal/x11/wire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestXInputEventDelivery_Simple(t *testing.T) {
	server, client, _, buffer := setupTestServerWithClient(t)

	// 1. Create a window
	windowID := clientXID(client, 100)
	server.windows[windowID] = &window{
		xid:        windowID,
		attributes: wire.WindowAttributes{},
		eventMasks: make(map[uint32]uint32),
	}

	// 2. Open the virtual pointer device (ID 2)
	openDevReq := &wire.OpenDeviceRequest{
		DeviceID: 2, // Virtual Pointer
	}
	reply := server.handleRequest(client, openDevReq, 1)
	assert.NotNil(t, reply)
	_, ok := reply.(*wire.OpenDeviceReply)
	assert.True(t, ok, "Expected OpenDeviceReply")

	// 3. Select XInput ButtonPress events on the window
	// Mask for DeviceButtonPress is DeviceButtonPressMask (1<<2 = 4)
	// Class = (Mask << 8) | DeviceID
	class := uint32(wire.DeviceButtonPressMask<<8) | 2
	selectReq := &wire.SelectExtensionEventRequest{
		Window:  wire.Window(windowID),
		Classes: []uint32{class},
	}
	server.handleRequest(client, selectReq, 1)

	// 4. Send a mouse down event
	// SendMouseEvent will trigger both core and XInput events if configured
	server.SendMouseEvent(windowID, "mousedown", 10, 10, 1)

	// 5. Verify delivery
	messages := drainMessages(t, buffer, client.byteOrder)

	// We might get core events if defaults allow, but we definitely want the XInput event
	var foundXInputEvent bool
	for _, msg := range messages {
		if inputEvent, ok := msg.(*wire.DeviceButtonPressEvent); ok {
			foundXInputEvent = true
			assert.Equal(t, byte(2), inputEvent.DeviceID)
			assert.Equal(t, uint32(windowID), inputEvent.Event)
			assert.Equal(t, byte(1), inputEvent.Detail)
		}
	}
	assert.True(t, foundXInputEvent, "Expected DeviceButtonPressEvent")
}

func TestXInputEventDelivery_Keyboard(t *testing.T) {
	server, client, _, buffer := setupTestServerWithClient(t)

	// 1. Create a window and focus it
	windowID := clientXID(client, 100)
	server.windows[windowID] = &window{
		xid:        windowID,
		attributes: wire.WindowAttributes{},
		eventMasks: make(map[uint32]uint32),
	}
	server.inputFocus = windowID

	// 2. Open the virtual keyboard device (ID 3)
	openDevReq := &wire.OpenDeviceRequest{
		DeviceID: 3, // Virtual Keyboard
	}
	reply := server.handleRequest(client, openDevReq, 1)
	assert.NotNil(t, reply)

	// 3. Select XInput KeyPress events
	// Mask for DeviceKeyPress is DeviceKeyPressMask (1<<0 = 1)
	class := uint32(wire.DeviceKeyPressMask<<8) | 3
	selectReq := &wire.SelectExtensionEventRequest{
		Window:  wire.Window(windowID),
		Classes: []uint32{class},
	}
	server.handleRequest(client, selectReq, 1)

	// 4. Send a key down event
	server.SendKeyboardEvent(windowID, "keydown", "KeyA", false, false, false, false)

	// 5. Verify delivery
	messages := drainMessages(t, buffer, client.byteOrder)

	var foundXInputEvent bool
	for _, msg := range messages {
		if inputEvent, ok := msg.(*wire.DeviceKeyPressEvent); ok {
			foundXInputEvent = true
			assert.Equal(t, byte(3), inputEvent.DeviceID)
			assert.Equal(t, uint32(windowID), inputEvent.Event)
			// Detail/KeyCode checks depends on keymap, skipping for now
		}
	}
	assert.True(t, foundXInputEvent, "Expected DeviceKeyPressEvent")
}

func TestXInput2_QueryVersion(t *testing.T) {
	server, client, _, _ := setupTestServerWithClient(t)

	// XIQueryVersion
	req := &wire.XIQueryVersionRequest{
		MajorVersion: 2,
		MinorVersion: 2,
	}
	reply := server.handleRequest(client, req, 1)
	assert.NotNil(t, reply)
	xiReply, ok := reply.(*wire.XIQueryVersionReply)
	if assert.True(t, ok, "Expected XIQueryVersionReply, got %T", reply) {
		assert.Equal(t, uint16(2), xiReply.MajorVersion)
		assert.Equal(t, uint16(2), xiReply.MinorVersion)
	}
}

func TestXInput2_SelectEvents(t *testing.T) {
	server, client, _, _ := setupTestServerWithClient(t)
	windowID := clientXID(client, 100)
	server.windows[windowID] = &window{xid: windowID, eventMasks: make(map[uint32]uint32)}

	// XISelectEvents
	mask := []uint32{0} // Empty mask for now
	req := &wire.XISelectEventsRequest{
		Window:   wire.Window(windowID),
		NumMasks: 1,
		Masks: []wire.XIEventMask{
			{
				DeviceID: 2, // Virtual Pointer
				MaskLen:  uint16(len(mask)),
				Mask:     mask,
			},
		},
	}
	reply := server.handleRequest(client, req, 1)
	if reply != nil {
		if err, ok := reply.(wire.Error); ok {
			t.Fatalf("XISelectEvents returned an error: %v", err)
		}
	}

	// Verify mask is stored
	assert.NotNil(t, client.xi2EventMasks)
	masks, ok := client.xi2EventMasks[uint32(windowID)]
	assert.True(t, ok, "Window masks should be present")
	devMask, ok := masks[2] // Device 2
	assert.True(t, ok, "Device mask should be present")
	assert.Equal(t, mask, devMask)
}

func TestXInputGrab_Active(t *testing.T) {
	server, client, _, buffer := setupTestServerWithClient(t)

	// 1. Create a window and listen for Core events
	windowID := clientXID(client, 100)
	server.windows[windowID] = &window{
		xid:        windowID,
		attributes: wire.WindowAttributes{EventMask: wire.ButtonPressMask},
		eventMasks: map[uint32]uint32{client.id: wire.ButtonPressMask},
	}

	// 2. Open device
	server.handleRequest(client, &wire.OpenDeviceRequest{DeviceID: 2}, 1)

	// 3. Active Grab Device
	mask := uint32(wire.DeviceButtonPressMask<<8) | 2
	grabReq := &wire.GrabDeviceRequest{
		GrabWindow:  uint32(windowID),
		DeviceID:    2,
		OwnerEvents: false,
		NumClasses:  1,
		Classes:     []uint32{mask},
		Time:        0,
	}
	reply := server.handleRequest(client, grabReq, 2)
	require.NotNil(t, reply, "GrabDevice should return a reply")
	if err, ok := reply.(wire.Error); ok {
		t.Fatalf("GrabDevice failed: %v", err)
	}
	grabReply, ok := reply.(*wire.GrabDeviceReply)
	require.True(t, ok, "Expected GrabDeviceReply")
	assert.Equal(t, wire.GrabSuccess, grabReply.Status)

	// 4. Send event
	server.SendMouseEvent(windowID, "mousedown", 10, 10, 1)

	// 5. Verify
	messages := drainMessages(t, buffer, client.byteOrder)
	var foundXInput bool
	var foundCore bool
	for _, msg := range messages {
		if _, ok := msg.(*wire.DeviceButtonPressEvent); ok {
			foundXInput = true
		}
		if _, ok := msg.(*wire.ButtonPressEvent); ok {
			foundCore = true
		}
	}
	assert.True(t, foundXInput, "Should receive XInput event")
	assert.False(t, foundCore, "Should NOT receive Core event due to device grab")
}

func TestXInputGrab_PassiveButton(t *testing.T) {
	server, client, _, buffer := setupTestServerWithClient(t)

	// 1. Create window with Core event mask
	windowID := clientXID(client, 100)
	server.windows[windowID] = &window{
		xid:        windowID,
		attributes: wire.WindowAttributes{EventMask: wire.ButtonPressMask},
		eventMasks: map[uint32]uint32{client.id: wire.ButtonPressMask},
	}

	// 2. Open device
	server.handleRequest(client, &wire.OpenDeviceRequest{DeviceID: 2}, 1)

	// 3. Establish Passive Grab (GrabDeviceButton)
	mask := uint32(wire.DeviceButtonPressMask<<8) | 2
	passiveReq := &wire.GrabDeviceButtonRequest{
		GrabWindow:  wire.Window(windowID),
		DeviceID:    2,
		Button:      1, // Left button
		Modifiers:   wire.AnyModifier,
		OwnerEvents: false,
		NumClasses:  1,
		Classes:     []uint32{mask},
	}
	server.handleRequest(client, passiveReq, 2)

	// 4. Send mousedown (should activate grab)
	server.SendMouseEvent(windowID, "mousedown", 10, 10, 1)

	// 5. Verify
	messages := drainMessages(t, buffer, client.byteOrder)
	var foundXInput bool
	var foundCore bool
	for _, msg := range messages {
		if _, ok := msg.(*wire.DeviceButtonPressEvent); ok {
			foundXInput = true
		}
		if _, ok := msg.(*wire.ButtonPressEvent); ok {
			foundCore = true
		}
	}
	assert.True(t, foundXInput, "Should receive XInput event from passive grab")
	assert.False(t, foundCore, "Should NOT receive Core event due to activated device grab")
}

func TestXInputGrab_PassiveKey(t *testing.T) {
	server, client, _, buffer := setupTestServerWithClient(t)

	// 1. Create window
	windowID := clientXID(client, 100)
	server.windows[windowID] = &window{
		xid:        windowID,
		attributes: wire.WindowAttributes{EventMask: wire.KeyPressMask},
		eventMasks: map[uint32]uint32{client.id: wire.KeyPressMask},
	}
	server.inputFocus = windowID

	// 2. Open device
	server.handleRequest(client, &wire.OpenDeviceRequest{DeviceID: 3}, 1)

	// 3. Passive Grab Key
	mask := uint32(wire.DeviceKeyPressMask<<8) | 3
	passiveReq := &wire.GrabDeviceKeyRequest{
		GrabWindow:  wire.Window(windowID),
		DeviceID:    3,
		Key:         byte(jsCodeToX11Keycode["KeyA"]),
		Modifiers:   wire.AnyModifier,
		OwnerEvents: false,
		NumClasses:  1,
		Classes:     []uint32{mask},
	}
	server.handleRequest(client, passiveReq, 2)

	// 4. Send keydown
	server.SendKeyboardEvent(windowID, "keydown", "KeyA", false, false, false, false)

	// 5. Verify
	messages := drainMessages(t, buffer, client.byteOrder)
	var foundXInput bool
	var foundCore bool
	for _, msg := range messages {
		if _, ok := msg.(*wire.DeviceKeyPressEvent); ok {
			foundXInput = true
		}
		if _, ok := msg.(*wire.KeyEvent); ok {
			foundCore = true
		}
	}
	assert.True(t, foundXInput, "Should receive XInput event from passive grab")
	assert.False(t, foundCore, "Should NOT receive Core event due to activated device grab")
}

func TestXIRawMotionDelivery(t *testing.T) {
	t.Run("NonZeroDelta", func(t *testing.T) {
		s, client, _, buffer := setupTestServerWithClient(t)

		// Create a window to send events to
		winID := clientXID(client, 1)
		s.windows[winID] = &window{
			xid:    winID,
			parent: xID(s.rootWindowID()), // Root
			mapped: true,
			attributes: wire.WindowAttributes{
				EventMask: 0,
			},
			eventMasks: map[uint32]uint32{client.id: 0},
		}

		// Select XI_RawMotion (17) on Root Window (0)
		// 17 is in the first uint32 word. 1<<17 = 0x20000
		mask := []uint32{0x20000}
		req := &wire.XISelectEventsRequest{
			Window:   0, // Root
			NumMasks: 1,
			Masks: []wire.XIEventMask{
				{
					DeviceID: wire.XIAllMasterDevices,
					MaskLen:  1,
					Mask:     mask,
				},
			},
		}
		// Encode and handle request to ensure state is updated
		s.handleRequest(client, req, 1)

		// Check if mask was recorded
		if masks, ok := client.xi2EventMasks[0]; !ok {
			t.Fatal("XISelectEvents failed to record mask for root window")
		} else if m, ok := masks[wire.XIAllMasterDevices]; !ok || len(m) == 0 || m[0]&0x20000 == 0 {
			t.Fatal("XISelectEvents failed to record XI_RawMotion bit")
		}

		// Clear buffer before triggering event
		buffer.Reset()

		// Trigger Mouse Move on the window
		s.SendMouseEvent(winID, "mousemove", 100, 100, 0)

		// Read from client connection buffer
		msg := buffer.Bytes()
		if len(msg) == 0 {
			t.Fatal("Timeout waiting for XI_RawMotion event (buffer empty)")
		}

		// Decode message
		// We expect a GenericEvent (35)
		if len(msg) < 32 {
			t.Fatalf("Received message too short: %d", len(msg))
		}
		if msg[0] != 35 {
			t.Errorf("Expected GenericEvent (35), got %d", msg[0])
		}
		// Check extension opcode (byte 1)
		if msg[1] != byte(wire.XInputOpcode) {
			t.Errorf("Expected XInputOpcode (%d), got %d", wire.XInputOpcode, msg[1])
		}
		// Check event type (bytes 8-10)
		eventType := binary.LittleEndian.Uint16(msg[8:10])
		if eventType != 17 { // XI_RawMotion
			t.Errorf("Expected XI_RawMotion (17), got %d", eventType)
		}

		// Verify content of XIRawEvent
		// Header: 32 bytes
		// Mask len at 22 (uint16)
		// Valuators mask follows header.
		maskLen := binary.LittleEndian.Uint16(msg[22:24])
		if maskLen != 1 {
			t.Errorf("Expected maskLen 1, got %d", maskLen)
		}

		// Mask at byte 28 (4 bytes for maskLen 1)
		eventMask := binary.LittleEndian.Uint32(msg[28:32])
		// Expect bits 0 (X) and 1 (Y) set -> 3
		if eventMask != 3 {
			t.Errorf("Expected mask 3 (X|Y), got %d", eventMask)
		}

		// Values start at 28 + 4 = 32
		// Two axes set, so 2 * 8 bytes for values, then 2 * 8 bytes for raw values.
		// Value for X (axis 0)
		valXInt := int32(binary.LittleEndian.Uint32(msg[32:36]))
		// valXFrac := binary.LittleEndian.Uint32(msg[36:40])
		// Value for Y (axis 1)
		valYInt := int32(binary.LittleEndian.Uint32(msg[40:44]))
		// valYFrac := binary.LittleEndian.Uint32(msg[44:48])

		// Delta was 100 (from 0,0 to 100,100)
		if valXInt != 100 {
			t.Errorf("Expected valXInt 100, got %d", valXInt)
		}
		if valYInt != 100 {
			t.Errorf("Expected valYInt 100, got %d", valYInt)
		}
	})

	t.Run("ZeroDelta", func(t *testing.T) {
		s, client, _, buffer := setupTestServerWithClient(t)

		// Create a window to send events to
		winID := clientXID(client, 1)
		s.windows[winID] = &window{
			xid:    winID,
			parent: xID(s.rootWindowID()), // Root
			mapped: true,
			attributes: wire.WindowAttributes{
				EventMask: 0,
			},
			eventMasks: map[uint32]uint32{client.id: 0},
		}

		// Select XI_RawMotion on Root Window
		mask := []uint32{0x20000}
		req := &wire.XISelectEventsRequest{
			Window:   0, // Root
			NumMasks: 1,
			Masks: []wire.XIEventMask{
				{
					DeviceID: wire.XIAllMasterDevices,
					MaskLen:  1,
					Mask:     mask,
				},
			},
		}
		s.handleRequest(client, req, 1)

		// Set initial pointer position
		s.pointerX = 50
		s.pointerY = 50

		// Clear buffer before triggering event
		buffer.Reset()

		// Trigger Mouse Move with no change in position
		s.SendMouseEvent(winID, "mousemove", 50, 50, 0)

		// Read from client connection buffer
		msg := buffer.Bytes()
		if len(msg) == 0 {
			t.Fatal("Timeout waiting for XI_RawMotion event (buffer empty)")
		}

		// Verify key parts of the event
		assert.Equal(t, byte(35), msg[0], "Expected GenericEvent")
		assert.Equal(t, byte(wire.XInputOpcode), msg[1], "Expected XInputOpcode")
		eventType := binary.LittleEndian.Uint16(msg[8:10])
		assert.Equal(t, uint16(17), eventType, "Expected XI_RawMotion")

		// Verify valuators
		maskLen := binary.LittleEndian.Uint16(msg[22:24])
		assert.Equal(t, uint16(1), maskLen, "Expected maskLen 1")
		eventMask := binary.LittleEndian.Uint32(msg[28:32])
		assert.Equal(t, uint32(3), eventMask, "Expected mask for X and Y axes")

		valXInt := int32(binary.LittleEndian.Uint32(msg[32:36]))
		valYInt := int32(binary.LittleEndian.Uint32(msg[40:44]))
		assert.Equal(t, int32(0), valXInt, "Expected zero delta for X")
		assert.Equal(t, int32(0), valYInt, "Expected zero delta for Y")
	})
}

func TestXIRawMotionDelivery_NotSelected(t *testing.T) {
	s, client, _, buffer := setupTestServerWithClient(t)

	// Create a window
	winID := clientXID(client, 1)
	s.windows[winID] = &window{
		xid:        winID,
		parent:     xID(s.rootWindowID()),
		mapped:     true,
		eventMasks: make(map[uint32]uint32),
	}

	// Do NOT select XI_RawMotion

	// Trigger Mouse Move
	s.SendMouseEvent(winID, "mousemove", 100, 100, 0)

	// Should receive nothing
	if buffer.Len() > 0 {
		t.Errorf("Received unexpected message: %x", buffer.Bytes())
	}
}
