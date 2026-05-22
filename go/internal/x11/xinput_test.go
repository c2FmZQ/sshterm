//go:build x11 && !wasm

package x11

import (
	"testing"

	"github.com/c2FmZQ/sshterm/internal/x11/wire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGrabDeviceKeyRequest(t *testing.T) {
	server, _, _, _ := setupTestServerWithClient(t)
	client := server.clients[1]

	windowID := clientXID(client, 10)
	server.windows[windowID] = &window{
		xid: windowID,
	}

	req := &wire.GrabDeviceKeyRequest{
		GrabWindow: wire.Window(windowID),
		Modifiers:  wire.ShiftMask,
		Key:        38, // KeyA
		DeviceID:   3,  // Virtual Keyboard
	}
	reply := server.handleXInputRequest(client, req, 2)
	if reply != nil {
		if err, ok := reply.(wire.Error); ok {
			t.Fatalf("GrabDeviceKeyRequest failed: %v", err)
		}
	}

	grabs, ok := server.passiveDeviceGrabs[windowID]
	assert.True(t, ok, "No passive device grabs found for window")
	require.Len(t, grabs, 1, "Expected 1 passive device grab")
	assert.Equal(t, byte(3), grabs[0].deviceID)
	assert.Equal(t, wire.KeyCode(38), grabs[0].key)
	assert.Equal(t, uint16(wire.ShiftMask), grabs[0].modifiers)
}

func TestUngrabDeviceKeyRequest(t *testing.T) {
	server, _, _, _ := setupTestServerWithClient(t)
	client := server.clients[1]

	windowID := clientXID(client, 10)
	server.windows[windowID] = &window{
		xid: windowID,
	}
	server.passiveDeviceGrabs[windowID] = []*passiveDeviceGrab{
		{
			deviceID:  3,
			key:       38,
			modifiers: wire.ShiftMask,
		},
	}

	req := &wire.UngrabDeviceKeyRequest{
		GrabWindow: wire.Window(windowID),
		Modifiers:  wire.ShiftMask,
		Key:        38, // KeyA
		DeviceID:   3,  // Virtual Keyboard
	}
	server.handleXInputRequest(client, req, 3)

	assert.Len(t, server.passiveDeviceGrabs[windowID], 0, "Expected passive device grab to be removed")
}

func TestXIQueryPointer_DeepTraversal(t *testing.T) {
	server, _, _, clientBuffer := setupTestServerWithClient(t)
	client := server.clients[1]

	// Window hierarchy: root -> parent (10,10) -> child (20,20) -> grandchild (30,30)
	parentID := clientXID(client, 100)
	childID := clientXID(client, 101)
	grandchildID := clientXID(client, 102)

	server.windows[parentID] = &window{
		xid:      parentID,
		parent:   xID(server.rootWindowID()),
		x:        10,
		y:        10,
		width:    100,
		height:   100,
		mapped:   true,
		children: []xID{childID},
	}
	server.windows[childID] = &window{
		xid:      childID,
		parent:   parentID,
		x:        10,
		y:        10,
		width:    50,
		height:   50,
		mapped:   true,
		children: []xID{grandchildID},
	}
	server.windows[grandchildID] = &window{
		xid:    grandchildID,
		parent: childID,
		x:      10,
		y:      10,
		width:  20,
		height: 20,
		mapped: true,
	}
	// Stacking order
	server.windows[xID(server.rootWindowID())].children = []xID{parentID}
	server.windows[parentID].children = []xID{childID}
	server.windows[childID].children = []xID{grandchildID}

	// Pointer at (35, 35) absolute, which is inside the grandchild
	server.pointerX = 35
	server.pointerY = 35

	// Query relative to the parent window
	req := &wire.XIQueryPointerRequest{
		Window:   wire.Window(parentID),
		DeviceID: 2, // Virtual Pointer
	}
	reply := server.handleXInputRequest(client, req, 2)
	assert.NotNil(t, reply, "XIQueryPointer should return a reply")

	encodedReply := reply.EncodeMessage(client.byteOrder)
	clientBuffer.Write(encodedReply)

	opcodes := wire.Opcodes{Major: wire.XInputOpcode, Minor: wire.XIQueryPointer}
	replyMsg, err := wire.ParseReply(opcodes, clientBuffer.Bytes(), client.byteOrder)
	assert.NoError(t, err, "Failed to parse XIQueryPointerReply")
	queryReply, ok := replyMsg.(*wire.XIQueryPointerReply)
	if assert.True(t, ok, "Expected *wire.XIQueryPointerReply, got %T", replyMsg) {
		assert.Equal(t, uint32(childID), uint32(queryReply.Child), "Expected direct child to be the child under the pointer")
		// WinX/Y should be relative to parent window (10, 10)
		// Pointer (35,35) - Parent (10,10) = (25, 25)
		assert.Equal(t, int32(25<<16), queryReply.WinX, "WinX mismatch")
		assert.Equal(t, int32(25<<16), queryReply.WinY, "WinY mismatch")
	}
}

func TestDeviceBellRequest(t *testing.T) {
	server, _, mockFrontend, _ := setupTestServerWithClient(t)
	client := server.clients[1]

	req := &wire.DeviceBellRequest{
		DeviceID:      3,
		FeedbackID:    1,
		FeedbackClass: 2,
		Percent:       50,
	}
	server.handleXInputRequest(client, req, 2)

	assert.Len(t, mockFrontend.DeviceBellCalls, 1, "Expected DeviceBell to be called on the frontend")
	call := mockFrontend.DeviceBellCalls[0]
	assert.Equal(t, byte(3), call[0])
	assert.Equal(t, byte(1), call[1])
	assert.Equal(t, byte(2), call[2])
	assert.Equal(t, int8(50), call[3])
}

func TestXIChangeHierarchyRequest(t *testing.T) {
	server, _, mockFrontend, _ := setupTestServerWithClient(t)
	client := server.clients[1]

	req := &wire.XIChangeHierarchyRequest{
		Changes: []wire.XIChangeHierarchyChange{
			&wire.XIDetachSlave{DeviceID: 5},
		},
	}
	server.handleXInputRequest(client, req, 2)

	assert.Len(t, mockFrontend.XIChangeHierarchyCalls, 1, "Expected XIChangeHierarchy to be called on the frontend")
	call := mockFrontend.XIChangeHierarchyCalls[0]
	changes := call[0].([]wire.XIChangeHierarchyChange)
	assert.Len(t, changes, 1)
	detach, ok := changes[0].(*wire.XIDetachSlave)
	assert.True(t, ok, "Expected XIDetachSlave change")
	assert.Equal(t, uint16(5), detach.DeviceID)
}

func TestChangeFeedbackControlRequest(t *testing.T) {
	server, _, mockFrontend, _ := setupTestServerWithClient(t)
	client := server.clients[1]

	req := &wire.ChangeFeedbackControlRequest{
		DeviceID:  3,
		ControlID: 1,
		Mask:      0xff,
		Control:   []byte{1, 2, 3},
	}
	server.handleXInputRequest(client, req, 2)

	assert.Len(t, mockFrontend.ChangeFeedbackControlCalls, 1, "Expected ChangeFeedbackControl to be called on the frontend")
	call := mockFrontend.ChangeFeedbackControlCalls[0]
	assert.Equal(t, byte(3), call[0])
	assert.Equal(t, byte(1), call[1])
	assert.Equal(t, uint32(0xff), call[2])
	assert.Equal(t, []byte{1, 2, 3}, call[3])
}

func TestChangeDeviceKeyMappingRequest(t *testing.T) {
	server, _, mockFrontend, _ := setupTestServerWithClient(t)
	client := server.clients[1]

	req := &wire.ChangeDeviceKeyMappingRequest{
		DeviceID:          3,
		FirstKey:          10,
		KeysymsPerKeycode: 1,
		KeycodeCount:      1,
		Keysyms:           []uint32{123},
	}
	server.handleXInputRequest(client, req, 2)

	assert.Len(t, mockFrontend.ChangeDeviceKeyMappingCalls, 1, "Expected ChangeDeviceKeyMapping to be called on the frontend")
	call := mockFrontend.ChangeDeviceKeyMappingCalls[0]
	assert.Equal(t, byte(3), call[0])
	assert.Equal(t, byte(10), call[1])
	assert.Equal(t, byte(1), call[2])
	assert.Equal(t, byte(1), call[3])
	assert.Equal(t, []uint32{123}, call[4])
}

func TestSetDeviceModifierMappingRequest(t *testing.T) {
	server, _, mockFrontend, clientBuffer := setupTestServerWithClient(t)
	client := server.clients[1]

	req := &wire.SetDeviceModifierMappingRequest{
		DeviceID: 3,
		Keycodes: []byte{1, 2, 3},
	}
	reply := server.handleXInputRequest(client, req, 2)
	assert.NotNil(t, reply, "SetDeviceModifierMapping should return a reply")

	encodedReply := reply.EncodeMessage(client.byteOrder)
	clientBuffer.Write(encodedReply)

	opcodes := wire.Opcodes{Major: wire.XInputOpcode, Minor: wire.XSetDeviceModifierMapping}
	replyMsg, err := wire.ParseReply(opcodes, clientBuffer.Bytes(), client.byteOrder)
	if assert.NoError(t, err, "Failed to parse SetDeviceModifierMappingReply") {
		modReply, ok := replyMsg.(*wire.SetDeviceModifierMappingReply)
		if assert.True(t, ok, "Expected *wire.SetDeviceModifierMappingReply, got %T", replyMsg) {
			assert.Equal(t, byte(0), modReply.Status, "Expected success status")
		}
	}

	assert.Len(t, mockFrontend.SetDeviceModifierMappingCalls, 1, "Expected SetDeviceModifierMapping to be called on the frontend")
	call := mockFrontend.SetDeviceModifierMappingCalls[0]
	assert.Equal(t, byte(3), call[0])
	assert.Equal(t, []byte{1, 2, 3}, call[1])
}

func TestSetDeviceButtonMappingRequest(t *testing.T) {
	server, _, mockFrontend, clientBuffer := setupTestServerWithClient(t)
	client := server.clients[1]

	req := &wire.SetDeviceButtonMappingRequest{
		DeviceID: 2,
		Map:      []byte{1, 3, 2},
	}
	reply := server.handleXInputRequest(client, req, 2)
	assert.NotNil(t, reply, "SetDeviceButtonMapping should return a reply")

	encodedReply := reply.EncodeMessage(client.byteOrder)
	clientBuffer.Write(encodedReply)

	opcodes := wire.Opcodes{Major: wire.XInputOpcode, Minor: wire.XSetDeviceButtonMapping}
	replyMsg, err := wire.ParseReply(opcodes, clientBuffer.Bytes(), client.byteOrder)
	assert.NoError(t, err, "Failed to parse SetDeviceButtonMappingReply")
	buttonReply, ok := replyMsg.(*wire.SetDeviceButtonMappingReply)
	assert.True(t, ok, "Expected *wire.SetDeviceButtonMappingReply, got %T", replyMsg)
	assert.Equal(t, byte(0), buttonReply.Status, "Expected success status")

	assert.Len(t, mockFrontend.SetDeviceButtonMappingCalls, 1, "Expected SetDeviceButtonMapping to be called on the frontend")
	call := mockFrontend.SetDeviceButtonMappingCalls[0]
	assert.Equal(t, byte(2), call[0])
	assert.Equal(t, []byte{1, 3, 2}, call[1])
}

func TestGetFeedbackControlRequest(t *testing.T) {
	server, _, mockFrontend, clientBuffer := setupTestServerWithClient(t)
	client := server.clients[1]

	req := &wire.GetFeedbackControlRequest{
		DeviceID: 3,
	}
	reply := server.handleXInputRequest(client, req, 2)
	assert.NotNil(t, reply, "GetFeedbackControl should return a reply")

	encodedReply := reply.EncodeMessage(client.byteOrder)
	clientBuffer.Write(encodedReply)

	opcodes := wire.Opcodes{Major: wire.XInputOpcode, Minor: wire.XGetFeedbackControl}
	replyMsg, err := wire.ParseReply(opcodes, clientBuffer.Bytes(), client.byteOrder)
	assert.NoError(t, err, "Failed to parse GetFeedbackControlReply")
	_, ok := replyMsg.(*wire.GetFeedbackControlReply)
	assert.True(t, ok, "Expected *wire.GetFeedbackControlReply, got %T", replyMsg)

	assert.Len(t, mockFrontend.GetFeedbackControlCalls, 1, "Expected GetFeedbackControl to be called on the frontend")
	call := mockFrontend.GetFeedbackControlCalls[0]
	assert.Equal(t, byte(3), call[0])
}

func TestGetDeviceKeyMappingRequest(t *testing.T) {
	server, _, mockFrontend, clientBuffer := setupTestServerWithClient(t)
	client := server.clients[1]

	req := &wire.GetDeviceKeyMappingRequest{
		DeviceID: 3,
		FirstKey: 10,
		Count:    2,
	}
	reply := server.handleXInputRequest(client, req, 2)
	assert.NotNil(t, reply, "GetDeviceKeyMapping should return a reply")

	encodedReply := reply.EncodeMessage(client.byteOrder)
	clientBuffer.Write(encodedReply)

	opcodes := wire.Opcodes{Major: wire.XInputOpcode, Minor: wire.XGetDeviceKeyMapping}
	replyMsg, err := wire.ParseReply(opcodes, clientBuffer.Bytes(), client.byteOrder)
	assert.NoError(t, err, "Failed to parse GetDeviceKeyMappingReply")
	getReply, ok := replyMsg.(*wire.GetDeviceKeyMappingReply)
	assert.True(t, ok, "Expected *wire.GetDeviceKeyMappingReply, got %T", replyMsg)
	assert.Equal(t, byte(1), getReply.KeysymsPerKeycode, "KeysymsPerKeycode mismatch")
	assert.Len(t, getReply.Keysyms, 2, "Keysyms length mismatch")

	assert.Len(t, mockFrontend.GetDeviceKeyMappingCalls, 1, "Expected GetDeviceKeyMapping to be called on the frontend")
	call := mockFrontend.GetDeviceKeyMappingCalls[0]
	assert.Equal(t, byte(3), call[0])
	assert.Equal(t, byte(10), call[1])
	assert.Equal(t, byte(2), call[2])
}

func TestGetDeviceModifierMappingRequest(t *testing.T) {
	server, _, mockFrontend, clientBuffer := setupTestServerWithClient(t)
	client := server.clients[1]

	req := &wire.GetDeviceModifierMappingRequest{
		DeviceID: 3,
	}
	reply := server.handleXInputRequest(client, req, 2)
	assert.NotNil(t, reply, "GetDeviceModifierMapping should return a reply")

	encodedReply := reply.EncodeMessage(client.byteOrder)
	clientBuffer.Write(encodedReply)

	opcodes := wire.Opcodes{Major: wire.XInputOpcode, Minor: wire.XGetDeviceModifierMapping}
	replyMsg, err := wire.ParseReply(opcodes, clientBuffer.Bytes(), client.byteOrder)
	assert.NoError(t, err, "Failed to parse GetDeviceModifierMappingReply")
	_, ok := replyMsg.(*wire.GetDeviceModifierMappingReply)
	assert.True(t, ok, "Expected *wire.GetDeviceModifierMappingReply, got %T", replyMsg)

	assert.Len(t, mockFrontend.GetDeviceModifierMappingCalls, 1, "Expected GetDeviceModifierMapping to be called on the frontend")
	call := mockFrontend.GetDeviceModifierMappingCalls[0]
	assert.Equal(t, byte(3), call[0])
}

func TestGetDeviceButtonMappingRequest(t *testing.T) {
	server, _, mockFrontend, clientBuffer := setupTestServerWithClient(t)
	client := server.clients[1]

	req := &wire.GetDeviceButtonMappingRequest{
		DeviceID: 2,
	}
	reply := server.handleXInputRequest(client, req, 2)
	assert.NotNil(t, reply, "GetDeviceButtonMapping should return a reply")

	encodedReply := reply.EncodeMessage(client.byteOrder)
	clientBuffer.Write(encodedReply)

	opcodes := wire.Opcodes{Major: wire.XInputOpcode, Minor: wire.XGetDeviceButtonMapping}
	replyMsg, err := wire.ParseReply(opcodes, clientBuffer.Bytes(), client.byteOrder)
	assert.NoError(t, err, "Failed to parse GetDeviceButtonMappingReply")
	_, ok := replyMsg.(*wire.GetDeviceButtonMappingReply)
	assert.True(t, ok, "Expected *wire.GetDeviceButtonMappingReply, got %T", replyMsg)

	assert.Len(t, mockFrontend.GetDeviceButtonMappingCalls, 1, "Expected GetDeviceButtonMapping to be called on the frontend")
	call := mockFrontend.GetDeviceButtonMappingCalls[0]
	assert.Equal(t, byte(2), call[0])
}

func TestQueryDeviceStateRequest(t *testing.T) {
	server, _, mockFrontend, clientBuffer := setupTestServerWithClient(t)
	client := server.clients[1]

	req := &wire.QueryDeviceStateRequest{
		DeviceID: 3,
	}
	reply := server.handleXInputRequest(client, req, 2)
	assert.NotNil(t, reply, "QueryDeviceState should return a reply")

	encodedReply := reply.EncodeMessage(client.byteOrder)
	clientBuffer.Write(encodedReply)

	opcodes := wire.Opcodes{Major: wire.XInputOpcode, Minor: wire.XQueryDeviceState}
	replyMsg, err := wire.ParseReply(opcodes, clientBuffer.Bytes(), client.byteOrder)
	assert.NoError(t, err, "Failed to parse QueryDeviceStateReply")
	_, ok := replyMsg.(*wire.QueryDeviceStateReply)
	assert.True(t, ok, "Expected *wire.QueryDeviceStateReply, got %T", replyMsg)

	assert.Len(t, mockFrontend.QueryDeviceStateCalls, 1, "Expected QueryDeviceState to be called on the frontend")
	call := mockFrontend.QueryDeviceStateCalls[0]
	assert.Equal(t, byte(3), call[0])
}

func TestGetSetDeviceFocusRequest(t *testing.T) {
	server, _, _, clientBuffer := setupTestServerWithClient(t)
	client := server.clients[1]

	// 1. Set the focus
	focusWindowID := clientXID(client, 10)
	setReq := &wire.SetDeviceFocusRequest{
		Focus:    wire.Window(focusWindowID),
		DeviceID: 3, // Virtual Keyboard
	}
	server.handleXInputRequest(client, setReq, 2)
	assert.Equal(t, focusWindowID, server.inputFocus, "inputFocus was not set correctly")

	// 2. Get the focus and verify
	getReq := &wire.GetDeviceFocusRequest{DeviceID: 3}
	reply := server.handleXInputRequest(client, getReq, 3)
	assert.NotNil(t, reply, "GetDeviceFocus should return a reply")

	encodedReply := reply.EncodeMessage(client.byteOrder)
	clientBuffer.Write(encodedReply)

	opcodes := wire.Opcodes{Major: wire.XInputOpcode, Minor: wire.XGetDeviceFocus}
	replyMsg, err := wire.ParseReply(opcodes, clientBuffer.Bytes(), client.byteOrder)
	assert.NoError(t, err, "Failed to parse GetDeviceFocusReply")
	focusReply, ok := replyMsg.(*wire.GetDeviceFocusReply)
	assert.True(t, ok, "Expected *wire.GetDeviceFocusReply, got %T", replyMsg)

	assert.Equal(t, uint32(focusWindowID), focusReply.Focus, "GetDeviceFocus returned incorrect focus window")
}

func TestGrabDeviceButtonRequest(t *testing.T) {
	server, _, _, _ := setupTestServerWithClient(t)
	client := server.clients[1]

	windowID := clientXID(client, 10)
	server.windows[windowID] = &window{
		xid: windowID,
	}

	req := &wire.GrabDeviceButtonRequest{
		GrabWindow: wire.Window(windowID),
		Modifiers:  wire.ShiftMask,
		Button:     1,
		DeviceID:   2, // Virtual Pointer
	}
	server.handleXInputRequest(client, req, 2)

	grabs, ok := server.passiveDeviceGrabs[windowID]
	assert.True(t, ok, "No passive device grabs found for window")
	assert.Len(t, grabs, 1, "Expected 1 passive device grab")
	assert.Equal(t, byte(2), grabs[0].deviceID)
	assert.Equal(t, byte(1), grabs[0].button)
	assert.Equal(t, uint16(wire.ShiftMask), grabs[0].modifiers)
}

func TestUngrabDeviceButtonRequest(t *testing.T) {
	server, _, _, _ := setupTestServerWithClient(t)
	client := server.clients[1]

	windowID := clientXID(client, 10)
	server.windows[windowID] = &window{
		xid: windowID,
	}
	server.passiveDeviceGrabs[windowID] = []*passiveDeviceGrab{
		{
			deviceID:  2,
			button:    1,
			modifiers: wire.ShiftMask,
		},
	}

	req := &wire.UngrabDeviceButtonRequest{
		GrabWindow: wire.Window(windowID),
		Modifiers:  wire.ShiftMask,
		Button:     1,
		DeviceID:   2,
	}
	server.handleXInputRequest(client, req, 3)

	assert.Len(t, server.passiveDeviceGrabs[windowID], 0, "Expected passive device grab to be removed")
}
