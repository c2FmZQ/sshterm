//go:build x11 && !wasm

package x11

import (
	"testing"

	"github.com/c2FmZQ/sshterm/internal/x11/wire"
	"github.com/stretchr/testify/assert"
)

func TestXIGrabDeviceRequest(t *testing.T) {
	server, _, _, clientBuffer := setupTestServerWithClient(t)
	client := server.clients[1]

	windowID := clientXID(client, 10)
	server.windows[windowID] = &window{
		xid: windowID,
	}

	req := &wire.XIGrabDeviceRequest{
		DeviceID:         2, // Virtual Pointer
		GrabWindow:       wire.Window(windowID),
		Time:             0,
		Cursor:           0,
		GrabMode:         1,
		PairedDeviceMode: 1,
		OwnerEvents:      true,
		MaskLen:          1,
		Mask:             []byte{0x04, 0x00, 0x00, 0x00}, // ButtonPress
	}
	reply := server.handleXInputRequest(client, req, 2)
	if reply == nil {
		t.Fatal("XIGrabDevice should return a reply")
	}
	if err, ok := reply.(wire.Error); ok {
		t.Fatalf("XIGrabDevice failed: %v", err)
	}

	encodedReply := reply.EncodeMessage(client.byteOrder)
	clientBuffer.Write(encodedReply)

	opcodes := wire.Opcodes{Major: wire.XInputOpcode, Minor: wire.XIGrabDevice}
	replyMsg, err := wire.ParseReply(opcodes, clientBuffer.Bytes(), client.byteOrder)
	assert.NoError(t, err, "Failed to parse XIGrabDeviceReply")
	grabReply, ok := replyMsg.(*wire.XIGrabDeviceReply)
	assert.True(t, ok, "Expected *wire.XIGrabDeviceReply, got %T", replyMsg)
	assert.Equal(t, byte(wire.GrabSuccess), grabReply.Status, "Expected success status")

	assert.Contains(t, server.deviceGrabs, byte(2))
	grab := server.deviceGrabs[2]
	assert.Equal(t, windowID, grab.window)
	assert.True(t, grab.ownerEvents)
}

func TestXIUngrabDeviceRequest(t *testing.T) {
	server, _, _, _ := setupTestServerWithClient(t)
	client := server.clients[1]

	windowID := clientXID(client, 10)
	server.deviceGrabs[2] = &deviceGrab{
		clientID: client.id,
		window:   windowID,
	}

	req := &wire.XIUngrabDeviceRequest{
		DeviceID: 2,
		Time:     0,
	}
	server.handleXInputRequest(client, req, 3)

	assert.NotContains(t, server.deviceGrabs, byte(2), "Expected device grab to be removed")
}

func TestXIPassiveGrabDeviceRequest(t *testing.T) {
	server, _, _, clientBuffer := setupTestServerWithClient(t)
	client := server.clients[1]

	windowID := clientXID(client, 10)
	server.windows[windowID] = &window{
		xid: windowID,
	}

	req := &wire.XIPassiveGrabDeviceRequest{
		DeviceID:         2,
		GrabWindow:       wire.Window(windowID),
		Time:             0,
		Cursor:           0,
		Detail:           1, // Button 1
		NumModifiers:     0, // Any modifier
		MaskLen:          1,
		GrabType:         wire.XI_ButtonPress,
		GrabMode:         1,
		PairedDeviceMode: 1,
		OwnerEvents:      true,
		Mask:             []byte{0x04, 0x00, 0x00, 0x00},
		Modifiers:        []byte{},
	}

	reply := server.handleXInputRequest(client, req, 2)
	if reply == nil {
		t.Fatal("XIPassiveGrabDevice should return a reply")
	}

	encodedReply := reply.EncodeMessage(client.byteOrder)
	clientBuffer.Write(encodedReply)

	opcodes := wire.Opcodes{Major: wire.XInputOpcode, Minor: wire.XIPassiveGrabDevice}
	replyMsg, err := wire.ParseReply(opcodes, clientBuffer.Bytes(), client.byteOrder)
	assert.NoError(t, err, "Failed to parse XIPassiveGrabDeviceReply")

	pReply, ok := replyMsg.(*wire.XIPassiveGrabDeviceReply)
	assert.True(t, ok, "Expected *wire.XIPassiveGrabDeviceReply")
	assert.Equal(t, uint16(0), pReply.NumModifiers)

	// Check state
	grabs, ok := server.passiveDeviceGrabs[windowID]
	assert.True(t, ok)
	found := false
	for _, g := range grabs {
		if g.deviceID == 2 && g.detail == 1 && len(g.xi2Modifiers) == 0 && g.xi2GrabType == int(wire.XI_ButtonPress) {
			found = true
			break
		}
	}
	assert.True(t, found, "Expected passive grab with AnyModifier")
}

func TestXIPassiveUngrabDeviceRequest(t *testing.T) {
	server, _, _, _ := setupTestServerWithClient(t)
	client := server.clients[1]

	windowID := clientXID(client, 10)
	server.windows[windowID] = &window{
		xid: windowID,
	}

	server.passiveDeviceGrabs[windowID] = []*passiveDeviceGrab{
		{
			clientID:     client.id,
			deviceID:     2,
			detail:       1,
			xi2Modifiers: []uint32{},
			xi2GrabType:  int(wire.XI_ButtonPress),
		},
	}

	req := &wire.XIPassiveUngrabDeviceRequest{
		DeviceID:     2,
		GrabWindow:   wire.Window(windowID),
		Detail:       1,
		NumModifiers: 0,
		GrabType:     wire.XI_ButtonPress,
		Modifiers:    []byte{},
	}

	server.handleXInputRequest(client, req, 3)

	assert.Len(t, server.passiveDeviceGrabs[windowID], 0, "Expected passive grab to be removed")
}

func TestXIAllowEventsRequest(t *testing.T) {
	server, _, mockFrontend, _ := setupTestServerWithClient(t)
	client := server.clients[1]

	req := &wire.XIAllowEventsRequest{
		DeviceID:   2,
		EventMode:  1, // AsyncDevice
		Time:       0,
		TouchID:    0,
		GrabWindow: 0,
	}

	server.handleXInputRequest(client, req, 4)

	// We expect AllowEvents to be called on frontend
	assert.Len(t, mockFrontend.AllowEventsCalls, 1)
	assert.Equal(t, uint32(1), mockFrontend.AllowEventsCalls[0][0]) // clientID
	assert.Equal(t, byte(1), mockFrontend.AllowEventsCalls[0][1])   // mode
}
