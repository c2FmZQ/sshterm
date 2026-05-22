//go:build x11 && !wasm

package x11

import (
	"bytes"
	"testing"

	"github.com/c2FmZQ/sshterm/internal/x11/wire"
	"github.com/stretchr/testify/assert"
)

func TestEventDelivery_SingleClient_CorrectWindow(t *testing.T) {
	server, client, _, clientBuffer := setupTestServerWithClient(t)

	// Create two windows for the client
	windowID1 := clientXID(client, 100)
	windowID2 := clientXID(client, 200)
	server.windows[windowID1] = &window{xid: windowID1, attributes: wire.WindowAttributes{EventMask: wire.ButtonPressMask}, eventMasks: map[uint32]uint32{client.id: wire.ButtonPressMask}}
	server.windows[windowID2] = &window{xid: windowID2, attributes: wire.WindowAttributes{EventMask: wire.KeyPressMask}, eventMasks: map[uint32]uint32{client.id: wire.KeyPressMask}}

	// --- Test Mouse Event Delivery ---
	server.SendMouseEvent(windowID1, "mousedown", 10, 10, 1)
	assert.True(t, clientBuffer.Len() > 0, "Client buffer should not be empty after mouse event")
	msg, err := wire.ParseEvent(clientBuffer.Bytes(), client.byteOrder)
	assert.NoError(t, err, "Failed to parse event from client buffer")
	buttonEvent, ok := msg.(*wire.ButtonPressEvent)
	assert.True(t, ok, "Expected a ButtonPressEvent")
	assert.Equal(t, uint32(windowID1), buttonEvent.Event, "Event should be for window 1")
	clientBuffer.Reset()

	// --- Test Keyboard Event Delivery ---
	server.inputFocus = windowID2 // Set focus to the window expecting the event
	server.SendKeyboardEvent(windowID2, "keydown", "KeyA", false, false, false, false)
	assert.True(t, clientBuffer.Len() > 0, "Client buffer should not be empty after keyboard event")
	msg, err = wire.ParseEvent(clientBuffer.Bytes(), client.byteOrder)
	assert.NoError(t, err, "Failed to parse event from client buffer")
	keyEvent, ok := msg.(*wire.KeyEvent)
	assert.True(t, ok, "Expected a KeyEvent")
	assert.Equal(t, uint32(windowID2), keyEvent.Event, "Event should be for window 2")
}

func TestEventDelivery_PassiveButtonGrab(t *testing.T) {
	server, client, _, clientBuffer := setupTestServerWithClient(t)
	windowID := clientXID(client, 1)
	server.windows[windowID] = &window{xid: windowID, eventMasks: make(map[uint32]uint32)}

	// Client grabs button 1 on the window
	req := &wire.GrabButtonRequest{
		GrabWindow: wire.Window(windowID),
		EventMask:  wire.ButtonPressMask,
		Button:     1,
		Modifiers:  wire.AnyModifier,
	}
	server.handleGrabButton(client, req, 1)

	// Send a mouse event that should activate the grab
	server.SendMouseEvent(windowID, "mousedown", 20, 20, 1)
	assert.True(t, clientBuffer.Len() > 0, "Client buffer should not be empty")

	// Verify the event was delivered
	msg, err := wire.ParseEvent(clientBuffer.Bytes(), client.byteOrder)
	assert.NoError(t, err)
	buttonEvent, ok := msg.(*wire.ButtonPressEvent)
	assert.True(t, ok)
	assert.Equal(t, uint32(windowID), buttonEvent.Event, "Event delivered to wrong window")
}

func TestEventDelivery_PassiveKeyGrab(t *testing.T) {
	server, client, _, clientBuffer := setupTestServerWithClient(t)
	windowID := clientXID(client, 1)
	server.windows[windowID] = &window{xid: windowID, eventMasks: make(map[uint32]uint32)}

	req := &wire.GrabKeyRequest{
		GrabWindow: wire.Window(windowID),
		Key:        54, // 'c'
		Modifiers:  wire.AnyModifier,
	}
	server.handleGrabKey(client, req, 1)

	server.SendKeyboardEvent(windowID, "keydown", "KeyC", false, false, false, false)
	assert.True(t, clientBuffer.Len() > 0)

	msg, err := wire.ParseEvent(clientBuffer.Bytes(), client.byteOrder)
	assert.NoError(t, err)
	keyEvent, ok := msg.(*wire.KeyEvent)
	assert.True(t, ok)
	assert.Equal(t, uint32(windowID), keyEvent.Event, "Event delivered to wrong window")
}

func TestEventDelivery_ActivePointerGrab(t *testing.T) {
	server, _, _, clientBuffers := setupTestServerWithClients(t, 2)
	client1, client2 := server.clients[1], server.clients[2]
	client1Buffer := clientBuffers[0]
	client2Buffer := clientBuffers[1]

	windowID := clientXID(client1, 2) // Window belongs to client 1
	server.windows[windowID] = &window{xid: windowID, attributes: wire.WindowAttributes{EventMask: wire.ButtonPressMask}, eventMasks: map[uint32]uint32{client1.id: wire.ButtonPressMask}}

	// Client 2 grabs the pointer on client 1's window
	grabReq := &wire.GrabPointerRequest{
		GrabWindow:  wire.Window(windowID),
		EventMask:   wire.ButtonPressMask,
		PointerMode: wire.GrabModeAsync,
	}
	reply := server.handleGrabPointer(client2, grabReq, 1)
	grabReply, ok := reply.(*wire.GrabPointerReply)
	assert.True(t, ok)
	assert.Equal(t, byte(0), grabReply.Status) // GrabStatusSuccess

	// Send a mouse event to the window
	server.SendMouseEvent(windowID, "mousedown", 5, 5, 1)

	// Assert that client 2 (the grabber) got the event
	assert.True(t, client2Buffer.Len() > 0, "Grabbing client should receive event")
	msg, _ := wire.ParseEvent(client2Buffer.Bytes(), client2.byteOrder)
	buttonEvent, _ := msg.(*wire.ButtonPressEvent)
	assert.Equal(t, uint32(windowID), buttonEvent.Event, "Event should be for the grabbed window")

	// Assert that client 1 (the owner) did NOT get the event
	assert.Equal(t, 0, client1Buffer.Len(), "Owner client should not receive event when ownerEvents is false")
}

func TestEventDelivery_ActiveKeyboardGrab(t *testing.T) {
	server, _, _, clientBuffers := setupTestServerWithClients(t, 2)
	client1, client2 := server.clients[1], server.clients[2]
	client1Buffer := clientBuffers[0]
	client2Buffer := clientBuffers[1]

	windowID := clientXID(client1, 2) // Window belongs to client 1
	server.windows[windowID] = &window{xid: windowID, attributes: wire.WindowAttributes{EventMask: wire.KeyPressMask}, eventMasks: map[uint32]uint32{client1.id: wire.KeyPressMask}}

	// Client 2 grabs the keyboard on client 1's window
	grabReq := &wire.GrabKeyboardRequest{
		GrabWindow:   wire.Window(windowID),
		KeyboardMode: wire.GrabModeAsync,
	}
	reply := server.handleGrabKeyboard(client2, grabReq, 1)
	grabReply, ok := reply.(*wire.GrabKeyboardReply)
	assert.True(t, ok)
	assert.Equal(t, byte(0), grabReply.Status) // GrabStatusSuccess

	// Send a key event to the window
	server.SendKeyboardEvent(windowID, "keydown", "KeyD", false, false, false, false)

	// Assert that client 2 (the grabber) got the event
	assert.True(t, client2Buffer.Len() > 0, "Grabbing client should receive event")
	msg, _ := wire.ParseEvent(client2Buffer.Bytes(), client2.byteOrder)
	keyEvent, _ := msg.(*wire.KeyEvent)
	assert.Equal(t, uint32(windowID), keyEvent.Event, "Event should be for the grabbed window")

	// Assert that client 1 (the owner) did NOT get the event
	assert.Equal(t, 0, client1Buffer.Len(), "Owner client should not receive event")
}

func TestEventDelivery_OwnerEventsTrue(t *testing.T) {
	server, _, _, clientBuffers := setupTestServerWithClients(t, 2)
	client1, client2 := server.clients[1], server.clients[2]
	client1Buffer := clientBuffers[0]
	client2Buffer := clientBuffers[1]

	windowID := clientXID(client1, 1) // Window belongs to client 1
	server.windows[windowID] = &window{xid: windowID, attributes: wire.WindowAttributes{EventMask: wire.ButtonPressMask}, eventMasks: map[uint32]uint32{client1.id: wire.ButtonPressMask}}

	// Client 2 grabs button 1 on the window with ownerEvents = true
	req := &wire.GrabButtonRequest{
		GrabWindow:  wire.Window(windowID),
		EventMask:   wire.ButtonPressMask,
		Button:      1,
		Modifiers:   wire.AnyModifier,
		OwnerEvents: true,
	}
	server.handleGrabButton(client2, req, 1)

	// Send a mouse event that activates the grab
	server.SendMouseEvent(windowID, "mousedown", 20, 20, 1)

	// Check that BOTH clients received the event
	assert.True(t, client1Buffer.Len() > 0, "Client 1 (owner) should receive the event")
	assert.True(t, client2Buffer.Len() > 0, "Client 2 (grabber) should receive the event")

	// Verify the event content for both
	for i, buffer := range []*bytes.Buffer{client1Buffer, client2Buffer} {
		client := server.clients[uint32(i+1)]
		msg, err := wire.ParseEvent(buffer.Bytes(), client.byteOrder)
		assert.NoError(t, err, "Failed to parse event for client %d", i+1)
		buttonEvent, ok := msg.(*wire.ButtonPressEvent)
		assert.True(t, ok, "Expected ButtonPressEvent for client %d", i+1)
		assert.Equal(t, uint32(windowID), buttonEvent.Event, "Event for client %d has wrong window ID", i+1)
	}
}
