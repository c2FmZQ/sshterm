//go:build x11 && !wasm

package x11

import (
	"testing"

	"github.com/c2FmZQ/sshterm/internal/x11/wire"
	"github.com/stretchr/testify/assert"
)

func TestAllowEvents_Queuing(t *testing.T) {
	server, client, _, clientBuffer := setupTestServerWithClient(t)
	windowID := clientXID(client, 1)
	server.windows[windowID] = &window{
		xid:        windowID,
		mapped:     true,
		width:      100,
		height:     100,
		attributes: wire.WindowAttributes{EventMask: wire.PointerMotionMask | wire.ButtonPressMask},
	}
	server.pointerX = 50
	server.pointerY = 50

	// 1. Grab pointer in Sync mode
	grabReq := &wire.GrabPointerRequest{
		GrabWindow:   wire.Window(windowID),
		EventMask:    wire.PointerMotionMask | wire.ButtonPressMask,
		PointerMode:  wire.GrabModeSync,
		KeyboardMode: wire.GrabModeAsync,
	}
	server.handleGrabPointer(client, grabReq, 1)
	assert.True(t, server.pointerFrozen, "Pointer should be frozen after Sync grab")

	// 2. Send mouse events - should be queued
	clientBuffer.Reset()
	server.SendMouseEvent(windowID, "mousemove", 10, 10, 0)
	assert.Equal(t, 0, clientBuffer.Len(), "Event should be queued, not sent")
	assert.Equal(t, 1, len(server.pointerEventQueue), "Queue should have 1 event")

	// 3. AllowEvents (AsyncPointer)
	allowReq := &wire.AllowEventsRequest{
		Mode: wire.AsyncPointer,
	}
	server.handleAllowEvents(client, allowReq, 2)
	assert.False(t, server.pointerFrozen, "Pointer should be unfrozen")
	assert.Equal(t, 0, len(server.pointerEventQueue), "Queue should be empty")
	assert.True(t, clientBuffer.Len() > 0, "Queued event should be flushed to client")

	// Verify the event
	msg, err := wire.ParseEvent(clientBuffer.Bytes(), client.byteOrder)
	assert.NoError(t, err)
	_, ok := msg.(*wire.MotionNotifyEvent)
	assert.True(t, ok, "Expected MotionNotifyEvent")
}

func TestAllowEvents_KeyboardQueuing(t *testing.T) {
	server, client, _, clientBuffer := setupTestServerWithClient(t)
	windowID := clientXID(client, 1)
	server.windows[windowID] = &window{
		xid:        windowID,
		attributes: wire.WindowAttributes{EventMask: wire.KeyPressMask},
	}
	server.inputFocus = windowID

	// 1. Grab keyboard in Sync mode
	grabReq := &wire.GrabKeyboardRequest{
		GrabWindow:   wire.Window(windowID),
		PointerMode:  wire.GrabModeAsync,
		KeyboardMode: wire.GrabModeSync,
	}
	server.handleGrabKeyboard(client, grabReq, 1)
	assert.True(t, server.keyboardFrozen, "Keyboard should be frozen after Sync grab")

	// 2. Send key events - should be queued
	clientBuffer.Reset()
	server.SendKeyboardEvent(windowID, "keydown", "KeyA", false, false, false, false)
	assert.Equal(t, 0, clientBuffer.Len(), "Event should be queued, not sent")
	assert.Equal(t, 1, len(server.keyboardEventQueue), "Queue should have 1 event")

	// 3. AllowEvents (AsyncKeyboard)
	allowReq := &wire.AllowEventsRequest{
		Mode: wire.AsyncKeyboard,
	}
	server.handleAllowEvents(client, allowReq, 2)
	assert.False(t, server.keyboardFrozen, "Keyboard should be unfrozen")
	assert.Equal(t, 0, len(server.keyboardEventQueue), "Queue should be empty")
	assert.True(t, clientBuffer.Len() > 0, "Queued event should be flushed to client")
}
