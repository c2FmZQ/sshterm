//go:build x11 && !wasm

package x11

import (
	"testing"

	"github.com/c2FmZQ/sshterm/internal/x11/wire"
	"github.com/stretchr/testify/assert"
)

func TestGrabPointer_FrontendIntegration(t *testing.T) {
	server, client, mockFrontend, _ := setupTestServerWithClient(t)
	windowID := clientXID(client, 1)
	server.windows[windowID] = &window{xid: windowID}

	req := &wire.GrabPointerRequest{
		GrabWindow:   wire.Window(windowID),
		OwnerEvents:  false,
		EventMask:    wire.ButtonPressMask,
		PointerMode:  wire.GrabModeAsync,
		KeyboardMode: wire.GrabModeAsync,
		ConfineTo:    0,
		Cursor:       0,
		Time:         0,
	}

	reply := server.handleGrabPointer(client, req, 1)
	grabReply, ok := reply.(*wire.GrabPointerReply)
	assert.True(t, ok)
	assert.Equal(t, byte(wire.GrabSuccess), grabReply.Status)

	// Verify frontend was called
	assert.Equal(t, 1, len(mockFrontend.GrabPointerCalls))
	call := mockFrontend.GrabPointerCalls[0]
	assert.Equal(t, windowID, call.grabWindow)
	assert.Equal(t, false, call.ownerEvents)
	assert.Equal(t, uint16(wire.ButtonPressMask), call.eventMask)

	// Test UngrabPointer
	ungrabReq := &wire.UngrabPointerRequest{Time: 0}
	server.handleUngrabPointer(client, ungrabReq, 2)

	assert.Equal(t, 1, len(mockFrontend.UngrabPointerCalls))
}

func TestKeyboardEvent_PointerRoot(t *testing.T) {
	server, client, _, clientBuffer := setupTestServerWithClient(t)
	windowID := clientXID(client, 1)
	server.windows[windowID] = &window{xid: windowID, attributes: wire.WindowAttributes{EventMask: wire.KeyPressMask}}

	// Set input focus to PointerRoot (1)
	server.inputFocus = 1

	// Send keyboard event, pointing at windowID
	// The function signature is: SendKeyboardEvent(xid xID, eventType string, code string, altKey, ctrlKey, shiftKey, metaKey bool)
	// We simulate the frontend detecting the mouse over windowID
	server.SendKeyboardEvent(windowID, "keydown", "KeyA", false, false, false, false)

	// Verify event delivery
	assert.True(t, clientBuffer.Len() > 0, "Client should receive event when focus is PointerRoot and mouse is over window")
	msg, err := wire.ParseEvent(clientBuffer.Bytes(), client.byteOrder)
	assert.NoError(t, err)
	keyEvent, ok := msg.(*wire.KeyEvent)
	assert.True(t, ok)
	assert.Equal(t, uint32(windowID), keyEvent.Event)
}
