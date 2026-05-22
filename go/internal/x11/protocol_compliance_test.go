//go:build x11 && !wasm

package x11

import (
	"testing"

	"github.com/c2FmZQ/sshterm/internal/x11/wire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateWindow_Validation(t *testing.T) {
	server, client, _, _ := setupTestServerWithClient(t)

	// 1. Test Zero Width/Height
	createReq := &wire.CreateWindowRequest{
		Drawable: wire.Window(clientXID(client, 1)),
		Parent:   wire.Window(server.rootWindowID()),
		Width:    0,
		Height:   100,
	}
	reply := server.handleCreateWindow(client, createReq, 1)
	assert.NotNil(t, reply)
	err, ok := reply.(wire.Error)
	require.True(t, ok)
	assert.Equal(t, wire.ValueErrorCode, err.Code())

	// 2. Test InputOnly depth must be 0
	createReq = &wire.CreateWindowRequest{
		Drawable: wire.Window(clientXID(client, 2)),
		Parent:   wire.Window(server.rootWindowID()),
		Width:    100,
		Height:   100,
		Depth:    24,
		Class:    wire.InputOnly,
	}
	reply = server.handleCreateWindow(client, createReq, 2)
	assert.NotNil(t, reply)
	err, ok = reply.(wire.Error)
	require.True(t, ok)
	assert.Equal(t, wire.MatchErrorCode, err.Code())

	// 3. Test InputOnly border width must be 0
	createReq = &wire.CreateWindowRequest{
		Drawable:    wire.Window(clientXID(client, 3)),
		Parent:      wire.Window(server.rootWindowID()),
		Width:       100,
		Height:      100,
		Depth:       0,
		BorderWidth: 1,
		Class:       wire.InputOnly,
	}
	reply = server.handleCreateWindow(client, createReq, 3)
	assert.NotNil(t, reply)
	err, ok = reply.(wire.Error)
	require.True(t, ok)
	assert.Equal(t, wire.MatchErrorCode, err.Code())
}

func TestConfigureWindow_Validation(t *testing.T) {
	server, client, _, _ := setupTestServerWithClient(t)
	windowID := clientXID(client, 1)
	server.windows[windowID] = &window{xid: windowID, width: 100, height: 100, eventMasks: make(map[uint32]uint32)}

	// Test updating width to 0
	confReq := &wire.ConfigureWindowRequest{
		Window:    wire.Window(windowID),
		ValueMask: 1 << 2, // width
		Values:    []uint32{0},
	}
	reply := server.handleConfigureWindow(client, confReq, 1)
	assert.NotNil(t, reply)
	err, ok := reply.(wire.Error)
	require.True(t, ok)
	assert.Equal(t, wire.ValueErrorCode, err.Code())
}

func TestPutImage_DepthValidation(t *testing.T) {
	server, client, _, _ := setupTestServerWithClient(t)
	windowID := clientXID(client, 1)
	server.windows[windowID] = &window{xid: windowID, depth: 24, eventMasks: make(map[uint32]uint32)}
	gcID := clientXID(client, 2)
	server.gcs[gcID] = wire.GC{}

	// 1. Test depth mismatch for ZPixmap (format 2)
	putReq := &wire.PutImageRequest{
		Drawable: wire.Drawable(windowID),
		Gc:       wire.GContext(gcID),
		Width:    10,
		Height:   10,
		Format:   2, // ZPixmap
		Depth:    8, // Mismatch (window is 24)
		Data:     make([]byte, 100),
	}
	reply := server.handlePutImage(client, putReq, 1)
	assert.NotNil(t, reply)
	err, ok := reply.(wire.Error)
	require.True(t, ok)
	assert.Equal(t, wire.MatchErrorCode, err.Code())

	// 2. Test XYBitmap (format 0) must have depth 1
	putReq = &wire.PutImageRequest{
		Drawable: wire.Drawable(windowID),
		Gc:       wire.GContext(gcID),
		Width:    10,
		Height:   10,
		Format:   0, // XYBitmap
		Depth:    8, // Mismatch (XYBitmap must be 1)
		Data:     make([]byte, 100),
	}
	reply = server.handlePutImage(client, putReq, 2)
	assert.NotNil(t, reply)
	err, ok = reply.(wire.Error)
	require.True(t, ok)
	assert.Equal(t, wire.MatchErrorCode, err.Code())

	// 3. Test XYBitmap (format 0) with depth 1 works on depth 24 drawable
	putReq = &wire.PutImageRequest{
		Drawable: wire.Drawable(windowID),
		Gc:       wire.GContext(gcID),
		Width:    10,
		Height:   10,
		Format:   0, // XYBitmap
		Depth:    1, // Correct for XYBitmap
		Data:     make([]byte, 20),
	}
	reply = server.handlePutImage(client, putReq, 3)
	assert.Nil(t, reply, "PutImage should succeed for XYBitmap with depth 1")
}

func TestMandatoryNotifications(t *testing.T) {
	server, clients, _, buffers := setupTestServerWithClients(t, 2)
	client1, client2 := clients[0], clients[1]
	buf1, buf2 := buffers[0], buffers[1]

	// 1. CreateNotify: Client 2 listens on root window
	server.windows[xID(server.rootWindowID())].eventMasks[client2.id] = wire.SubstructureNotifyMask
	
	windowID := clientXID(client1, 100)
	createReq := &wire.CreateWindowRequest{
		Drawable: wire.Window(windowID),
		Parent:   wire.Window(server.rootWindowID()),
		Width:    100,
		Height:   100,
		Depth:    24,
	}
	server.handleCreateWindow(client1, createReq, 1)

	// Client 2 should receive CreateNotify
	msgs := drainMessages(t, buf2, client2.byteOrder)
	found := false
	for _, m := range msgs {
		if ev, ok := m.(*wire.CreateNotifyEvent); ok {
			assert.Equal(t, uint32(windowID), ev.Window)
			found = true
		}
	}
	assert.True(t, found, "Expected CreateNotifyEvent on client 2")

	// 2. MapNotify: Client 1 listens on windowID
	server.windows[windowID].eventMasks[client1.id] = wire.StructureNotifyMask
	mapReq := &wire.MapWindowRequest{Window: wire.Window(windowID)}
	server.handleMapWindow(client1, mapReq, 2)

	msgs = drainMessages(t, buf1, client1.byteOrder)
	found = false
	for _, m := range msgs {
		if ev, ok := m.(*wire.MapNotifyEvent); ok {
			assert.Equal(t, uint32(windowID), ev.Window)
			found = true
		}
	}
	assert.True(t, found, "Expected MapNotifyEvent on client 1")

	// 3. UnmapNotify
	unmapReq := &wire.UnmapWindowRequest{Window: wire.Window(windowID)}
	server.handleUnmapWindow(client1, unmapReq, 3)

	msgs = drainMessages(t, buf1, client1.byteOrder)
	found = false
	for _, m := range msgs {
		if ev, ok := m.(*wire.UnmapNotifyEvent); ok {
			assert.Equal(t, uint32(windowID), ev.Window)
			found = true
		}
	}
	assert.True(t, found, "Expected UnmapNotifyEvent on client 1")

	// 4. ConfigureNotify
	confReq := &wire.ConfigureWindowRequest{
		Window:    wire.Window(windowID),
		ValueMask: 1 << 0, // x
		Values:    []uint32{50},
	}
	server.handleConfigureWindow(client1, confReq, 4)

	msgs = drainMessages(t, buf1, client1.byteOrder)
	found = false
	for _, m := range msgs {
		if ev, ok := m.(*wire.ConfigureNotifyEvent); ok {
			assert.Equal(t, uint32(windowID), ev.Window)
			assert.Equal(t, int16(50), ev.X)
			found = true
		}
	}
	assert.True(t, found, "Expected ConfigureNotifyEvent on client 1")

	// 5. DestroyNotify
	destroyReq := &wire.DestroyWindowRequest{Window: wire.Window(windowID)}
	server.handleDestroyWindow(client1, destroyReq, 5)

	msgs = drainMessages(t, buf1, client1.byteOrder)
	found = false
	for _, m := range msgs {
		if ev, ok := m.(*wire.DestroyNotifyEvent); ok {
			assert.Equal(t, uint32(windowID), ev.Window)
			found = true
		}
	}
	assert.True(t, found, "Expected DestroyNotifyEvent on client 1")
}

func TestParentRelativeStacking(t *testing.T) {
	server, client, _, _ := setupTestServerWithClient(t)
	rootID := xID(server.rootWindowID())

	win1 := clientXID(client, 1)
	win2 := clientXID(client, 2)
	win3 := clientXID(client, 3)

	// Create 3 top-level windows
	for _, id := range []xID{win1, win2, win3} {
		req := &wire.CreateWindowRequest{
			Drawable: wire.Window(id),
			Parent:   wire.Window(rootID),
			Width:    100,
			Height:   100,
			Depth:    24,
		}
		server.handleCreateWindow(client, req, 1)
		// Map them so they are hit-testable
		server.handleMapWindow(client, &wire.MapWindowRequest{Window: wire.Window(id)}, 1)
	}

	// Default stacking: win1, win2, win3 (top)
	assert.Equal(t, []xID{win1, win2, win3}, server.windows[rootID].children)
	assert.Equal(t, win3, server.findTopLevelWindowAt(10, 10))

	// Move win1 to top
	server.moveWindowToTop(win1)
	assert.Equal(t, []xID{win2, win3, win1}, server.windows[rootID].children)
	assert.Equal(t, win1, server.findTopLevelWindowAt(10, 10))

	// Move win3 to bottom
	server.moveWindowToBottom(win3)
	assert.Equal(t, []xID{win3, win2, win1}, server.windows[rootID].children)
}

func TestIntegerOverflowPrevention(t *testing.T) {
	server, client, _, _ := setupTestServerWithClient(t)
	rootID := xID(server.rootWindowID())

	// Create a chain of deeply nested windows to test absolute coordinate accumulation
	// Use large offsets that would overflow int16 if not handled correctly
	currParent := rootID
	expectedAbsX := int32(0)
	
	// Nest 10 windows, each at (5000, 5000)
	for i := 1; i <= 10; i++ {
		winID := clientXID(client, uint32(i))
		req := &wire.CreateWindowRequest{
			Drawable: wire.Window(winID),
			Parent:   wire.Window(currParent),
			X:        5000,
			Y:        5000,
			Width:    100,
			Height:   100,
			Depth:    24,
		}
		server.handleCreateWindow(client, req, 1)
		currParent = winID
		expectedAbsX += 5000
	}

	// Translate (10, 10) in the deepest child to root
	translateReq := &wire.TranslateCoordsRequest{
		SrcWindow: wire.Window(currParent),
		DstWindow: wire.Window(rootID),
		SrcX:      10,
		SrcY:      10,
	}
	reply := server.handleTranslateCoords(client, translateReq, 1)
	transReply, ok := reply.(*wire.TranslateCoordsReply)
	require.True(t, ok)

	// expectedAbsX is 50000. int16 would overflow (max 32767).
	// We expect the result to be correctly calculated as int32 and then cast/wrapped to int16.
	// 50010 as int16 is -15526
	assert.Equal(t, int16(expectedAbsX+10), transReply.DstX)
}

func TestPropertyCleanup(t *testing.T) {
	server, client, _, _ := setupTestServerWithClient(t)
	windowID := clientXID(client, 1)
	server.windows[windowID] = &window{xid: windowID, eventMasks: make(map[uint32]uint32)}
	
	atom := server.GetAtom("MY_PROP")
	server.ChangeProperty(windowID, atom, atom, 8, []byte("hello"))
	assert.Contains(t, server.properties, windowID)

	// Destroy window
	server.destroyWindow(windowID, true)
	assert.NotContains(t, server.properties, windowID, "Properties should be cleaned up on window destruction")
}

func TestInternAtom_OnlyIfExists(t *testing.T) {
	server, client, _, _ := setupTestServerWithClient(t)

	// 1. Intern a new atom with OnlyIfExists=true (should fail/return None)
	req := &wire.InternAtomRequest{
		OnlyIfExists: true,
		Name:         "NON_EXISTENT_ATOM",
	}
	reply := server.handleInternAtom(client, req, 1)
	internReply, ok := reply.(*wire.InternAtomReply)
	require.True(t, ok)
	assert.Equal(t, uint32(0), internReply.Atom)

	// 2. Intern with OnlyIfExists=false (should create)
	req.OnlyIfExists = false
	reply = server.handleInternAtom(client, req, 2)
	internReply, ok = reply.(*wire.InternAtomReply)
	require.True(t, ok)
	assert.NotEqual(t, uint32(0), internReply.Atom)
	atomID := internReply.Atom

	// 3. Intern again with OnlyIfExists=true (should succeed now)
	req.OnlyIfExists = true
	reply = server.handleInternAtom(client, req, 3)
	internReply, ok = reply.(*wire.InternAtomReply)
	require.True(t, ok)
	assert.Equal(t, atomID, internReply.Atom)
}

func TestXInput_DynamicOffsets(t *testing.T) {
	server, client, _, clientBuffer := setupTestServerWithClient(t)
	
	// Verify server initialization
	assert.Equal(t, byte(64), server.xinputFirstEvent)
	assert.Equal(t, byte(64), server.xinputFirstError)

	// QueryExtension for XInput
	queryReq := &wire.QueryExtensionRequest{Name: wire.XInputExtensionName}
	reply := server.handleQueryExtension(client, queryReq, 1)
	queryReply, ok := reply.(*wire.QueryExtensionReply)
	require.True(t, ok)
	assert.Equal(t, byte(64), queryReply.FirstEvent)

	// Send an XInput event and verify encoded code
	windowID := clientXID(client, 1)
	server.windows[windowID] = &window{xid: windowID, eventMasks: make(map[uint32]uint32)}
	
	// DeviceKeyPress is 4. Base is 64. Total should be 68.
	event := &wire.DeviceKeyPressEvent{
		DeviceID: 3,
		Event:    uint32(windowID),
	}
	server.sendEvent(client, event)
	
	assert.True(t, clientBuffer.Len() >= 32)
	encoded := clientBuffer.Bytes()
	assert.Equal(t, byte(68), encoded[0], "Encoded event code should include base offset")
	
	// Parse it back
	decoded, err := wire.ParseEvent(encoded, client.byteOrder)
	assert.NoError(t, err)
	decodedEvent, ok := decoded.(*wire.DeviceKeyPressEvent)
	require.True(t, ok)
	assert.Equal(t, byte(64), decodedEvent.BaseEventCode)
}
