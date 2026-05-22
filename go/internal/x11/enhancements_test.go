//go:build x11 && !wasm

package x11

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/c2FmZQ/sshterm/internal/x11/wire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// clientXID creates a full xID from a client and a local ID.
func clientXID(client *x11Client, localID uint32) xID {
	return xID((client.id << resourceIDShift) | localID)
}

func TestQueryBestSize(t *testing.T) {
	server, client, mockFrontend, _ := setupTestServerWithClient(t)
	drawableID := clientXID(client, 1)
	server.pixmaps[drawableID] = &pixmap{} // Create the drawable

	testCases := []struct {
		class         byte
		width, height uint16
	}{
		{0, 16, 16},   // Cursor
		{1, 100, 100}, // Tile
		{2, 200, 200}, // Stipple
	}

	for _, tc := range testCases {
		req := &wire.QueryBestSizeRequest{
			Class:    tc.class,
			Drawable: wire.Drawable(drawableID),
			Width:    tc.width,
			Height:   tc.height,
		}
		reply := server.handleQueryBestSize(client, req, 1)

		assert.NotNil(t, reply, "QueryBestSize should return a reply")
		bestSizeReply, ok := reply.(*wire.QueryBestSizeReply)
		require.True(t, ok, "Expected QueryBestSizeReply")

		assert.Equal(t, tc.width, bestSizeReply.Width, "Width should match for class %d", tc.class)
		assert.Equal(t, tc.height, bestSizeReply.Height, "Height should match for class %d", tc.class)
	}
	assert.Len(t, mockFrontend.QueryBestSizeCalls, len(testCases), "Expected QueryBestSize to be called for each test case")
}

func TestRotateProperties(t *testing.T) {
	server, client, _, _ := setupTestServerWithClient(t)
	windowID := clientXID(client, 1)
	server.windows[windowID] = &window{xid: windowID, eventMasks: make(map[uint32]uint32)} // Create the window

	// Setup initial properties
	atom1 := server.GetAtom("PROP1")
	atom2 := server.GetAtom("PROP2")
	atom3 := server.GetAtom("PROP3")
	server.properties[windowID] = map[uint32]*property{
		atom1: {data: []byte("value1")},
		atom2: {data: []byte("value2")},
		atom3: {data: []byte("value3")},
	}

	req := &wire.RotatePropertiesRequest{
		Window: wire.Window(windowID),
		Delta:  1,
		Atoms:  []wire.Atom{wire.Atom(atom1), wire.Atom(atom2), wire.Atom(atom3)},
	}
	server.handleRotateProperties(client, req, 1)

	props := server.properties[windowID]
	assert.Equal(t, "value3", string(props[atom1].data), "Property 1 should have value 3 after rotation")
	assert.Equal(t, "value1", string(props[atom2].data), "Property 2 should have value 1 after rotation")
	assert.Equal(t, "value2", string(props[atom3].data), "Property 3 should have value 2 after rotation")
}

func TestSetGetPointerMapping(t *testing.T) {
	server, client, mockFrontend, _ := setupTestServerWithClient(t)
	newMap := []byte{3, 1, 2}

	// 1. Set the mapping
	setReq := &wire.SetPointerMappingRequest{Map: newMap}
	reply := server.handleSetPointerMapping(client, setReq, 1)
	setReply, ok := reply.(*wire.SetPointerMappingReply)
	require.True(t, ok)
	assert.Equal(t, byte(0), setReply.Status, "SetPointerMapping should be successful")
	require.Len(t, mockFrontend.SetPointerMappingCalls, 1, "Expected frontend to be called for Set")
	assert.Equal(t, newMap, mockFrontend.SetPointerMappingCalls[0])

	// 2. Get the mapping
	getReq := &wire.GetPointerMappingRequest{}
	reply = server.handleGetPointerMapping(client, getReq, 2)
	getReply, ok := reply.(*wire.GetPointerMappingReply)
	require.True(t, ok)
	assert.Equal(t, newMap, getReply.PMap, "GetPointerMapping should return the newly set map")
}

func TestGetSetModifierMapping(t *testing.T) {
	server, client, _, _ := setupTestServerWithClient(t)
	keycodes := []wire.KeyCode{10, 20, 30, 0, 0, 0, 0, 0} // 1 keycode per modifier for 8 modifiers

	// 1. Set the mapping
	setReq := &wire.SetModifierMappingRequest{
		KeyCodesPerModifier: 1,
		KeyCodes:            keycodes,
	}
	reply := server.handleSetModifierMapping(client, setReq, 1)
	setReply, ok := reply.(*wire.SetModifierMappingReply)
	require.True(t, ok)
	assert.Equal(t, byte(0), setReply.Status, "SetModifierMapping should be successful")

	// 2. Get the mapping
	getReq := &wire.GetModifierMappingRequest{}
	reply = server.handleGetModifierMapping(client, getReq, 2)
	getReply, ok := reply.(*wire.GetModifierMappingReply)
	require.True(t, ok)
	assert.Equal(t, byte(1), getReply.KeyCodesPerModifier, "KeycodesPerModifier should be 1")
	assert.Equal(t, keycodes, getReply.KeyCodes, "GetModifierMapping should return the set keycodes")
}

func TestQueryKeymap(t *testing.T) {
	server, client, _, _ := setupTestServerWithClient(t)

	// Simulate some pressed keys
	server.pressedKeys[38] = true // Key 'a'
	server.pressedKeys[56] = true // Key 'Shift'

	req := &wire.QueryKeymapRequest{}
	reply := server.handleQueryKeymap(client, req, 1)
	keymapReply, ok := reply.(*wire.QueryKeymapReply)
	require.True(t, ok)

	// Check if the bits for the pressed keys are set
	assert.NotZero(t, keymapReply.Keys[38/8]&(1<<(38%8)), "Key 'a' should be marked as pressed")
	assert.NotZero(t, keymapReply.Keys[56/8]&(1<<(56%8)), "Key 'Shift' should be marked as pressed")
}

func TestTranslateCoords(t *testing.T) {
	server, client, _, _ := setupTestServerWithClient(t)

	parentID := clientXID(client, 1)
	server.windows[parentID] = &window{xid: parentID, parent: xID(server.rootWindowID()), x: 100, y: 100, eventMasks: make(map[uint32]uint32)}

	req := &wire.TranslateCoordsRequest{
		SrcWindow: wire.Window(parentID),
		DstWindow: wire.Window(server.rootWindowID()),
		SrcX:      10,
		SrcY:      20,
	}
	reply := server.handleTranslateCoords(client, req, 1)
	translateReply, ok := reply.(*wire.TranslateCoordsReply)
	require.True(t, ok)

	assert.Equal(t, true, translateReply.SameScreen, "SameScreen should be true")
	assert.Equal(t, uint32(0), translateReply.Child, "Child should be None")
	assert.Equal(t, int16(110), translateReply.DstX, "Translated X coordinate is incorrect")
	assert.Equal(t, int16(120), translateReply.DstY, "Translated Y coordinate is incorrect")
}

func TestTranslateCoordsWithChild(t *testing.T) {
	server, client, _, _ := setupTestServerWithClient(t)

	parentID := clientXID(client, 1)
	childID := clientXID(client, 2)
	server.windows[parentID] = &window{
		xid:        parentID,
		parent:     xID(server.rootWindowID()),
		x:          100,
		y:          100,
		width:      200,
		height:     200,
		children:   []xID{childID},
		mapped:     true,
		eventMasks: make(map[uint32]uint32),
	}
	server.windows[childID] = &window{
		xid:        childID,
		parent:     parentID,
		x:          10,
		y:          20,
		width:      50,
		height:     50,
		mapped:     true,
		eventMasks: make(map[uint32]uint32),
	}
	// Put child on top of parent in the stacking order
	server.windows[xID(server.rootWindowID())].children = []xID{parentID}

	req := &wire.TranslateCoordsRequest{
		SrcWindow: wire.Window(server.rootWindowID()),
		DstWindow: wire.Window(parentID),
		SrcX:      115, // A point inside the child window
		SrcY:      125,
	}
	reply := server.handleTranslateCoords(client, req, 1)
	translateReply, ok := reply.(*wire.TranslateCoordsReply)
	require.True(t, ok)

	assert.Equal(t, uint32(childID), translateReply.Child, "TranslateCoords should identify the child window")
	assert.Equal(t, int16(15), translateReply.DstX, "Translated X should be relative to the destination window")
	assert.Equal(t, int16(25), translateReply.DstY, "Translated Y should be relative to the destination window")
}

func TestGetMotionEvents(t *testing.T) {
	server, client, _, _ := setupTestServerWithClient(t)
	windowID := clientXID(client, 1)
	server.windows[windowID] = &window{xid: windowID, eventMasks: make(map[uint32]uint32)} // Create the window

	// Populate motion buffer
	server.motionEvents = []motionEvent{
		{time: 1000, x: 10, y: 10, window: windowID},
		{time: 1010, x: 12, y: 15, window: windowID},
		{time: 1020, x: 15, y: 20, window: windowID},
	}

	req := &wire.GetMotionEventsRequest{
		Window: wire.Window(windowID),
		Start:  1005,
		Stop:   1025,
	}
	reply := server.handleGetMotionEvents(client, req, 1)
	motionReply, ok := reply.(*wire.GetMotionEventsReply)
	require.True(t, ok, "Expected GetMotionEventsReply")
	require.Len(t, motionReply.Events, 2, "Should return 2 events within the time range")
	assert.Equal(t, uint32(1010), motionReply.Events[0].Time)
	assert.Equal(t, int16(12), motionReply.Events[0].X)
	assert.Equal(t, int16(15), motionReply.Events[0].Y)
	assert.Equal(t, uint32(1020), motionReply.Events[1].Time)
}

func TestListProperties(t *testing.T) {
	server, client, _, _ := setupTestServerWithClient(t)
	windowID := clientXID(client, 1)
	server.windows[windowID] = &window{xid: windowID, eventMasks: make(map[uint32]uint32)} // Create the window
	atom1 := server.GetAtom("PROP1")
	atom2 := server.GetAtom("PROP2")

	server.properties[windowID] = map[uint32]*property{
		atom1: {},
		atom2: {},
	}

	req := &wire.ListPropertiesRequest{Window: wire.Window(windowID)}
	reply := server.handleListProperties(client, req, 1)
	listReply, ok := reply.(*wire.ListPropertiesReply)
	require.True(t, ok)
	assert.ElementsMatch(t, []uint32{atom1, atom2}, listReply.Atoms, "Listed properties should match")
}

func TestAllocNamedColor(t *testing.T) {
	server, client, _, _ := setupTestServerWithClient(t)

	req := &wire.AllocNamedColorRequest{
		Cmap: wire.Colormap(server.defaultColormap),
		Name: []byte("blue"),
	}

	reply := server.handleAllocNamedColor(client, req, 1)
	colorReply, ok := reply.(*wire.AllocNamedColorReply)
	require.True(t, ok)

	assert.NotZero(t, colorReply.Pixel, "Pixel value should be allocated")
	// "blue" is #0000FF
	assert.Equal(t, uint16(0x0000), colorReply.ExactRed, "Exact red is wrong for blue")
	assert.Equal(t, uint16(0x0000), colorReply.ExactGreen, "Exact green is wrong for blue")
	assert.Equal(t, uint16(0xFFFF), colorReply.ExactBlue, "Exact blue is wrong for blue")
}

func TestAllocColorCells_TrueColor(t *testing.T) {
	server, client, _, clientBuffer := setupTestServerWithClient(t)
	colormapID := clientXID(client, 1)
	server.colormaps[colormapID] = &colormap{
		visual: wire.VisualType{Class: wire.TrueColor}, // Read-only colormap
	}

	req := &wire.AllocColorCellsRequest{
		Cmap:   wire.Colormap(colormapID),
		Colors: 2,
		Planes: 0,
	}

	// Should fail with BadAccess on a read-only colormap
	errReply := server.handleAllocColorCells(client, req, 1)
	encoded := errReply.EncodeMessage(client.byteOrder)
	clientBuffer.Write(encoded)

	msg, err := wire.ParseError(clientBuffer.Bytes(), client.byteOrder)
	require.NoError(t, err)
	assert.Equal(t, wire.AccessErrorCode, msg.Code(), "AllocColorCells on TrueColor should return BadAccess")
}

func TestAllocColorCells_PseudoColor(t *testing.T) {
	server, client, _, _ := setupTestServerWithClient(t)
	colormapID := clientXID(client, 1)
	server.colormaps[colormapID] = &colormap{
		visual:    wire.VisualType{Class: wire.PseudoColor, ColormapEntries: 256},
		pixels:    make(map[uint32]wire.XColorItem),
		allocated: make([]bool, 256),
		writable:  make([]bool, 256),
		clientID:  make([]uint32, 256),
	}

	req := &wire.AllocColorCellsRequest{
		Cmap:   wire.Colormap(colormapID),
		Colors: 5, // Request 5 contiguous cells
		Planes: 0,
	}

	reply := server.handleAllocColorCells(client, req, 1)
	allocReply, ok := reply.(*wire.AllocColorCellsReply)
	require.True(t, ok)
	assert.Len(t, allocReply.Pixels, 5, "Should allocate 5 pixel values")

	// Check that the allocated cells are now marked as allocated and writable
	for _, pixel := range allocReply.Pixels {
		assert.True(t, server.colormaps[colormapID].allocated[pixel], "Allocated cell should be marked as allocated")
		assert.True(t, server.colormaps[colormapID].writable[pixel], "Allocated cell should be marked as writable")
	}
}

func TestCopyColormapAndFree(t *testing.T) {
	server, client, _, _ := setupTestServerWithClient(t)
	srcCmapID := clientXID(client, 1)
	dstCmapID := clientXID(client, 2)

	server.colormaps[srcCmapID] = &colormap{
		visual:    wire.VisualType{VisualID: 1, Class: wire.PseudoColor, ColormapEntries: 256},
		pixels:    make(map[uint32]wire.XColorItem),
		allocated: make([]bool, 256),
		writable:  make([]bool, 256),
		clientID:  make([]uint32, 256),
	}
	// Add a color item owned by this client
	server.colormaps[srcCmapID].pixels[1] = wire.XColorItem{Pixel: 1, Red: 0xffff, ClientID: client.id}
	server.colormaps[srcCmapID].allocated[1] = true
	server.colormaps[srcCmapID].clientID[1] = client.id

	req := &wire.CopyColormapAndFreeRequest{
		SrcCmap: wire.Colormap(srcCmapID),
		Mid:     wire.Colormap(dstCmapID),
	}

	server.handleCopyColormapAndFree(client, req, 1)

	srcCmap, srcExists := server.colormaps[srcCmapID]
	dstCmap, dstExists := server.colormaps[dstCmapID]

	assert.True(t, srcExists, "Source colormap should still exist (per our implementation move logic)")
	assert.False(t, srcCmap.allocated[1], "Color item should be freed in source")

	require.True(t, dstExists, "Destination colormap should be created")
	assert.Contains(t, dstCmap.pixels, uint32(1), "Color item should be copied to destination")
	assert.True(t, dstCmap.allocated[1], "Color item should be marked as allocated in destination")
}

func TestAllocColorCells_WritableVisuals(t *testing.T) {
	server, client, _, clientBuffer := setupTestServerWithClient(t)
	colormapID := clientXID(client, 1)

	for _, class := range []byte{wire.GrayScale, wire.DirectColor} {
		server.colormaps[colormapID] = &colormap{
			visual:    wire.VisualType{Class: class, ColormapEntries: 256},
			pixels:    make(map[uint32]wire.XColorItem),
			allocated: make([]bool, 256),
			writable:  make([]bool, 256),
			clientID:  make([]uint32, 256),
		}
		req := &wire.AllocColorCellsRequest{
			Cmap:   wire.Colormap(colormapID),
			Colors: 1,
			Planes: 0,
		}
		reply := server.handleAllocColorCells(client, req, 1)
		_, ok := reply.(*wire.AllocColorCellsReply)
		assert.True(t, ok, "AllocColorCells should succeed for class %v", class)
	}

	for _, class := range []byte{wire.StaticGray, wire.StaticColor} {
		server.colormaps[colormapID] = &colormap{
			visual: wire.VisualType{Class: class},
		}
		req := &wire.AllocColorCellsRequest{
			Cmap:   wire.Colormap(colormapID),
			Colors: 1,
			Planes: 0,
		}
		errReply := server.handleAllocColorCells(client, req, 1)
		encoded := errReply.EncodeMessage(client.byteOrder)
		clientBuffer.Reset()
		clientBuffer.Write(encoded)
		msg, err := wire.ParseError(clientBuffer.Bytes(), client.byteOrder)
		require.NoError(t, err)
		assert.Equal(t, wire.AccessErrorCode, msg.Code(), "AllocColorCells on class %v should return BadAccess", class)
	}
}

func TestAllocColorPlanes_Visuals(t *testing.T) {
	server, client, _, clientBuffer := setupTestServerWithClient(t)
	colormapID := clientXID(client, 1)

	// DirectColor should succeed
	server.colormaps[colormapID] = &colormap{
		visual:    wire.VisualType{Class: wire.DirectColor, ColormapEntries: 256},
		pixels:    make(map[uint32]wire.XColorItem),
		allocated: make([]bool, 256),
		writable:  make([]bool, 256),
		clientID:  make([]uint32, 256),
	}
	req := &wire.AllocColorPlanesRequest{
		Cmap:   wire.Colormap(colormapID),
		Colors: 2,
		Reds:   1,
		Greens: 1,
		Blues:  1,
	}
	reply := server.handleAllocColorPlanes(client, req, 1)
	_, ok := reply.(*wire.AllocColorPlanesReply)
	assert.True(t, ok, "AllocColorPlanes should succeed for DirectColor")

	// PseudoColor should succeed
	server.colormaps[colormapID] = &colormap{
		visual:    wire.VisualType{Class: wire.PseudoColor, ColormapEntries: 256},
		pixels:    make(map[uint32]wire.XColorItem),
		allocated: make([]bool, 256),
		writable:  make([]bool, 256),
		clientID:  make([]uint32, 256),
	}
	reply2 := server.handleAllocColorPlanes(client, req, 2)
	_, ok = reply2.(*wire.AllocColorPlanesReply)
	assert.True(t, ok, "AllocColorPlanes should succeed for PseudoColor")

	// TrueColor should fail with BadMatch
	server.colormaps[colormapID] = &colormap{
		visual: wire.VisualType{Class: wire.TrueColor},
	}
	errReply := server.handleAllocColorPlanes(client, req, 3)
	encoded := errReply.EncodeMessage(client.byteOrder)
	clientBuffer.Reset()
	clientBuffer.Write(encoded)
	msg, err := wire.ParseError(clientBuffer.Bytes(), client.byteOrder)
	require.NoError(t, err)
	assert.Equal(t, wire.MatchErrorCode, msg.Code(), "AllocColorPlanes on TrueColor should return BadMatch")
}

// Helper to decode a single message from a buffer for testing replies.
func decodeSingleReply(t *testing.T, buffer *bytes.Buffer, order binary.ByteOrder, seq uint16, opcodes wire.Opcodes) (wire.ServerMessage, error) {
	t.Helper()
	return wire.ParseReply(opcodes, buffer.Bytes(), order)
}
