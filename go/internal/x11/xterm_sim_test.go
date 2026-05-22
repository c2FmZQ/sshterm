//go:build x11 && !wasm

package x11

import (
	"testing"

	"github.com/c2FmZQ/sshterm/internal/x11/wire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestXTermSimulation(t *testing.T) {
	server, client, mockFrontend, clientBuffer := setupTestServerWithClient(t)

	// --- 1. Connection Setup & Extensions ---
	// (Skipping detailed extension queries as they are mostly handled internally or return empty/default)

	// --- 2. Window Creation ---
	// Log: CreateWindowRequest{Depth:0x18, Drawable:0x100010, Parent:0x0, ...}
	// Note: 0x100010 is client 1, resource 0x10
	xtermWindowID := clientXID(client, 0x10)
	rootWindowID := xID(server.rootWindowID())

	createWindowReq := &wire.CreateWindowRequest{
		Depth:       24,
		Drawable:    wire.Window(xtermWindowID),
		Parent:      wire.Window(rootWindowID),
		X:           0,
		Y:           0,
		Width:       800, // Approximate from log (0x463 = 1123? No, wait log says 0x463 is root width)
		Height:      600,
		BorderWidth: 1,
		Class:       wire.InputOutput,
		Visual:      0, // CopyFromParent
		ValueMask:   wire.CWBackPixel | wire.CWEventMask | wire.CWColormap,
		Values: wire.WindowAttributes{
			BackgroundPixel: 0xFFFFFF,
			EventMask:       wire.StructureNotifyMask | wire.KeyPressMask | wire.ButtonPressMask | wire.ExposureMask,
			Colormap:        1,
		},
	}
	reply := server.handleCreateWindow(client, createWindowReq, 1)
	require.Nil(t, reply, "handleCreateWindow returned error: %v", reply)

	// Verify window created in frontend
	assert.Equal(t, 1, len(mockFrontend.CreateWindowCalls), "Frontend CreateWindow should be called")
	assert.Equal(t, xtermWindowID, mockFrontend.CreateWindowCalls[0].xid)

	// Check internal server state
	assert.Contains(t, server.windows, xtermWindowID)

	// --- 3. Properties ---
	// Log: ChangePropertyRequest{Window:0x100010, Property:0x27 (WM_NAME), ... Data:"xterm"}
	wmNameAtom := server.GetAtom("WM_NAME") // 39
	changePropReq := &wire.ChangePropertyRequest{
		Window:   wire.Window(xtermWindowID),
		Property: wire.Atom(wmNameAtom),
		Type:     wire.Atom(31), // STRING
		Format:   8,
		Data:     []byte("xterm"),
	}
	server.handleChangeProperty(client, changePropReq, 2)

	// Verify frontend title set
	assert.Equal(t, 1, len(mockFrontend.SetWindowTitleCalls))
	assert.Equal(t, "xterm", mockFrontend.SetWindowTitleCalls[0].title)

	// --- 4. Resources (GC, Pixmap) ---
	// Log: CreateGCRequest{Cid:0x100014, ...}
	gcID := clientXID(client, 0x14)
	createGCReq := &wire.CreateGCRequest{
		Cid:       wire.GContext(gcID),
		Drawable:  wire.Drawable(xtermWindowID),
		ValueMask: wire.GCForeground | wire.GCBackground,
		Values: wire.GC{
			Foreground: 0x000000,
			Background: 0xFFFFFF,
		},
	}
	server.handleCreateGC(client, createGCReq, 3)
	assert.Contains(t, server.gcs, gcID)

	// --- 5. Mapping ---
	// Log: MapWindowRequest{Window:0x100010}
	mapWindowReq := &wire.MapWindowRequest{Window: wire.Window(xtermWindowID)}
	server.handleMapWindow(client, mapWindowReq, 4)

	// Verify frontend map
	assert.Contains(t, mockFrontend.MapWindowCalls, xtermWindowID)

	// --- 6. Drawing ---
	// Log: ImageText8Request{Drawable:0x100010, Gc:0x100014, X:2, Y:13, Text:" "}
	// Log: ImageText8Request{... Text:"$"}
	// Log: ImageText8Request{... Text:"robin@touchback ~"}

	drawTextReq := &wire.ImageText8Request{
		Drawable: wire.Drawable(xtermWindowID),
		Gc:       wire.GContext(gcID),
		X:        10,
		Y:        20,
		Text:     []byte("robin@touchback ~"),
	}
	server.handleImageText8(client, drawTextReq, 5)

	// Verify frontend drawing call
	require.Equal(t, 1, len(mockFrontend.ImageText8Calls))
	assert.Equal(t, xtermWindowID, mockFrontend.ImageText8Calls[0].drawable)
	assert.Equal(t, gcID, mockFrontend.ImageText8Calls[0].gcID)
	assert.Equal(t, []byte("robin@touchback ~"), mockFrontend.ImageText8Calls[0].text)

	// --- 7. Event Handling Simulation ---
	// User moves mouse into window -> EnterNotify
	// The frontend would call server.SendPointerCrossingEvent
	server.SendPointerCrossingEvent(true, xtermWindowID, 100, 100, 10, 10, 0, 0, 0)

	// Verify event delivered to client
	msgs := drainMessages(t, clientBuffer, client.byteOrder)
	foundEnter := false
	for _, msg := range msgs {
		if _, ok := msg.(*wire.EnterNotifyEvent); ok {
			foundEnter = true
			break
		}
	}
	assert.True(t, foundEnter, "Client should receive EnterNotify event")
}
