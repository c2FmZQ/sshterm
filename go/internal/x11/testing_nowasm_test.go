//go:build x11 && !wasm

package x11

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/c2FmZQ/sshterm/internal/x11/wire"
)

// setupTestServerWithClient creates a new x11Server with a mock frontend and a single mock client.
// It returns the server instance, the client, the mock frontend, and a buffer that captures all data sent to the mock client.
func setupTestServerWithClient(t *testing.T) (*x11Server, *x11Client, *MockX11Frontend, *bytes.Buffer) {
	server, clients, mockFrontend, buffers := setupTestServerWithClients(t, 1)
	return server, clients[0], mockFrontend, buffers[0]
}

func setupTestServerWithClients(t *testing.T, numClients int) (*x11Server, []*x11Client, *MockX11Frontend, []*bytes.Buffer) {
	t.Helper()
	mockFrontend := &MockX11Frontend{}
	server := &x11Server{
		logger:             &testLogger{t: t},
		frontend:           mockFrontend,
		windows:            make(map[xID]*window),
		gcs:                make(map[xID]wire.GC),
		pixmaps:            make(map[xID]*pixmap),
		cursors:            make(map[xID]bool),
		selections:         make(map[uint32]*selectionOwner),
		properties:         make(map[xID]map[uint32]*property),
		colormaps:          make(map[xID]*colormap),
		clients:            make(map[uint32]*x11Client),
		nextClientID:       1,
		passiveGrabs:       make(map[xID][]*passiveGrab),
		passiveDeviceGrabs: make(map[xID][]*passiveDeviceGrab),
		deviceGrabs:        make(map[byte]*deviceGrab),
		keymap:             make(map[byte][]uint32),
		fonts:              make(map[xID]bool),
		defaultColormap:    1,
		xinputFirstEvent:   64,
		xinputFirstError:   64,
		startTime:          time.Now(),
		pressedKeys:        make(map[byte]bool),
		dirtyDrawables:     make(map[xID]bool),
		byteOrder:          binary.LittleEndian,
		rootVisual:         wire.VisualType{VisualID: 1, Class: wire.TrueColor, ColormapEntries: 256},
		visualID:           1,
	}
	server.visuals = map[uint32]wire.VisualType{1: server.rootVisual}
	server.windows[xID(0)] = &window{
		xid:    xID(0),
		width:  1024,
		height: 768,
		depth:  24,
		visual: 1,
		attributes: wire.WindowAttributes{
			Class: wire.InputOutput,
		},
		children: make([]xID, 0),
		eventMasks: make(map[uint32]uint32),
	}
	server.initAtoms()
	server.initRequestHandlers()
	server.colormaps[xID(server.defaultColormap)] = &colormap{
		visual:    server.rootVisual,
		pixels:    make(map[uint32]wire.XColorItem),
		allocated: make([]bool, server.rootVisual.ColormapEntries),
		clientID:  make([]uint32, server.rootVisual.ColormapEntries),
		writable:  make([]bool, server.rootVisual.ColormapEntries),
	}
	for k, v := range KeyCodeToKeysym {
		server.keymap[k] = []uint32{v}
	}

	t.Cleanup(func() {
		x11ServerInstance = nil
	})

	var clients []*x11Client
	var buffers []*bytes.Buffer

	for i := 0; i < numClients; i++ {
		clientBuffer := new(bytes.Buffer)
		client := &x11Client{
			id:          server.nextClientID,
			conn:        &testConn{r: new(bytes.Buffer), w: clientBuffer},
			sequence:    0,
			byteOrder:   byteOrder,
			saveSet:     make(map[uint32]bool),
			openDevices: make(map[byte]*wire.DeviceInfo),
		}
		server.clients[client.id] = client
		server.nextClientID++
		clients = append(clients, client)
		buffers = append(buffers, clientBuffer)
	}

	return server, clients, mockFrontend, buffers
}
