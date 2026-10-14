//go:build x11 && !wasm

package x11

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/c2FmZQ/sshterm/internal/x11/wire"
)

func findPseudoColorVisual(s *x11Server) (wire.VisualID, bool) {
	for _, v := range s.visuals {
		if v.Class == wire.PseudoColor {
			return wire.VisualID(v.VisualID), true
		}
	}
	return 0, false
}

func TestAllocColorCells(t *testing.T) {
	s, client, _, _ := setupTestServerWithClient(t)
	pseudoColorVisualID, ok := findPseudoColorVisual(s)
	if !ok {
		t.Skip("no PseudoColor visual found")
	}

	winID := wire.Window(clientXID(client, 2))
	cmapID := wire.Colormap(clientXID(client, 1))

	// Create a window with a PseudoColor visual
	req := &wire.CreateWindowRequest{
		Drawable: winID,
		Parent:   0,
		Width:    10,
		Height:   10,
		Visual:   pseudoColorVisualID,
	}
	s.handleCreateWindow(client, req, 1)

	// Create a colormap with a PseudoColor visual (AllocNone = 0)
	req2 := &wire.CreateColormapRequest{
		Mid:    cmapID,
		Window: winID,
		Visual: pseudoColorVisualID,
		Alloc:  0,
	}
	s.handleCreateColormap(client, req2, 2)

	// Allocate color cells
	req3 := &wire.AllocColorCellsRequest{
		Cmap:   cmapID,
		Colors: 10,
		Planes: 2,
	}
	reply := s.handleAllocColorCells(client, req3, 3)
	require.NotNil(t, reply)
	require.IsType(t, &wire.AllocColorCellsReply{}, reply)
	replyCasted := reply.(*wire.AllocColorCellsReply)
	assert.Equal(t, 10, len(replyCasted.Pixels))
	assert.Equal(t, 2, len(replyCasted.Masks))

	// Allocate more color cells than available
	req4 := &wire.AllocColorCellsRequest{
		Cmap:   cmapID,
		Colors: 300,
		Planes: 0,
	}
	reply2 := s.handleAllocColorCells(client, req4, 4)
	require.NotNil(t, reply2)
	require.IsType(t, &wire.GenericError{}, reply2)
	assert.Equal(t, byte(wire.AllocErrorCode), reply2.(*wire.GenericError).Code())
}

func TestAllocColorPlanes(t *testing.T) {
	s, client, _, _ := setupTestServerWithClient(t)
	pseudoColorVisualID, ok := findPseudoColorVisual(s)
	if !ok {
		t.Skip("no PseudoColor visual found")
	}

	winID := wire.Window(clientXID(client, 2))
	cmapID := wire.Colormap(clientXID(client, 1))

	// Create a window with a PseudoColor visual
	req := &wire.CreateWindowRequest{
		Drawable: winID,
		Parent:   0,
		Width:    10,
		Height:   10,
		Visual:   pseudoColorVisualID,
	}
	s.handleCreateWindow(client, req, 1)

	// Create a colormap with a PseudoColor visual (AllocNone = 0)
	req2 := &wire.CreateColormapRequest{
		Mid:    cmapID,
		Window: winID,
		Visual: pseudoColorVisualID,
		Alloc:  0,
	}
	s.handleCreateColormap(client, req2, 2)

	// Allocate color planes
	req3 := &wire.AllocColorPlanesRequest{
		Cmap:   cmapID,
		Colors: 10,
		Reds:   1,
		Greens: 1,
		Blues:  1,
	}
	reply := s.handleAllocColorPlanes(client, req3, 3)
	require.NotNil(t, reply)
	require.IsType(t, &wire.AllocColorPlanesReply{}, reply)
	replyCasted := reply.(*wire.AllocColorPlanesReply)
	assert.Equal(t, 10, len(replyCasted.Pixels))
	assert.Equal(t, uint32(1), replyCasted.RedMask)
	assert.Equal(t, uint32(2), replyCasted.GreenMask)
	assert.Equal(t, uint32(4), replyCasted.BlueMask)

	// Allocate more color planes than available
	req4 := &wire.AllocColorPlanesRequest{
		Cmap:   cmapID,
		Colors: 300,
		Reds:   1,
		Greens: 1,
		Blues:  1,
	}
	reply2 := s.handleAllocColorPlanes(client, req4, 4)
	require.NotNil(t, reply2)
	require.IsType(t, &wire.GenericError{}, reply2)
	assert.Equal(t, byte(wire.AllocErrorCode), reply2.(*wire.GenericError).Code())
}
