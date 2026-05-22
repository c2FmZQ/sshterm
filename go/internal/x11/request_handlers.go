//go:build x11

package x11

import (
	"github.com/c2FmZQ/sshterm/internal/x11/wire"
)

//
// Handlers for X11 requests
//

func (s *x11Server) handleCreateWindow(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.CreateWindowRequest)
	xid := xID(p.Drawable)
	parentXID := xID(p.Parent)
	if err := s.checkClientID(xid, client, seq, wire.CreateWindow, 0); err != nil {
		return err
	}
	// Check if the window ID is already in use
	if s.resourceExists(xid) {
		s.logger.Errorf("X11: CreateWindow: ID %d already in use", xid)
		return wire.NewGenericError(seq, uint32(p.Drawable), 0, wire.CreateWindow, wire.IDChoiceErrorCode)
	}

	if _, ok := s.windows[parentXID]; !ok && uint32(parentXID) != s.rootWindowID() {
		return wire.NewGenericError(seq, uint32(p.Parent), 0, wire.CreateWindow, wire.WindowErrorCode)
	}

	if p.Width == 0 || p.Height == 0 {
		return wire.NewGenericError(seq, 0, 0, wire.CreateWindow, wire.ValueErrorCode)
	}

	effectiveClass := uint32(p.Class)
	if effectiveClass == 0 { // CopyFromParent
		if parentWindow, ok := s.windows[parentXID]; ok {
			effectiveClass = parentWindow.attributes.Class
		} else {
			effectiveClass = wire.InputOutput
		}
	}

	if effectiveClass == uint32(wire.InputOnly) {
		if p.Depth != 0 || p.BorderWidth != 0 {
			return wire.NewGenericError(seq, 0, 0, wire.CreateWindow, wire.MatchErrorCode)
		}
	}

	parent, _ := s.windows[parentXID]
	if parent != nil && parent.attributes.Class == wire.InputOnly && effectiveClass == wire.InputOutput {
		return wire.NewGenericError(seq, 0, 0, wire.CreateWindow, wire.MatchErrorCode)
	}

	effectiveVisual := uint32(p.Visual)
	if effectiveVisual == 0 {
		if parent != nil {
			effectiveVisual = parent.visual
		} else if uint32(parentXID) == s.rootWindowID() {
			effectiveVisual = s.rootVisual.VisualID
		}
	}

	newWindow := &window{
		xid:         xid,
		parent:      parentXID,
		x:           p.X,
		y:           p.Y,
		width:       p.Width,
		height:      p.Height,
		borderWidth: p.BorderWidth,
		depth:       p.Depth,
		children:    []xID{},
		attributes:  p.Values,
		eventMasks:  make(map[uint32]uint32),
		visual:      effectiveVisual,
	}
	if p.ValueMask&wire.CWEventMask != 0 {
		newWindow.eventMasks[client.id] = p.Values.EventMask
	}
	newWindow.attributes.Class = effectiveClass

	if p.ValueMask&wire.CWColormap != 0 && p.Values.Colormap != 0 {
		if cm, ok := s.colormaps[xID(p.Values.Colormap)]; !ok {
			return wire.NewGenericError(seq, uint32(p.Values.Colormap), 0, wire.CreateWindow, wire.ColormapErrorCode)
		} else if cm.visual.VisualID != effectiveVisual {
			return wire.NewGenericError(seq, 0, 0, wire.CreateWindow, wire.MatchErrorCode)
		}
		newWindow.colormap = xID(p.Values.Colormap)
	} else if parent != nil {
		newWindow.colormap = parent.colormap
		newWindow.attributes.Colormap = wire.Colormap(parent.colormap)
	} else {
		newWindow.colormap = xID(s.defaultColormap)
		newWindow.attributes.Colormap = wire.Colormap(s.defaultColormap)
	}
	s.windows[xid] = newWindow

	// Add to parent's children list
	if parent != nil {
		parent.children = append(parent.children, xid)
	}
	s.frontend.CreateWindow(xid, parentXID, int32(p.X), int32(p.Y), uint32(p.Width), uint32(p.Height), uint32(p.Depth), p.ValueMask, p.Values)
	s.sendCreateNotifyEvent(xid)
	return nil
}

func (s *x11Server) handleChangeWindowAttributes(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.ChangeWindowAttributesRequest)
	xid := xID(p.Window)
	if err := s.checkWindow(xid, seq, wire.ChangeWindowAttributes, 0); err != nil {
		return err
	}
	if err := s.checkClientID(xid, client, seq, wire.ChangeWindowAttributes, 0); err != nil {
		return err
	}
	if w, ok := s.windows[xid]; ok {
		if p.ValueMask&wire.CWBackPixmap != 0 {
			w.attributes.BackgroundPixmap = p.Values.BackgroundPixmap
		}
		if p.ValueMask&wire.CWBackPixel != 0 {
			w.attributes.BackgroundPixel = p.Values.BackgroundPixel
		}
		if p.ValueMask&wire.CWBorderPixmap != 0 {
			w.attributes.BorderPixmap = p.Values.BorderPixmap
		}
		if p.ValueMask&wire.CWBorderPixel != 0 {
			w.attributes.BorderPixel = p.Values.BorderPixel
		}
		if p.ValueMask&wire.CWBitGravity != 0 {
			w.attributes.BitGravity = p.Values.BitGravity
		}
		if p.ValueMask&wire.CWWinGravity != 0 {
			w.attributes.WinGravity = p.Values.WinGravity
		}
		if p.ValueMask&wire.CWBackingStore != 0 {
			w.attributes.BackingStore = p.Values.BackingStore
		}
		if p.ValueMask&wire.CWBackingPlanes != 0 {
			w.attributes.BackingPlanes = p.Values.BackingPlanes
		}
		if p.ValueMask&wire.CWBackingPixel != 0 {
			w.attributes.BackingPixel = p.Values.BackingPixel
		}
		if p.ValueMask&wire.CWOverrideRedirect != 0 {
			w.attributes.OverrideRedirect = p.Values.OverrideRedirect
		}
		if p.ValueMask&wire.CWSaveUnder != 0 {
			w.attributes.SaveUnder = p.Values.SaveUnder
		}
		if p.ValueMask&wire.CWEventMask != 0 {
			w.eventMasks[client.id] = p.Values.EventMask
		}
		if p.ValueMask&wire.CWDontPropagate != 0 {
			w.attributes.DontPropagateMask = p.Values.DontPropagateMask
		}
		if p.ValueMask&wire.CWColormap != 0 {
			if cm, ok := s.colormaps[xID(p.Values.Colormap)]; !ok {
				return wire.NewGenericError(seq, uint32(p.Values.Colormap), 0, wire.ChangeWindowAttributes, wire.ColormapErrorCode)
			} else if cm.visual.VisualID != w.visual {
				return wire.NewGenericError(seq, 0, 0, wire.ChangeWindowAttributes, wire.MatchErrorCode)
			}
			w.attributes.Colormap = p.Values.Colormap
			w.colormap = xID(p.Values.Colormap)
		}
		if p.ValueMask&wire.CWCursor != 0 {
			w.attributes.Cursor = p.Values.Cursor
			s.frontend.SetWindowCursor(xid, xID(p.Values.Cursor))
		}
	}
	s.frontend.ChangeWindowAttributes(xid, p.ValueMask, p.Values)
	return nil
}

func (s *x11Server) handleGetWindowAttributes(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.GetWindowAttributesRequest)
	xid := xID(p.Window)
	if err := s.checkWindow(xid, seq, wire.GetWindowAttributes, 0); err != nil {
		return err
	}
	w, ok := s.windows[xid]
	if !ok {
		// Handle root window
		return &wire.GetWindowAttributesReply{
			Sequence:           seq,
			BackingStore:       0,
			VisualID:           s.rootVisual.VisualID,
			Class:              uint16(wire.InputOutput),
			BitGravity:         0,
			WinGravity:         0,
			BackingPlanes:      0,
			BackingPixel:       0,
			SaveUnder:          0,
			MapIsInstalled:     1,
			MapState:           2, // Viewable
			OverrideRedirect:   0,
			Colormap:           uint32(s.defaultColormap),
			AllEventMasks:      0,
			YourEventMask:      0,
			DoNotPropagateMask: 0,
		}
	}
	return &wire.GetWindowAttributesReply{
		Sequence:           seq,
		BackingStore:       byte(w.attributes.BackingStore),
		VisualID:           w.visual,
		Class:              uint16(w.attributes.Class),
		BitGravity:         byte(w.attributes.BitGravity),
		WinGravity:         byte(w.attributes.WinGravity),
		BackingPlanes:      w.attributes.BackingPlanes,
		BackingPixel:       w.attributes.BackingPixel,
		SaveUnder:          wire.BoolToByte(w.attributes.SaveUnder),
		MapIsInstalled:     wire.BoolToByte(w.attributes.MapIsInstalled),
		MapState:           w.mapState(),
		OverrideRedirect:   wire.BoolToByte(w.attributes.OverrideRedirect),
		Colormap:           uint32(w.attributes.Colormap),
		AllEventMasks:      w.attributes.EventMask,
		YourEventMask:      w.attributes.EventMask,
		DoNotPropagateMask: uint16(w.attributes.DontPropagateMask),
	}
}

func (s *x11Server) handleDestroyWindow(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.DestroyWindowRequest)
	xid := xID(p.Window)
	if uint32(xid) == s.rootWindowID() {
		return nil
	}
	if err := s.checkWindow(xid, seq, wire.DestroyWindow, 0); err != nil {
		return err
	}
	if err := s.checkClientID(xid, client, seq, wire.DestroyWindow, 0); err != nil {
		return err
	}
	s.destroyWindow(xid, true)
	return nil
}

func (s *x11Server) handleDestroySubwindows(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.DestroySubwindowsRequest)
	xid := xID(p.Window)
	if err := s.checkWindow(xid, seq, wire.DestroySubwindows, 0); err != nil {
		return err
	}
	if err := s.checkClientID(xid, client, seq, wire.DestroySubwindows, 0); err != nil {
		return err
	}
	if parent, ok := s.windows[xid]; ok {
		children := make([]xID, len(parent.children))
		copy(children, parent.children)
		for _, childID := range children {
			s.destroyWindow(childID, false)
		}
		parent.children = []xID{}
	}
	s.frontend.DestroySubwindows(xid)
	return nil
}

func (s *x11Server) handleChangeSaveSet(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.ChangeSaveSetRequest)
	xid := xID(p.Window)
	if err := s.checkWindow(xid, seq, wire.ChangeSaveSet, 0); err != nil {
		return err
	}
	if err := s.checkClientID(xid, client, seq, wire.ChangeSaveSet, 0); err != nil {
		return err
	}
	if p.Mode == 0 { // Insert
		client.saveSet[uint32(p.Window)] = true
	} else { // Delete
		delete(client.saveSet, uint32(p.Window))
	}
	return nil
}

func (s *x11Server) handleReparentWindow(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.ReparentWindowRequest)
	windowXID := xID(p.Window)
	parentXID := xID(p.Parent)
	if err := s.checkWindow(windowXID, seq, wire.ReparentWindow, 0); err != nil {
		return err
	}
	if err := s.checkClientID(windowXID, client, seq, wire.ReparentWindow, 0); err != nil {
		return err
	}
	if err := s.checkWindow(parentXID, seq, wire.ReparentWindow, 0); err != nil {
		return err
	}

	if s.isDescendant(windowXID, parentXID) {
		return wire.NewGenericError(seq, uint32(p.Parent), 0, wire.ReparentWindow, wire.MatchErrorCode)
	}

	window, ok := s.windows[windowXID]
	if !ok {
		return wire.NewGenericError(seq, uint32(p.Window), 0, wire.ReparentWindow, wire.WindowErrorCode)
	}

	oldParent, ok := s.windows[window.parent]
	if !ok && uint32(window.parent) != s.rootWindowID() {
		return wire.NewGenericError(seq, uint32(window.parent), 0, wire.ReparentWindow, wire.WindowErrorCode)
	}
	newParent := s.windows[parentXID]

	// Remove from old parent's children
	if ok {
		for i, childID := range oldParent.children {
			if childID == window.xid {
				oldParent.children = append(oldParent.children[:i], oldParent.children[i+1:]...)
				break
			}
		}
	}

	// Add to new parent's children
	if newParent != nil {
		newParent.children = append(newParent.children, window.xid)
	}

	// Update window's state
	window.parent = parentXID
	window.x = p.X
	window.y = p.Y

	// Note: Reparenting adds the window to the top of the new parent's stacking
	// order. The `children` slice in the new parent now maintains this order.

	s.frontend.ReparentWindow(windowXID, parentXID, p.X, p.Y)
	return nil
}

func (s *x11Server) handleMapWindow(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.MapWindowRequest)
	xid := xID(p.Window)
	if err := s.checkWindow(xid, seq, wire.MapWindow, 0); err != nil {
		return err
	}
	if err := s.checkClientID(xid, client, seq, wire.MapWindow, 0); err != nil {
		return err
	}
	if w, ok := s.windows[xid]; ok {
		w.mapped = true
		// Move to top of stack on map
		s.moveWindowToTop(xid)
		s.frontend.MapWindow(xid)
		s.sendExposeEvent(xid, 0, 0, w.width, w.height)
		s.sendMapNotifyEvent(xid)
	}
	return nil
}

func (s *x11Server) handleMapSubwindows(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.MapSubwindowsRequest)
	xid := xID(p.Window)
	if err := s.checkWindow(xid, seq, wire.MapSubwindows, 0); err != nil {
		return err
	}
	if err := s.checkClientID(xid, client, seq, wire.MapSubwindows, 0); err != nil {
		return err
	}
	if parentWindow, ok := s.windows[xid]; ok {
		for _, childID := range parentWindow.children {
			childXID := xID(childID)
			if childWindow, ok := s.windows[childXID]; ok {
				childWindow.mapped = true
				s.frontend.MapWindow(childXID)
				s.sendExposeEvent(childXID, 0, 0, childWindow.width, childWindow.height)
			}
		}
	}
	return nil
}

func (s *x11Server) handleUnmapWindow(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.UnmapWindowRequest)
	xid := xID(p.Window)
	if err := s.checkWindow(xid, seq, wire.UnmapWindow, 0); err != nil {
		return err
	}
	if err := s.checkClientID(xid, client, seq, wire.UnmapWindow, 0); err != nil {
		return err
	}
	if w, ok := s.windows[xid]; ok {
		w.mapped = false
		s.frontend.UnmapWindow(xid)
		s.sendUnmapNotifyEvent(xid, false)
	}
	return nil
}

func (s *x11Server) handleUnmapSubwindows(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.UnmapSubwindowsRequest)
	xid := xID(p.Window)
	if err := s.checkWindow(xid, seq, wire.UnmapSubwindows, 0); err != nil {
		return err
	}
	if err := s.checkClientID(xid, client, seq, wire.UnmapSubwindows, 0); err != nil {
		return err
	}
	if parentWindow, ok := s.windows[xid]; ok {
		for _, childID := range parentWindow.children {
			childXID := xID(childID)
			if childWindow, ok := s.windows[childXID]; ok {
				childWindow.mapped = false
				s.frontend.UnmapWindow(childXID)
			}
		}
	}
	return nil
}

func (s *x11Server) handleConfigureWindow(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.ConfigureWindowRequest)
	xid := xID(p.Window)
	if err := s.checkWindow(xid, seq, wire.ConfigureWindow, 0); err != nil {
		return err
	}
	if err := s.checkClientID(xid, client, seq, wire.ConfigureWindow, 0); err != nil {
		return err
	}
	if uint32(xid) == s.rootWindowID() {
		return wire.NewGenericError(seq, uint32(p.Window), 0, wire.ConfigureWindow, wire.MatchErrorCode)
	}

	// Calculate expected number of values
	expectedValues := 0
	for i := 0; i < 7; i++ {
		if (p.ValueMask & (1 << i)) != 0 {
			expectedValues++
		}
	}
	if len(p.Values) < expectedValues {
		return wire.NewGenericError(seq, 0, 0, wire.ConfigureWindow, wire.ValueErrorCode)
	}

	if w, ok := s.windows[xid]; ok {
		valueIndex := 0
		if (p.ValueMask & (1 << 0)) != 0 { // x
			w.x = int16(p.Values[valueIndex])
			valueIndex++
		}
		if (p.ValueMask & (1 << 1)) != 0 { // y
			w.y = int16(p.Values[valueIndex])
			valueIndex++
		}
		if (p.ValueMask & (1 << 2)) != 0 { // width
			w.width = uint16(p.Values[valueIndex])
			if w.width == 0 {
				return wire.NewGenericError(seq, 0, 0, wire.ConfigureWindow, wire.ValueErrorCode)
			}
			valueIndex++
		}
		if (p.ValueMask & (1 << 3)) != 0 { // height
			w.height = uint16(p.Values[valueIndex])
			if w.height == 0 {
				return wire.NewGenericError(seq, 0, 0, wire.ConfigureWindow, wire.ValueErrorCode)
			}
			valueIndex++
		}
		if (p.ValueMask & (1 << 4)) != 0 { // border-width
			w.borderWidth = uint16(p.Values[valueIndex])
			valueIndex++
		}
	}

	if p.ValueMask&wire.CWStackMode != 0 {
		var stackMode, sibling uint32
		valueIndex := 0
		// The order of values is determined by the bit position in the value-mask (from LSB to MSB).
		if (p.ValueMask & (1 << 0)) != 0 { // x
			valueIndex++
		}
		if (p.ValueMask & (1 << 1)) != 0 { // y
			valueIndex++
		}
		if (p.ValueMask & (1 << 2)) != 0 { // width
			valueIndex++
		}
		if (p.ValueMask & (1 << 3)) != 0 { // height
			valueIndex++
		}
		if (p.ValueMask & (1 << 4)) != 0 { // border-width
			valueIndex++
		}
		if (p.ValueMask & wire.CWSibling) != 0 {
			sibling = p.Values[valueIndex]
			valueIndex++
		}
		if (p.ValueMask & wire.CWStackMode) != 0 {
			stackMode = p.Values[valueIndex]
		}

		if stackMode > 4 {
			return wire.NewGenericError(seq, stackMode, 0, wire.ConfigureWindow, wire.ValueErrorCode)
		}

		s.reconfigureStacking(xid, stackMode, xID(sibling))
	}

	s.frontend.ConfigureWindow(xid, p.ValueMask, p.Values)
	if w, ok := s.windows[xid]; ok {
		s.sendConfigureNotifyEvent(xid, w.x, w.y, w.width, w.height, w.borderWidth, 0)
	}
	return nil
}

func (s *x11Server) handleCirculateWindow(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.CirculateWindowRequest)
	xid := xID(p.Window)
	if err := s.checkWindow(xid, seq, wire.CirculateWindow, 0); err != nil {
		return err
	}
	if err := s.checkClientID(xid, client, seq, wire.CirculateWindow, 0); err != nil {
		return err
	}
	if _, ok := s.windows[xid]; !ok {
		return wire.NewGenericError(seq, uint32(p.Window), 0, wire.CirculateWindow, wire.WindowErrorCode)
	}
	if p.Direction == 0 { // RaiseLowest
		s.moveWindowToTop(xid)
	} else { // LowerHighest
		s.moveWindowToBottom(xid)
	}

	s.frontend.CirculateWindow(xid, p.Direction)
	return nil
}

func (s *x11Server) handleGetGeometry(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.GetGeometryRequest)
	xid := xID(p.Drawable)
	if err := s.checkDrawable(xid, seq, wire.GetGeometry, 0); err != nil {
		return err
	}
	if uint32(xid) == s.rootWindowID() {
		return &wire.GetGeometryReply{
			Sequence:    seq,
			Depth:       s.rootVisual.Depth,
			Root:        s.rootWindowID(),
			X:           0,
			Y:           0,
			Width:       s.config.ScreenWidth,
			Height:      s.config.ScreenHeight,
			BorderWidth: 0,
		}
	}
	if w, ok := s.windows[xid]; ok {
		return &wire.GetGeometryReply{
			Sequence:    seq,
			Depth:       w.depth,
			Root:        s.rootWindowID(),
			X:           w.x,
			Y:           w.y,
			Width:       w.width,
			Height:      w.height,
			BorderWidth: w.borderWidth,
		}
	}
	if p, ok := s.pixmaps[xid]; ok {
		return &wire.GetGeometryReply{
			Sequence:    seq,
			Depth:       p.depth,
			Root:        s.rootWindowID(),
			X:           0,
			Y:           0,
			Width:       p.width,
			Height:      p.height,
			BorderWidth: 0,
		}
	}
	// Should not be reached if checkDrawable is correct.
	return wire.NewGenericError(seq, uint32(xid), 0, wire.GetGeometry, wire.DrawableErrorCode)
}

func (s *x11Server) handleQueryTree(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.QueryTreeRequest)
	xid := xID(p.Window)
	if err := s.checkWindow(xid, seq, wire.QueryTree, 0); err != nil {
		return err
	}
	window, ok := s.windows[xid]
	if !ok {
		// Should not happen as checkWindow passed, but handles root if not in map
		return &wire.QueryTreeReply{
			Sequence: seq,
			Root:     s.rootWindowID(),
		}
	}

	children := make([]uint32, len(window.children))
	for i, childXID := range window.children {
		children[i] = uint32(childXID)
	}

	return &wire.QueryTreeReply{
		Sequence:    seq,
		Root:        s.rootWindowID(),
		Parent:      uint32(window.parent),
		NumChildren: uint16(len(children)),
		Children:    children,
	}
}

func (s *x11Server) handleInternAtom(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.InternAtomRequest)
	var atomID uint32
	if p.OnlyIfExists {
		var ok bool
		atomID, ok = s.atoms[p.Name]
		if !ok {
			atomID = 0 // None
		}
	} else {
		atomID = s.GetAtom(p.Name)
	}

	return &wire.InternAtomReply{
		Sequence: seq,
		Atom:     atomID,
	}
}

func (s *x11Server) handleGetAtomName(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.GetAtomNameRequest)
	name, ok := s.atomNames[uint32(p.Atom)]
	if !ok {
		return wire.NewGenericError(seq, uint32(p.Atom), 0, wire.GetAtomName, wire.AtomErrorCode)
	}
	return &wire.GetAtomNameReply{
		Sequence:   seq,
		NameLength: uint16(len(name)),
		Name:       name,
	}
}

func (s *x11Server) handleChangeProperty(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.ChangePropertyRequest)
	xid := xID(p.Window)
	if err := s.checkWindow(xid, seq, wire.ChangeProperty, 0); err != nil {
		return err
	}
	if err := s.checkClientID(xid, client, seq, wire.ChangeProperty, 0); err != nil {
		return err
	}
	s.ChangeProperty(xid, uint32(p.Property), uint32(p.Type), byte(p.Format), p.Data)
	return nil
}

func (s *x11Server) handleDeleteProperty(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.DeletePropertyRequest)
	xid := xID(p.Window)
	if err := s.checkWindow(xid, seq, wire.DeleteProperty, 0); err != nil {
		return err
	}
	if err := s.checkClientID(xid, client, seq, wire.DeleteProperty, 0); err != nil {
		return err
	}
	s.DeleteProperty(xid, uint32(p.Property))
	return nil
}

func (s *x11Server) handleGetProperty(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.GetPropertyRequest)
	xid := xID(p.Window)
	if err := s.checkWindow(xid, seq, wire.GetProperty, 0); err != nil {
		return err
	}
	prop := s.GetProperty(xid, uint32(p.Property))

	if prop == nil {
		return &wire.GetPropertyReply{
			Sequence: seq,
			Format:   0,
		}
	}

	// Calculate slice
	byteOffset := uint64(p.Offset) * 4
	byteLength := uint64(p.Length) * 4
	totalLen := uint64(len(prop.data))

	if byteOffset >= totalLen {
		return &wire.GetPropertyReply{
			Sequence:              seq,
			Format:                prop.format,
			PropertyType:          prop.typeAtom,
			BytesAfter:            0,
			ValueLenInFormatUnits: 0,
			Value:                 nil,
		}
	}

	end := byteOffset + byteLength
	if end > totalLen {
		end = totalLen
	}
	dataToSend := prop.data[byteOffset:end]
	bytesAfter := totalLen - end

	var valueLenInFormatUnits uint32
	if prop.format == 8 {
		valueLenInFormatUnits = uint32(len(dataToSend))
	} else if prop.format == 16 {
		valueLenInFormatUnits = uint32(len(dataToSend) / 2)
	} else if prop.format == 32 {
		valueLenInFormatUnits = uint32(len(dataToSend) / 4)
	}

	if p.Delete && bytesAfter == 0 && (p.Type == 0 || prop.typeAtom == uint32(p.Type)) {
		s.DeleteProperty(xid, uint32(p.Property))
	}

	if p.Type != 0 && prop.typeAtom != uint32(p.Type) {
		return &wire.GetPropertyReply{
			Sequence:              seq,
			Format:                prop.format,
			PropertyType:          prop.typeAtom,
			BytesAfter:            uint32(totalLen), // Full length
			ValueLenInFormatUnits: 0,
			Value:                 nil,
		}
	}

	return &wire.GetPropertyReply{
		Sequence:              seq,
		Format:                prop.format,
		PropertyType:          prop.typeAtom,
		BytesAfter:            uint32(bytesAfter),
		ValueLenInFormatUnits: valueLenInFormatUnits,
		Value:                 dataToSend,
	}
}

func (s *x11Server) handleListProperties(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.ListPropertiesRequest)
	xid := xID(p.Window)
	if err := s.checkWindow(xid, seq, wire.ListProperties, 0); err != nil {
		return err
	}
	propIDs := s.ListProperties(xid)
	return &wire.ListPropertiesReply{
		Sequence:      seq,
		NumProperties: uint16(len(propIDs)),
		Atoms:         propIDs,
	}
}

func (s *x11Server) handleSetSelectionOwner(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.SetSelectionOwnerRequest)
	selectionAtom := uint32(p.Selection)
	ownerWindow := uint32(p.Owner)
	time := uint32(p.Time)

	if time == 0 { // CurrentTime
		time = s.serverTime()
	}

	// "If the timestamp is not CurrentTime and is less than the timestamp of the last successful SetSelectionOwner request for the selection, the request is ignored."
	currentOwner, ok := s.selections[selectionAtom]
	if ok && time < currentOwner.time && p.Time != 0 {
		return nil
	}

	if ownerWindow == 0 { // None
		delete(s.selections, selectionAtom)
	} else {
		if err := s.checkWindow(xID(ownerWindow), seq, wire.SetSelectionOwner, 0); err != nil {
			return err
		}
		s.selections[selectionAtom] = &selectionOwner{
			window: xID(ownerWindow),
			time:   time,
		}
	}

	if ok && currentOwner.window != 0 && (currentOwner.window != xID(ownerWindow)) {
		// Send SelectionClear to old owner
		if oldClient, ok := s.clients[((uint32(currentOwner.window) >> resourceIDShift) & clientIDMask)]; ok {
			event := &wire.SelectionClearEvent{
				Sequence:  oldClient.sequence - 1, // Approximate
				Time:      time,
				Owner:     uint32(currentOwner.window),
				Selection: selectionAtom,
			}
			s.sendEvent(oldClient, event)
		}
	}
	return nil
}

func (s *x11Server) handleGetSelectionOwner(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.GetSelectionOwnerRequest)
	selectionAtom := uint32(p.Selection)
	var owner uint32
	if o, ok := s.selections[selectionAtom]; ok {
		owner = uint32(o.window)
	}
	return &wire.GetSelectionOwnerReply{
		Sequence: seq,
		Owner:    owner,
	}
}

func (s *x11Server) handleConvertSelection(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.ConvertSelectionRequest)
	selectionAtom := uint32(p.Selection)
	targetAtom := uint32(p.Target)
	propertyAtom := uint32(p.Property)
	requestor := xID(p.Requestor)
	time := uint32(p.Time)
	if time == 0 {
		time = s.serverTime()
	}

	if err := s.checkWindow(requestor, seq, wire.ConvertSelection, 0); err != nil {
		return err
	}

	owner, ok := s.selections[selectionAtom]

	// Special handling for CLIPBOARD if no owner
	clipboardAtom := s.GetAtom("CLIPBOARD")
	if !ok && selectionAtom == clipboardAtom {
		go func() {
			content, err := s.frontend.ReadClipboard()
			if err != nil {
				s.SendSelectionNotify(requestor, selectionAtom, targetAtom, 0, nil)
				return
			}

			targetName := s.GetAtomName(targetAtom)
			var propertyType uint32
			var data []byte
			var format byte

			switch targetName {
			case "STRING", "TEXT", "UTF8_STRING":
				propertyType = s.GetAtom(targetName)
				data = []byte(content)
				format = 8
			default:
				// If the target is not a known string type, we cannot convert.
				// Send a SelectionNotify with property None.
				s.SendSelectionNotify(requestor, selectionAtom, targetAtom, 0, nil)
				return
			}

			s.mu.Lock()
			defer s.mu.Unlock()
			s.ChangeProperty(requestor, propertyAtom, propertyType, format, data)
			s.SendSelectionNotify(requestor, selectionAtom, targetAtom, propertyAtom, nil)
		}()
		return nil
	}

	if ok {
		// Send SelectionRequest to owner
		if ownerClient, ok := s.clients[((uint32(owner.window) >> resourceIDShift) & clientIDMask)]; ok {
			event := &wire.SelectionRequestEvent{
				Sequence:  ownerClient.sequence - 1,
				Time:      time,
				Owner:     uint32(owner.window),
				Requestor: uint32(requestor),
				Selection: selectionAtom,
				Target:    targetAtom,
				Property:  propertyAtom,
			}
			s.sendEvent(ownerClient, event)
		}
		return nil
	}

	// No owner, send SelectionNotify with property None
	s.SendSelectionNotify(requestor, selectionAtom, targetAtom, 0, nil)
	return nil
}

func (s *x11Server) handleSendEvent(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.SendEventRequest)
	destination := xID(p.Destination)

	destWindow, ok := s.windows[destination]
	if !ok {
		// If destination is not a valid window, do nothing.
		return nil
	}

	targetClient, ok := s.clients[((uint32(destWindow.xid) >> resourceIDShift) & clientIDMask)]
	if !ok {
		// If the client owning the window is gone, do nothing.
		return nil
	}

	event, err := wire.ParseEvent(p.EventData, s.byteOrder)
	if err != nil {
		s.logger.Errorf("X11: SendEvent: failed to parse event: %v", err)
		return nil
	}

	var eventMask uint32
	switch e := event.(type) {
	case *wire.KeyEvent:
		if e.Opcode == wire.KeyPress {
			eventMask = wire.KeyPressMask
		} else {
			eventMask = wire.KeyReleaseMask
		}
	case *wire.ButtonPressEvent:
		eventMask = wire.ButtonPressMask
	case *wire.ButtonReleaseEvent:
		eventMask = wire.ButtonReleaseMask
	case *wire.MotionNotifyEvent:
		eventMask = wire.PointerMotionMask
	}

	if p.Propagate || (destWindow.attributes.EventMask&eventMask) != 0 {
		s.sendEvent(targetClient, &wire.X11RawEvent{Data: p.EventData})
	}

	return nil
}

func (s *x11Server) handleGrabPointer(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.GrabPointerRequest)
	grabWindow := xID(p.GrabWindow)
	if err := s.checkWindow(grabWindow, seq, wire.GrabPointer, 0); err != nil {
		return err
	}
	if p.ConfineTo != 0 {
		if err := s.checkWindow(xID(p.ConfineTo), seq, wire.GrabPointer, 0); err != nil {
			return err
		}
	}
	if p.Cursor != 0 {
		if err := s.checkCursor(xID(p.Cursor), seq, wire.GrabPointer, 0); err != nil {
			return err
		}
	}

	if p.Time != 0 {
		if uint32(p.Time) < s.pointerGrabTime || uint32(p.Time) > s.serverTime() {
			return &wire.GrabPointerReply{Sequence: seq, Status: wire.GrabInvalidTime}
		}
	}

	if s.pointerGrabWindow != 0 && s.pointerGrabClientID != client.id {
		return &wire.GrabPointerReply{
			Sequence: seq,
			Status:   wire.AlreadyGrabbed,
		}
	}

	s.pointerGrabWindow = grabWindow
	s.pointerGrabClientID = client.id
	s.pointerGrabOwner = p.OwnerEvents
	s.pointerGrabEventMask = p.EventMask
	s.pointerGrabTime = uint32(p.Time)
	if s.pointerGrabTime == 0 {
		s.pointerGrabTime = s.serverTime()
	}
	s.pointerGrabMode = p.PointerMode
	s.keyboardGrabMode = p.KeyboardMode
	s.pointerGrabConfineTo = xID(p.ConfineTo)
	s.pointerGrabCursor = xID(p.Cursor)

	if p.PointerMode == wire.GrabModeSync {
		s.pointerFrozen = true
	}
	if p.KeyboardMode == wire.GrabModeSync {
		s.keyboardFrozen = true
	}

	if p.Cursor != 0 {
		s.frontend.SetWindowCursor(grabWindow, s.pointerGrabCursor)
	}

	if status := s.frontend.GrabPointer(grabWindow, p.OwnerEvents, p.EventMask, p.PointerMode, p.KeyboardMode, uint32(p.ConfineTo), uint32(p.Cursor), uint32(p.Time)); status != 0 {
		// If frontend fails, rollback? Or just return success as X11 server state is updated?
		// Usually frontend should mirror server state.
		// For now, we assume success if server state is updated, but ideally we should respect frontend status.
		// However, GrabPointer return type in X11 is specific.
		// Let's assume frontend logic mirrors X11 logic and returns 0 on success.
		if status != wire.GrabSuccess {
			s.pointerGrabWindow = 0
			return &wire.GrabPointerReply{Sequence: seq, Status: status}
		}
	}

	return &wire.GrabPointerReply{
		Sequence: seq,
		Status:   wire.GrabSuccess,
	}
}

func (s *x11Server) handleUngrabPointer(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.UngrabPointerRequest)
	if p.Time != 0 && uint32(p.Time) < s.pointerGrabTime {
		// Ignore
		return nil
	}
	s.pointerGrabWindow = 0
	s.pointerGrabClientID = 0
	s.pointerGrabOwner = false
	s.pointerGrabEventMask = 0
	s.pointerGrabTime = 0
	s.pointerGrabMode = 0
	s.keyboardGrabMode = 0
	s.pointerGrabConfineTo = 0
	s.pointerGrabCursor = 0
	s.flushPointerEvents()
	s.frontend.UngrabPointer(uint32(p.Time))
	return nil
}

func (s *x11Server) handleGrabButton(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.GrabButtonRequest)
	grabWindow := xID(p.GrabWindow)
	if _, ok := s.windows[grabWindow]; !ok {
		return wire.NewGenericError(seq, uint32(p.GrabWindow), 0, wire.GrabButton, wire.WindowErrorCode)
	}

	grab := &passiveGrab{
		clientID:     client.id,
		button:       p.Button,
		modifiers:    p.Modifiers,
		owner:        p.OwnerEvents,
		eventMask:    p.EventMask,
		cursor:       xID(p.Cursor),
		pointerMode:  p.PointerMode,
		keyboardMode: p.KeyboardMode,
		confineTo:    xID(p.ConfineTo),
	}
	s.passiveGrabs[grabWindow] = append(s.passiveGrabs[grabWindow], grab)
	return nil
}

func (s *x11Server) handleUngrabButton(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.UngrabButtonRequest)
	grabWindow := xID(p.GrabWindow)
	if err := s.checkWindow(grabWindow, seq, wire.UngrabButton, 0); err != nil {
		return err
	}
	if grabs, ok := s.passiveGrabs[grabWindow]; ok {
		for i, grab := range grabs {
			if grab.button == p.Button && grab.modifiers == p.Modifiers {
				s.passiveGrabs[grabWindow] = append(grabs[:i], grabs[i+1:]...)
				break
			}
		}
	}
	return nil
}

func (s *x11Server) handleChangeActivePointerGrab(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.ChangeActivePointerGrabRequest)
	if s.pointerGrabClientID == client.id && s.pointerGrabWindow != 0 {
		if p.Cursor != 0 {
			cursorXID := xID(p.Cursor)
			if err := s.checkCursor(cursorXID, seq, wire.ChangeActivePointerGrab, 0); err != nil {
				return err
			}
			s.frontend.SetWindowCursor(s.pointerGrabWindow, cursorXID)
		}
		s.pointerGrabEventMask = p.EventMask
		if p.Time == 0 || uint32(p.Time) >= s.pointerGrabTime {
			s.pointerGrabTime = uint32(p.Time)
		}
	}
	return nil
}

func (s *x11Server) handleGrabKeyboard(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.GrabKeyboardRequest)
	grabWindow := xID(p.GrabWindow)
	if err := s.checkWindow(grabWindow, seq, wire.GrabKeyboard, 0); err != nil {
		return err
	}
	if p.Time != 0 {
		if uint32(p.Time) < s.keyboardGrabTime || uint32(p.Time) > s.serverTime() {
			return &wire.GrabKeyboardReply{Sequence: seq, Status: wire.GrabInvalidTime}
		}
	}

	if s.keyboardGrabWindow != 0 && s.keyboardGrabClientID != client.id {
		return &wire.GrabKeyboardReply{
			Sequence: seq,
			Status:   wire.AlreadyGrabbed,
		}
	}

	s.keyboardGrabWindow = grabWindow
	s.keyboardGrabClientID = client.id
	s.keyboardGrabOwner = p.OwnerEvents
	s.keyboardGrabTime = uint32(p.Time)
	if s.keyboardGrabTime == 0 {
		s.keyboardGrabTime = s.serverTime()
	}
	s.keyboardGrabMode = p.KeyboardMode
	s.pointerGrabMode = p.PointerMode

	if p.PointerMode == wire.GrabModeSync {
		s.pointerFrozen = true
	}
	if p.KeyboardMode == wire.GrabModeSync {
		s.keyboardFrozen = true
	}

	return &wire.GrabKeyboardReply{
		Sequence: seq,
		Status:   wire.GrabSuccess,
	}
}

func (s *x11Server) handleUngrabKeyboard(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.UngrabKeyboardRequest)
	if p.Time != 0 && uint32(p.Time) < s.keyboardGrabTime {
		// Ignore
		return nil
	}
	s.keyboardGrabWindow = 0
	s.keyboardGrabClientID = 0
	s.keyboardGrabOwner = false
	s.keyboardGrabTime = 0
	s.keyboardGrabMode = 0
	s.flushKeyboardEvents()
	return nil
}

func (s *x11Server) handleGrabKey(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.GrabKeyRequest)
	grabWindow := xID(p.GrabWindow)
	if _, ok := s.windows[grabWindow]; !ok {
		return wire.NewGenericError(seq, uint32(p.GrabWindow), 0, wire.GrabKey, wire.WindowErrorCode)
	}
	grab := &passiveGrab{
		clientID:     client.id,
		key:          p.Key,
		modifiers:    p.Modifiers,
		owner:        p.OwnerEvents,
		pointerMode:  p.PointerMode,
		keyboardMode: p.KeyboardMode,
	}
	s.passiveGrabs[grabWindow] = append(s.passiveGrabs[grabWindow], grab)
	return nil
}

func (s *x11Server) handleUngrabKey(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.UngrabKeyRequest)
	grabWindow := xID(p.GrabWindow)
	if err := s.checkWindow(grabWindow, seq, wire.UngrabKey, 0); err != nil {
		return err
	}
	if grabs, ok := s.passiveGrabs[grabWindow]; ok {
		newGrabs := make([]*passiveGrab, 0, len(grabs))
		for _, grab := range grabs {
			if !(grab.key == p.Key && (p.Modifiers == wire.AnyModifier || grab.modifiers == p.Modifiers)) {
				newGrabs = append(newGrabs, grab)
			}
		}
		s.passiveGrabs[grabWindow] = newGrabs
	}
	return nil
}

func (s *x11Server) handleAllowEvents(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.AllowEventsRequest)
	debugf("X11: handleAllowEvents mode=%d time=%d", p.Mode, p.Time)

	switch p.Mode {
	case wire.AsyncPointer:
		s.flushPointerEvents()
	case wire.SyncPointer:
		// TODO: Full implementation of SyncPointer
		s.flushPointerEvents()
	case wire.ReplayPointer:
		// TODO: Full implementation of ReplayPointer
		s.flushPointerEvents()
	case wire.AsyncKeyboard:
		s.flushKeyboardEvents()
	case wire.SyncKeyboard:
		// TODO: Full implementation of SyncKeyboard
		s.flushKeyboardEvents()
	case wire.ReplayKeyboard:
		// TODO: Full implementation of ReplayKeyboard
		s.flushKeyboardEvents()
	case wire.AsyncBoth:
		s.flushPointerEvents()
		s.flushKeyboardEvents()
	case wire.SyncBoth:
		// TODO: Full implementation of SyncBoth
		s.flushPointerEvents()
		s.flushKeyboardEvents()
	}

	s.frontend.AllowEvents(client.id, p.Mode, uint32(p.Time))
	return nil
}

func (s *x11Server) handleGrabServer(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	if !s.serverGrabbed {
		s.serverGrabbed = true
		s.grabbingClientID = client.id
	}
	return nil
}

func (s *x11Server) handleUngrabServer(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	s.serverGrabbed = false
	s.grabbingClientID = 0
	return nil
}

func (s *x11Server) handleQueryPointer(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.QueryPointerRequest)
	xid := xID(p.Drawable)
	if err := s.checkDrawable(xid, seq, wire.QueryPointer, 0); err != nil {
		return err
	}
	winX, winY := s.pointerX, s.pointerY
	absX, absY, ok := s.getAbsoluteWindowCoords(xid)
	if ok {
		winX -= absX
		winY -= absY
	}

	var childID xID
	// Only search for children if the requested drawable is a window
	if _, isWindow := s.windows[xid]; isWindow {
		childID = s.findChildWindowAt(xid, winX, winY)
	}

	debugf("X11: QueryPointer drawable=%d", xid)
	return &wire.QueryPointerReply{
		Sequence:   seq,
		SameScreen: true,
		Root:       s.rootWindowID(),
		Child:      uint32(childID),
		RootX:      s.pointerX,
		RootY:      s.pointerY,
		WinX:       winX,
		WinY:       winY,
		Mask:       s.pointerState,
	}
}

func (s *x11Server) handleGetMotionEvents(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.GetMotionEventsRequest)
	if err := s.checkWindow(xID(p.Window), seq, wire.GetMotionEvents, 0); err != nil {
		return err
	}
	startTime := p.Start
	stopTime := p.Stop
	if stopTime == 0 {
		stopTime = wire.Timestamp(s.serverTime())
	}

	var events []wire.TimeCoord
	for _, ev := range s.motionEvents {
		if wire.Timestamp(ev.time) >= startTime && wire.Timestamp(ev.time) <= stopTime {
			if ev.window == xID(p.Window) {
				events = append(events, wire.TimeCoord{
					Time: ev.time,
					X:    ev.x,
					Y:    ev.y,
				})
			}
		}
	}

	return &wire.GetMotionEventsReply{
		Sequence: seq,
		NEvents:  uint32(len(events)),
		Events:   events,
	}
}

func (s *x11Server) handleTranslateCoords(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.TranslateCoordsRequest)
	srcWindow := xID(p.SrcWindow)
	dstWindow := xID(p.DstWindow)

	if p.SrcWindow != wire.Window(s.rootWindowID()) {
		if err := s.checkWindow(srcWindow, seq, wire.TranslateCoords, 0); err != nil {
			return err
		}
	}
	if p.DstWindow != wire.Window(s.rootWindowID()) {
		if err := s.checkWindow(dstWindow, seq, wire.TranslateCoords, 0); err != nil {
			return err
		}
	}

	srcAbsX, srcAbsY, ok := s.getAbsoluteWindowCoords(srcWindow)
	if !ok && p.SrcWindow != wire.Window(s.rootWindowID()) {
		// This should not happen if checkWindow passed
		return wire.NewGenericError(seq, uint32(p.SrcWindow), 0, wire.TranslateCoords, wire.WindowErrorCode)
	}

	dstAbsX, dstAbsY, ok := s.getAbsoluteWindowCoords(dstWindow)
	if !ok && p.DstWindow != wire.Window(s.rootWindowID()) {
		// This should not happen if checkWindow passed
		return wire.NewGenericError(seq, uint32(p.DstWindow), 0, wire.TranslateCoords, wire.WindowErrorCode)
	}

	// Calculate the absolute coordinates of the point
	absPointX := int32(srcAbsX) + int32(p.SrcX)
	absPointY := int32(srcAbsY) + int32(p.SrcY)

	// Translate to be relative to the destination window
	dstX := int16(absPointX - int32(dstAbsX))
	dstY := int16(absPointY - int32(dstAbsY))

	var childID xID
	if uint32(dstWindow) == s.rootWindowID() {
		childID = s.findTopLevelWindowAt(dstX, dstY)
	} else if w, isWindow := s.windows[dstWindow]; isWindow && w.mapped {
		childID = s.findChildWindowAt(dstWindow, dstX, dstY)
	}

	return &wire.TranslateCoordsReply{
		Sequence:   seq,
		SameScreen: true,
		Child:      uint32(childID),
		DstX:       dstX,
		DstY:       dstY,
	}
}

func (s *x11Server) handleWarpPointer(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.WarpPointerRequest)
	if p.SrcWindow != 0 {
		if err := s.checkWindow(xID(p.SrcWindow), seq, wire.WarpPointer, 0); err != nil {
			return err
		}
	}
	if p.DstWindow != 0 {
		if err := s.checkWindow(xID(p.DstWindow), seq, wire.WarpPointer, 0); err != nil {
			return err
		}
	}
	s.frontend.WarpPointer(p.DstX, p.DstY)
	return nil
}

func (s *x11Server) handleSetInputFocus(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.SetInputFocusRequest)
	xid := xID(p.Focus)
	// Focus can be None(0) or PointerRoot(1).
	if uint32(p.Focus) > 1 {
		if err := s.checkWindow(xid, seq, wire.SetInputFocus, 0); err != nil {
			return err
		}
	}

	if s.inputFocus != xid {
		oldFocus := s.inputFocus
		s.inputFocus = xid

		// Send FocusOut to the old focus window
		if oldFocus != 0 && uint32(oldFocus) != 1 {
			if w, ok := s.windows[oldFocus]; ok {
				for clientID, mask := range w.eventMasks {
					if mask&wire.FocusChangeMask != 0 {
						if c, ok := s.clients[clientID]; ok {
							var eventSeq uint16
							if c == client {
								eventSeq = seq
							} else {
								eventSeq = c.sequence - 1
							}
							s.sendEvent(c, &wire.FocusOutEvent{
								Sequence: eventSeq,
								Window:   uint32(oldFocus),
								Mode:     0, // Normal
								Detail:   0, // NotifyAncestor
							})
						}
					}
				}
			}
		}

		// Send FocusIn to the new focus window
		if xid != 0 && uint32(xid) != 1 {
			if w, ok := s.windows[xid]; ok {
				for clientID, mask := range w.eventMasks {
					if mask&wire.FocusChangeMask != 0 {
						if c, ok := s.clients[clientID]; ok {
							var eventSeq uint16
							if c == client {
								eventSeq = seq
							} else {
								eventSeq = c.sequence - 1
							}
							s.sendEvent(c, &wire.FocusInEvent{
								Sequence: eventSeq,
								Window:   uint32(xid),
								Mode:     0, // Normal
								Detail:   0, // NotifyAncestor
							})
						}
					}
				}
			}
		}
	}

	s.frontend.SetInputFocus(xid, p.RevertTo)
	return nil
}

func (s *x11Server) handleGetInputFocus(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	return &wire.GetInputFocusReply{
		Sequence: seq,
		RevertTo: 1, // RevertToParent
		Focus:    uint32(s.inputFocus),
	}
}

func (s *x11Server) handleQueryKeymap(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	var keymap [32]byte
	for keycode := range s.pressedKeys {
		byteIndex := keycode / 8
		bitIndex := keycode % 8
		if byteIndex < 32 {
			keymap[byteIndex] |= (1 << bitIndex)
		}
	}
	return &wire.QueryKeymapReply{
		Sequence: seq,
		Keys:     keymap,
	}
}

func (s *x11Server) handleOpenFont(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.OpenFontRequest)
	fid := xID(p.Fid)
	if err := s.checkClientID(fid, client, seq, wire.OpenFont, 0); err != nil {
		return err
	}
	if s.resourceExists(fid) {
		s.logger.Errorf("X11: OpenFont: ID %s already in use", fid)
		return wire.NewGenericError(seq, uint32(p.Fid), 0, wire.OpenFont, wire.IDChoiceErrorCode)
	}
	s.fonts[fid] = true
	s.frontend.OpenFont(fid, p.Name)
	return nil
}

func (s *x11Server) handleCloseFont(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.CloseFontRequest)
	fid := xID(p.Fid)
	if err := s.checkFont(fid, seq, wire.CloseFont, 0); err != nil {
		return err
	}
	delete(s.fonts, fid)
	s.frontend.CloseFont(fid)
	return nil
}

func (s *x11Server) handleQueryFont(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.QueryFontRequest)
	fid := xID(p.Fid)
	if err := s.checkFont(fid, seq, wire.QueryFont, 0); err != nil {
		return err
	}
	minBounds, maxBounds, minCharOrByte2, maxCharOrByte2, defaultChar, drawDirection, minByte1, maxByte1, allCharsExist, fontAscent, fontDescent, charInfos, fontProps := s.frontend.QueryFont(fid)

	return &wire.QueryFontReply{
		Sequence:       seq,
		MinBounds:      minBounds,
		MaxBounds:      maxBounds,
		MinCharOrByte2: minCharOrByte2,
		MaxCharOrByte2: maxCharOrByte2,
		DefaultChar:    defaultChar,
		NumFontProps:   uint16(len(fontProps)),
		DrawDirection:  drawDirection,
		MinByte1:       minByte1,
		MaxByte1:       maxByte1,
		AllCharsExist:  allCharsExist,
		FontAscent:     fontAscent,
		FontDescent:    fontDescent,
		NumCharInfos:   uint32(len(charInfos)),
		CharInfos:      charInfos,
		FontProps:      fontProps,
	}
}

func (s *x11Server) handleQueryTextExtents(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.QueryTextExtentsRequest)
	fid := xID(p.Fid)
	if err := s.checkFont(fid, seq, wire.QueryTextExtents, 0); err != nil {
		return err
	}
	drawDirection, fontAscent, fontDescent, overallAscent, overallDescent, overallWidth, overallLeft, overallRight := s.frontend.QueryTextExtents(fid, p.Text)
	return &wire.QueryTextExtentsReply{
		Sequence:       seq,
		DrawDirection:  drawDirection,
		FontAscent:     fontAscent,
		FontDescent:    fontDescent,
		OverallAscent:  overallAscent,
		OverallDescent: overallDescent,
		OverallWidth:   int32(overallWidth),
		OverallLeft:    int32(overallLeft),
		OverallRight:   int32(overallRight),
	}
}

func (s *x11Server) handleListFonts(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.ListFontsRequest)
	fontNames := s.frontend.ListFonts(p.MaxNames, p.Pattern)

	return &wire.ListFontsReply{
		Sequence:  seq,
		FontNames: fontNames,
	}
}

func (s *x11Server) handleListFontsWithInfo(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.ListFontsWithInfoRequest)
	fontNames := s.frontend.ListFonts(p.MaxNames, p.Pattern)
	// Use a temporary FID that is unique to this client to avoid conflicts.
	// We use the client's resource ID base and a high-range local ID.
	tempFID := xID((client.id << 20) | 0xFFFFF)

	for _, name := range fontNames {
		s.frontend.OpenFont(tempFID, name)
		minBounds, maxBounds, minCharOrByte2, maxCharOrByte2, defaultChar, drawDirection, minByte1, maxByte1, allCharsExist, fontAscent, fontDescent, _, fontProps := s.frontend.QueryFont(tempFID)
		s.frontend.CloseFont(tempFID)

		reply := &wire.ListFontsWithInfoReply{
			Sequence:      seq,
			NameLength:    byte(len(name)),
			MinBounds:     minBounds,
			MaxBounds:     maxBounds,
			MinChar:       minCharOrByte2,
			MaxChar:       maxCharOrByte2,
			DefaultChar:   defaultChar,
			NFontProps:    uint16(len(fontProps)),
			DrawDirection: drawDirection,
			MinByte1:      minByte1,
			MaxByte1:      maxByte1,
			AllCharsExist: allCharsExist,
			FontAscent:    fontAscent,
			FontDescent:   fontDescent,
			NReplies:      1 + uint32(len(fontNames)-1), // This field is not actually used by clients usually, but let's be approximate
			FontProps:     fontProps,
			FontName:      name,
		}
		client.send(reply)
	}

	// Final reply
	lastReply := &wire.ListFontsWithInfoReply{
		Sequence: seq,
		FontName: "",
	}
	client.send(lastReply)
	return nil
}

func (s *x11Server) handleSetFontPath(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.SetFontPathRequest)
	s.fontPath = p.Paths
	return nil
}

func (s *x11Server) handleGetFontPath(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	return &wire.GetFontPathReply{
		Sequence: seq,
		Paths:    s.fontPath,
	}
}

func (s *x11Server) handleCreatePixmap(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.CreatePixmapRequest)
	xid := xID(p.Pid)
	if err := s.checkClientID(xid, client, seq, wire.CreatePixmap, 0); err != nil {
		return err
	}

	// Check if the pixmap ID is already in use
	if s.resourceExists(xid) {
		s.logger.Errorf("X11: CreatePixmap: ID %s already in use", xid)
		return wire.NewGenericError(seq, uint32(p.Pid), 0, wire.CreatePixmap, wire.IDChoiceErrorCode)
	}
	if err := s.checkDrawable(xID(p.Drawable), seq, wire.CreatePixmap, 0); err != nil {
		return err
	}

	s.pixmaps[xid] = &pixmap{
		width:  p.Width,
		height: p.Height,
		depth:  p.Depth,
	}
	s.frontend.CreatePixmap(xid, xID(p.Drawable), uint32(p.Width), uint32(p.Height), uint32(p.Depth))
	return nil
}

func (s *x11Server) handleFreePixmap(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.FreePixmapRequest)
	xid := xID(p.Pid)
	if err := s.checkPixmap(xid, seq, wire.FreePixmap, 0); err != nil {
		return err
	}
	if err := s.checkClientID(xid, client, seq, wire.FreePixmap, 0); err != nil {
		return err
	}
	delete(s.pixmaps, xid)
	s.frontend.FreePixmap(xid)
	return nil
}

func (s *x11Server) handleCreateGC(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.CreateGCRequest)
	xid := xID(p.Cid)
	if err := s.checkClientID(xid, client, seq, wire.CreateGC, 0); err != nil {
		return err
	}

	// Check if the GC ID is already in use
	if s.resourceExists(xid) {
		s.logger.Errorf("X11: CreateGC: ID %s already in use", xid)
		return wire.NewGenericError(seq, uint32(xid), 0, wire.CreateGC, wire.IDChoiceErrorCode)
	}
	if err := s.checkDrawable(xID(p.Drawable), seq, wire.CreateGC, 0); err != nil {
		return err
	}

	s.gcs[xid] = p.Values
	s.frontend.CreateGC(xid, p.ValueMask, p.Values)
	return nil
}

func (s *x11Server) handleChangeGC(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.ChangeGCRequest)
	xid := xID(p.Gc)
	if err := s.checkGC(xid, seq, wire.ChangeGC, 0); err != nil {
		return err
	}
	if existingGC, ok := s.gcs[xid]; ok {
		if p.ValueMask&wire.GCFunction != 0 {
			existingGC.Function = p.Values.Function
		}
		if p.ValueMask&wire.GCPlaneMask != 0 {
			existingGC.PlaneMask = p.Values.PlaneMask
		}
		if p.ValueMask&wire.GCForeground != 0 {
			existingGC.Foreground = p.Values.Foreground
		}
		if p.ValueMask&wire.GCBackground != 0 {
			existingGC.Background = p.Values.Background
		}
		if p.ValueMask&wire.GCLineWidth != 0 {
			existingGC.LineWidth = p.Values.LineWidth
		}
		if p.ValueMask&wire.GCLineStyle != 0 {
			existingGC.LineStyle = p.Values.LineStyle
		}
		if p.ValueMask&wire.GCCapStyle != 0 {
			existingGC.CapStyle = p.Values.CapStyle
		}
		if p.ValueMask&wire.GCJoinStyle != 0 {
			existingGC.JoinStyle = p.Values.JoinStyle
		}
		if p.ValueMask&wire.GCFillStyle != 0 {
			existingGC.FillStyle = p.Values.FillStyle
		}
		if p.ValueMask&wire.GCFillRule != 0 {
			existingGC.FillRule = p.Values.FillRule
		}
		if p.ValueMask&wire.GCTile != 0 {
			existingGC.Tile = p.Values.Tile
		}
		if p.ValueMask&wire.GCStipple != 0 {
			existingGC.Stipple = p.Values.Stipple
		}
		if p.ValueMask&wire.GCTileStipXOrigin != 0 {
			existingGC.TileStipXOrigin = p.Values.TileStipXOrigin
		}
		if p.ValueMask&wire.GCTileStipYOrigin != 0 {
			existingGC.TileStipYOrigin = p.Values.TileStipYOrigin
		}
		if p.ValueMask&wire.GCFont != 0 {
			existingGC.Font = p.Values.Font
		}
		if p.ValueMask&wire.GCSubwindowMode != 0 {
			existingGC.SubwindowMode = p.Values.SubwindowMode
		}
		if p.ValueMask&wire.GCGraphicsExposures != 0 {
			existingGC.GraphicsExposures = p.Values.GraphicsExposures
		}
		if p.ValueMask&wire.GCClipXOrigin != 0 {
			existingGC.ClipXOrigin = p.Values.ClipXOrigin
		}
		if p.ValueMask&wire.GCClipYOrigin != 0 {
			existingGC.ClipYOrigin = p.Values.ClipYOrigin
		}
		if p.ValueMask&wire.GCClipMask != 0 {
			existingGC.ClipMask = p.Values.ClipMask
		}
		if p.ValueMask&wire.GCDashOffset != 0 {
			existingGC.DashOffset = p.Values.DashOffset
		}
		if p.ValueMask&wire.GCDashes != 0 {
			existingGC.Dashes = p.Values.Dashes
		}
		if p.ValueMask&wire.GCArcMode != 0 {
			existingGC.ArcMode = p.Values.ArcMode
		}
	}
	s.frontend.ChangeGC(xid, p.ValueMask, p.Values)
	return nil
}

func (s *x11Server) handleCopyGC(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.CopyGCRequest)
	srcGC := xID(p.SrcGC)
	dstGC := xID(p.DstGC)
	if err := s.checkGC(srcGC, seq, wire.CopyGC, 0); err != nil {
		return err
	}
	if err := s.checkGC(dstGC, seq, wire.CopyGC, 0); err != nil {
		return err
	}
	s.frontend.CopyGC(srcGC, dstGC)
	return nil
}

func (s *x11Server) handleSetDashes(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.SetDashesRequest)
	gc := xID(p.GC)
	if err := s.checkGC(gc, seq, wire.SetDashes, 0); err != nil {
		return err
	}
	s.frontend.SetDashes(gc, p.DashOffset, p.Dashes)
	return nil
}

func (s *x11Server) handleSetClipRectangles(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.SetClipRectanglesRequest)
	gc := xID(p.GC)
	if err := s.checkGC(gc, seq, wire.SetClipRectangles, 0); err != nil {
		return err
	}
	s.frontend.SetClipRectangles(gc, p.ClippingX, p.ClippingY, p.Rectangles, p.Ordering)
	return nil
}

func (s *x11Server) handleFreeGC(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.FreeGCRequest)
	gcID := xID(p.GC)
	if err := s.checkGC(gcID, seq, wire.FreeGC, 0); err != nil {
		return err
	}
	if err := s.checkClientID(gcID, client, seq, wire.FreeGC, 0); err != nil {
		return err
	}
	delete(s.gcs, gcID)
	s.frontend.FreeGC(gcID)
	return nil
}

func (s *x11Server) handleClearArea(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.ClearAreaRequest)
	drawable := xID(p.Window)
	if err := s.checkWindow(drawable, seq, wire.ClearArea, 0); err != nil {
		return err
	}
	s.frontend.ClearArea(drawable, int32(p.X), int32(p.Y), int32(p.Width), int32(p.Height))
	return nil
}

func (s *x11Server) handleCopyArea(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.CopyAreaRequest)
	gcID := xID(p.Gc)
	srcDrawable := xID(p.SrcDrawable)
	dstDrawable := xID(p.DstDrawable)
	if err := s.checkGC(gcID, seq, wire.CopyArea, 0); err != nil {
		return err
	}
	if err := s.checkDrawable(srcDrawable, seq, wire.CopyArea, 0); err != nil {
		return err
	}
	if err := s.checkDrawable(dstDrawable, seq, wire.CopyArea, 0); err != nil {
		return err
	}
	s.frontend.CopyArea(srcDrawable, dstDrawable, gcID, int32(p.SrcX), int32(p.SrcY), int32(p.DstX), int32(p.DstY), int32(p.Width), int32(p.Height))
	return nil
}

func (s *x11Server) handleCopyPlane(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.CopyPlaneRequest)
	gcID := xID(p.Gc)
	srcDrawable := xID(p.SrcDrawable)
	dstDrawable := xID(p.DstDrawable)
	if err := s.checkGC(gcID, seq, wire.CopyPlane, 0); err != nil {
		return err
	}
	if err := s.checkDrawable(srcDrawable, seq, wire.CopyPlane, 0); err != nil {
		return err
	}
	if err := s.checkDrawable(dstDrawable, seq, wire.CopyPlane, 0); err != nil {
		return err
	}
	s.frontend.CopyPlane(srcDrawable, dstDrawable, gcID, int32(p.SrcX), int32(p.SrcY), int32(p.DstX), int32(p.DstY), int32(p.Width), int32(p.Height), int32(p.PlaneMask))
	return nil
}

func (s *x11Server) handlePolyPoint(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.PolyPointRequest)
	drawable := xID(p.Drawable)
	gcID := xID(p.Gc)
	if err := s.checkGC(gcID, seq, wire.PolyPoint, 0); err != nil {
		return err
	}
	if err := s.checkDrawable(drawable, seq, wire.PolyPoint, 0); err != nil {
		return err
	}
	s.frontend.PolyPoint(drawable, gcID, p.Coordinates)
	return nil
}

func (s *x11Server) handlePolyLine(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.PolyLineRequest)
	drawable := xID(p.Drawable)
	gcID := xID(p.Gc)
	if err := s.checkGC(gcID, seq, wire.PolyLine, 0); err != nil {
		return err
	}
	if err := s.checkDrawable(drawable, seq, wire.PolyLine, 0); err != nil {
		return err
	}
	s.frontend.PolyLine(drawable, gcID, p.Coordinates)
	return nil
}

func (s *x11Server) handlePolySegment(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.PolySegmentRequest)
	drawable := xID(p.Drawable)
	gcID := xID(p.Gc)
	if err := s.checkGC(gcID, seq, wire.PolySegment, 0); err != nil {
		return err
	}
	if err := s.checkDrawable(drawable, seq, wire.PolySegment, 0); err != nil {
		return err
	}
	s.frontend.PolySegment(drawable, gcID, p.Segments)
	return nil
}

func (s *x11Server) handlePolyRectangle(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.PolyRectangleRequest)
	drawable := xID(p.Drawable)
	gcID := xID(p.Gc)
	if err := s.checkGC(gcID, seq, wire.PolyRectangle, 0); err != nil {
		return err
	}
	if err := s.checkDrawable(drawable, seq, wire.PolyRectangle, 0); err != nil {
		return err
	}
	s.frontend.PolyRectangle(drawable, gcID, p.Rectangles)
	return nil
}

func (s *x11Server) handlePolyArc(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.PolyArcRequest)
	drawable := xID(p.Drawable)
	gcID := xID(p.Gc)
	if err := s.checkGC(gcID, seq, wire.PolyArc, 0); err != nil {
		return err
	}
	if err := s.checkDrawable(drawable, seq, wire.PolyArc, 0); err != nil {
		return err
	}
	s.frontend.PolyArc(drawable, gcID, p.Arcs)
	return nil
}

func (s *x11Server) handleFillPoly(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.FillPolyRequest)
	drawable := xID(p.Drawable)
	gcID := xID(p.Gc)
	if err := s.checkGC(gcID, seq, wire.FillPoly, 0); err != nil {
		return err
	}
	if err := s.checkDrawable(drawable, seq, wire.FillPoly, 0); err != nil {
		return err
	}
	s.frontend.FillPoly(drawable, gcID, p.Coordinates)
	return nil
}

func (s *x11Server) handlePolyFillRectangle(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.PolyFillRectangleRequest)
	drawable := xID(p.Drawable)
	gcID := xID(p.Gc)
	if err := s.checkGC(gcID, seq, wire.PolyFillRectangle, 0); err != nil {
		return err
	}
	if err := s.checkDrawable(drawable, seq, wire.PolyFillRectangle, 0); err != nil {
		return err
	}
	s.frontend.PolyFillRectangle(drawable, gcID, p.Rectangles)
	return nil
}

func (s *x11Server) handlePolyFillArc(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.PolyFillArcRequest)
	drawable := xID(p.Drawable)
	gcID := xID(p.Gc)
	if err := s.checkGC(gcID, seq, wire.PolyFillArc, 0); err != nil {
		return err
	}
	if err := s.checkDrawable(drawable, seq, wire.PolyFillArc, 0); err != nil {
		return err
	}
	s.frontend.PolyFillArc(drawable, gcID, p.Arcs)
	return nil
}

func (s *x11Server) handlePutImage(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.PutImageRequest)
	drawable := xID(p.Drawable)
	gcID := xID(p.Gc)
	if err := s.checkGC(gcID, seq, wire.PutImage, 0); err != nil {
		return err
	}
	if err := s.checkDrawable(drawable, seq, wire.PutImage, 0); err != nil {
		return err
	}

	var targetDepth byte
	if w, ok := s.windows[drawable]; ok {
		targetDepth = w.depth
	} else if pm, ok := s.pixmaps[drawable]; ok {
		targetDepth = pm.depth
	} else if uint32(drawable) == s.rootWindowID() {
		targetDepth = s.rootVisual.Depth
	}

	if p.Format == 0 { // XYBitmap
		if p.Depth != 1 {
			return wire.NewGenericError(seq, 0, 0, wire.PutImage, wire.MatchErrorCode)
		}
	} else if p.Depth != targetDepth {
		return wire.NewGenericError(seq, 0, 0, wire.PutImage, wire.MatchErrorCode)
	}
	expectedLen := s.calculateImageSize(p.Width, p.Height, p.Format, p.Depth, p.LeftPad)
	if len(p.Data) < expectedLen {
		s.logger.Errorf("X11: PutImage: data length %d is less than expected %d", len(p.Data), expectedLen)
		return wire.NewGenericError(seq, 0, 0, wire.PutImage, wire.LengthErrorCode)
	}
	s.frontend.PutImage(drawable, gcID, p.Format, p.Width, p.Height, p.DstX, p.DstY, p.LeftPad, p.Depth, p.Data)
	return nil
}

func (s *x11Server) handleGetImage(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.GetImageRequest)
	if err := s.checkDrawable(xID(p.Drawable), seq, wire.GetImage, 0); err != nil {
		return err
	}
	imgData, err := s.frontend.GetImage(xID(p.Drawable), int32(p.X), int32(p.Y), int32(p.Width), int32(p.Height), p.PlaneMask)
	if err != nil {
		return wire.NewGenericError(seq, 0, 0, wire.GetImage, wire.MatchErrorCode)
	}
	var depth byte = 24 // Default
	visualID := s.visualID
	xid := xID(p.Drawable)
	if w, ok := s.windows[xid]; ok {
		depth = w.depth
	} else if pm, ok := s.pixmaps[xid]; ok {
		depth = pm.depth
		visualID = 0
	}
	return &wire.GetImageReply{
		Sequence:  seq,
		Depth:     depth,
		VisualID:  visualID,
		ImageData: imgData,
	}
}

func (s *x11Server) handlePolyText8(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.PolyText8Request)
	drawable := xID(p.Drawable)
	gcID := xID(p.GC)
	if err := s.checkGC(gcID, seq, wire.PolyText8, 0); err != nil {
		return err
	}
	if err := s.checkDrawable(drawable, seq, wire.PolyText8, 0); err != nil {
		return err
	}
	s.frontend.PolyText8(drawable, gcID, int32(p.X), int32(p.Y), p.Items)
	return nil
}

func (s *x11Server) handlePolyText16(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.PolyText16Request)
	drawable := xID(p.Drawable)
	gcID := xID(p.GC)
	if err := s.checkGC(gcID, seq, wire.PolyText16, 0); err != nil {
		return err
	}
	if err := s.checkDrawable(drawable, seq, wire.PolyText16, 0); err != nil {
		return err
	}
	s.frontend.PolyText16(drawable, gcID, int32(p.X), int32(p.Y), p.Items)
	return nil
}

func (s *x11Server) handleImageText8(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.ImageText8Request)
	drawable := xID(p.Drawable)
	gcID := xID(p.Gc)
	if err := s.checkGC(gcID, seq, wire.ImageText8, 0); err != nil {
		return err
	}
	if err := s.checkDrawable(drawable, seq, wire.ImageText8, 0); err != nil {
		return err
	}
	s.frontend.ImageText8(drawable, gcID, int32(p.X), int32(p.Y), p.Text)
	return nil
}

func (s *x11Server) handleImageText16(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.ImageText16Request)
	drawable := xID(p.Drawable)
	gcID := xID(p.Gc)
	if err := s.checkGC(gcID, seq, wire.ImageText16, 0); err != nil {
		return err
	}
	if err := s.checkDrawable(drawable, seq, wire.ImageText16, 0); err != nil {
		return err
	}
	s.frontend.ImageText16(drawable, gcID, int32(p.X), int32(p.Y), p.Text)
	return nil
}

func (s *x11Server) handleCreateColormap(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.CreateColormapRequest)
	xid := xID(p.Mid)
	if err := s.checkClientID(xid, client, seq, wire.CreateColormap, 0); err != nil {
		return err
	}

	if s.resourceExists(xid) {
		s.logger.Errorf("X11: CreateColormap: ID %s already in use", xid)
		return wire.NewGenericError(seq, uint32(p.Mid), 0, wire.CreateColormap, wire.IDChoiceErrorCode)
	}
	if err := s.checkWindow(xID(p.Window), seq, wire.CreateColormap, 0); err != nil {
		return err
	}
	visual, ok := s.visuals[uint32(p.Visual)]
	if !ok {
		return wire.NewGenericError(seq, uint32(p.Visual), 0, wire.CreateColormap, wire.ValueErrorCode)
	}

	newColormap := &colormap{
		visual:    visual,
		pixels:    make(map[uint32]wire.XColorItem),
		allocated: make([]bool, visual.ColormapEntries),
		clientID:  make([]uint32, visual.ColormapEntries),
		writable:  make([]bool, visual.ColormapEntries),
	}

	if p.Alloc == 1 { // All
		for i := range newColormap.writable {
			newColormap.allocated[i] = true
			newColormap.writable[i] = true
			newColormap.clientID[i] = client.id
		}
	}

	s.colormaps[xid] = newColormap
	return nil
}

func (s *x11Server) handleFreeColormap(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.FreeColormapRequest)
	xid := xID(p.Cmap)
	if err := s.checkColormap(xid, seq, wire.FreeColormap, 0); err != nil {
		return err
	}
	if err := s.checkClientID(xid, client, seq, wire.FreeColormap, 0); err != nil {
		return err
	}
	delete(s.colormaps, xid)
	return nil
}

func (s *x11Server) handleCopyColormapAndFree(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.CopyColormapAndFreeRequest)
	srcCmapID := xID(p.SrcCmap)
	if err := s.checkColormap(srcCmapID, seq, wire.CopyColormapAndFree, 0); err != nil {
		return err
	}
	srcCmap := s.colormaps[srcCmapID]

	newCmapID := xID(p.Mid)
	if _, exists := s.colormaps[newCmapID]; exists {
		return wire.NewGenericError(seq, uint32(p.Mid), 0, wire.CopyColormapAndFree, wire.IDChoiceErrorCode)
	}

	newCmap := &colormap{
		visual:    srcCmap.visual,
		pixels:    make(map[uint32]wire.XColorItem),
		allocated: make([]bool, srcCmap.visual.ColormapEntries),
		clientID:  make([]uint32, srcCmap.visual.ColormapEntries),
		writable:  make([]bool, srcCmap.visual.ColormapEntries),
	}
	s.colormaps[newCmapID] = newCmap

	for i := 0; i < int(srcCmap.visual.ColormapEntries); i++ {
		if srcCmap.allocated[i] && srcCmap.clientID[i] == client.id {
			newCmap.allocated[i] = true
			newCmap.clientID[i] = client.id
			newCmap.writable[i] = srcCmap.writable[i]
			if color, ok := srcCmap.pixels[uint32(i)]; ok {
				newCmap.pixels[uint32(i)] = color
			}
			// Free from source
			srcCmap.allocated[i] = false
			srcCmap.clientID[i] = 0
			srcCmap.writable[i] = false
			delete(srcCmap.pixels, uint32(i))
		}
	}
	return nil
}

func (s *x11Server) handleInstallColormap(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.InstallColormapRequest)
	xid := xID(p.Cmap)
	if err := s.checkColormap(xid, seq, wire.InstallColormap, 0); err != nil {
		return err
	}

	s.installedColormap = xid

	for winID, win := range s.windows {
		if win.colormap == xid {
			client, ok := s.clients[((uint32(winID) >> resourceIDShift) & clientIDMask)]
			if !ok {
				debugf("X11: InstallColormap unknown client %d", ((uint32(winID) >> resourceIDShift) & clientIDMask))
				continue
			}
			event := &wire.ColormapNotifyEvent{
				Sequence: client.sequence - 1,
				Window:   uint32(winID),
				Colormap: uint32(p.Cmap),
				New:      true,
				State:    0, // Installed
			}
			s.sendEvent(client, event)
		}
	}
	return nil
}

func (s *x11Server) handleUninstallColormap(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.UninstallColormapRequest)
	xid := xID(p.Cmap)
	if err := s.checkColormap(xid, seq, wire.UninstallColormap, 0); err != nil {
		return err
	}

	if s.installedColormap == xid {
		s.installedColormap = xID(s.defaultColormap)
	}

	for winID, win := range s.windows {
		if win.colormap == xid {
			client, ok := s.clients[((uint32(winID) >> resourceIDShift) & clientIDMask)]
			if !ok {
				debugf("X11: UninstallColormap unknown client %d", ((uint32(winID) >> resourceIDShift) & clientIDMask))
				continue
			}
			event := &wire.ColormapNotifyEvent{
				Sequence: client.sequence - 1,
				Window:   uint32(winID),
				Colormap: uint32(p.Cmap),
				New:      false,
				State:    1, // Uninstalled
			}
			s.sendEvent(client, event)
		}
	}
	return nil
}

func (s *x11Server) handleListInstalledColormaps(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.ListInstalledColormapsRequest)
	if err := s.checkWindow(xID(p.Window), seq, wire.ListInstalledColormaps, 0); err != nil {
		return err
	}
	var colormaps []uint32
	if s.installedColormap != 0 {
		colormaps = append(colormaps, uint32(s.installedColormap))
	}

	return &wire.ListInstalledColormapsReply{
		Sequence:     seq,
		NumColormaps: uint16(len(colormaps)),
		Colormaps:    colormaps,
	}
}

func (s *x11Server) handleAllocColor(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.AllocColorRequest)
	xid := xID(p.Cmap)
	if uint32(xid) == s.defaultColormap {
		xid = xID(uint32(xid))
	}
	cm, ok := s.colormaps[xid]
	if !ok {
		return wire.NewGenericError(seq, uint32(p.Cmap), 0, wire.AllocColor, wire.ColormapErrorCode)
	}

	var pixel uint32
	if cm.visual.Class == wire.TrueColor || cm.visual.Class == wire.DirectColor {
		r := uint32(p.Red) >> (16 - wire.BitCount(cm.visual.RedMask))
		g := uint32(p.Green) >> (16 - wire.BitCount(cm.visual.GreenMask))
		b := uint32(p.Blue) >> (16 - wire.BitCount(cm.visual.BlueMask))

		pixel = (r << wire.BitOffset(cm.visual.RedMask)) |
			(g << wire.BitOffset(cm.visual.GreenMask)) |
			(b << wire.BitOffset(cm.visual.BlueMask))
	} else {
		// Check if the color is already allocated
		found := false
		for i := 0; i < int(cm.visual.ColormapEntries); i++ {
			if cm.allocated[i] && !cm.writable[i] {
				item := cm.pixels[uint32(i)]
				if item.Red == p.Red && item.Green == p.Green && item.Blue == p.Blue {
					pixel = uint32(i)
					found = true
					break
				}
			}
		}
		if !found {
			// Find an unallocated cell
			for i := 0; i < int(cm.visual.ColormapEntries); i++ {
				if !cm.allocated[i] {
					pixel = uint32(i)
					cm.allocated[i] = true
					cm.clientID[i] = client.id
					found = true
					break
				}
			}
		}
		if !found {
			return wire.NewGenericError(seq, 0, 0, wire.AllocColor, wire.AllocErrorCode)
		}
	}

	cm.pixels[pixel] = wire.XColorItem{Red: p.Red, Green: p.Green, Blue: p.Blue, ClientID: client.id}

	return &wire.AllocColorReply{
		Sequence: seq,
		Red:      p.Red,
		Green:    p.Green,
		Blue:     p.Blue,
		Pixel:    pixel,
	}
}

func (s *x11Server) handleAllocNamedColor(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.AllocNamedColorRequest)
	cmap := xID(p.Cmap)
	if uint32(cmap) == s.defaultColormap {
		cmap = xID(uint32(cmap))
	}
	cm, ok := s.colormaps[cmap]
	if !ok {
		return wire.NewError(wire.ColormapErrorCode, seq, uint32(p.Cmap), wire.Opcodes{Major: p.OpCode(), Minor: 0})
	}

	name := string(p.Name)
	rgb, ok := lookupColor(name)
	if !ok {
		return wire.NewError(wire.NameErrorCode, seq, 0, wire.Opcodes{Major: p.OpCode(), Minor: 0})
	}

	exactRed := scale8to16(rgb.Red)
	exactGreen := scale8to16(rgb.Green)
	exactBlue := scale8to16(rgb.Blue)

	var pixel uint32
	if cm.visual.Class == wire.TrueColor || cm.visual.Class == wire.DirectColor {
		r := uint32(exactRed) >> (16 - wire.BitCount(cm.visual.RedMask))
		g := uint32(exactGreen) >> (16 - wire.BitCount(cm.visual.GreenMask))
		b := uint32(exactBlue) >> (16 - wire.BitCount(cm.visual.BlueMask))

		pixel = (r << wire.BitOffset(cm.visual.RedMask)) |
			(g << wire.BitOffset(cm.visual.GreenMask)) |
			(b << wire.BitOffset(cm.visual.BlueMask))
	} else {
		// Check if the color is already allocated
		found := false
		for i := 0; i < int(cm.visual.ColormapEntries); i++ {
			if cm.allocated[i] && !cm.writable[i] {
				item := cm.pixels[uint32(i)]
				if item.Red == exactRed && item.Green == exactGreen && item.Blue == exactBlue {
					pixel = uint32(i)
					found = true
					break
				}
			}
		}
		if !found {
			// Find an unallocated cell
			for i := 0; i < int(cm.visual.ColormapEntries); i++ {
				if !cm.allocated[i] {
					pixel = uint32(i)
					cm.allocated[i] = true
					cm.clientID[i] = client.id
					found = true
					break
				}
			}
		}
		if !found {
			return wire.NewGenericError(seq, 0, 0, wire.AllocNamedColor, wire.AllocErrorCode)
		}
	}

	cm.pixels[pixel] = wire.XColorItem{Red: exactRed, Green: exactGreen, Blue: exactBlue, ClientID: client.id}

	return &wire.AllocNamedColorReply{
		Sequence:   seq,
		Pixel:      pixel,
		ExactRed:   exactRed,
		ExactGreen: exactGreen,
		ExactBlue:  exactBlue,
		Red:        exactRed,
		Green:      exactGreen,
		Blue:       exactBlue,
	}
}

func (s *x11Server) findAllocatableCells(cm *colormap, n uint32) []uint32 {
	if n == 0 {
		return []uint32{}
	}
	pixels := make([]uint32, 0, n)
	for i := 0; i < len(cm.allocated); i++ {
		if uint32(len(pixels)) == n {
			break
		}
		if !cm.allocated[i] {
			pixels = append(pixels, uint32(i))
		}
	}

	if uint32(len(pixels)) < n {
		return nil
	}
	return pixels
}

func (s *x11Server) handleAllocColorCells(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.AllocColorCellsRequest)
	cm, ok := s.colormaps[xID(p.Cmap)]
	if !ok {
		return wire.NewGenericError(seq, uint32(p.Cmap), 0, wire.AllocColorCells, wire.ColormapErrorCode)
	}
	if cm.visual.Class != wire.PseudoColor {
		return wire.NewGenericError(seq, 0, 0, wire.AllocColorCells, wire.AccessErrorCode)
	}
	nreq := uint32(p.Colors) + uint32(p.Planes)
	if nreq > 0 && len(cm.writable) == 0 {
		return wire.NewGenericError(seq, 0, 0, wire.AllocColorCells, wire.AllocErrorCode)
	}

	pixels := s.findAllocatableCells(cm, nreq)

	if pixels == nil {
		return wire.NewGenericError(seq, 0, 0, wire.AllocColorCells, wire.AllocErrorCode)
	}

	for _, pixel := range pixels {
		cm.allocated[pixel] = true
		cm.writable[pixel] = true
		cm.clientID[pixel] = client.id
	}

	return &wire.AllocColorCellsReply{
		Sequence: seq,
		Pixels:   pixels[:p.Colors],
		Masks:    pixels[p.Colors:],
	}
}

func (s *x11Server) handleAllocColorPlanes(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.AllocColorPlanesRequest)
	cm, ok := s.colormaps[xID(p.Cmap)]
	if !ok {
		return wire.NewGenericError(seq, uint32(p.Cmap), 0, wire.AllocColorPlanes, wire.ColormapErrorCode)
	}
	if cm.visual.Class != wire.PseudoColor {
		return wire.NewGenericError(seq, 0, 0, wire.AllocColorPlanes, wire.MatchErrorCode)
	}
	nreq := uint32(p.Reds) + uint32(p.Greens) + uint32(p.Blues)
	if nreq > 0 && len(cm.writable) == 0 {
		return wire.NewGenericError(seq, 0, 0, wire.AllocColorPlanes, wire.AllocErrorCode)
	}

	pixels := s.findAllocatableCells(cm, uint32(p.Colors))
	if pixels == nil {
		return wire.NewGenericError(seq, 0, 0, wire.AllocColorPlanes, wire.AllocErrorCode)
	}

	for _, pixel := range pixels {
		cm.allocated[pixel] = true
		cm.writable[pixel] = true
		cm.clientID[pixel] = client.id
	}

	redMask := uint32(0)
	greenMask := uint32(0)
	blueMask := uint32(0)
	// Note: The protocol says the masks are disjoint.
	// This implementation is still simplified.
	for i := 0; i < int(p.Reds); i++ {
		if i < len(pixels) {
			redMask |= 1 << pixels[i]
		}
	}
	for i := 0; i < int(p.Greens); i++ {
		if int(p.Reds)+i < len(pixels) {
			greenMask |= 1 << pixels[int(p.Reds)+i]
		}
	}
	for i := 0; i < int(p.Blues); i++ {
		if int(p.Reds)+int(p.Greens)+i < len(pixels) {
			blueMask |= 1 << pixels[int(p.Reds)+int(p.Greens)+i]
		}
	}

	numPixels := int(p.Colors)
	if numPixels > len(pixels) {
		numPixels = len(pixels)
	}

	return &wire.AllocColorPlanesReply{
		Sequence:  seq,
		Pixels:    pixels[:numPixels],
		RedMask:   redMask,
		GreenMask: greenMask,
		BlueMask:  blueMask,
	}
}

func (s *x11Server) handleFreeColors(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.FreeColorsRequest)
	xid := xID(p.Cmap)
	if uint32(xid) == s.defaultColormap {
		xid = xID(uint32(xid))
	}
	cm, ok := s.colormaps[xid]
	if !ok {
		return wire.NewGenericError(seq, uint32(p.Cmap), 0, wire.FreeColors, wire.ColormapErrorCode)
	}

	for _, pixel := range p.Pixels {
		if pixel < uint32(len(cm.allocated)) {
			cm.allocated[pixel] = false
			cm.writable[pixel] = false
			cm.clientID[pixel] = 0
		}
		delete(cm.pixels, pixel)
	}
	return nil
}

func (s *x11Server) handleStoreColors(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.StoreColorsRequest)
	xid := xID(p.Cmap)
	if uint32(xid) == s.defaultColormap {
		xid = xID(uint32(xid))
	}
	cm, ok := s.colormaps[xid]
	if !ok {
		return wire.NewGenericError(seq, uint32(p.Cmap), 0, wire.StoreColors, wire.ColormapErrorCode)
	}

	for _, item := range p.Items {
		c, exists := cm.pixels[item.Pixel]
		if !exists {
			c = wire.XColorItem{}
		}

		if item.Flags&wire.DoRed != 0 {
			c.Red = item.Red
		}
		if item.Flags&wire.DoGreen != 0 {
			c.Green = item.Green
		}
		if item.Flags&wire.DoBlue != 0 {
			c.Blue = item.Blue
		}
		cm.pixels[item.Pixel] = c
	}
	return nil
}

func (s *x11Server) handleStoreNamedColor(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.StoreNamedColorRequest)
	xid := xID(p.Cmap)
	if uint32(xid) == s.defaultColormap {
		xid = xID(uint32(xid))
	}
	cm, ok := s.colormaps[xid]
	if !ok {
		return wire.NewGenericError(seq, uint32(p.Cmap), 0, wire.StoreNamedColor, wire.ColormapErrorCode)
	}

	rgb, ok := lookupColor(p.Name)
	if !ok {
		return wire.NewGenericError(seq, 0, 0, wire.StoreNamedColor, wire.NameErrorCode)
	}

	c, exists := cm.pixels[p.Pixel]
	if !exists {
		c = wire.XColorItem{}
	}

	if p.Flags&wire.DoRed != 0 {
		c.Red = scale8to16(rgb.Red)
	}
	if p.Flags&wire.DoGreen != 0 {
		c.Green = scale8to16(rgb.Green)
	}
	if p.Flags&wire.DoBlue != 0 {
		c.Blue = scale8to16(rgb.Blue)
	}
	cm.pixels[p.Pixel] = c
	return nil
}

func (s *x11Server) handleQueryColors(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.QueryColorsRequest)
	cmap := xID(p.Cmap)
	if uint32(cmap) == s.defaultColormap {
		cmap = xID(uint32(cmap))
	}
	cm, ok := s.colormaps[cmap]
	if !ok {
		return wire.NewGenericError(seq, uint32(p.Cmap), 0, wire.QueryColors, wire.ColormapErrorCode)
	}

	colors := make([]wire.XColorItem, len(p.Pixels))
	for i, pixel := range p.Pixels {
		color, ok := cm.pixels[pixel]
		if !ok {
			// If the pixel is not in the colormap, return black
			color = wire.XColorItem{Red: 0, Green: 0, Blue: 0}
		}
		colors[i] = color
	}

	return &wire.QueryColorsReply{
		Sequence: seq,
		Colors:   colors,
	}
}

func (s *x11Server) handleLookupColor(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.LookupColorRequest)
	// cmapID := client.xID(uint32(p.Cmap))

	color, ok := lookupColor(p.Name)
	if !ok {
		return wire.NewGenericError(seq, uint32(p.Cmap), 0, wire.LookupColor, wire.NameErrorCode)
	}

	return &wire.LookupColorReply{
		Sequence:   seq,
		Red:        scale8to16(color.Red),
		Green:      scale8to16(color.Green),
		Blue:       scale8to16(color.Blue),
		ExactRed:   scale8to16(color.Red),
		ExactGreen: scale8to16(color.Green),
		ExactBlue:  scale8to16(color.Blue),
	}
}

func (s *x11Server) handleCreateCursor(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.CreateCursorRequest)
	cursorXID := xID(p.Cid)
	if err := s.checkClientID(cursorXID, client, seq, wire.CreateCursor, 0); err != nil {
		return err
	}
	if _, exists := s.cursors[cursorXID]; exists {
		s.logger.Errorf("X11: CreateCursor: ID %s already in use", cursorXID)
		return wire.NewGenericError(seq, uint32(p.Cid), 0, wire.CreateCursor, wire.IDChoiceErrorCode)
	}

	sourceXID := xID(p.Source)
	if err := s.checkPixmap(sourceXID, seq, wire.CreateCursor, 0); err != nil {
		return err
	}
	maskXID := xID(p.Mask)
	if p.Mask != 0 {
		if err := s.checkPixmap(maskXID, seq, wire.CreateCursor, 0); err != nil {
			return err
		}
	}

	s.cursors[cursorXID] = true
	foreColor := [3]uint16{p.ForeRed, p.ForeGreen, p.ForeBlue}
	backColor := [3]uint16{p.BackRed, p.BackGreen, p.BackBlue}
	s.frontend.CreateCursor(cursorXID, sourceXID, maskXID, foreColor, backColor, p.X, p.Y)
	return nil
}

func (s *x11Server) handleCreateGlyphCursor(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.CreateGlyphCursorRequest)
	// Check if the cursor ID is already in use
	if _, exists := s.cursors[xID(p.Cid)]; exists {
		s.logger.Errorf("X11: CreateGlyphCursor: ID %d already in use", p.Cid)
		return wire.NewGenericError(seq, uint32(p.Cid), 0, wire.CreateGlyphCursor, wire.IDChoiceErrorCode)
	}
	if err := s.checkFont(xID(p.SourceFont), seq, wire.CreateGlyphCursor, 0); err != nil {
		return err
	}
	if p.MaskFont != 0 {
		if err := s.checkFont(xID(p.MaskFont), seq, wire.CreateGlyphCursor, 0); err != nil {
			return err
		}
	}

	s.cursors[xID(p.Cid)] = true
	s.frontend.CreateCursorFromGlyph(xID(p.Cid), xID(p.SourceFont), p.SourceChar, xID(p.MaskFont), p.MaskChar, p.ForeColor, p.BackColor)
	return nil
}

func (s *x11Server) handleFreeCursor(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.FreeCursorRequest)
	xid := xID(p.Cursor)
	if err := s.checkCursor(xid, seq, wire.FreeCursor, 0); err != nil {
		return err
	}
	if err := s.checkClientID(xid, client, seq, wire.FreeCursor, 0); err != nil {
		return err
	}
	delete(s.cursors, xid)
	s.frontend.FreeCursor(xid)
	return nil
}

func (s *x11Server) handleRecolorCursor(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.RecolorCursorRequest)
	xid := xID(p.Cursor)
	if err := s.checkCursor(xid, seq, wire.RecolorCursor, 0); err != nil {
		return err
	}
	if err := s.checkClientID(xid, client, seq, wire.RecolorCursor, 0); err != nil {
		return err
	}
	s.frontend.RecolorCursor(xID(p.Cursor), p.ForeColor, p.BackColor)
	return nil
}

func (s *x11Server) handleQueryBestSize(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.QueryBestSizeRequest)
	if err := s.checkDrawable(xID(p.Drawable), seq, wire.QueryBestSize, 0); err != nil {
		return err
	}
	width, height := s.frontend.QueryBestSize(p.Class, xID(p.Drawable), p.Width, p.Height)
	return &wire.QueryBestSizeReply{
		Sequence: seq,
		Width:    width,
		Height:   height,
	}
}

func (s *x11Server) handleQueryExtension(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.QueryExtensionRequest)
	debugf("X11: QueryExtension name=%s", p.Name)

	switch p.Name {
	case wire.BigRequestsExtensionName:
		return &wire.QueryExtensionReply{
			Sequence:    seq,
			Present:     true,
			MajorOpcode: byte(wire.BigRequestsOpcode),
			FirstEvent:  0,
			FirstError:  0,
		}
	case wire.XInputExtensionName:
		return &wire.QueryExtensionReply{
			Sequence:    seq,
			Present:     true,
			MajorOpcode: byte(wire.XInputOpcode),
			FirstEvent:  s.xinputFirstEvent,
			FirstError:  s.xinputFirstError,
		}
	default:
		return &wire.QueryExtensionReply{
			Sequence:    seq,
			Present:     false,
			MajorOpcode: 0,
			FirstEvent:  0,
			FirstError:  0,
		}
	}
}

func (s *x11Server) handleListExtensions(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	extensions := []string{
		wire.BigRequestsExtensionName,
		wire.XInputExtensionName,
	}
	return &wire.ListExtensionsReply{
		Sequence: seq,
		NNames:   byte(len(extensions)),
		Names:    extensions,
	}
}

func (s *x11Server) handleChangeKeyboardMapping(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.ChangeKeyboardMappingRequest)
	keySymIndex := 0
	for i := 0; i < int(p.KeyCodeCount); i++ {
		keyCode := p.FirstKeyCode + wire.KeyCode(i)
		syms := make([]uint32, p.KeySymsPerKeyCode)
		for j := 0; j < int(p.KeySymsPerKeyCode); j++ {
			syms[j] = p.KeySyms[keySymIndex]
			keySymIndex++
		}
		s.keymap[byte(keyCode)] = syms
	}
	return nil
}

func (s *x11Server) handleGetKeyboardMapping(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.GetKeyboardMappingRequest)
	if p.FirstKeyCode < wire.KeyCode(s.minKeycode) || p.FirstKeyCode+wire.KeyCode(p.Count-1) > wire.KeyCode(s.maxKeycode) {
		return wire.NewGenericError(seq, uint32(p.FirstKeyCode), 0, wire.GetKeyboardMapping, wire.ValueErrorCode)
	}

	maxSyms := byte(0)
	for i := 0; i < int(p.Count); i++ {
		keyCode := p.FirstKeyCode + wire.KeyCode(i)
		if syms, ok := s.keymap[byte(keyCode)]; ok {
			if byte(len(syms)) > maxSyms {
				maxSyms = byte(len(syms))
			}
		}
	}
	if maxSyms == 0 {
		maxSyms = 1
	}

	keySyms := make([]uint32, 0, int(p.Count)*int(maxSyms))
	for i := 0; i < int(p.Count); i++ {
		keyCode := p.FirstKeyCode + wire.KeyCode(i)
		syms, ok := s.keymap[byte(keyCode)]
		for j := 0; j < int(maxSyms); j++ {
			if ok && j < len(syms) {
				keySyms = append(keySyms, syms[j])
			} else {
				keySyms = append(keySyms, 0) // NoSymbol
			}
		}
	}
	return &wire.GetKeyboardMappingReply{
		Sequence:          seq,
		KeySymsPerKeycode: maxSyms,
		KeySyms:           keySyms,
	}
}

func (s *x11Server) handleChangeKeyboardControl(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.ChangeKeyboardControlRequest)
	s.frontend.ChangeKeyboardControl(p.ValueMask, p.Values)
	return nil
}

func (s *x11Server) handleGetKeyboardControl(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	kc, _ := s.frontend.GetKeyboardControl()
	return &wire.GetKeyboardControlReply{
		Sequence:         seq,
		KeyClickPercent:  byte(kc.KeyClickPercent),
		BellPercent:      byte(kc.BellPercent),
		BellPitch:        uint16(kc.BellPitch),
		BellDuration:     uint16(kc.BellDuration),
		LedMask:          uint32(kc.Led),
		GlobalAutoRepeat: byte(kc.AutoRepeatMode),
		AutoRepeats:      [32]byte{},
	}
}

func (s *x11Server) handleBell(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.BellRequest)
	s.frontend.Bell(p.Percent)
	return nil
}

func (s *x11Server) handleChangePointerControl(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.ChangePointerControlRequest)
	s.frontend.ChangePointerControl(p.AccelerationNumerator, p.AccelerationDenominator, p.Threshold, p.DoAcceleration, p.DoThreshold)
	return nil
}

func (s *x11Server) handleGetPointerControl(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	accelNumerator, accelDenominator, threshold, _ := s.frontend.GetPointerControl()
	return &wire.GetPointerControlReply{
		Sequence:         seq,
		AccelNumerator:   accelNumerator,
		AccelDenominator: accelDenominator,
		Threshold:        threshold,
	}
}

func (s *x11Server) handleSetScreenSaver(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.SetScreenSaverRequest)
	s.frontend.SetScreenSaver(p.Timeout, p.Interval, p.PreferBlank, p.AllowExpose)
	return nil
}

func (s *x11Server) handleGetScreenSaver(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	timeout, interval, preferBlank, allowExpose, _ := s.frontend.GetScreenSaver()
	return &wire.GetScreenSaverReply{
		Sequence:    seq,
		Timeout:     uint16(timeout),
		Interval:    uint16(interval),
		PreferBlank: preferBlank,
		AllowExpose: allowExpose,
	}
}

func (s *x11Server) handleChangeHosts(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.ChangeHostsRequest)
	s.frontend.ChangeHosts(p.Mode, p.Host)
	return nil
}

func (s *x11Server) handleListHosts(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	hosts, _ := s.frontend.ListHosts()
	return &wire.ListHostsReply{
		Sequence: seq,
		NumHosts: uint16(len(hosts)),
		Hosts:    hosts,
	}
}

func (s *x11Server) handleSetAccessControl(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.SetAccessControlRequest)
	s.frontend.SetAccessControl(p.Mode)
	return nil
}

func (s *x11Server) handleSetCloseDownMode(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.SetCloseDownModeRequest)
	s.frontend.SetCloseDownMode(p.Mode)
	return nil
}

func (s *x11Server) handleKillClient(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.KillClientRequest)
	s.frontend.KillClient(p.Resource)
	return nil
}

func (s *x11Server) handleRotateProperties(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.RotatePropertiesRequest)
	err := s.RotateProperties(xID(p.Window), p.Delta, p.Atoms)
	if err != nil {
		return wire.NewGenericError(seq, uint32(p.Window), 0, wire.RotateProperties, wire.MatchErrorCode)
	}
	return nil
}

func (s *x11Server) handleForceScreenSaver(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.ForceScreenSaverRequest)
	s.frontend.ForceScreenSaver(p.Mode)
	return nil
}

func (s *x11Server) handleSetPointerMapping(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.SetPointerMappingRequest)
	status, _ := s.frontend.SetPointerMapping(p.Map)
	return &wire.SetPointerMappingReply{
		Sequence: seq,
		Status:   status,
	}
}

func (s *x11Server) handleGetPointerMapping(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	pMap, _ := s.frontend.GetPointerMapping()
	return &wire.GetPointerMappingReply{
		Sequence: seq,
		Length:   byte(len(pMap)),
		PMap:     pMap,
	}
}

func (s *x11Server) handleSetModifierMapping(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	p := req.(*wire.SetModifierMappingRequest)
	status, _ := s.frontend.SetModifierMapping(p.KeyCodesPerModifier, p.KeyCodes)
	return &wire.SetModifierMappingReply{
		Sequence: seq,
		Status:   status,
	}
}

func (s *x11Server) handleGetModifierMapping(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	keyCodes, err := s.frontend.GetModifierMapping()
	if err != nil {
		return wire.NewGenericError(seq, 0, 0, wire.GetModifierMapping, wire.ImplementationErrorCode)
	}
	return &wire.GetModifierMappingReply{
		Sequence:            seq,
		KeyCodesPerModifier: byte(len(keyCodes) / 8),
		KeyCodes:            keyCodes,
	}
}

func (s *x11Server) handleNoOperation(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	return nil
}

func (s *x11Server) handleEnableBigRequests(client *x11Client, req wire.Request, seq uint16) messageEncoder {
	client.bigRequestsEnabled = true
	return &wire.BigRequestsEnableReply{
		Sequence:         seq,
		MaxRequestLength: 0x100000,
	}
}
