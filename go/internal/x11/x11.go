//go:build x11

package x11

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"runtime/debug"

	"sync"

	"golang.org/x/crypto/ssh"
)

type xID struct {
	client uint32
	local  uint32
}

func (x xID) String() string {
	return fmt.Sprintf("%d-%d", x.client, x.local)
}

var (
	x11ServerInstance *x11Server
	once              sync.Once
)

func Enabled() bool {
	return true
}

// Logger is the interface for logging.
type Logger interface {
	Errorf(format string, args ...interface{})
	Infof(format string, args ...interface{})
	Printf(format string, args ...interface{})
}

// X11FrontendAPI is the interface for the X11 frontend.
type X11FrontendAPI interface {
	CreateWindow(xid xID, parent, x, y, width, height, depth, valueMask uint32, values *WindowAttributes)
	ChangeWindowAttributes(xid xID, valueMask uint32, values *WindowAttributes)
	GetWindowAttributes(xid xID) *WindowAttributes
	ChangeProperty(xid xID, property, typeAtom, format uint32, data []byte)
	CreateGC(xid xID, gc *GC)
	ChangeGC(xid xID, valueMask uint32, gc *GC)
	DestroyWindow(xid xID)
	DestroyAllWindowsForClient(clientID uint32)
	MapWindow(xid xID)
	UnmapWindow(xid xID)
	ConfigureWindow(xid xID, valueMask uint16, values []uint32)
	PutImage(drawable xID, gc *GC, format uint8, width, height uint16, dstX, dstY int16, leftPad, depth uint8, data []byte)
	PolyLine(drawable xID, gc *GC, points []uint32)
	PolyFillRectangle(drawable xID, gc *GC, rects []uint32)
	FillPoly(drawable xID, gc *GC, points []uint32)
	PolySegment(drawable xID, gc *GC, segments []uint32)
	PolyPoint(drawable xID, gc *GC, points []uint32)
	PolyRectangle(drawable xID, gc *GC, rects []uint32)
	PolyArc(drawable xID, gc *GC, arcs []uint32)
	PolyFillArc(drawable xID, gc *GC, arcs []uint32)
	ClearArea(drawable xID, x, y, width, height int32)
	CopyArea(srcDrawable, dstDrawable xID, gc *GC, srcX, srcY, dstX, dstY, width, height int32)
	GetImage(drawable xID, x, y, width, height int32, format uint32) ([]byte, error)
	ReadClipboard() (string, error)
	WriteClipboard(string) error
	UpdatePointerPosition(x, y int16)
	Bell(percent int8)
	GetAtom(clientID uint32, name string) uint32
	GetAtomName(atom uint32) string
	ListProperties(window xID) []uint32
	GetProperty(window xID, property uint32) ([]byte, uint32, uint32)
	ImageText8(drawable xID, gc *GC, x, y int32, text []byte)
	ImageText16(drawable xID, gc *GC, x, y int32, text []uint16)
	PolyText8(drawable xID, gc *GC, x, y int32, items []PolyText8Item)
	PolyText16(drawable xID, gc *GC, x, y int32, items []PolyText16Item)
	CreatePixmap(xid, drawable xID, width, height, depth uint32)
	FreePixmap(xid xID)
	CopyPixmap(srcID, dstID, gcID xID, srcX, srcY, width, height, dstX, dstY uint32)
	CreateCursorFromGlyph(cursorID uint32, glyphID uint16)
	SetWindowCursor(windowID xID, cursorID xID)
	CopyGC(srcGC, dstGC xID)
	FreeGC(gc xID)
	FreeCursor(cursorID xID)
	SendEvent(eventData messageEncoder)
	GetFocusWindow(clientID uint32) xID
	ConvertSelection(selection, target, property uint32, requestor xID)
	GrabPointer(grabWindow xID, ownerEvents bool, eventMask uint16, pointerMode, keyboardMode byte, confineTo uint32, cursor uint32, time uint32) byte
	UngrabPointer(time uint32)
	GrabKeyboard(grabWindow xID, ownerEvents bool, time uint32, pointerMode, keyboardMode byte) byte
	UngrabKeyboard(time uint32)
	GetCanvasOperations() []CanvasOperation
	GetRGBColor(colormap xID, pixel uint32) (r, g, b uint32)
	OpenFont(fid xID, name string)
	QueryFont(fid xID) (minBounds, maxBounds xCharInfo, minCharOrByte2, maxCharOrByte2, defaultChar uint16, drawDirection uint8, minByte1, maxByte1 uint8, allCharsExist bool, fontAscent, fontDescent int16, charInfos []xCharInfo)
	CloseFont(fid xID)
	ListFonts(maxNames uint16, pattern string) []string
	AllowEvents(clientID uint32, mode byte, time uint32)
}

type XError interface {
	Code() byte
	Sequence() uint16
	BadValue() uint32
	MinorOp() byte
	MajorOp() byte
}

// CanvasOperation represents a single canvas drawing operation captured from the frontend.
type CanvasOperation struct {
	Type        string `json:"type"`
	Args        []any  `json:"args"`
	FillStyle   string `json:"fillStyle"`
	StrokeStyle string `json:"strokeStyle"`
}

// request represents an X11 request.
type request struct {
	opcode   reqCode
	data     byte
	length   uint16
	sequence uint16
	body     []byte
}

type window struct {
	xid           xID
	parent        uint32
	x, y          int16
	width, height uint16
	mapped        bool
	depth         byte
	children      []uint32
	attributes    *WindowAttributes
	colormap      xID
}

func (w *window) mapState() byte {
	if !w.mapped {
		return 0 // Unmapped
	}
	return 2 // Viewable
}

type colormap struct {
	pixels map[uint32]color
}

type x11Server struct {
	logger             Logger
	byteOrder          binary.ByteOrder
	frontend           X11FrontendAPI
	windows            map[xID]*window
	gcs                map[xID]*GC
	pixmaps            map[xID]bool
	cursors            map[xID]bool
	selections         map[xID]uint32
	colormaps          map[xID]*colormap
	defaultColormap    uint32
	installedColormap  xID
	visualID           uint32
	rootVisual         visualType
	blackPixel         uint32
	whitePixel         uint32
	pointerX, pointerY int16
	clients            map[uint32]*x11Client
	nextClientID       uint32
}

func (s *x11Server) UpdatePointerPosition(x, y int16) {
	s.pointerX = x
	s.pointerY = y
}

func (s *x11Server) SendMouseEvent(xid xID, eventType string, x, y, detail int32) {
	log.Printf("X11: SendMouseEvent xid=%s type=%s x=%d y=%d detail=%d", xid, eventType, x, y, detail)
	client, ok := s.clients[xid.client]
	if !ok {
		log.Print("X11: Failed to write mount event: client not found")
		return
	}

	event := &motionNotifyEvent{
		sequence:   client.sequence,
		detail:     0, // 0 for Normal
		time:       0, // 0 for now
		root:       s.rootWindowID(),
		event:      xid.local,
		child:      0, // 0 for now
		rootX:      int16(x),
		rootY:      int16(y),
		eventX:     int16(x),
		eventY:     int16(y),
		state:      uint16(detail),
		sameScreen: true,
	}

	if err := client.send(event); err != nil {
		log.Printf("X11: Failed to write mouse event: %v", err)
	}
}

func (s *x11Server) SendKeyboardEvent(xid xID, eventType string, keyCode int, altKey, ctrlKey, shiftKey, metaKey bool) {
	// Implement sending keyboard event to client
	// This will involve constructing an X11 event packet and writing it to client.conn
	log.Printf("X11: SendKeyboardEvent xid=%s type=%s keyCode=%d alt=%t ctrl=%t shift=%t meta=%t", xid, eventType, keyCode, altKey, ctrlKey, shiftKey, metaKey)
	client, ok := s.clients[xid.client]
	if !ok {
		log.Printf("X11: SendKeyboardEvent unknown client %d", xid.client)
		return
	}

	state := uint16(0)
	if shiftKey {
		state |= 1 // ShiftMask
	}
	if ctrlKey {
		state |= 4 // ControlMask
	}
	if altKey {
		state |= 8 // Mod1Mask (Alt key)
	}
	if metaKey {
		state |= 64 // Mod4Mask (Meta key)
	}

	event := &keyEvent{
		sequence:   client.sequence,
		detail:     byte(keyCode),
		time:       0, // TODO: Get actual time
		root:       s.rootWindowID(),
		event:      xid.local,
		child:      0, // No child for now
		rootX:      s.pointerX,
		rootY:      s.pointerY,
		eventX:     s.pointerX, // Assuming pointer is always in the window for now
		eventY:     s.pointerY, // Assuming pointer is always in the window for now
		state:      state,
		sameScreen: true,
	}

	if eventType == "keydown" {
		event.encodeMessage(client.byteOrder)[0] = 2 // KeyPress
	} else if eventType == "keyup" {
		event.encodeMessage(client.byteOrder)[0] = 3 // KeyRelease
	} else {
		log.Printf("X11: Unknown keyboard event type: %s", eventType)
		return
	}

	if err := client.send(event); err != nil {
		log.Printf("X11: Failed to write keyboard event: %v", err)
	}
}

func (s *x11Server) sendConfigureNotifyEvent(windowID xID, x, y int16, width, height uint16) {
	log.Printf("X11: Sending ConfigureNotify event for window %d", windowID)
	client, ok := s.clients[windowID.client]
	if !ok {
		log.Print("X11: Failed to write ConfigureNotify event: client not found")
		return
	}

	event := &configureNotifyEvent{
		sequence:         client.sequence,
		event:            windowID.local,
		window:           windowID.local,
		aboveSibling:     0, // None
		x:                x,
		y:                y,
		width:            width,
		height:           height,
		borderWidth:      0,
		overrideRedirect: false,
	}

	if err := client.send(event); err != nil {
		log.Printf("X11: Failed to write ConfigureNotify event: %v", err)
	}
}

func (s *x11Server) sendExposeEvent(windowID xID, x, y, width, height uint16) {
	log.Printf("X11: Sending Expose event for window %s", windowID)
	client, ok := s.clients[windowID.client]
	if !ok {
		log.Printf("X11: sendExposeEvent unknown client %d", windowID.client)
		return
	}

	event := &exposeEvent{
		sequence: client.sequence,
		window:   windowID.local,
		x:        x,
		y:        y,
		width:    width,
		height:   height,
		count:    0, // count = 0, no more expose events to follow
	}

	if err := client.send(event); err != nil {
		log.Printf("X11: Failed to write Expose event: %v", err)
	}
}

func (s *x11Server) SendClientMessageEvent(windowID xID, messageTypeAtom uint32, data [20]byte) {
	log.Printf("X11: Sending ClientMessage event for window %s", windowID)
	client, ok := s.clients[windowID.client]
	if !ok {
		log.Printf("X11: SendClientMessageEvent unknown client %d", windowID.client)
		return
	}

	event := &clientMessageEvent{
		sequence:    client.sequence,
		format:      32, // Format is always 32 for ClientMessage
		window:      windowID.local,
		messageType: messageTypeAtom,
		data:        data,
	}

	if err := client.send(event); err != nil {
		log.Printf("X11: Failed to write ClientMessage event: %v", err)
	}
}

func (s *x11Server) SendSelectionNotify(requestor xID, selection, target, property uint32, data []byte) {
	client, ok := s.clients[requestor.client]
	if !ok {
		log.Printf("X11: SendSelectionNotify unknown client %d", requestor.client)
		return
	}

	event := &selectionNotifyEvent{
		sequence:  client.sequence,
		requestor: requestor.local,
		selection: selection,
		target:    target,
		property:  property,
		time:      0, // TODO: Get actual time
	}
	s.sendEvent(client, event)
}

func (s *x11Server) sendEvent(client *x11Client, event messageEncoder) {
	if err := client.send(event); err != nil {
		s.logger.Errorf("Failed to write event: %v", err)
	}
}

func (s *x11Server) GetRGBColor(colormap xID, pixel uint32) (r, g, b uint32) {
	if colormap.local == s.defaultColormap {
		colormap.client = 0
	}
	if cm, ok := s.colormaps[colormap]; ok {
		if color, ok := cm.pixels[pixel]; ok {
			log.Printf("GetRGBColor: cmap:%s pixel:%x return %+v", colormap, pixel, color)
			return uint32(color.Red), uint32(color.Green), uint32(color.Blue)
		}
		r = (pixel & 0xff0000) >> 16
		g = (pixel & 0x00ff00) >> 8
		b = (pixel & 0x0000ff)
		log.Printf("GetRGBColor: cmap:%s pixel:%x return RGB for pixel", colormap, pixel)
		return r, g, b
	}
	// Explicitly handle black and white pixels based on server's setup
	if pixel == s.blackPixel {
		log.Printf("GetRGBColor: cmap:%s pixel:%x return blackPixel", colormap, pixel)
		return 0, 0, 0 // Black
	}
	if pixel == s.whitePixel {
		log.Printf("GetRGBColor: cmap:%s pixel:%x return whitePixel", colormap, pixel)
		return 0xFF, 0xFF, 0xFF // White
	}
	// For TrueColor visuals, the pixel value directly encodes RGB components.
	if s.rootVisual.class == 4 { // TrueColor
		r = (pixel & s.rootVisual.redMask) >> calculateShift(s.rootVisual.redMask)
		g = (pixel & s.rootVisual.greenMask) >> calculateShift(s.rootVisual.greenMask)
		b = (pixel & s.rootVisual.blueMask) >> calculateShift(s.rootVisual.blueMask)
		log.Printf("GetRGBColor: cmap:%s pixel:%x return RGB for pixel", colormap, pixel)
		return r, g, b
	}
	// Default to black if not found
	log.Printf("GetRGBColor: cmap:%s pixel:%x return black", colormap, pixel)
	return 0, 0, 0
}

// calculateShift determines the right shift needed to extract the color component.
func calculateShift(mask uint32) uint32 {
	if mask == 0 {
		return 0
	}
	shift := uint32(0)
	for (mask & 1) == 0 {
		mask >>= 1
		shift++
	}
	return shift
}

func (s *x11Server) rootWindowID() uint32 {
	return 0
}

func (s *x11Server) readRequest(client *x11Client) (*request, error) {
	var reqHeader [4]byte
	if _, err := io.ReadFull(client.conn, reqHeader[:]); err != nil {
		return nil, err
	}
	log.Printf("X11: Raw request header: %x", reqHeader)
	client.sequence++
	req := &request{
		opcode:   reqCode(reqHeader[0]),
		data:     reqHeader[1],
		length:   client.byteOrder.Uint16(reqHeader[2:4]),
		sequence: client.sequence,
	}
	req.body = make([]byte, (req.length*4)-4)
	if _, err := io.ReadFull(client.conn, req.body); err != nil {
		return nil, err
	}
	return req, nil
}

func (s *x11Server) cleanupClient(client *x11Client) {
	s.frontend.DestroyAllWindowsForClient(client.id)
	delete(s.clients, client.id)
}

func (s *x11Server) serve(client *x11Client) {
	defer client.conn.Close()
	defer s.cleanupClient(client)
	for {
		req, err := s.readRequest(client)
		if err != nil {
			if err != io.EOF {
				s.logger.Errorf("Failed to read X11 request: %v", err)
			}
			break
		}
		reply := s.handleRequest(client, req)
		if reply != nil {
			if err := client.send(reply); err != nil {
				s.logger.Errorf("Failed to write reply: %v", err)
			}
		}
	}
}

func (s *x11Server) handleRequest(client *x11Client, req *request) (reply messageEncoder) {
	log.Printf("X11: Received opcode: %d", req.opcode)
	defer func() {
		if r := recover(); r != nil {
			s.logger.Errorf("X11 Request Handler Panic: %v\n%s", r, debug.Stack())
			// Construct a generic X11 error reply (Request error)
			reply = client.sendError(&GenericError{
				seq:      req.sequence,
				badValue: uint32(req.opcode),
				minorOp:  0,
				majorOp:  req.opcode,
				code:     1, // Request error code
			})
		}
	}()

	switch req.opcode {
	case CreateWindow:
		p := parseCreateWindowRequest(s.byteOrder, req.body)
		xid := client.xID(p.Drawable)
		parentXID := client.xID(p.Parent)
		// Check if the window ID is already in use
		if _, exists := s.windows[xid]; exists {
			s.logger.Errorf("X11: CreateWindow: ID %d already in use", xid)
			return client.sendError(&GenericError{seq: req.sequence, badValue: p.Drawable, majorOp: CreateWindow, code: IDChoiceError})
		}

		newWindow := &window{
			xid:        xid,
			parent:     p.Parent,
			x:          p.X,
			y:          p.Y,
			width:      p.Width,
			height:     p.Height,
			depth:      byte(req.data),
			children:   []uint32{},
			attributes: p.Values,
		}
		if p.Values.Colormap > 0 {
			newWindow.colormap = client.xID(p.Values.Colormap)
		} else {
			newWindow.colormap = xID{local: s.defaultColormap}
		}
		s.windows[xid] = newWindow

		// Add to parent's children list
		if parentWindow, ok := s.windows[parentXID]; ok {
			parentWindow.children = append(parentWindow.children, p.Drawable)
		}
		s.frontend.CreateWindow(xid, p.Parent, uint32(p.X), uint32(p.Y), uint32(p.Width), uint32(p.Height), uint32(req.data), p.ValueMask, p.Values)

	case GetWindowAttributes:
		p := parseGetWindowAttributesRequest(s.byteOrder, req.body)
		xid := client.xID(p.Drawable)
		w, ok := s.windows[xid]
		if !ok {
			return nil
		}
		return &getWindowAttributesReply{
			sequence:           req.sequence,
			backingStore:       byte(w.attributes.BackingStore),
			visualID:           s.visualID,
			class:              1, // Class: InputOutput
			bitGravity:         byte(w.attributes.BitGravity),
			winGravity:         byte(w.attributes.WinGravity),
			backingPlanes:      w.attributes.BackingPlanes,
			backingPixel:       w.attributes.BackingPixel,
			saveUnder:          w.attributes.SaveUnder != 0,
			mapped:             w.mapped,
			mapState:           w.mapState(),
			overrideRedirect:   w.attributes.OverrideRedirect != 0,
			colormap:           w.attributes.Colormap,
			allEventMasks:      w.attributes.EventMask,
			yourEventMask:      w.attributes.EventMask, // Assuming client's event mask is the same for now
			doNotPropagateMask: 0,                      // Not explicitly stored in window attributes
		}
	case DestroyWindow:
		p := parseMapWindowRequest(s.byteOrder, req.body)
		xid := client.xID(p.Window)
		delete(s.windows, xid)
		s.frontend.DestroyWindow(xid)

	case UnmapWindow:
		p := parseUnmapWindowRequest(s.byteOrder, req.body)
		xid := client.xID(p.Window)
		if w, ok := s.windows[xid]; ok {
			w.mapped = false
		}
		s.frontend.UnmapWindow(xid)

	case MapWindow:
		p := parseMapWindowRequest(s.byteOrder, req.body)
		xid := client.xID(p.Window)
		if w, ok := s.windows[xid]; ok {
			w.mapped = true
			s.frontend.MapWindow(xid)
			s.sendExposeEvent(xid, 0, 0, w.width, w.height)
		}

	case MapSubwindows:
		p := parseMapWindowRequest(s.byteOrder, req.body)
		xid := client.xID(p.Window)
		if parentWindow, ok := s.windows[xid]; ok {
			for _, childID := range parentWindow.children {
				childXID := xID{client: xid.client, local: childID}
				if childWindow, ok := s.windows[childXID]; ok {
					childWindow.mapped = true
					s.frontend.MapWindow(childXID)
					s.sendExposeEvent(childXID, 0, 0, childWindow.width, childWindow.height)
				}
			}
		}

	case ConfigureWindow:
		p := parseConfigureWindowRequest(s.byteOrder, req.body)
		xid := client.xID(p.Window)
		s.frontend.ConfigureWindow(xid, p.ValueMask, p.Values)

	case GetGeometry:
		p := parseGetGeometryRequest(s.byteOrder, req.body)
		xid := client.xID(p.Drawable)
		w, ok := s.windows[xid]
		if !ok {
			return nil
		}
		return &getGeometryReply{
			sequence:    req.sequence,
			depth:       w.depth,
			root:        s.rootWindowID(),
			x:           w.x,
			y:           w.y,
			width:       w.width,
			height:      w.height,
			borderWidth: 0, // Border width is not stored in window struct, assuming 0 for now
		}
	case QueryTree:
		// Not implemented yet

	case InternAtom:
		p := parseInternAtomRequest(s.byteOrder, req.body)
		atomID := s.frontend.GetAtom(client.id, p.Name)

		return &internAtomReply{
			sequence: req.sequence,
			atom:     atomID,
		}

	case GetAtomName:
		p := parseGetAtomNameRequest(s.byteOrder, req.body)
		name := s.frontend.GetAtomName(p.Atom)
		return &getAtomNameReply{
			sequence:   req.sequence,
			nameLength: uint16(len(name)),
			name:       name,
		}

	case ChangeProperty:
		p := parseChangePropertyRequest(s.byteOrder, req.body)
		xid := client.xID(p.Window)
		s.frontend.ChangeProperty(xid, p.Property, p.Type, uint32(p.Format), p.Data)

	case SendEvent:
		p := parseSendEventRequest(s.byteOrder, req.body)
		// The X11 client sends an event to another client.
		// We need to forward this event to the appropriate frontend.
		// For now, we'll just log it and pass it to the frontend.
		s.frontend.SendEvent(&x11RawEvent{data: p.EventData})

	case QueryPointer:
		p := parseQueryPointerRequest(s.byteOrder, req.body)
		xid := client.xID(p.Drawable)
		log.Printf("X11: QueryPointer drawable=%d", xid)
		return &queryPointerReply{
			sequence:   req.sequence,
			sameScreen: true,
			root:       s.rootWindowID(),
			child:      p.Drawable,
			rootX:      s.pointerX,
			rootY:      s.pointerY,
			winX:       s.pointerX, // Assuming pointer is always in the window for now
			winY:       s.pointerY, // Assuming pointer is always in the window for now
			mask:       0,          // No buttons pressed
		}
	case ListProperties:
		p := parseListPropertiesRequest(s.byteOrder, req.body)
		xid := client.xID(p.Window)
		atoms := s.frontend.ListProperties(xid)
		return &listPropertiesReply{
			sequence:      req.sequence,
			numProperties: uint16(len(atoms)),
			atoms:         atoms,
		}

	case CreateGC:
		p := parseCreateGCRequest(s.byteOrder, req.body)
		xid := client.xID(p.Cid)

		// Check if the GC ID is already in use
		if _, exists := s.gcs[xid]; exists {
			s.logger.Errorf("X11: CreateGC: ID %s already in use", xid)
			return client.sendError(&GenericError{seq: req.sequence, badValue: xid.local, majorOp: CreateGC, code: IDChoiceError})
		}

		s.gcs[xid] = p.Values
		s.frontend.CreateGC(xid, p.Values)

	case ChangeGC:
		p := parseChangeGCRequest(s.byteOrder, req.body)
		xid := client.xID(p.Gc)
		if existingGC, ok := s.gcs[xid]; ok {
			if p.ValueMask&GCFunction != 0 {
				existingGC.Function = p.Values.Function
			}
			if p.ValueMask&GCPlaneMask != 0 {
				existingGC.PlaneMask = p.Values.PlaneMask
			}
			if p.ValueMask&GCForeground != 0 {
				existingGC.Foreground = p.Values.Foreground
			}
			if p.ValueMask&GCBackground != 0 {
				existingGC.Background = p.Values.Background
			}
			if p.ValueMask&GCLineWidth != 0 {
				existingGC.LineWidth = p.Values.LineWidth
			}
			if p.ValueMask&GCLineStyle != 0 {
				existingGC.LineStyle = p.Values.LineStyle
			}
			if p.ValueMask&GCCapStyle != 0 {
				existingGC.CapStyle = p.Values.CapStyle
			}
			if p.ValueMask&GCJoinStyle != 0 {
				existingGC.JoinStyle = p.Values.JoinStyle
			}
			if p.ValueMask&GCFillStyle != 0 {
				existingGC.FillStyle = p.Values.FillStyle
			}
			if p.ValueMask&GCFillRule != 0 {
				existingGC.FillRule = p.Values.FillRule
			}
			if p.ValueMask&GCTile != 0 {
				existingGC.Tile = p.Values.Tile
			}
			if p.ValueMask&GCStipple != 0 {
				existingGC.Stipple = p.Values.Stipple
			}
			if p.ValueMask&GCTileStipXOrigin != 0 {
				existingGC.TileStipXOrigin = p.Values.TileStipXOrigin
			}
			if p.ValueMask&GCTileStipYOrigin != 0 {
				existingGC.TileStipYOrigin = p.Values.TileStipYOrigin
			}
			if p.ValueMask&GCFont != 0 {
				existingGC.Font = p.Values.Font
			}
			if p.ValueMask&GCSubwindowMode != 0 {
				existingGC.SubwindowMode = p.Values.SubwindowMode
			}
			if p.ValueMask&GCGraphicsExposures != 0 {
				existingGC.GraphicsExposures = p.Values.GraphicsExposures
			}
			if p.ValueMask&GCClipXOrigin != 0 {
				existingGC.ClipXOrigin = p.Values.ClipXOrigin
			}
			if p.ValueMask&GCClipYOrigin != 0 {
				existingGC.ClipYOrigin = p.Values.ClipYOrigin
			}
			if p.ValueMask&GCClipMask != 0 {
				existingGC.ClipMask = p.Values.ClipMask
			}
			if p.ValueMask&GCDashOffset != 0 {
				existingGC.DashOffset = p.Values.DashOffset
			}
			if p.ValueMask&GCDashList != 0 {
				existingGC.Dashes = p.Values.Dashes
			}
			if p.ValueMask&GCArcMode != 0 {
				existingGC.ArcMode = p.Values.ArcMode
			}
		}
		s.frontend.ChangeGC(xid, p.ValueMask, p.Values)

	case ClearArea:
		p := parseClearAreaRequest(s.byteOrder, req.body)
		s.frontend.ClearArea(client.xID(p.Window), int32(p.X), int32(p.Y), int32(p.Width), int32(p.Height))

	case CopyArea:
		p := parseCopyAreaRequest(s.byteOrder, req.body)
		gc, ok := s.gcs[client.xID(p.Gc)]
		if !ok {
			return
		}
		s.frontend.CopyArea(client.xID(p.SrcDrawable), client.xID(p.DstDrawable), gc, int32(p.SrcX), int32(p.SrcY), int32(p.DstX), int32(p.DstY), int32(p.Width), int32(p.Height))

	case PolyPoint:
		p := parsePolyPointRequest(s.byteOrder, req.body)
		gc, ok := s.gcs[client.xID(p.Gc)]
		if !ok {
			return
		}
		s.frontend.PolyPoint(client.xID(p.Drawable), gc, p.Coordinates)

	case PolyLine:
		p := parsePolyLineRequest(s.byteOrder, req.body)
		gc, ok := s.gcs[client.xID(p.Gc)]
		if !ok {
			return
		}
		s.frontend.PolyLine(client.xID(p.Drawable), gc, p.Coordinates)

	case PolySegment:
		p := parsePolySegmentRequest(s.byteOrder, req.body)
		gc, ok := s.gcs[client.xID(p.Gc)]
		if !ok {
			return
		}
		s.frontend.PolySegment(client.xID(p.Drawable), gc, p.Segments)

	case PolyArc:
		p := parsePolyArcRequest(s.byteOrder, req.body)
		gc, ok := s.gcs[client.xID(p.Gc)]
		if !ok {
			return
		}
		s.frontend.PolyArc(client.xID(p.Drawable), gc, p.Arcs)

	case PolyRectangle:
		p := parsePolyRectangleRequest(s.byteOrder, req.body)
		gc, ok := s.gcs[client.xID(p.Gc)]
		if !ok {
			return
		}
		s.frontend.PolyRectangle(client.xID(p.Drawable), gc, p.Rectangles)

	case FillPoly:
		p := parseFillPolyRequest(s.byteOrder, req.body)
		gc, ok := s.gcs[client.xID(p.Gc)]
		if !ok {
			return
		}
		s.frontend.FillPoly(client.xID(p.Drawable), gc, p.Coordinates)

	case PolyFillRectangle:
		p := parsePolyFillRectangleRequest(s.byteOrder, req.body)
		gc, ok := s.gcs[client.xID(p.Gc)]
		if !ok {
			return
		}
		s.frontend.PolyFillRectangle(client.xID(p.Drawable), gc, p.Rectangles)

	case PolyFillArc:
		p := parsePolyFillArcRequest(s.byteOrder, req.body)
		gc, ok := s.gcs[client.xID(p.Gc)]
		if !ok {
			return
		}
		s.frontend.PolyFillArc(client.xID(p.Drawable), gc, p.Arcs)

	case PutImage:
		log.Printf("X11: Server received PutImage request")
		p := parsePutImageRequest(s.byteOrder, req.body)
		p.Format = req.data
		gc, ok := s.gcs[client.xID(p.Gc)]
		if !ok {
			return
		}
		s.frontend.PutImage(client.xID(p.Drawable), gc, p.Format, p.Width, p.Height, p.DstX, p.DstY, p.LeftPad, p.Depth, p.Data)

	case GetImage:
		p := parseGetImageRequest(s.byteOrder, req.body)
		p.Format = req.data
		imgData, err := s.frontend.GetImage(client.xID(p.Drawable), int32(p.X), int32(p.Y), int32(p.Width), int32(p.Height), p.PlaneMask)
		if err != nil {
			s.logger.Errorf("Failed to get image: %v", err)
			return nil
		}
		return &getImageReply{
			sequence:  req.sequence,
			depth:     24, // Assuming 24-bit depth for now
			visualID:  s.visualID,
			imageData: imgData,
		}
	case GetProperty:
		p := parseGetPropertyRequest(s.byteOrder, req.body)

		data, typ, format := s.frontend.GetProperty(client.xID(p.Window), p.Property)

		// Handle offset and length
		var propData []byte
		bytesAfter := 0
		if p.Offset*4 < uint32(len(data)) {
			start := p.Offset * 4
			end := start + p.Length*4
			if end > uint32(len(data)) {
				end = uint32(len(data))
			}
			propData = data[start:end]
			bytesAfter = len(data) - int(end)
		} else {
			bytesAfter = len(data)
		}

		n := len(propData)
		var valueLenInFormatUnits uint32
		if format == 8 {
			valueLenInFormatUnits = uint32(n)
		} else if format == 16 {
			valueLenInFormatUnits = uint32(n / 2)
		} else if format == 32 {
			valueLenInFormatUnits = uint32(n / 4)
		}

		return &getPropertyReply{
			sequence:              req.sequence,
			format:                byte(format),
			propertyType:          typ,
			bytesAfter:            uint32(bytesAfter),
			valueLenInFormatUnits: valueLenInFormatUnits,
			value:                 propData,
		}

	case ImageText8:
		p := parseImageText8Request(s.byteOrder, req.body)
		gc, ok := s.gcs[client.xID(p.Gc)]
		if !ok {
			return
		}
		s.frontend.ImageText8(client.xID(p.Drawable), gc, int32(p.X), int32(p.Y), p.Text)

	case ImageText16:
		p := parseImageText16Request(s.byteOrder, req.body)
		gc, ok := s.gcs[client.xID(p.Gc)]
		if !ok {
			return
		}
		s.frontend.ImageText16(client.xID(p.Drawable), gc, int32(p.X), int32(p.Y), p.Text)

	case PolyText8:
		p := parsePolyText8Request(s.byteOrder, req.body)
		gc, ok := s.gcs[client.xID(p.Gc)]
		if !ok {
			return
		}
		s.frontend.PolyText8(client.xID(p.Drawable), gc, int32(p.X), int32(p.Y), p.Items)

	case PolyText16:
		p := parsePolyText16Request(s.byteOrder, req.body)
		gc, ok := s.gcs[client.xID(p.Gc)]
		if !ok {
			return
		}
		s.frontend.PolyText16(client.xID(p.Drawable), gc, int32(p.X), int32(p.Y), p.Items)

	case Bell:
		p := parseBellRequest(req.data)
		s.frontend.Bell(p.Percent)

	case CreatePixmap:
		p := parseCreatePixmapRequest(s.byteOrder, req.body)
		p.Depth = req.data
		xid := client.xID(p.Pid)

		// Check if the pixmap ID is already in use
		if _, exists := s.pixmaps[xid]; exists {
			s.logger.Errorf("X11: CreatePixmap: ID %s already in use", xid)
			return client.sendError(&GenericError{seq: req.sequence, badValue: p.Pid, majorOp: CreatePixmap, code: IDChoiceError})
		}

		s.pixmaps[xid] = true // Mark pixmap ID as used
		s.frontend.CreatePixmap(xid, client.xID(p.Drawable), uint32(p.Width), uint32(p.Height), uint32(p.Depth))

	case FreePixmap:
		p := parseFreePixmapRequest(s.byteOrder, req.body)
		xid := client.xID(p.Pid)
		delete(s.pixmaps, xid)
		s.frontend.FreePixmap(xid)

	case CreateGlyphCursor:
		p := parseCreateGlyphCursorRequest(s.byteOrder, req.body)

		// Check if the cursor ID is already in use
		if _, exists := s.cursors[client.xID(p.Cid)]; exists {
			s.logger.Errorf("X11: CreateGlyphCursor: ID %d already in use", p.Cid)
			return client.sendError(&GenericError{seq: req.sequence, badValue: p.Cid, majorOp: CreateGlyphCursor, code: IDChoiceError})
		}

		s.cursors[client.xID(p.Cid)] = true
		s.frontend.CreateCursorFromGlyph(p.Cid, p.SourceChar)

	case ChangeWindowAttributes:
		p := parseChangeWindowAttributesRequest(s.byteOrder, req.body)
		xid := client.xID(p.Window)
		if w, ok := s.windows[xid]; ok {
			if p.ValueMask&CWBackPixmap != 0 {
				w.attributes.BackgroundPixmap = p.Values.BackgroundPixmap
			}
			if p.ValueMask&CWBackPixel != 0 {
				w.attributes.BackgroundPixel = p.Values.BackgroundPixel
			}
			if p.ValueMask&CWBorderPixmap != 0 {
				w.attributes.BorderPixmap = p.Values.BorderPixmap
			}
			if p.ValueMask&CWBorderPixel != 0 {
				w.attributes.BorderPixel = p.Values.BorderPixel
			}
			if p.ValueMask&CWBitGravity != 0 {
				w.attributes.BitGravity = p.Values.BitGravity
			}
			if p.ValueMask&CWWinGravity != 0 {
				w.attributes.WinGravity = p.Values.WinGravity
			}
			if p.ValueMask&CWBackingStore != 0 {
				w.attributes.BackingStore = p.Values.BackingStore
			}
			if p.ValueMask&CWBackingPlanes != 0 {
				w.attributes.BackingPlanes = p.Values.BackingPlanes
			}
			if p.ValueMask&CWBackingPixel != 0 {
				w.attributes.BackingPixel = p.Values.BackingPixel
			}
			if p.ValueMask&CWOverrideRedirect != 0 {
				w.attributes.OverrideRedirect = p.Values.OverrideRedirect
			}
			if p.ValueMask&CWSaveUnder != 0 {
				w.attributes.SaveUnder = p.Values.SaveUnder
			}
			if p.ValueMask&CWEventMask != 0 {
				w.attributes.EventMask = p.Values.EventMask
			}
			if p.ValueMask&CWDontPropagate != 0 {
				w.attributes.DontPropagateMask = p.Values.DontPropagateMask
			}
			if p.ValueMask&CWColormap != 0 {
				w.attributes.Colormap = p.Values.Colormap
			}
			if p.ValueMask&CWCursor != 0 {
				w.attributes.Cursor = p.Values.Cursor
				s.frontend.SetWindowCursor(xid, client.xID(p.Values.Cursor))
			}
		}
		s.frontend.ChangeWindowAttributes(xid, p.ValueMask, p.Values)

	case CopyGC:
		srcGC := client.xID(s.byteOrder.Uint32(req.body[0:4]))
		dstGC := client.xID(s.byteOrder.Uint32(req.body[4:8]))
		s.frontend.CopyGC(srcGC, dstGC)

	case FreeGC:
		gcID := client.xID(s.byteOrder.Uint32(req.body[0:4]))
		s.frontend.FreeGC(gcID)

	case FreeCursor:
		p := parseFreeCursorRequest(s.byteOrder, req.body)
		xid := client.xID(p.Cursor)
		delete(s.cursors, xid)
		s.frontend.FreeCursor(xid)

	case TranslateCoords:
		p := parseTranslateCoordsRequest(s.byteOrder, req.body)
		srcWindow := client.xID(p.SrcWindow)
		dstWindow := client.xID(p.DstWindow)

		// Simplified implementation: assume windows are direct children of the root
		src, srcOk := s.windows[srcWindow]
		dst, dstOk := s.windows[dstWindow]
		if !srcOk || !dstOk {
			// One of the windows doesn't exist, can't translate
			return nil
		}

		dstX := src.x + p.SrcX - dst.x
		dstY := src.y + p.SrcY - dst.y

		return &translateCoordsReply{
			sequence:   req.sequence,
			sameScreen: true,
			child:      0, // No child for now
			dstX:       dstX,
			dstY:       dstY,
		}

	case GetInputFocus:
		return &getInputFocusReply{
			sequence: req.sequence,
			revertTo: 1, // RevertToParent
			focus:    s.frontend.GetFocusWindow(client.id).local,
		}

	case SetSelectionOwner:
		p := parseSetSelectionOwnerRequest(s.byteOrder, req.body)
		s.selections[client.xID(p.Selection)] = p.Owner

	case GetSelectionOwner:
		p := parseGetSelectionOwnerRequest(s.byteOrder, req.body)
		owner := s.selections[client.xID(p.Selection)]
		return &getSelectionOwnerReply{
			sequence: req.sequence,
			owner:    owner,
		}

	case ConvertSelection:
		p := parseConvertSelectionRequest(s.byteOrder, req.body)
		s.frontend.ConvertSelection(p.Selection, p.Target, p.Property, client.xID(p.Requestor))

	case GrabPointer:
		p := parseGrabPointerRequest(s.byteOrder, req.body)
		grabWindow := client.xID(p.GrabWindow)
		status := s.frontend.GrabPointer(grabWindow, p.OwnerEvents, p.EventMask, p.PointerMode, p.KeyboardMode, p.ConfineTo, p.Cursor, p.Time)
		return &grabPointerReply{
			sequence: req.sequence,
			status:   status,
		}

	case UngrabPointer:
		p := parseUngrabPointerRequest(s.byteOrder, req.body)
		s.frontend.UngrabPointer(p.Time)

	case GrabKeyboard:
		p := parseGrabKeyboardRequest(s.byteOrder, req.body)
		grabWindow := client.xID(p.GrabWindow)
		status := s.frontend.GrabKeyboard(grabWindow, p.OwnerEvents, p.Time, p.PointerMode, p.KeyboardMode)
		return &grabKeyboardReply{
			sequence: req.sequence,
			status:   status,
		}

	case UngrabKeyboard:
		p := parseUngrabKeyboardRequest(s.byteOrder, req.body)
		s.frontend.UngrabKeyboard(p.Time)

	case AllowEvents:
		p := parseAllowEventsRequest(s.byteOrder, req.body)
		p.Mode = req.data
		s.frontend.AllowEvents(client.id, p.Mode, p.Time)

	case QueryBestSize:
		p := parseQueryBestSizeRequest(s.byteOrder, req.body)
		log.Printf("X11: QueryBestSize class=%d drawable=%d width=%d height=%d", p.Class, p.Drawable, p.Width, p.Height)

		return &queryBestSizeReply{
			sequence: req.sequence,
			width:    p.Width,
			height:   p.Height,
		}

	case CreateColormap:
		p := parseCreateColormapRequest(s.byteOrder, req.body)
		xid := client.xID(p.Mid)

		if _, exists := s.colormaps[xid]; exists {
			return client.sendError(&GenericError{seq: req.sequence, badValue: p.Mid, majorOp: CreateColormap, code: ColormapError})
		}

		newColormap := &colormap{
			pixels: make(map[uint32]color),
		}

		if p.Alloc == 1 { // All
			// For TrueColor, pre-allocating doesn't make much sense as pixels are calculated.
			// For other visual types, this would be important.
			// For now, we'll just create an empty map.
		}

		s.colormaps[xid] = newColormap

	case FreeColormap:
		p := parseFreeColormapRequest(s.byteOrder, req.body)
		xid := client.xID(p.Cmap)
		if _, ok := s.colormaps[xid]; !ok {
			return client.sendError(&GenericError{seq: req.sequence, badValue: p.Cmap, majorOp: FreeColormap, code: ColormapError})
		}
		delete(s.colormaps, xid)

	case QueryExtension:
		p := parseQueryExtensionRequest(s.byteOrder, req.body)
		log.Printf("X11: QueryExtension name=%s", p.Name)

		return &queryExtensionReply{
			sequence:    req.sequence,
			present:     false,
			majorOpcode: 0,
			firstEvent:  0,
			firstError:  0,
		}

	case StoreNamedColor:
		log.Print("StoreNamedColor: not implemented")

	case StoreColors:
		p := parseStoreColorsRequest(s.byteOrder, req.body)
		xid := client.xID(p.Cmap)
		cm, ok := s.colormaps[xid]
		if !ok {
			return client.sendError(&GenericError{seq: req.sequence, badValue: p.Cmap, majorOp: StoreColors, code: ColormapError})
		}

		for _, item := range p.Items {
			c, exists := cm.pixels[item.Pixel]
			if !exists {
				c = color{}
			}

			if item.Flags&DoRed != 0 {
				c.Red = item.Red
			}
			if item.Flags&DoGreen != 0 {
				c.Green = item.Green
			}
			if item.Flags&DoBlue != 0 {
				c.Blue = item.Blue
			}
			cm.pixels[item.Pixel] = c
		}

	case AllocNamedColor:
		p := parseAllocNamedColorRequest(s.byteOrder, req.body)
		return s.handleAllocNamedColor(client, *p)

	case QueryColors:
		p := parseQueryColorsRequest(s.byteOrder, req.body)
		cmapID := p.Cmap
		pixels := p.Pixels

		var colors []color
		for _, pixel := range pixels {
			color, ok := s.colormaps[cmapID].pixels[pixel]
			if !ok {
				return client.sendError(&GenericError{seq: req.sequence, badValue: pixel, majorOp: QueryColors, code: ValueError})
			}
			colors = append(colors, color)
		}

		return &queryColorsReply{
			sequence: req.sequence,
			colors:   colors,
		}

	case LookupColor:
		p := parseLookupColorRequest(s.byteOrder, req.body)
		cmapID := xID{local: p.Cmap}

		color, ok := lookupColor(p.Name)
		if !ok {
			// TODO: This should be BadName, not BadColor
			return client.sendError(&GenericError{seq: req.sequence, badValue: cmapID.local, majorOp: LookupColor, code: ColormapError})
		}

		return &lookupColorReply{
			sequence:   req.sequence,
			red:        scale8to16(color.Red),
			green:      scale8to16(color.Green),
			blue:       scale8to16(color.Blue),
			exactRed:   scale8to16(color.Red),
			exactGreen: scale8to16(color.Green),
			exactBlue:  scale8to16(color.Blue),
		}

	case AllocColor:
		p := parseAllocColorRequest(s.byteOrder, req.body)

		xid := client.xID(p.Cmap)
		cm, ok := s.colormaps[xid]
		if !ok {
			return client.sendError(&GenericError{seq: req.sequence, badValue: p.Cmap, majorOp: AllocColor, code: ColormapError})
		}

		// Simple allocation for TrueColor: construct pixel value from RGB
		r8 := byte(p.Red >> 8)
		g8 := byte(p.Green >> 8)
		b8 := byte(p.Blue >> 8)
		pixel := (uint32(r8) << 16) | (uint32(g8) << 8) | uint32(b8)

		cm.pixels[pixel] = color{Red: p.Red, Green: p.Green, Blue: p.Blue}

		return &allocColorReply{
			sequence: req.sequence,
			red:      p.Red,
			green:    p.Green,
			blue:     p.Blue,
			pixel:    pixel,
		}

	case ListFonts:
		p := parseListFontsRequest(s.byteOrder, req.body)

		fontNames := s.frontend.ListFonts(p.MaxNames, p.Pattern)

		return &listFontsReply{
			sequence:  req.sequence,
			numFonts:  uint16(len(fontNames)),
			fontNames: fontNames,
		}

	case OpenFont:
		p := parseOpenFontRequest(s.byteOrder, req.body)
		s.frontend.OpenFont(client.xID(p.Fid), p.Name)

	case CloseFont:
		p := parseCloseFontRequest(s.byteOrder, req.body)
		s.frontend.CloseFont(client.xID(p.Fid))

	case QueryFont:
		p := parseQueryFontRequest(s.byteOrder, req.body)
		minBounds, maxBounds, minCharOrByte2, maxCharOrByte2, defaultChar, drawDirection, minByte1, maxByte1, allCharsExist, fontAscent, fontDescent, charInfos := s.frontend.QueryFont(client.xID(p.Fid))

		return &queryFontReply{
			sequence:       req.sequence,
			minBounds:      minBounds,
			maxBounds:      maxBounds,
			minCharOrByte2: minCharOrByte2,
			maxCharOrByte2: maxCharOrByte2,
			defaultChar:    defaultChar,
			numFontProps:   0, // Not implemented yet
			drawDirection:  drawDirection,
			minByte1:       minByte1,
			maxByte1:       maxByte1,
			allCharsExist:  allCharsExist,
			fontAscent:     fontAscent,
			fontDescent:    fontDescent,
			numCharInfos:   uint32(len(charInfos)),
			charInfos:      charInfos,
		}

	case FreeColors:
		p := parseFreeColorsRequest(s.byteOrder, req.body)
		xid := client.xID(p.Cmap)
		cm, ok := s.colormaps[xid]
		if !ok {
			return client.sendError(&GenericError{seq: req.sequence, badValue: p.Cmap, majorOp: FreeColors, code: ColormapError})
		}

		for _, pixel := range p.Pixels {
			delete(cm.pixels, pixel)
		}

	case InstallColormap:
		p := parseInstallColormapRequest(s.byteOrder, req.body)
		xid := client.xID(p.Cmap)
		_, ok := s.colormaps[xid]
		if !ok {
			return client.sendError(&GenericError{seq: req.sequence, badValue: p.Cmap, majorOp: InstallColormap, code: ColormapError})
		}

		s.installedColormap = xid

		for winID, win := range s.windows {
			if win.colormap == xid {
				client, ok := s.clients[winID.client]
				if !ok {
					log.Printf("X11: InstallColormap unknown client %d", winID.client)
					continue
				}
				event := &colormapNotifyEvent{
					sequence: client.sequence,
					window:   winID.local,
					colormap: p.Cmap,
					new:      true,
					state:    0, // Installed
				}
				s.sendEvent(client, event)
			}
		}
		return nil

	case UninstallColormap:
		p := parseUninstallColormapRequest(s.byteOrder, req.body)
		xid := client.xID(p.Cmap)
		_, ok := s.colormaps[xid]
		if !ok {
			return client.sendError(&GenericError{seq: req.sequence, badValue: p.Cmap, majorOp: UninstallColormap, code: ColormapError})
		}

		if s.installedColormap == xid {
			s.installedColormap = xID{local: s.defaultColormap}
		}

		for winID, win := range s.windows {
			if win.colormap == xid {
				client, ok := s.clients[winID.client]
				if !ok {
					log.Printf("X11: UninstallColormap unknown client %d", winID.client)
					continue
				}
				event := &colormapNotifyEvent{
					sequence: client.sequence,
					window:   winID.local,
					colormap: p.Cmap,
					new:      false,
					state:    1, // Uninstalled
				}
				s.sendEvent(client, event)
			}
		}
		return nil

	case ListInstalledColormaps:
		// windowID := p.Window // Not used for now

		var colormaps []uint32
		if s.installedColormap.local != 0 {
			colormaps = append(colormaps, s.installedColormap.local)
		}

		return &listInstalledColormapsReply{
			sequence:     req.sequence,
			numColormaps: uint16(len(colormaps)),
			colormaps:    colormaps,
		}

	default:
		log.Printf("Unknown X11 request opcode: %d", req.opcode)
	}
	return nil
}


func (s *x11Server) handleAllocNamedColor(client *x11Client, p AllocNamedColorRequest) messageEncoder {
	if _, ok := s.colormaps[p.Cmap]; !ok {
		return client.sendError(&BadColor{
			seq:      p.Sequence,
			badValue: p.Cmap.local,
			minorOp:  p.MinorOp,
			majorOp:  p.MajorOp,
		})
	}

	name := string(p.Name)
	rgb, ok := lookupColor(name)
	if !ok {
		// TODO: This should be BadName, not BadColor
		return client.sendError(&BadColor{
			seq:      p.Sequence,
			badValue: p.Cmap.local, // TODO: This should be the atom for the name, not the colormap
			minorOp:  p.MinorOp,
			majorOp:  p.MajorOp,
		})
	}

	exactRed := scale8to16(rgb.Red)
	exactGreen := scale8to16(rgb.Green)
	exactBlue := scale8to16(rgb.Blue)

	// For now, we only support TrueColor visuals, so we just allocate the color directly.
	// TODO: Implement proper colormap handling.
	pixel := (uint32(rgb.Red) << 16) | (uint32(rgb.Green) << 8) | uint32(rgb.Blue)

	return &allocColorReply{
		sequence: p.Sequence,
		red:      exactRed,
		green:    exactGreen,
		blue:     exactBlue,
		pixel:    pixel,
	}
}

func (s *x11Server) handshake(client *x11Client) {
	var handshake [12]byte
	if _, err := io.ReadFull(client.conn, handshake[:]); err != nil {
		s.logger.Errorf("x11 handshake: %v", err)
		return
	}

	var order binary.ByteOrder
	if handshake[0] == 'B' {
		order = binary.BigEndian
	} else {
		order = binary.LittleEndian
	}
	s.byteOrder = order
	client.byteOrder = order
	authProtoNameLen := order.Uint16(handshake[6:8])
	authProtoDataLen := order.Uint16(handshake[8:10])
	authLen := authProtoNameLen + authProtoDataLen
	if pad := authLen % 4; pad != 0 {
		authLen += 4 - pad
	}
	if _, err := io.CopyN(io.Discard, client.conn, int64(authLen)); err != nil {
		s.logger.Errorf("Failed to discard auth details: %v", err)
		return
	}

	setup := newDefaultSetup()

	// Create the setup response message encoder
	responseMsg := &setupResponse{
		success:                  1, // Success
		protocolVersion:          11,
		releaseNumber:            setup.releaseNumber,
		resourceIDBase:           setup.resourceIDBase,
		resourceIDMask:           setup.resourceIDMask,
		motionBufferSize:         setup.motionBufferSize,
		vendorLength:             setup.vendorLength,
		maxRequestLength:         setup.maxRequestLength,
		numScreens:               setup.numScreens,
		numPixmapFormats:         setup.numPixmapFormats,
		imageByteOrder:           setup.imageByteOrder,
		bitmapFormatBitOrder:     setup.bitmapFormatBitOrder,
		bitmapFormatScanlineUnit: setup.bitmapFormatScanlineUnit,
		bitmapFormatScanlinePad:  setup.bitmapFormatScanlinePad,
		minKeycode:               setup.minKeycode,
		maxKeycode:               setup.maxKeycode,
		vendorString:             setup.vendorString,
		pixmapFormats:            setup.pixmapFormats,
		screens:                  setup.screens,
	}

	if err := client.send(responseMsg); err != nil {
		s.logger.Errorf("x11 handshake write: %v", err)
		return
	}
	s.visualID = setup.screens[0].rootVisual
	s.rootVisual = setup.screens[0].depths[0].visuals[0]
	s.blackPixel = setup.screens[0].blackPixel
	s.whitePixel = setup.screens[0].whitePixel
}

func HandleX11Forwarding(logger Logger, client *ssh.Client) {
	x11channels := client.HandleChannelOpen("x11")
	go func() {
		for ch := range x11channels {
			channel, requests, err := ch.Accept()
			if err != nil {
				logger.Errorf("x11 channel accept: %v", err)
				continue
			}
			go ssh.DiscardRequests(requests)

			once.Do(func() {
				x11ServerInstance = &x11Server{
					logger:     logger,
					windows:    make(map[xID]*window),
					gcs:        make(map[xID]*GC),
					pixmaps:    make(map[xID]bool),
					cursors:    make(map[xID]bool),
					selections: make(map[xID]uint32),
					colormaps: map[xID]*colormap{
						xID{local: 0x1}: {
							pixels: map[uint32]color{
								0x000000: color{0x00, 0x00, 0x00},
								1:        color{0xff, 0xff, 0xff},
								0xffffff: color{0xff, 0xff, 0xff},
							},
						},
					},
					defaultColormap: 0x1,
					clients:         make(map[uint32]*x11Client),
					nextClientID:    1,
				}
				x11ServerInstance.frontend = newX11Frontend(logger, x11ServerInstance)
			})

			client := &x11Client{
				id:        x11ServerInstance.nextClientID,
				conn:      channel,
				sequence:  0,
				byteOrder: binary.LittleEndian, // Default, will be updated in handshake
			}
			x11ServerInstance.clients[client.id] = client
			x11ServerInstance.nextClientID++
			go func() {
				x11ServerInstance.handshake(client)
				x11ServerInstance.serve(client)
			}()
		}
	}()
}
