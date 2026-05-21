//go:build x11

package wire

import (
	"bytes"
	"encoding/binary"
	"io"
	"sync"
)

// ServerMessage is an interface for any message sent from the X server to the client.
type ServerMessage interface {
	// EncodeMessage encodes the message into a byte slice.
	EncodeMessage(order binary.ByteOrder) []byte
}

// ReplyTracker tracks expected reply opcodes for a given sequence number.
type ReplyTracker struct {
	mu               sync.Mutex
	sequenceToOpcode map[uint16]Opcodes
}

// NewReplyTracker creates a new ReplyTracker.
func NewReplyTracker() *ReplyTracker {
	return &ReplyTracker{
		sequenceToOpcode: make(map[uint16]Opcodes),
	}
}

// Expect registers an expected reply opcode for a given sequence number.
func (rt *ReplyTracker) Expect(sequence uint16, opcodes Opcodes) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.sequenceToOpcode[sequence] = opcodes
}

func (rt *ReplyTracker) pop(sequence uint16) (Opcodes, bool) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	opcodes, ok := rt.sequenceToOpcode[sequence]
	if ok {
		delete(rt.sequenceToOpcode, sequence)
	}
	return opcodes, ok
}

var (
	defaultReplyTracker = NewReplyTracker()
)

// ExpectReply registers an expected reply opcode for a given sequence number on the default tracker.
// Deprecated: Use ReplyTracker.Expect instead.
func ExpectReply(sequence uint16, opcodes Opcodes) {
	defaultReplyTracker.Expect(sequence, opcodes)
}

// ReadServerMessages reads messages from the X server connection and sends them to a channel.
// It uses the default tracker for replies.
// Deprecated: Use ReadServerMessagesWithTracker instead.
func ReadServerMessages(conn io.Reader, order binary.ByteOrder) <-chan ServerMessage {
	return ReadServerMessagesWithTracker(conn, order, defaultReplyTracker)
}

// ReadServerMessagesWithTracker reads messages from the X server connection and sends them to a channel.
// It uses the provided tracker to match replies with their request opcodes.
func ReadServerMessagesWithTracker(conn io.Reader, order binary.ByteOrder, tracker *ReplyTracker) <-chan ServerMessage {
	ch := make(chan ServerMessage, 1)
	go func() {
		defer close(ch)
		for {
			header := make([]byte, 32)
			if _, err := io.ReadFull(conn, header); err != nil {
				if err != io.EOF {
					debugf("X11: failed to read server message header: %v", err)
				}
				return
			}

			msgType := header[0]
			sequenceNumber := order.Uint16(header[2:4])

			debugf("X11 received server message: type=%d, sequence=%d", msgType, sequenceNumber)

			switch msgType {
			case 0:
				p, err := ParseError(header, order)
				if err != nil {
					debugf("X11 ReadServerMessages: ParseError(%x): %v", header, err)
					continue
				}
				ch <- p
			case 1:
				replyLength := 4 * order.Uint32(header[4:8])
				msg := append(header, make([]byte, replyLength)...)
				if _, err := io.ReadFull(conn, msg[32:]); err != nil {
					debugf("X11: failed to read remaining server message: %v", err)
					return
				}
				opcodes, ok := tracker.pop(sequenceNumber)
				if !ok {
					debugf("X11: unknown sequence number %d", sequenceNumber)
					continue
				}

				p, err := ParseReply(opcodes, msg, order)
				if err != nil {
					debugf("X11 ReadServerMessages: ParseReply(%x): %v", msg, err)
					continue
				}
				ch <- p
			default:
				p, err := ParseEvent(header, order)
				if err != nil {
					debugf("X11 ReadServerMessages: ParseEvent(%x): %v", header, err)
					continue
				}
				ch <- p
			}
		}
	}()

	return ch
}

// ParseReply parses a reply message based on the request opcode.
func ParseReply(opcodes Opcodes, msg []byte, order binary.ByteOrder) (ServerMessage, error) {
	switch opcodes.Major {
	case GetWindowAttributes:
		return ParseGetWindowAttributesReply(order, msg)
	case GetGeometry:
		return ParseGetGeometryReply(order, msg)
	case InternAtom:
		return ParseInternAtomReply(order, msg)
	case GetAtomName:
		return ParseGetAtomNameReply(order, msg)
	case GetProperty:
		return ParseGetPropertyReply(order, msg)
	case ListProperties:
		return ParseListPropertiesReply(order, msg)
	case QueryTextExtents:
		return ParseQueryTextExtentsReply(order, msg)
	case GetMotionEvents:
		return ParseGetMotionEventsReply(order, msg)
	case GetSelectionOwner:
		return ParseGetSelectionOwnerReply(order, msg)
	case GrabPointer:
		return ParseGrabPointerReply(order, msg)
	case GrabKeyboard:
		return ParseGrabKeyboardReply(order, msg)
	case QueryPointer:
		return ParseQueryPointerReply(order, msg)
	case TranslateCoords:
		return ParseTranslateCoordsReply(order, msg)
	case GetInputFocus:
		return ParseGetInputFocusReply(order, msg)
	case QueryFont:
		return ParseQueryFontReply(order, msg)
	case ListFonts:
		return ParseListFontsReply(order, msg)
	case GetImage:
		return ParseGetImageReply(order, msg)
	case AllocColor:
		return ParseAllocColorReply(order, msg)
	case AllocNamedColor:
		return ParseAllocNamedColorReply(order, msg)
	case ListInstalledColormaps:
		return ParseListInstalledColormapsReply(order, msg)
	case QueryColors:
		return ParseQueryColorsReply(order, msg)
	case LookupColor:
		return ParseLookupColorReply(order, msg)
	case QueryBestSize:
		return ParseQueryBestSizeReply(order, msg)
	case QueryExtension:
		return ParseQueryExtensionReply(order, msg)
	case GetKeyboardMapping:
		return ParseGetKeyboardMappingReply(order, msg)
	case GetKeyboardControl:
		return ParseGetKeyboardControlReply(order, msg)
	case GetPointerMapping:
		return ParseGetPointerMappingReply(order, msg)
	case SetPointerMapping:
		return ParseSetPointerMappingReply(order, msg)
	case GetModifierMapping:
		return ParseGetModifierMappingReply(order, msg)
	case SetModifierMapping:
		return ParseSetModifierMappingReply(order, msg)
	case GetScreenSaver:
		return ParseGetScreenSaverReply(order, msg)
	case ListHosts:
		return ParseListHostsReply(order, msg)
	case QueryKeymap:
		return ParseQueryKeymapReply(order, msg)
	case GetFontPath:
		return ParseGetFontPathReply(order, msg)
	case ListFontsWithInfo:
		return ParseListFontsWithInfoReply(order, msg)
	case QueryTree:
		return ParseQueryTreeReply(order, msg)
	case AllocColorCells:
		return ParseAllocColorCellsReply(order, msg)
	case AllocColorPlanes:
		return ParseAllocColorPlanesReply(order, msg)
	case ListExtensions:
		return ParseListExtensionsReply(order, msg)
	case GetPointerControl:
		return ParseGetPointerControlReply(order, msg)
	case XInputOpcode:
		return parseXInputReply(opcodes.Minor, order, msg)
	case BigRequestsOpcode:
		return &BigRequestsEnableReply{
			Sequence:         order.Uint16(msg[2:4]),
			MaxRequestLength: order.Uint32(msg[8:12]),
		}, nil
	default:
		return nil, NewError(RequestErrorCode, 0, 0, Opcodes{Major: opcodes.Major, Minor: 0})
	}
}

func parseXInputReply(minorOpcode uint8, order binary.ByteOrder, b []byte) (ServerMessage, error) {
	switch minorOpcode {
	case XGetExtensionVersion:
		return ParseGetExtensionVersionReply(order, b)
	case XListInputDevices:
		return ParseListInputDevicesReply(order, b)
	case XOpenDevice:
		return ParseOpenDeviceReply(order, b)
	case XCloseDevice:
		return ParseCloseDeviceReply(order, b)
	case XSetDeviceMode:
		return ParseSetDeviceModeReply(order, b)
	case XGetSelectedExtensionEvents:
		return ParseGetSelectedExtensionEventsReply(order, b)
	case XGetDeviceDontPropagateList:
		return ParseGetDeviceDontPropagateListReply(order, b)
	case XGetDeviceMotionEvents:
		return ParseGetDeviceMotionEventsReply(order, b)
	case XChangeKeyboardDevice:
		return ParseChangeKeyboardDeviceReply(order, b)
	case XChangePointerDevice:
		return ParseChangePointerDeviceReply(order, b)
	case XGrabDevice:
		return ParseGrabDeviceReply(order, b)
	case XGetDeviceFocus:
		return ParseGetDeviceFocusReply(order, b)
	case XGetFeedbackControl:
		return ParseGetFeedbackControlReply(order, b)
	case XGetDeviceKeyMapping:
		return ParseGetDeviceKeyMappingReply(order, b)
	case XGetDeviceModifierMapping:
		return ParseGetDeviceModifierMappingReply(order, b)
	case XSetDeviceModifierMapping:
		return ParseSetDeviceModifierMappingReply(order, b)
	case XGetDeviceButtonMapping:
		return ParseGetDeviceButtonMappingReply(order, b)
	case XSetDeviceButtonMapping:
		return ParseSetDeviceButtonMappingReply(order, b)
	case XQueryDeviceState:
		return ParseQueryDeviceStateReply(order, b)
	case XSetDeviceValuators:
		return ParseSetDeviceValuatorsReply(order, b)
	case XGetDeviceControl:
		return ParseGetDeviceControlReply(order, b)
	case XChangeDeviceControl:
		return ParseChangeDeviceControlReply(order, b)
	case XIQueryVersion:
		return ParseXIQueryVersionReply(order, b)
	case XIQueryPointer:
		return ParseXIQueryPointerReply(order, b)
	case XIGrabDevice:
		return ParseXIGrabDeviceReply(order, b)
	case XIPassiveGrabDevice:
		return ParseXIPassiveGrabDeviceReply(order, b)
	}
	return nil, NewError(RequestErrorCode, 0, 0, Opcodes{Major: XInputOpcode, Minor: minorOpcode})
}

// XCharInfo describes font character metrics.
type XCharInfo struct {
	LeftSideBearing  int16  // Left side bearing
	RightSideBearing int16  // Right side bearing
	CharacterWidth   uint16 // Character width
	Ascent           int16  // Ascent
	Descent          int16  // Descent
	Attributes       uint16 // Attributes
}

// BoolToByte converts a bool to a byte (1 for true, 0 for false).
func BoolToByte(b bool) byte {
	if b {
		return 1
	}
	return 0
}

// ByteToBool converts a byte to a bool (true if non-zero, false if zero).
func ByteToBool(b byte) bool {
	return b != 0
}

// GetWindowAttributesReply represents a reply to a GetWindowAttributes request.
type GetWindowAttributesReply struct {
	ReplyType          byte   // Always 1 for Reply
	BackingStore       byte   // Backing store hint
	Sequence           uint16 // Sequence number
	Length             uint32 // Reply length
	VisualID           uint32 // Visual ID
	Class              uint16 // Window class (InputOutput, InputOnly)
	BitGravity         byte   // Bit gravity
	WinGravity         byte   // Window gravity
	BackingPlanes      uint32 // Backing planes
	BackingPixel       uint32 // Backing pixel
	SaveUnder          byte   // Save under hint
	MapIsInstalled     byte   // True if map is installed
	MapState           byte   // Map state (Unmapped, Unviewable, Viewable)
	OverrideRedirect   byte   // Override redirect flag
	Colormap           uint32 // Colormap ID
	AllEventMasks      uint32 // Set of all selected events
	YourEventMask      uint32 // Set of events selected by this client
	DoNotPropagateMask uint16 // Set of events not propagated
}

// EncodeMessage encodes the GetWindowAttributesReply into a byte slice.
func (r *GetWindowAttributesReply) EncodeMessage(order binary.ByteOrder) []byte {
	reply := make([]byte, 44)
	reply[0] = 1 // Reply type
	reply[1] = r.BackingStore
	order.PutUint16(reply[2:4], r.Sequence)
	order.PutUint32(reply[4:8], 3) // Reply length (3 * 4 bytes = 12 bytes, plus 32 bytes header = 44 bytes total)
	order.PutUint32(reply[8:12], r.VisualID)
	order.PutUint16(reply[12:14], r.Class)
	reply[14] = r.BitGravity
	reply[15] = r.WinGravity
	order.PutUint32(reply[16:20], r.BackingPlanes)
	order.PutUint32(reply[20:24], r.BackingPixel)
	reply[24] = r.SaveUnder
	reply[25] = r.MapIsInstalled
	reply[26] = r.MapState
	reply[27] = r.OverrideRedirect
	order.PutUint32(reply[28:32], r.Colormap)
	order.PutUint32(reply[32:36], r.AllEventMasks)
	order.PutUint32(reply[36:40], r.YourEventMask)
	order.PutUint16(reply[40:42], r.DoNotPropagateMask)
	// reply[42:44] is padding
	return reply
}

// ParseGetWindowAttributesReply parses a GetWindowAttributes reply.
func ParseGetWindowAttributesReply(order binary.ByteOrder, b []byte) (*GetWindowAttributesReply, error) {
	if len(b) < 44 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	r := &GetWindowAttributesReply{
		ReplyType:          b[0],
		BackingStore:       b[1],
		Sequence:           order.Uint16(b[2:4]),
		Length:             order.Uint32(b[4:8]),
		VisualID:           order.Uint32(b[8:12]),
		Class:              order.Uint16(b[12:14]),
		BitGravity:         b[14],
		WinGravity:         b[15],
		BackingPlanes:      order.Uint32(b[16:20]),
		BackingPixel:       order.Uint32(b[20:24]),
		SaveUnder:          b[24],
		MapIsInstalled:     b[25],
		MapState:           b[26],
		OverrideRedirect:   b[27],
		Colormap:           order.Uint32(b[28:32]),
		AllEventMasks:      order.Uint32(b[32:36]),
		YourEventMask:      order.Uint32(b[36:40]),
		DoNotPropagateMask: order.Uint16(b[40:42]),
	}
	return r, nil
}

// GetGeometryReply represents a reply to a GetGeometry request.
type GetGeometryReply struct {
	Sequence      uint16 // Sequence number
	Depth         byte   // Depth of drawable
	Root          uint32 // Root window ID
	X, Y          int16  // Coordinates
	Width, Height uint16 // Dimensions
	BorderWidth   uint16 // Border width
}

// EncodeMessage encodes the GetGeometryReply into a byte slice.
func (r *GetGeometryReply) EncodeMessage(order binary.ByteOrder) []byte {
	reply := make([]byte, 32)
	reply[0] = 1 // Reply type
	reply[1] = r.Depth
	order.PutUint16(reply[2:4], r.Sequence)
	order.PutUint32(reply[4:8], 0) // Reply length (0 * 4 bytes = 0 bytes, plus 32 bytes header = 32 bytes total)
	order.PutUint32(reply[8:12], r.Root)
	order.PutUint16(reply[12:14], uint16(r.X))
	order.PutUint16(reply[14:16], uint16(r.Y))
	order.PutUint16(reply[16:18], r.Width)
	order.PutUint16(reply[18:20], r.Height)
	order.PutUint16(reply[20:22], r.BorderWidth)
	return reply
}

// ParseGetGeometryReply parses a GetGeometry reply.
func ParseGetGeometryReply(order binary.ByteOrder, b []byte) (*GetGeometryReply, error) {
	if len(b) < 32 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	r := &GetGeometryReply{
		Depth:       b[1],
		Sequence:    order.Uint16(b[2:4]),
		Root:        order.Uint32(b[8:12]),
		X:           int16(order.Uint16(b[12:14])),
		Y:           int16(order.Uint16(b[14:16])),
		Width:       order.Uint16(b[16:18]),
		Height:      order.Uint16(b[18:20]),
		BorderWidth: order.Uint16(b[20:22]),
	}
	return r, nil
}

// InternAtomReply represents a reply to an InternAtom request.
type InternAtomReply struct {
	Sequence uint16 // Sequence number
	Atom     uint32 // Atom ID
}

// EncodeMessage encodes the InternAtomReply into a byte slice.
func (r *InternAtomReply) EncodeMessage(order binary.ByteOrder) []byte {
	reply := make([]byte, 32)
	reply[0] = 1 // Reply type
	// byte 1 is unused
	order.PutUint16(reply[2:4], r.Sequence)
	order.PutUint32(reply[4:8], 0) // Reply length (0 * 4 bytes = 0 bytes, plus 32 bytes header = 32 bytes total)
	order.PutUint32(reply[8:12], r.Atom)
	// reply[12:32] is padding
	return reply
}

// ParseInternAtomReply parses an InternAtom reply.
func ParseInternAtomReply(order binary.ByteOrder, b []byte) (*InternAtomReply, error) {
	if len(b) < 32 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	r := &InternAtomReply{
		Sequence: order.Uint16(b[2:4]),
		Atom:     order.Uint32(b[8:12]),
	}
	return r, nil
}

// GetAtomNameReply represents a reply to a GetAtomName request.
type GetAtomNameReply struct {
	Sequence   uint16 // Sequence number
	NameLength uint16 // Length of name
	Name       string // Atom name
}

// EncodeMessage encodes the GetAtomNameReply into a byte slice.
func (r *GetAtomNameReply) EncodeMessage(order binary.ByteOrder) []byte {
	nameLen := len(r.Name)
	p := (4 - (nameLen % 4)) % 4
	reply := make([]byte, 32+nameLen+p)
	reply[0] = 1 // Reply type
	// byte 1 is unused
	order.PutUint16(reply[2:4], r.Sequence)
	order.PutUint32(reply[4:8], uint32((nameLen+p)/4)) // Reply length
	order.PutUint16(reply[8:10], uint16(nameLen))
	// reply[10:32] is padding
	copy(reply[32:], r.Name)
	return reply
}

// ParseGetAtomNameReply parses a GetAtomName reply.
func ParseGetAtomNameReply(order binary.ByteOrder, b []byte) (*GetAtomNameReply, error) {
	if len(b) < 32 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	nameLen := order.Uint16(b[8:10])
	if len(b) < 32+int(nameLen) {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	r := &GetAtomNameReply{
		Sequence:   order.Uint16(b[2:4]),
		NameLength: nameLen,
		Name:       string(b[32 : 32+nameLen]),
	}
	return r, nil
}

// GetPropertyReply represents a reply to a GetProperty request.
type GetPropertyReply struct {
	Sequence              uint16 // Sequence number
	Format                byte   // Property format (8, 16, or 32)
	PropertyType          uint32 // Type atom
	BytesAfter            uint32 // Number of bytes remaining
	ValueLenInFormatUnits uint32 // Length of value in format units
	Value                 []byte // Property value data
}

// EncodeMessage encodes the GetPropertyReply into a byte slice.
func (r *GetPropertyReply) EncodeMessage(order binary.ByteOrder) []byte {
	n := len(r.Value)
	p := (4 - (n % 4)) % 4
	replyLen := (n + p) / 4

	reply := make([]byte, 32+n+p)
	reply[0] = 1 // Reply type
	reply[1] = r.Format
	order.PutUint16(reply[2:4], r.Sequence)
	order.PutUint32(reply[4:8], uint32(replyLen)) // Reply length
	order.PutUint32(reply[8:12], r.PropertyType)
	order.PutUint32(reply[12:16], r.BytesAfter)
	order.PutUint32(reply[16:20], r.ValueLenInFormatUnits)
	// reply[20:32] is padding
	copy(reply[32:], r.Value)
	return reply
}

// ParseGetPropertyReply parses a GetProperty reply.
func ParseGetPropertyReply(order binary.ByteOrder, b []byte) (*GetPropertyReply, error) {
	if len(b) < 32 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	valLen := order.Uint32(b[4:8]) * 4
	if len(b) < 32+int(valLen) {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	r := &GetPropertyReply{
		Sequence:              order.Uint16(b[2:4]),
		Format:                b[1],
		PropertyType:          order.Uint32(b[8:12]),
		BytesAfter:            order.Uint32(b[12:16]),
		ValueLenInFormatUnits: order.Uint32(b[16:20]),
		Value:                 b[32 : 32+valLen],
	}
	return r, nil
}

// ListPropertiesReply represents a reply to a ListProperties request.
type ListPropertiesReply struct {
	Sequence      uint16   // Sequence number
	NumProperties uint16   // Number of properties
	Atoms         []uint32 // List of property atoms
}

// EncodeMessage encodes the ListPropertiesReply into a byte slice.
func (r *ListPropertiesReply) EncodeMessage(order binary.ByteOrder) []byte {
	numAtoms := len(r.Atoms)
	reply := make([]byte, 32+numAtoms*4)
	reply[0] = 1 // Reply type
	// byte 1 is unused
	order.PutUint16(reply[2:4], r.Sequence)
	order.PutUint32(reply[4:8], uint32(numAtoms)) // Reply length
	order.PutUint16(reply[8:10], uint16(numAtoms))
	// reply[10:32] is padding
	for i, atom := range r.Atoms {
		order.PutUint32(reply[32+i*4:], atom)
	}
	return reply
}

// ParseListPropertiesReply parses a ListProperties reply.
func ParseListPropertiesReply(order binary.ByteOrder, b []byte) (*ListPropertiesReply, error) {
	if len(b) < 32 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	numAtoms := order.Uint16(b[8:10])
	if len(b) < 32+int(numAtoms)*4 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	atoms := make([]uint32, numAtoms)
	for i := 0; i < int(numAtoms); i++ {
		atoms[i] = order.Uint32(b[32+i*4:])
	}
	r := &ListPropertiesReply{
		Sequence:      order.Uint16(b[2:4]),
		NumProperties: numAtoms,
		Atoms:         atoms,
	}
	return r, nil
}

// QueryTextExtentsReply represents a reply to a QueryTextExtents request.
type QueryTextExtentsReply struct {
	Sequence       uint16 // Sequence number
	DrawDirection  byte   // Draw direction
	FontAscent     int16  // Font ascent
	FontDescent    int16  // Font descent
	OverallAscent  int16  // Overall ascent
	OverallDescent int16  // Overall descent
	OverallWidth   int32  // Overall width
	OverallLeft    int32  // Overall left bearing
	OverallRight   int32  // Overall right bearing
}

// EncodeMessage encodes the QueryTextExtentsReply into a byte slice.
func (r *QueryTextExtentsReply) EncodeMessage(order binary.ByteOrder) []byte {
	reply := make([]byte, 32)
	reply[0] = 1 // Reply type
	reply[1] = r.DrawDirection
	order.PutUint16(reply[2:4], r.Sequence)
	order.PutUint32(reply[4:8], 0)
	order.PutUint16(reply[8:10], uint16(r.FontAscent))
	order.PutUint16(reply[10:12], uint16(r.FontDescent))
	order.PutUint16(reply[12:14], uint16(r.OverallAscent))
	order.PutUint16(reply[14:16], uint16(r.OverallDescent))
	order.PutUint32(reply[16:20], uint32(r.OverallWidth))
	order.PutUint32(reply[20:24], uint32(r.OverallLeft))
	order.PutUint32(reply[24:28], uint32(r.OverallRight))
	return reply
}

// ParseQueryTextExtentsReply parses a QueryTextExtents reply.
func ParseQueryTextExtentsReply(order binary.ByteOrder, b []byte) (*QueryTextExtentsReply, error) {
	if len(b) < 32 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	r := &QueryTextExtentsReply{
		Sequence:       order.Uint16(b[2:4]),
		DrawDirection:  b[1],
		FontAscent:     int16(order.Uint16(b[8:10])),
		FontDescent:    int16(order.Uint16(b[10:12])),
		OverallAscent:  int16(order.Uint16(b[12:14])),
		OverallDescent: int16(order.Uint16(b[14:16])),
		OverallWidth:   int32(order.Uint32(b[16:20])),
		OverallLeft:    int32(order.Uint32(b[20:24])),
		OverallRight:   int32(order.Uint32(b[24:28])),
	}
	return r, nil
}

// GetMotionEventsReply represents a reply to a GetMotionEvents request.
type GetMotionEventsReply struct {
	Sequence uint16      // Sequence number
	NEvents  uint32      // Number of events
	Events   []TimeCoord // List of time coordinates
}

// TimeCoord represents a time-coordinate pair in GetMotionEvents.
type TimeCoord struct {
	Time uint32 // Time
	X, Y int16  // Coordinates
}

// EncodeMessage encodes the GetMotionEventsReply into a byte slice.
func (r *GetMotionEventsReply) EncodeMessage(order binary.ByteOrder) []byte {
	reply := make([]byte, 32+len(r.Events)*8)
	reply[0] = 1 // Reply type
	order.PutUint16(reply[2:4], r.Sequence)
	order.PutUint32(reply[4:8], uint32(len(r.Events)*2))
	order.PutUint32(reply[8:12], r.NEvents)
	for i, event := range r.Events {
		order.PutUint32(reply[32+i*8:], event.Time)
		order.PutUint16(reply[32+i*8+4:], uint16(event.X))
		order.PutUint16(reply[32+i*8+6:], uint16(event.Y))
	}
	return reply
}

// ParseGetMotionEventsReply parses a GetMotionEvents reply.
func ParseGetMotionEventsReply(order binary.ByteOrder, b []byte) (*GetMotionEventsReply, error) {
	if len(b) < 32 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	nEvents := order.Uint32(b[8:12])
	if len(b) < 32+int(nEvents)*8 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	events := make([]TimeCoord, nEvents)
	for i := 0; i < int(nEvents); i++ {
		events[i] = TimeCoord{
			Time: order.Uint32(b[32+i*8:]),
			X:    int16(order.Uint16(b[32+i*8+4:])),
			Y:    int16(order.Uint16(b[32+i*8+6:])),
		}
	}
	r := &GetMotionEventsReply{
		Sequence: order.Uint16(b[2:4]),
		NEvents:  nEvents,
		Events:   events,
	}
	return r, nil
}

// GetSelectionOwnerReply represents a reply to a GetSelectionOwner request.
type GetSelectionOwnerReply struct {
	Sequence uint16 // Sequence number
	Owner    uint32 // Owner window ID
}

// EncodeMessage encodes the GetSelectionOwnerReply into a byte slice.
func (r *GetSelectionOwnerReply) EncodeMessage(order binary.ByteOrder) []byte {
	reply := make([]byte, 32)
	reply[0] = 1 // Reply type
	// byte 1 is unused
	order.PutUint16(reply[2:4], r.Sequence)
	order.PutUint32(reply[4:8], 0) // Reply length (0 * 4 bytes = 0 bytes, plus 32 bytes header = 32 bytes total)
	order.PutUint32(reply[8:12], r.Owner)
	// reply[12:32] is padding
	return reply
}

// ParseGetSelectionOwnerReply parses a GetSelectionOwner reply.
func ParseGetSelectionOwnerReply(order binary.ByteOrder, b []byte) (*GetSelectionOwnerReply, error) {
	if len(b) < 32 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	r := &GetSelectionOwnerReply{
		Sequence: order.Uint16(b[2:4]),
		Owner:    order.Uint32(b[8:12]),
	}
	return r, nil
}

// GrabPointerReply represents a reply to a GrabPointer request.
type GrabPointerReply struct {
	Sequence uint16 // Sequence number
	Status   byte   // Grab status
}

// EncodeMessage encodes the GrabPointerReply into a byte slice.
func (r *GrabPointerReply) EncodeMessage(order binary.ByteOrder) []byte {
	reply := make([]byte, 32)
	reply[0] = 1 // Reply type
	reply[1] = r.Status
	order.PutUint16(reply[2:4], r.Sequence)
	order.PutUint32(reply[4:8], 0) // Reply length (0 * 4 bytes = 0 bytes, plus 32 bytes header = 32 bytes total)
	// reply[8:32] is padding
	return reply
}

// ParseGrabPointerReply parses a GrabPointer reply.
func ParseGrabPointerReply(order binary.ByteOrder, b []byte) (*GrabPointerReply, error) {
	if len(b) < 32 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	r := &GrabPointerReply{
		Sequence: order.Uint16(b[2:4]),
		Status:   b[1],
	}
	return r, nil
}

// GrabKeyboardReply represents a reply to a GrabKeyboard request.
type GrabKeyboardReply struct {
	Sequence uint16 // Sequence number
	Status   byte   // Grab status
}

// EncodeMessage encodes the GrabKeyboardReply into a byte slice.
func (r *GrabKeyboardReply) EncodeMessage(order binary.ByteOrder) []byte {
	reply := make([]byte, 32)
	reply[0] = 1 // Reply type
	reply[1] = r.Status
	order.PutUint16(reply[2:4], r.Sequence)
	order.PutUint32(reply[4:8], 0) // Reply length (0 * 4 bytes = 0 bytes, plus 32 bytes header = 32 bytes total)
	// reply[8:32] is padding
	return reply
}

// ParseGrabKeyboardReply parses a GrabKeyboard reply.
func ParseGrabKeyboardReply(order binary.ByteOrder, b []byte) (*GrabKeyboardReply, error) {
	if len(b) < 32 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	r := &GrabKeyboardReply{
		Sequence: order.Uint16(b[2:4]),
		Status:   b[1],
	}
	return r, nil
}

// QueryPointerReply represents a reply to a QueryPointer request.
type QueryPointerReply struct {
	Sequence     uint16 // Sequence number
	SameScreen   bool   // Same screen flag
	Root         uint32 // Root window ID
	Child        uint32 // Child window ID
	RootX, RootY int16  // Root coordinates
	WinX, WinY   int16  // Window coordinates
	Mask         uint16 // Modifier mask
}

// EncodeMessage encodes the QueryPointerReply into a byte slice.
func (r *QueryPointerReply) EncodeMessage(order binary.ByteOrder) []byte {
	reply := make([]byte, 32)
	reply[0] = 1 // Reply type
	reply[1] = BoolToByte(r.SameScreen)
	order.PutUint16(reply[2:4], r.Sequence)
	order.PutUint32(reply[4:8], 0) // Reply length (0 * 4 bytes = 0 bytes, plus 32 bytes header = 32 bytes total)
	order.PutUint32(reply[8:12], r.Root)
	order.PutUint32(reply[12:16], r.Child)
	order.PutUint16(reply[16:18], uint16(r.RootX))
	order.PutUint16(reply[18:20], uint16(r.RootY))
	order.PutUint16(reply[20:22], uint16(r.WinX))
	order.PutUint16(reply[22:24], uint16(r.WinY))
	order.PutUint16(reply[24:26], r.Mask)
	// reply[26:32] is padding
	return reply
}

// ParseQueryPointerReply parses a QueryPointer reply.
func ParseQueryPointerReply(order binary.ByteOrder, b []byte) (*QueryPointerReply, error) {
	if len(b) < 32 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	r := &QueryPointerReply{
		Sequence:   order.Uint16(b[2:4]),
		SameScreen: b[1] != 0,
		Root:       order.Uint32(b[8:12]),
		Child:      order.Uint32(b[12:16]),
		RootX:      int16(order.Uint16(b[16:18])),
		RootY:      int16(order.Uint16(b[18:20])),
		WinX:       int16(order.Uint16(b[20:22])),
		WinY:       int16(order.Uint16(b[22:24])),
		Mask:       order.Uint16(b[24:26]),
	}
	return r, nil
}

// TranslateCoordsReply represents a reply to a TranslateCoords request.
type TranslateCoordsReply struct {
	Sequence   uint16 // Sequence number
	SameScreen bool   // Same screen flag
	Child      uint32 // Child window ID
	DstX, DstY int16  // Destination coordinates
}

// EncodeMessage encodes the TranslateCoordsReply into a byte slice.
func (r *TranslateCoordsReply) EncodeMessage(order binary.ByteOrder) []byte {
	reply := make([]byte, 32)
	reply[0] = 1 // Reply type
	reply[1] = BoolToByte(r.SameScreen)
	order.PutUint16(reply[2:4], r.Sequence)
	order.PutUint32(reply[4:8], 0) // Reply length (0 * 4 bytes = 0 bytes, plus 32 bytes header = 32 bytes total)
	order.PutUint32(reply[8:12], r.Child)
	order.PutUint16(reply[12:14], uint16(r.DstX))
	order.PutUint16(reply[14:16], uint16(r.DstY))
	// reply[16:32] is padding
	return reply
}

// ParseTranslateCoordsReply parses a TranslateCoords reply.
func ParseTranslateCoordsReply(order binary.ByteOrder, b []byte) (*TranslateCoordsReply, error) {
	if len(b) < 32 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	r := &TranslateCoordsReply{
		Sequence:   order.Uint16(b[2:4]),
		SameScreen: b[1] != 0,
		Child:      order.Uint32(b[8:12]),
		DstX:       int16(order.Uint16(b[12:14])),
		DstY:       int16(order.Uint16(b[14:16])),
	}
	return r, nil
}

// GetInputFocusReply represents a reply to a GetInputFocus request.
type GetInputFocusReply struct {
	Sequence uint16 // Sequence number
	RevertTo byte   // RevertTo mode
	Focus    uint32 // Focus window ID
}

// EncodeMessage encodes the GetInputFocusReply into a byte slice.
func (r *GetInputFocusReply) EncodeMessage(order binary.ByteOrder) []byte {
	reply := make([]byte, 32)
	reply[0] = 1 // Reply type
	reply[1] = r.RevertTo
	order.PutUint16(reply[2:4], r.Sequence)
	order.PutUint32(reply[4:8], 0) // Reply length (0 * 4 bytes = 0 bytes, plus 32 bytes header = 32 bytes total)
	order.PutUint32(reply[8:12], r.Focus)
	// reply[12:32] is padding
	return reply
}

// ParseGetInputFocusReply parses a GetInputFocus reply.
func ParseGetInputFocusReply(order binary.ByteOrder, b []byte) (*GetInputFocusReply, error) {
	if len(b) < 32 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	r := &GetInputFocusReply{
		Sequence: order.Uint16(b[2:4]),
		RevertTo: b[1],
		Focus:    order.Uint32(b[8:12]),
	}
	return r, nil
}

// QueryFontReply represents a reply to a QueryFont request.
type QueryFontReply struct {
	Sequence       uint16      // Sequence number
	MinBounds      XCharInfo   // Minimum bounds
	MaxBounds      XCharInfo   // Maximum bounds
	MinCharOrByte2 uint16      // Minimum character or byte 2
	MaxCharOrByte2 uint16      // Maximum character or byte 2
	DefaultChar    uint16      // Default character
	NumFontProps   uint16      // Number of font properties
	DrawDirection  uint8       // Draw direction
	MinByte1       uint8       // Minimum byte 1
	MaxByte1       uint8       // Maximum byte 1
	AllCharsExist  bool        // All characters exist flag
	FontAscent     int16       // Font ascent
	FontDescent    int16       // Font descent
	NumCharInfos   uint32      // Number of character infos
	CharInfos      []XCharInfo // Character infos
	FontProps      []FontProp  // Font properties
}

// EncodeMessage encodes the QueryFontReply into a byte slice.
func (r *QueryFontReply) EncodeMessage(order binary.ByteOrder) []byte {
	numFontProps := len(r.FontProps)
	numCharInfos := len(r.CharInfos)

	reply := make([]byte, 60+8*numFontProps+12*numCharInfos)
	reply[0] = 1 // Reply
	reply[1] = 1 // font-info-present (True)
	order.PutUint16(reply[2:4], r.Sequence)
	order.PutUint32(reply[4:8], uint32(7+2*numFontProps+3*numCharInfos)) // Reply length

	// min-bounds
	order.PutUint16(reply[8:10], uint16(r.MinBounds.LeftSideBearing))
	order.PutUint16(reply[10:12], uint16(r.MinBounds.RightSideBearing))
	order.PutUint16(reply[12:14], uint16(r.MinBounds.CharacterWidth))
	order.PutUint16(reply[14:16], uint16(r.MinBounds.Ascent))
	order.PutUint16(reply[16:18], uint16(r.MinBounds.Descent))
	order.PutUint16(reply[18:20], r.MinBounds.Attributes)

	// max-bounds
	order.PutUint16(reply[24:26], uint16(r.MaxBounds.LeftSideBearing))
	order.PutUint16(reply[26:28], uint16(r.MaxBounds.RightSideBearing))
	order.PutUint16(reply[28:30], uint16(r.MaxBounds.CharacterWidth))
	order.PutUint16(reply[30:32], uint16(r.MaxBounds.Ascent))
	order.PutUint16(reply[32:34], uint16(r.MaxBounds.Descent))
	order.PutUint16(reply[34:36], r.MaxBounds.Attributes)

	order.PutUint16(reply[40:42], r.MinCharOrByte2)
	order.PutUint16(reply[42:44], r.MaxCharOrByte2)
	order.PutUint16(reply[44:46], r.DefaultChar)
	order.PutUint16(reply[46:48], uint16(numFontProps))

	reply[48] = r.DrawDirection & 0x1
	reply[49] = r.MinByte1
	reply[50] = r.MaxByte1
	reply[51] = BoolToByte(r.AllCharsExist)

	order.PutUint16(reply[52:54], uint16(r.FontAscent))
	order.PutUint16(reply[54:56], uint16(r.FontDescent))

	order.PutUint32(reply[56:60], uint32(len(r.CharInfos)))

	offset := 60
	for _, prop := range r.FontProps {
		order.PutUint32(reply[offset:], prop.Name)
		order.PutUint32(reply[offset+4:], prop.Value)
		offset += 8
	}
	for _, ci := range r.CharInfos {
		order.PutUint16(reply[offset:offset+2], uint16(ci.LeftSideBearing))
		order.PutUint16(reply[offset+2:offset+4], uint16(ci.RightSideBearing))
		order.PutUint16(reply[offset+4:offset+6], uint16(ci.CharacterWidth))
		order.PutUint16(reply[offset+6:offset+8], uint16(ci.Ascent))
		order.PutUint16(reply[offset+8:offset+10], uint16(ci.Descent))
		order.PutUint16(reply[offset+10:offset+12], ci.Attributes)
		offset += 12
	}
	return reply
}

// ParseQueryFontReply parses a QueryFont reply.
func ParseQueryFontReply(order binary.ByteOrder, b []byte) (*QueryFontReply, error) {
	if len(b) < 60 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	numFontProps := order.Uint16(b[46:48])
	numCharInfos := order.Uint32(b[56:60])
	if len(b) < 60+8*int(numFontProps)+12*int(numCharInfos) {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	var charInfos []XCharInfo
	if numCharInfos > 0 {
		charInfos = make([]XCharInfo, numCharInfos)
		offset := 60 + 8*int(numFontProps)
		for i := 0; i < int(numCharInfos); i++ {
			charInfos[i] = XCharInfo{
				LeftSideBearing:  int16(order.Uint16(b[offset:])),
				RightSideBearing: int16(order.Uint16(b[offset+2:])),
				CharacterWidth:   order.Uint16(b[offset+4:]),
				Ascent:           int16(order.Uint16(b[offset+6:])),
				Descent:          int16(order.Uint16(b[offset+8:])),
				Attributes:       order.Uint16(b[offset+10:]),
			}
			offset += 12
		}
	}

	var fontProps []FontProp
	if numFontProps > 0 {
		fontProps = make([]FontProp, numFontProps)
		offset := 60
		for i := 0; i < int(numFontProps); i++ {
			fontProps[i] = FontProp{
				Name:  order.Uint32(b[offset:]),
				Value: order.Uint32(b[offset+4:]),
			}
			offset += 8
		}
	}

	r := &QueryFontReply{
		Sequence: order.Uint16(b[2:4]),
		MinBounds: XCharInfo{
			LeftSideBearing:  int16(order.Uint16(b[8:10])),
			RightSideBearing: int16(order.Uint16(b[10:12])),
			CharacterWidth:   order.Uint16(b[12:14]),
			Ascent:           int16(order.Uint16(b[14:16])),
			Descent:          int16(order.Uint16(b[16:18])),
			Attributes:       order.Uint16(b[18:20]),
		},
		MaxBounds: XCharInfo{
			LeftSideBearing:  int16(order.Uint16(b[24:26])),
			RightSideBearing: int16(order.Uint16(b[26:28])),
			CharacterWidth:   order.Uint16(b[28:30]),
			Ascent:           int16(order.Uint16(b[30:32])),
			Descent:          int16(order.Uint16(b[32:34])),
			Attributes:       order.Uint16(b[34:36]),
		},
		MinCharOrByte2: order.Uint16(b[40:42]),
		MaxCharOrByte2: order.Uint16(b[42:44]),
		DefaultChar:    order.Uint16(b[44:46]),
		NumFontProps:   order.Uint16(b[46:48]),
		DrawDirection:  b[48],
		MinByte1:       b[49],
		MaxByte1:       b[50],
		AllCharsExist:  b[51] != 0,
		FontAscent:     int16(order.Uint16(b[52:54])),
		FontDescent:    int16(order.Uint16(b[54:56])),
		NumCharInfos:   numCharInfos,
		CharInfos:      charInfos,
		FontProps:      fontProps,
	}
	return r, nil
}

// ListFontsReply represents a reply to a ListFonts request.
type ListFontsReply struct {
	Sequence  uint16   // Sequence number
	FontNames []string // List of font names
}

// EncodeMessage encodes the ListFontsReply into a byte slice.
func (r *ListFontsReply) EncodeMessage(order binary.ByteOrder) []byte {
	var namesData []byte
	for _, name := range r.FontNames {
		namesData = append(namesData, byte(len(name)))
		namesData = append(namesData, []byte(name)...)
	}

	namesSize := len(namesData)
	padSize := (4 - (namesSize % 4)) % 4

	reply := make([]byte, 32+namesSize+padSize)
	reply[0] = 1 // Reply
	// byte 1 is unused
	order.PutUint16(reply[2:4], r.Sequence)
	order.PutUint32(reply[4:8], uint32((namesSize+padSize)/4)) // Reply length
	order.PutUint16(reply[8:10], uint16(len(r.FontNames)))
	// reply[10:32] is padding
	copy(reply[32:], namesData)
	return reply
}

// ParseListFontsReply parses a ListFonts reply.
func ParseListFontsReply(order binary.ByteOrder, b []byte) (*ListFontsReply, error) {
	if len(b) < 32 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	numFonts := order.Uint16(b[8:10])
	fontNames := make([]string, numFonts)
	offset := 32
	for i := 0; i < int(numFonts); i++ {
		if len(b) < offset+1 {
			return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
		}
		length := int(b[offset])
		if len(b) < offset+1+length {
			return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
		}
		fontNames[i] = string(b[offset+1 : offset+1+length])
		offset += 1 + length
	}
	r := &ListFontsReply{
		Sequence:  order.Uint16(b[2:4]),
		FontNames: fontNames,
	}
	return r, nil
}

// GetImageReply represents a reply to a GetImage request.
type GetImageReply struct {
	Sequence  uint16 // Sequence number
	Depth     byte   // Image depth
	VisualID  uint32 // Visual ID
	ImageData []byte // Image data
}

// EncodeMessage encodes the GetImageReply into a byte slice.
func (r *GetImageReply) EncodeMessage(order binary.ByteOrder) []byte {
	reply := make([]byte, 32+len(r.ImageData))
	reply[0] = 1 // Reply type
	reply[1] = r.Depth
	order.PutUint16(reply[2:4], r.Sequence)
	order.PutUint32(reply[4:8], uint32(len(r.ImageData)/4)) // Reply length
	order.PutUint32(reply[8:12], r.VisualID)
	// reply[12:32] is padding
	copy(reply[32:], r.ImageData)
	return reply
}

// ParseGetImageReply parses a GetImage reply.
func ParseGetImageReply(order binary.ByteOrder, b []byte) (*GetImageReply, error) {
	if len(b) < 32 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	length := order.Uint32(b[4:8]) * 4
	if len(b) < 32+int(length) {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	r := &GetImageReply{
		Sequence:  order.Uint16(b[2:4]),
		Depth:     b[1],
		VisualID:  order.Uint32(b[8:12]),
		ImageData: b[32 : 32+length],
	}
	return r, nil
}

// AllocColorReply represents a reply to an AllocColor request.
type AllocColorReply struct {
	Sequence uint16 // Sequence number
	Red      uint16 // Allocated Red
	Green    uint16 // Allocated Green
	Blue     uint16 // Allocated Blue
	Pixel    uint32 // Pixel value
}

// EncodeMessage encodes the AllocColorReply into a byte slice.
func (r *AllocColorReply) EncodeMessage(order binary.ByteOrder) []byte {
	reply := make([]byte, 32)
	reply[0] = 1 // Reply type
	// byte 1 is unused
	order.PutUint16(reply[2:4], r.Sequence)
	order.PutUint32(reply[4:8], 0) // Reply length (0 * 4 bytes = 0 bytes, plus 32 bytes header = 32 bytes total)
	order.PutUint16(reply[8:10], r.Red)
	order.PutUint16(reply[10:12], r.Green)
	order.PutUint16(reply[12:14], r.Blue)
	// reply[14:16] is padding
	order.PutUint32(reply[16:20], r.Pixel)
	// reply[20:32] is padding
	return reply
}

// ParseAllocColorReply parses an AllocColor reply.
func ParseAllocColorReply(order binary.ByteOrder, b []byte) (*AllocColorReply, error) {
	if len(b) < 32 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	r := &AllocColorReply{
		Sequence: order.Uint16(b[2:4]),
		Red:      order.Uint16(b[8:10]),
		Green:    order.Uint16(b[10:12]),
		Blue:     order.Uint16(b[12:14]),
		Pixel:    order.Uint32(b[16:20]),
	}
	return r, nil
}

// AllocNamedColorReply represents a reply to an AllocNamedColor request.
type AllocNamedColorReply struct {
	Sequence   uint16 // Sequence number
	Red        uint16 // Visual red
	Green      uint16 // Visual green
	Blue       uint16 // Visual blue
	ExactRed   uint16 // Exact red
	ExactGreen uint16 // Exact green
	ExactBlue  uint16 // Exact blue
	Pixel      uint32 // Pixel value
}

// EncodeMessage encodes the AllocNamedColorReply into a byte slice.
func (r *AllocNamedColorReply) EncodeMessage(order binary.ByteOrder) []byte {
	reply := make([]byte, 32)
	reply[0] = 1 // Reply type
	// byte 1 is unused
	order.PutUint16(reply[2:4], r.Sequence)
	order.PutUint32(reply[4:8], 0) // Reply length (0 * 4 bytes = 0 bytes, plus 32 bytes header = 32 bytes total)
	order.PutUint32(reply[8:12], r.Pixel)
	order.PutUint16(reply[12:14], r.ExactRed)
	order.PutUint16(reply[14:16], r.ExactGreen)
	order.PutUint16(reply[16:18], r.ExactBlue)
	order.PutUint16(reply[18:20], r.Red)
	order.PutUint16(reply[20:22], r.Green)
	order.PutUint16(reply[22:24], r.Blue)
	return reply
}

// ParseAllocNamedColorReply parses an AllocNamedColor reply.
func ParseAllocNamedColorReply(order binary.ByteOrder, b []byte) (*AllocNamedColorReply, error) {
	if len(b) < 32 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	r := &AllocNamedColorReply{
		Sequence:   order.Uint16(b[2:4]),
		Pixel:      order.Uint32(b[8:12]),
		ExactRed:   order.Uint16(b[12:14]),
		ExactGreen: order.Uint16(b[14:16]),
		ExactBlue:  order.Uint16(b[16:18]),
		Red:        order.Uint16(b[18:20]),
		Green:      order.Uint16(b[20:22]),
		Blue:       order.Uint16(b[22:24]),
	}
	return r, nil
}

// ListInstalledColormapsReply represents a reply to a ListInstalledColormaps request.
type ListInstalledColormapsReply struct {
	Sequence     uint16   // Sequence number
	NumColormaps uint16   // Number of colormaps
	Colormaps    []uint32 // List of colormap IDs
}

// EncodeMessage encodes the ListInstalledColormapsReply into a byte slice.
func (r *ListInstalledColormapsReply) EncodeMessage(order binary.ByteOrder) []byte {
	nColormaps := len(r.Colormaps)
	reply := make([]byte, 32+nColormaps*4)
	reply[0] = 1 // Reply
	// byte 1 is unused
	order.PutUint16(reply[2:4], r.Sequence)
	order.PutUint32(reply[4:8], uint32(nColormaps)) // length
	order.PutUint16(reply[8:10], uint16(nColormaps))
	// reply[10:32] is padding
	for i, cmap := range r.Colormaps {
		order.PutUint32(reply[32+i*4:], cmap)
	}
	return reply
}

// ParseListInstalledColormapsReply parses a ListInstalledColormaps reply.
func ParseListInstalledColormapsReply(order binary.ByteOrder, b []byte) (*ListInstalledColormapsReply, error) {
	if len(b) < 32 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	numColormaps := order.Uint16(b[8:10])
	if len(b) < 32+int(numColormaps)*4 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	colormaps := make([]uint32, numColormaps)
	for i := 0; i < int(numColormaps); i++ {
		colormaps[i] = order.Uint32(b[32+i*4:])
	}
	r := &ListInstalledColormapsReply{
		Sequence:     order.Uint16(b[2:4]),
		NumColormaps: numColormaps,
		Colormaps:    colormaps,
	}
	return r, nil
}

// QueryColorsReply represents a reply to a QueryColors request.
type QueryColorsReply struct {
	Sequence uint16       // Sequence number
	Colors   []XColorItem // List of color items
}

// EncodeMessage encodes the QueryColorsReply into a byte slice.
func (r *QueryColorsReply) EncodeMessage(order binary.ByteOrder) []byte {
	numColors := len(r.Colors)
	replies := make([]byte, numColors*8)
	for i, color := range r.Colors {
		order.PutUint16(replies[i*8:], color.Red)
		order.PutUint16(replies[i*8+2:], color.Green)
		order.PutUint16(replies[i*8+4:], color.Blue)
		// replies[i*8+6:i*8+8] unused
	}

	reply := make([]byte, 32+len(replies))
	reply[0] = 1 // Reply
	// byte 1 is unused
	order.PutUint16(reply[2:4], r.Sequence)
	order.PutUint32(reply[4:8], uint32(len(replies)/4)) // Reply length
	order.PutUint16(reply[8:10], uint16(numColors))
	// reply[10:32] is padding
	copy(reply[32:], replies)
	return reply
}

// ParseQueryColorsReply parses a QueryColors reply.
func ParseQueryColorsReply(order binary.ByteOrder, b []byte) (*QueryColorsReply, error) {
	if len(b) < 32 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	numColors := order.Uint16(b[8:10])
	if len(b) < 32+int(numColors)*8 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	colors := make([]XColorItem, numColors)
	for i := 0; i < int(numColors); i++ {
		colors[i] = XColorItem{
			Red:   order.Uint16(b[32+i*8:]),
			Green: order.Uint16(b[32+i*8+2:]),
			Blue:  order.Uint16(b[32+i*8+4:]),
		}
	}
	r := &QueryColorsReply{
		Sequence: order.Uint16(b[2:4]),
		Colors:   colors,
	}
	return r, nil
}

// LookupColorReply represents a reply to a LookupColor request.
type LookupColorReply struct {
	Sequence   uint16 // Sequence number
	Red        uint16 // Visual red
	Green      uint16 // Visual green
	Blue       uint16 // Visual blue
	ExactRed   uint16 // Exact red
	ExactGreen uint16 // Exact green
	ExactBlue  uint16 // Exact blue
}

// EncodeMessage encodes the LookupColorReply into a byte slice.
func (r *LookupColorReply) EncodeMessage(order binary.ByteOrder) []byte {
	reply := make([]byte, 32)
	reply[0] = 1 // Reply type
	// byte 1 is unused
	order.PutUint16(reply[2:4], r.Sequence)
	order.PutUint32(reply[4:8], 0) // Reply length (0 * 4 bytes = 0 bytes, plus 32 bytes header = 32 bytes total)
	order.PutUint16(reply[8:10], r.Red)
	order.PutUint16(reply[10:12], r.Green)
	order.PutUint16(reply[12:14], r.Blue)
	order.PutUint16(reply[14:16], r.ExactRed)
	order.PutUint16(reply[16:18], r.ExactGreen)
	order.PutUint16(reply[18:20], r.ExactBlue)
	// reply[20:32] is padding
	return reply
}

// ParseLookupColorReply parses a LookupColor reply.
func ParseLookupColorReply(order binary.ByteOrder, b []byte) (*LookupColorReply, error) {
	if len(b) < 32 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	r := &LookupColorReply{
		Sequence:   order.Uint16(b[2:4]),
		Red:        order.Uint16(b[8:10]),
		Green:      order.Uint16(b[10:12]),
		Blue:       order.Uint16(b[12:14]),
		ExactRed:   order.Uint16(b[14:16]),
		ExactGreen: order.Uint16(b[16:18]),
		ExactBlue:  order.Uint16(b[18:20]),
	}
	return r, nil
}

// QueryBestSizeReply represents a reply to a QueryBestSize request.
type QueryBestSizeReply struct {
	Sequence uint16 // Sequence number
	Width    uint16 // Best width
	Height   uint16 // Best height
}

// EncodeMessage encodes the QueryBestSizeReply into a byte slice.
func (r *QueryBestSizeReply) EncodeMessage(order binary.ByteOrder) []byte {
	reply := make([]byte, 32)
	reply[0] = 1 // Reply type
	// byte 1 is unused
	order.PutUint16(reply[2:4], r.Sequence)
	order.PutUint32(reply[4:8], 0) // Reply length (0 * 4 bytes = 0 bytes, plus 32 bytes header = 32 bytes total)
	order.PutUint16(reply[8:10], r.Width)
	order.PutUint16(reply[10:12], r.Height)
	// reply[12:32] is padding
	return reply
}

// ParseQueryBestSizeReply parses a QueryBestSize reply.
func ParseQueryBestSizeReply(order binary.ByteOrder, b []byte) (*QueryBestSizeReply, error) {
	if len(b) < 32 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	r := &QueryBestSizeReply{
		Sequence: order.Uint16(b[2:4]),
		Width:    order.Uint16(b[8:10]),
		Height:   order.Uint16(b[10:12]),
	}
	return r, nil
}

// QueryExtensionReply represents a reply to a QueryExtension request.
type QueryExtensionReply struct {
	Sequence    uint16 // Sequence number
	Present     bool   // Present flag
	MajorOpcode byte   // Major opcode
	FirstEvent  byte   // First event code
	FirstError  byte   // First error code
}

// EncodeMessage encodes the QueryExtensionReply into a byte slice.
func (r *QueryExtensionReply) EncodeMessage(order binary.ByteOrder) []byte {
	reply := make([]byte, 32)
	reply[0] = 1 // Reply type
	order.PutUint16(reply[2:4], r.Sequence)
	order.PutUint32(reply[4:8], 0) // Reply length (0 * 4 bytes = 0 bytes, plus 32 bytes header = 32 bytes total)
	reply[8] = BoolToByte(r.Present)
	reply[9] = r.MajorOpcode
	reply[10] = r.FirstEvent
	reply[11] = r.FirstError
	// reply[12:32] is padding
	return reply
}

// ParseQueryExtensionReply parses a QueryExtension reply.
func ParseQueryExtensionReply(order binary.ByteOrder, b []byte) (*QueryExtensionReply, error) {
	if len(b) < 32 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	r := &QueryExtensionReply{
		Sequence:    order.Uint16(b[2:4]),
		Present:     b[8] != 0,
		MajorOpcode: b[9],
		FirstEvent:  b[10],
		FirstError:  b[11],
	}
	return r, nil
}

// SetupResponse implements messageEncoder for the X11 setup response.
type SetupResponse struct {
	Success                  byte     // Success flag (1 = success)
	Reason                   string   // Reason for failure
	ProtocolVersion          uint16   // Protocol major version
	ReleaseNumber            uint32   // Release number
	ResourceIDBase           uint32   // Resource ID base
	ResourceIDMask           uint32   // Resource ID mask
	MotionBufferSize         uint32   // Motion buffer size
	VendorLength             uint16   // Vendor string length
	MaxRequestLength         uint16   // Maximum request length
	NumScreens               uint8    // Number of screens
	NumPixmapFormats         uint8    // Number of pixmap formats
	ImageByteOrder           uint8    // Image byte order
	BitmapFormatBitOrder     byte     // Bitmap bit order
	BitmapFormatScanlineUnit byte     // Bitmap scanline unit
	BitmapFormatScanlinePad  byte     // Bitmap scanline pad
	MinKeycode               uint8    // Minimum keycode
	MaxKeycode               uint8    // Maximum keycode
	VendorString             string   // Vendor string
	PixmapFormats            []Format // Pixmap formats
	Screens                  []Screen // Screens
	Data                     *Setup
}

// EncodeMessage encodes the SetupResponse into a byte slice.
func (r *SetupResponse) EncodeMessage(order binary.ByteOrder) []byte {
	if r.Success == 0 {
		reasonLen := len(r.Reason)
		paddedLen := (reasonLen + 3) &^ 3
		response := make([]byte, 8+paddedLen)
		response[0] = 0 // Failure
		response[1] = byte(reasonLen)
		order.PutUint16(response[2:4], 11) // Protocol Major
		order.PutUint16(response[4:6], 0)  // Protocol Minor
		order.PutUint16(response[6:8], uint16(paddedLen/4))
		copy(response[8:], []byte(r.Reason))
		return response
	}
	setupData := r.Data.marshal(order)
	response := make([]byte, 8+len(setupData))
	response[0] = r.Success
	// byte 1 is unused
	order.PutUint16(response[2:4], 11) // Protocol Major
	order.PutUint16(response[4:6], 0)  // Protocol Minor
	order.PutUint16(response[6:8], uint16(len(setupData)/4))
	copy(response[8:], setupData)
	return response
}

// Setup contains information about the X server setup.
type Setup struct {
	ReleaseNumber            uint32   // Release number
	ResourceIDBase           uint32   // Resource ID base
	ResourceIDMask           uint32   // Resource ID mask
	MotionBufferSize         uint32   // Motion buffer size
	VendorLength             uint16   // Vendor string length
	MaxRequestLength         uint16   // Maximum request length
	NumScreens               uint8    // Number of screens
	NumPixmapFormats         uint8    // Number of pixmap formats
	ImageByteOrder           uint8    // Image byte order
	BitmapFormatBitOrder     uint8    // Bitmap bit order
	BitmapFormatScanlineUnit uint8    // Bitmap scanline unit
	BitmapFormatScanlinePad  uint8    // Bitmap scanline pad
	MinKeycode               uint8    // Minimum keycode
	MaxKeycode               uint8    // Maximum keycode
	VendorString             string   // Vendor string
	PixmapFormats            []Format // Pixmap formats
	Screens                  []Screen // Screens
}

// Format describes a pixmap format.
type Format struct {
	Depth        uint8 // Depth
	BitsPerPixel uint8 // Bits per pixel
	ScanlinePad  uint8 // Scanline pad
}

// Screen describes a screen.
type Screen struct {
	Root                uint32       // Root window ID
	DefaultColormap     uint32       // Default colormap ID
	WhitePixel          uint32       // White pixel value
	BlackPixel          uint32       // Black pixel value
	CurrentInputMasks   uint32       // Current input masks
	WidthInPixels       uint16       // Width in pixels
	HeightInPixels      uint16       // Height in pixels
	WidthInMillimeters  uint16       // Width in millimeters
	HeightInMillimeters uint16       // Height in millimeters
	MinInstalledMaps    uint16       // Minimum installed colormaps
	MaxInstalledMaps    uint16       // Maximum installed colormaps
	RootVisual          uint32       // Root visual ID
	BackingStores       uint8        // Backing stores
	SaveUnders          bool         // Save unders flag
	RootDepth           uint8        // Root depth
	NumDepths           uint8        // Number of depths
	Depths              []Depth      // Depths
}

// Depth describes a depth and its visuals.
type Depth struct {
	Depth      uint8        // Depth
	NumVisuals uint16       // Number of visuals
	Visuals    []VisualType // Visuals
}

// VisualType describes a visual type.
type VisualType struct {
	VisualID        uint32 // Visual ID
	Class           uint8  // Class
	BitsPerRGBValue uint8  // Bits per RGB value
	ColormapEntries uint16 // Colormap entries
	RedMask         uint32 // Red mask
	GreenMask       uint32 // Green mask
	BlueMask        uint32 // Blue mask
	Depth           byte   // Internal depth (not part of the wire protocol VISUALTYPE structure)
}

// NewDefaultSetup creates a default Setup structure.
func NewDefaultSetup(config *ServerConfig) *Setup {
	s := &Setup{
		ReleaseNumber:            1,
		ResourceIDBase:           0,
		ResourceIDMask:           0x1FFFFF,
		MotionBufferSize:         256,
		VendorLength:             uint16(len(config.Vendor)),
		MaxRequestLength:         0xFFFF,
		NumScreens:               1,
		NumPixmapFormats:         6,
		ImageByteOrder:           0, // LSBFirst
		BitmapFormatBitOrder:     0, // LeastSignificant
		BitmapFormatScanlineUnit: 8,
		BitmapFormatScanlinePad:  8,
		MinKeycode:               8,
		MaxKeycode:               255,
		VendorString:             config.Vendor,
		PixmapFormats: []Format{
			{
				Depth:        1,
				BitsPerPixel: 1,
				ScanlinePad:  8,
			},
			{
				Depth:        4,
				BitsPerPixel: 4,
				ScanlinePad:  8,
			},
			{
				Depth:        8,
				BitsPerPixel: 8,
				ScanlinePad:  8,
			},
			{
				Depth:        16,
				BitsPerPixel: 16,
				ScanlinePad:  16,
			},
			{
				Depth:        24,
				BitsPerPixel: 32,
				ScanlinePad:  32,
			},
			{
				Depth:        32,
				BitsPerPixel: 32,
				ScanlinePad:  32,
			},
		},

		Screens: []Screen{
			{
				Root:                0,
				DefaultColormap:     1,
				WhitePixel:          0xffffff,
				BlackPixel:          0x000000,
				CurrentInputMasks:   0,
				WidthInPixels:       config.ScreenWidth,
				HeightInPixels:      config.ScreenHeight,
				WidthInMillimeters:  uint16(float64(config.ScreenWidth) * 25.4 / 96),
				HeightInMillimeters: uint16(float64(config.ScreenHeight) * 25.4 / 96),
				MinInstalledMaps:    1,
				MaxInstalledMaps:    1,
				RootVisual:          0x1,
				BackingStores:       2, // Always
				SaveUnders:          false,
				RootDepth:           24,
				NumDepths:           2,
				Depths: []Depth{
					{
						Depth:      1,
						NumVisuals: 1,
						Visuals: []VisualType{
							{
								VisualID:        0x2,
								Class:           0, // StaticGray
								BitsPerRGBValue: 1,
								ColormapEntries: 2,
								RedMask:         0,
								GreenMask:       0,
								BlueMask:        0,
							},
						},
					},
					{
						Depth:      24,
						NumVisuals: 6,
						Visuals: []VisualType{
							{
								VisualID:        0x1,
								Class:           4, // TrueColor
								BitsPerRGBValue: 8,
								ColormapEntries: 256,
								RedMask:         0xff0000,
								GreenMask:       0x00ff00,
								BlueMask:        0x0000ff,
							},
							{
								VisualID:        0x3,
								Class:           5, // DirectColor
								BitsPerRGBValue: 8,
								ColormapEntries: 256,
								RedMask:         0xff0000,
								GreenMask:       0x00ff00,
								BlueMask:        0x0000ff,
							},
							{
								VisualID:        0x4,
								Class:           0, // StaticGray
								BitsPerRGBValue: 8,
								ColormapEntries: 256,
							},
							{
								VisualID:        0x5,
								Class:           1, // GrayScale
								BitsPerRGBValue: 8,
								ColormapEntries: 256,
							},
							{
								VisualID:        0x6,
								Class:           2, // StaticColor
								BitsPerRGBValue: 8,
								ColormapEntries: 256,
							},
							{
								VisualID:        0x7,
								Class:           3, // PseudoColor
								BitsPerRGBValue: 8,
								ColormapEntries: 256,
							},
						},
					},
				},
			},
		},
	}
	if config.Screens != nil {
		s.Screens = config.Screens
	}
	return s
}

func (s *Setup) marshal(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, s.ReleaseNumber)
	binary.Write(buf, order, s.ResourceIDBase)
	binary.Write(buf, order, s.ResourceIDMask)
	binary.Write(buf, order, s.MotionBufferSize)
	binary.Write(buf, order, s.VendorLength)
	binary.Write(buf, order, s.MaxRequestLength)
	buf.WriteByte(s.NumScreens)
	buf.WriteByte(s.NumPixmapFormats)
	buf.WriteByte(s.ImageByteOrder)
	buf.WriteByte(s.BitmapFormatBitOrder)
	buf.WriteByte(s.BitmapFormatScanlineUnit)
	buf.WriteByte(s.BitmapFormatScanlinePad)
	buf.WriteByte(s.MinKeycode)
	buf.WriteByte(s.MaxKeycode)
	buf.Write([]byte{0, 0, 0, 0}) // 4 bytes of padding
	buf.WriteString(s.VendorString)
	if pad := (4 - (len(s.VendorString) % 4)) % 4; pad > 0 {
		buf.Write(make([]byte, pad))
	}
	for _, f := range s.PixmapFormats {
		f.marshal(buf, order)
	}
	for _, scr := range s.Screens {
		scr.marshal(buf, order)
	}
	return buf.Bytes()
}

func (f *Format) marshal(buf *bytes.Buffer, order binary.ByteOrder) {
	buf.WriteByte(f.Depth)
	buf.WriteByte(f.BitsPerPixel)
	buf.WriteByte(f.ScanlinePad)
	buf.Write([]byte{0, 0, 0, 0, 0}) // 5 bytes of padding
}

func (s *Screen) marshal(buf *bytes.Buffer, order binary.ByteOrder) {
	binary.Write(buf, order, s.Root)
	binary.Write(buf, order, s.DefaultColormap)
	binary.Write(buf, order, s.WhitePixel)
	binary.Write(buf, order, s.BlackPixel)
	binary.Write(buf, order, s.CurrentInputMasks)
	binary.Write(buf, order, s.WidthInPixels)
	binary.Write(buf, order, s.HeightInPixels)
	binary.Write(buf, order, s.WidthInMillimeters)
	binary.Write(buf, order, s.HeightInMillimeters)
	binary.Write(buf, order, s.MinInstalledMaps)
	binary.Write(buf, order, s.MaxInstalledMaps)
	binary.Write(buf, order, s.RootVisual)
	buf.WriteByte(s.BackingStores)
	if s.SaveUnders {
		buf.WriteByte(1)
	} else {
		buf.WriteByte(0)
	}
	buf.WriteByte(s.RootDepth)
	buf.WriteByte(s.NumDepths)
	for _, d := range s.Depths {
		d.marshal(buf, order)
	}
}

func (d *Depth) marshal(buf *bytes.Buffer, order binary.ByteOrder) {
	buf.WriteByte(d.Depth)
	buf.WriteByte(0) // padding
	binary.Write(buf, order, d.NumVisuals)
	buf.Write([]byte{0, 0, 0, 0}) // 4 bytes of padding
	for _, v := range d.Visuals {
		v.marshal(buf, order)
	}
}

func (v *VisualType) marshal(buf *bytes.Buffer, order binary.ByteOrder) {
	binary.Write(buf, order, v.VisualID)
	buf.WriteByte(v.Class)
	buf.WriteByte(v.BitsPerRGBValue)
	binary.Write(buf, order, v.ColormapEntries)
	binary.Write(buf, order, v.RedMask)
	binary.Write(buf, order, v.GreenMask)
	binary.Write(buf, order, v.BlueMask)
	buf.Write([]byte{0, 0, 0, 0}) // 4 bytes of padding
}

// SetPointerMappingReply represents a reply to a SetPointerMapping request.
type SetPointerMappingReply struct {
	Sequence uint16 // Sequence number
	Status   byte   // Status (MappingSuccess, MappingBusy)
}

// EncodeMessage encodes the SetPointerMappingReply into a byte slice.
func (r *SetPointerMappingReply) EncodeMessage(order binary.ByteOrder) []byte {
	reply := make([]byte, 32)
	reply[0] = 1 // Reply type
	reply[1] = r.Status
	order.PutUint16(reply[2:4], r.Sequence)
	order.PutUint32(reply[4:8], 0)
	return reply
}

// ParseSetPointerMappingReply parses a SetPointerMapping reply.
func ParseSetPointerMappingReply(order binary.ByteOrder, b []byte) (*SetPointerMappingReply, error) {
	if len(b) < 32 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	r := &SetPointerMappingReply{
		Sequence: order.Uint16(b[2:4]),
		Status:   b[1],
	}
	return r, nil
}

// GetPointerMappingReply represents a reply to a GetPointerMapping request.
type GetPointerMappingReply struct {
	Sequence uint16 // Sequence number
	Length   byte   // Length of map
	PMap     []byte // Map
}

// EncodeMessage encodes the GetPointerMappingReply into a byte slice.
func (r *GetPointerMappingReply) EncodeMessage(order binary.ByteOrder) []byte {
	reply := make([]byte, 32+len(r.PMap))
	reply[0] = 1 // Reply type
	reply[1] = r.Length
	order.PutUint16(reply[2:4], r.Sequence)
	order.PutUint32(reply[4:8], uint32((len(r.PMap)+3)/4))
	copy(reply[32:], r.PMap)
	return reply
}

// ParseGetPointerMappingReply parses a GetPointerMapping reply.
func ParseGetPointerMappingReply(order binary.ByteOrder, b []byte) (*GetPointerMappingReply, error) {
	if len(b) < 32 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	length := b[1]
	if len(b) < 32+int(length) {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	r := &GetPointerMappingReply{
		Sequence: order.Uint16(b[2:4]),
		Length:   length,
		PMap:     b[32 : 32+length],
	}
	return r, nil
}

// GetKeyboardMappingReply represents a reply to a GetKeyboardMapping request.
type GetKeyboardMappingReply struct {
	Sequence          uint16   // Sequence number
	KeySymsPerKeycode byte     // Keysyms per keycode
	KeySyms           []uint32 // List of keysyms
}

// OpCode returns the request opcode.
func (r *GetKeyboardMappingReply) OpCode() ReqCode { return GetKeyboardMapping }

// EncodeMessage encodes the GetKeyboardMappingReply into a byte slice.
func (r *GetKeyboardMappingReply) EncodeMessage(order binary.ByteOrder) []byte {
	numKeysyms := len(r.KeySyms)
	length := uint32(numKeysyms)

	reply := make([]byte, 32+numKeysyms*4)
	reply[0] = 1 // Reply type
	reply[1] = r.KeySymsPerKeycode
	order.PutUint16(reply[2:4], r.Sequence)
	order.PutUint32(reply[4:8], length)
	// bytes 8-31 are unused
	for i, keySym := range r.KeySyms {
		order.PutUint32(reply[32+i*4:], keySym)
	}
	return reply
}

// ParseGetKeyboardMappingReply parses a GetKeyboardMapping reply.
func ParseGetKeyboardMappingReply(order binary.ByteOrder, b []byte) (*GetKeyboardMappingReply, error) {
	if len(b) < 32 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	length := order.Uint32(b[4:8])
	if len(b) < 32+int(length)*4 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	keySyms := make([]uint32, length)
	for i := 0; i < int(length); i++ {
		keySyms[i] = order.Uint32(b[32+i*4:])
	}
	r := &GetKeyboardMappingReply{
		Sequence:          order.Uint16(b[2:4]),
		KeySymsPerKeycode: 1,
		KeySyms:           keySyms,
	}
	return r, nil
}

// GetKeyboardControlReply represents a reply to a GetKeyboardControl request.
type GetKeyboardControlReply struct {
	Sequence         uint16   // Sequence number
	KeyClickPercent  byte     // Key click volume
	BellPercent      byte     // Bell volume
	BellPitch        uint16   // Bell pitch
	BellDuration     uint16   // Bell duration
	LedMask          uint32   // LED mask
	GlobalAutoRepeat byte     // Global auto repeat mode
	AutoRepeats      [32]byte // Auto repeats
}

// EncodeMessage encodes the GetKeyboardControlReply into a byte slice.
func (r *GetKeyboardControlReply) EncodeMessage(order binary.ByteOrder) []byte {
	reply := make([]byte, 52)
	reply[0] = 1 // Reply type
	reply[1] = r.GlobalAutoRepeat
	order.PutUint16(reply[2:4], r.Sequence)
	order.PutUint32(reply[4:8], 5) // Reply length
	order.PutUint32(reply[8:12], r.LedMask)
	reply[12] = r.KeyClickPercent
	reply[13] = r.BellPercent
	order.PutUint16(reply[14:16], r.BellPitch)
	order.PutUint16(reply[16:18], r.BellDuration)
	// reply[18:20] is padding
	copy(reply[20:52], r.AutoRepeats[:])
	return reply
}

// ParseGetKeyboardControlReply parses a GetKeyboardControl reply.
func ParseGetKeyboardControlReply(order binary.ByteOrder, b []byte) (*GetKeyboardControlReply, error) {
	if len(b) < 52 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	r := &GetKeyboardControlReply{
		Sequence:         order.Uint16(b[2:4]),
		GlobalAutoRepeat: b[1],
		LedMask:          order.Uint32(b[8:12]),
		KeyClickPercent:  b[12],
		BellPercent:      b[13],
		BellPitch:        order.Uint16(b[14:16]),
		BellDuration:     order.Uint16(b[16:18]),
	}
	copy(r.AutoRepeats[:], b[20:52])
	return r, nil
}

// GetScreenSaverReply represents a reply to a GetScreenSaver request.
type GetScreenSaverReply struct {
	Sequence    uint16 // Sequence number
	Timeout     uint16 // Timeout
	Interval    uint16 // Interval
	PreferBlank byte   // Prefer blanking
	AllowExpose byte   // Allow exposures
}

// EncodeMessage encodes the GetScreenSaverReply into a byte slice.
func (r *GetScreenSaverReply) EncodeMessage(order binary.ByteOrder) []byte {
	reply := make([]byte, 32)
	reply[0] = 1 // Reply type
	order.PutUint16(reply[2:4], r.Sequence)
	order.PutUint32(reply[4:8], 0)
	order.PutUint16(reply[8:10], r.Timeout)
	order.PutUint16(reply[10:12], r.Interval)
	reply[12] = r.PreferBlank
	reply[13] = r.AllowExpose
	return reply
}

// ParseGetScreenSaverReply parses a GetScreenSaver reply.
func ParseGetScreenSaverReply(order binary.ByteOrder, b []byte) (*GetScreenSaverReply, error) {
	if len(b) < 32 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	r := &GetScreenSaverReply{
		Sequence:    order.Uint16(b[2:4]),
		Timeout:     order.Uint16(b[8:10]),
		Interval:    order.Uint16(b[10:12]),
		PreferBlank: b[12],
		AllowExpose: b[13],
	}
	return r, nil
}

// ListHostsReply represents a reply to a ListHosts request.
type ListHostsReply struct {
	Sequence uint16 // Sequence number
	NumHosts uint16 // Number of hosts
	Hosts    []Host // List of hosts
}

// EncodeMessage encodes the ListHostsReply into a byte slice.
func (r *ListHostsReply) EncodeMessage(order binary.ByteOrder) []byte {
	var data []byte
	for _, host := range r.Hosts {
		var hostData []byte
		hostData = append(hostData, host.Family)
		hostData = append(hostData, 0) // padding
		hostData = append(hostData, make([]byte, 2)...)
		order.PutUint16(hostData[2:4], uint16(len(host.Data)))
		hostData = append(hostData, host.Data...)
		pad := (4 - (len(host.Data) % 4)) % 4
		hostData = append(hostData, make([]byte, pad)...)
		data = append(data, hostData...)
	}
	reply := make([]byte, 32+len(data))
	reply[0] = 1 // Reply type
	order.PutUint16(reply[2:4], r.Sequence)
	order.PutUint32(reply[4:8], uint32(len(data)/4))
	order.PutUint16(reply[8:10], r.NumHosts)
	copy(reply[32:], data)
	return reply
}

// ParseListHostsReply parses a ListHosts reply.
func ParseListHostsReply(order binary.ByteOrder, b []byte) (*ListHostsReply, error) {
	if len(b) < 32 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	numHosts := order.Uint16(b[8:10])
	hosts := make([]Host, numHosts)
	offset := 32
	for i := 0; i < int(numHosts); i++ {
		if len(b) < offset+4 {
			return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
		}
		family := b[offset]
		length := int(order.Uint16(b[offset+2 : offset+4]))
		if len(b) < offset+4+length {
			return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
		}
		data := b[offset+4 : offset+4+length]
		hosts[i] = Host{
			Family: family,
			Data:   data,
		}
		offset += 4 + length + PadLen(length)
	}
	r := &ListHostsReply{
		Sequence: order.Uint16(b[2:4]),
		NumHosts: numHosts,
		Hosts:    hosts,
	}
	return r, nil
}

// SetModifierMappingReply represents a reply to a SetModifierMapping request.
type SetModifierMappingReply struct {
	Sequence uint16 // Sequence number
	Status   byte   // Status (MappingSuccess, MappingBusy)
}

// EncodeMessage encodes the SetModifierMappingReply into a byte slice.
func (r *SetModifierMappingReply) EncodeMessage(order binary.ByteOrder) []byte {
	reply := make([]byte, 32)
	reply[0] = 1 // Reply type
	reply[1] = r.Status
	order.PutUint16(reply[2:4], r.Sequence)
	order.PutUint32(reply[4:8], 0)
	return reply
}

// ParseSetModifierMappingReply parses a SetModifierMapping reply.
func ParseSetModifierMappingReply(order binary.ByteOrder, b []byte) (*SetModifierMappingReply, error) {
	if len(b) < 32 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	r := &SetModifierMappingReply{
		Sequence: order.Uint16(b[2:4]),
		Status:   b[1],
	}
	return r, nil
}

// GetModifierMappingReply represents a reply to a GetModifierMapping request.
type GetModifierMappingReply struct {
	Sequence            uint16    // Sequence number
	KeyCodesPerModifier byte      // Keycodes per modifier
	KeyCodes            []KeyCode // List of keycodes
}

// EncodeMessage encodes the GetModifierMappingReply into a byte slice.
func (r *GetModifierMappingReply) EncodeMessage(order binary.ByteOrder) []byte {
	keyCodes := make([]byte, len(r.KeyCodes))
	for i, kc := range r.KeyCodes {
		keyCodes[i] = byte(kc)
	}
	reply := make([]byte, 32+len(keyCodes))
	reply[0] = 1 // Reply type
	reply[1] = r.KeyCodesPerModifier
	order.PutUint16(reply[2:4], r.Sequence)
	order.PutUint32(reply[4:8], uint32((len(keyCodes)+3)/4))
	copy(reply[32:], keyCodes)
	return reply
}

// ParseGetModifierMappingReply parses a GetModifierMapping reply.
func ParseGetModifierMappingReply(order binary.ByteOrder, b []byte) (*GetModifierMappingReply, error) {
	if len(b) < 32 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	keyCodesPerModifier := b[1]
	if len(b) < 32+int(keyCodesPerModifier)*8 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	keyCodes := make([]KeyCode, int(keyCodesPerModifier)*8)
	for i := 0; i < len(keyCodes); i++ {
		keyCodes[i] = KeyCode(b[32+i])
	}
	r := &GetModifierMappingReply{
		Sequence:            order.Uint16(b[2:4]),
		KeyCodesPerModifier: keyCodesPerModifier,
		KeyCodes:            keyCodes,
	}
	return r, nil
}

// QueryKeymapReply represents a reply to a QueryKeymap request.
type QueryKeymapReply struct {
	Sequence uint16   // Sequence number
	Keys     [32]byte // Keyboard state
}

// EncodeMessage encodes the QueryKeymapReply into a byte slice.
func (r *QueryKeymapReply) EncodeMessage(order binary.ByteOrder) []byte {
	reply := make([]byte, 40)
	reply[0] = 1 // Reply type
	order.PutUint16(reply[2:4], r.Sequence)
	order.PutUint32(reply[4:8], 2)
	copy(reply[8:], r.Keys[:])
	return reply
}

// ParseQueryKeymapReply parses a QueryKeymap reply.
func ParseQueryKeymapReply(order binary.ByteOrder, b []byte) (*QueryKeymapReply, error) {
	if len(b) < 40 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	r := &QueryKeymapReply{
		Sequence: order.Uint16(b[2:4]),
	}
	copy(r.Keys[:], b[8:40])
	return r, nil
}

// GetFontPathReply represents a reply to a GetFontPath request.
type GetFontPathReply struct {
	Sequence uint16   // Sequence number
	NPaths   uint16   // Number of paths
	Paths    []string // List of paths
}

// EncodeMessage encodes the GetFontPathReply into a byte slice.
func (r *GetFontPathReply) EncodeMessage(order binary.ByteOrder) []byte {
	var data []byte
	for _, path := range r.Paths {
		data = append(data, byte(len(path)))
		data = append(data, path...)
	}
	p := (4 - (len(data) % 4)) % 4
	totalLen := 32 + len(data) + p

	reply := make([]byte, totalLen)
	reply[0] = 1 // Reply type
	order.PutUint16(reply[2:4], r.Sequence)
	order.PutUint32(reply[4:8], uint32((len(data)+p)/4))
	order.PutUint16(reply[8:10], r.NPaths)
	copy(reply[32:], data)
	return reply
}

// ParseGetFontPathReply parses a GetFontPath reply.
func ParseGetFontPathReply(order binary.ByteOrder, b []byte) (*GetFontPathReply, error) {
	if len(b) < 32 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	nPaths := order.Uint16(b[8:10])
	paths := make([]string, nPaths)
	offset := 32
	for i := 0; i < int(nPaths); i++ {
		if len(b) < offset+1 {
			return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
		}
		length := int(b[offset])
		if len(b) < offset+1+length {
			return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
		}
		paths[i] = string(b[offset+1 : offset+1+length])
		offset += 1 + length
	}
	r := &GetFontPathReply{
		Sequence: order.Uint16(b[2:4]),
		NPaths:   nPaths,
		Paths:    paths,
	}
	return r, nil
}

// ListFontsWithInfoReply represents a reply to a ListFontsWithInfo request.
type ListFontsWithInfoReply struct {
	Sequence      uint16     // Sequence number
	NameLength    byte       // Length of name
	MinBounds     XCharInfo  // Minimum bounds
	MaxBounds     XCharInfo  // Maximum bounds
	MinChar       uint16     // Minimum character
	MaxChar       uint16     // Maximum character
	DefaultChar   uint16     // Default character
	NFontProps    uint16     // Number of font properties
	DrawDirection byte       // Draw direction
	MinByte1      byte       // Minimum byte 1
	MaxByte1      byte       // Maximum byte 1
	AllCharsExist bool       // All characters exist flag
	FontAscent    int16      // Font ascent
	FontDescent   int16      // Font descent
	NReplies      uint32     // Number of replies remaining
	FontProps     []FontProp // Font properties
	FontName      string     // Font name
}

// FontProp represents a font property.
type FontProp struct {
	Name  uint32 // Name atom
	Value uint32 // Value
}

// EncodeMessage encodes the ListFontsWithInfoReply into a byte slice.
func (r *ListFontsWithInfoReply) EncodeMessage(order binary.ByteOrder) []byte {
	fontNameBytes := []byte(r.FontName)
	fontNameLen := len(fontNameBytes)
	p := (4 - (fontNameLen % 4)) % 4
	totalLen := 60 + len(r.FontProps)*8 + fontNameLen + p

	reply := make([]byte, totalLen)
	reply[0] = 1 // Reply type
	reply[1] = r.NameLength
	order.PutUint16(reply[2:4], r.Sequence)
	order.PutUint32(reply[4:8], uint32((totalLen-32)/4))

	// min-bounds
	order.PutUint16(reply[8:10], uint16(r.MinBounds.LeftSideBearing))
	order.PutUint16(reply[10:12], uint16(r.MinBounds.RightSideBearing))
	order.PutUint16(reply[12:14], r.MinBounds.CharacterWidth)
	order.PutUint16(reply[14:16], uint16(r.MinBounds.Ascent))
	order.PutUint16(reply[16:18], uint16(r.MinBounds.Descent))
	order.PutUint16(reply[18:20], r.MinBounds.Attributes)

	// max-bounds
	order.PutUint16(reply[24:26], uint16(r.MaxBounds.LeftSideBearing))
	order.PutUint16(reply[26:28], uint16(r.MaxBounds.RightSideBearing))
	order.PutUint16(reply[28:30], r.MaxBounds.CharacterWidth)
	order.PutUint16(reply[30:32], uint16(r.MaxBounds.Ascent))
	order.PutUint16(reply[32:34], uint16(r.MaxBounds.Descent))
	order.PutUint16(reply[34:36], r.MaxBounds.Attributes)

	order.PutUint16(reply[40:42], r.MinChar)
	order.PutUint16(reply[42:44], r.MaxChar)
	order.PutUint16(reply[44:46], r.DefaultChar)
	order.PutUint16(reply[46:48], r.NFontProps)
	reply[48] = r.DrawDirection
	reply[49] = r.MinByte1
	reply[50] = r.MaxByte1
	reply[51] = BoolToByte(r.AllCharsExist)
	order.PutUint16(reply[52:54], uint16(r.FontAscent))
	order.PutUint16(reply[54:56], uint16(r.FontDescent))
	order.PutUint32(reply[56:60], r.NReplies)

	offset := 60
	for _, prop := range r.FontProps {
		order.PutUint32(reply[offset:offset+4], prop.Name)
		order.PutUint32(reply[offset+4:offset+8], prop.Value)
		offset += 8
	}

	copy(reply[offset:], fontNameBytes)
	return reply
}

// ParseListFontsWithInfoReply parses a ListFontsWithInfo reply.
func ParseListFontsWithInfoReply(order binary.ByteOrder, b []byte) (*ListFontsWithInfoReply, error) {
	if len(b) < 60 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	nameLength := b[1]
	nFontProps := order.Uint16(b[46:48])
	if len(b) < 60+int(nFontProps)*8+int(nameLength) {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	fontProps := make([]FontProp, nFontProps)
	offset := 60
	for i := 0; i < int(nFontProps); i++ {
		fontProps[i] = FontProp{
			Name:  order.Uint32(b[offset:]),
			Value: order.Uint32(b[offset+4:]),
		}
		offset += 8
	}
	fontName := string(b[offset : offset+int(nameLength)])

	r := &ListFontsWithInfoReply{
		Sequence:   order.Uint16(b[2:4]),
		NameLength: nameLength,
		MinBounds: XCharInfo{
			LeftSideBearing:  int16(order.Uint16(b[8:10])),
			RightSideBearing: int16(order.Uint16(b[10:12])),
			CharacterWidth:   order.Uint16(b[12:14]),
			Ascent:           int16(order.Uint16(b[14:16])),
			Descent:          int16(order.Uint16(b[16:18])),
			Attributes:       order.Uint16(b[18:20]),
		},
		MaxBounds: XCharInfo{
			LeftSideBearing:  int16(order.Uint16(b[24:26])),
			RightSideBearing: int16(order.Uint16(b[26:28])),
			CharacterWidth:   order.Uint16(b[28:30]),
			Ascent:           int16(order.Uint16(b[30:32])),
			Descent:          int16(order.Uint16(b[32:34])),
			Attributes:       order.Uint16(b[34:36]),
		},
		MinChar:       order.Uint16(b[40:42]),
		MaxChar:       order.Uint16(b[42:44]),
		DefaultChar:   order.Uint16(b[44:46]),
		NFontProps:    nFontProps,
		DrawDirection: b[48],
		MinByte1:      b[49],
		MaxByte1:      b[50],
		AllCharsExist: b[51] != 0,
		FontAscent:    int16(order.Uint16(b[52:54])),
		FontDescent:   int16(order.Uint16(b[54:56])),
		NReplies:      order.Uint32(b[56:60]),
		FontProps:     fontProps,
		FontName:      fontName,
	}
	return r, nil
}

// QueryTreeReply represents a reply to a QueryTree request.
type QueryTreeReply struct {
	Sequence    uint16   // Sequence number
	Root        uint32   // Root window ID
	Parent      uint32   // Parent window ID
	NumChildren uint16   // Number of children
	Children    []uint32 // List of children
}

// EncodeMessage encodes the QueryTreeReply into a byte slice.
func (r *QueryTreeReply) EncodeMessage(order binary.ByteOrder) []byte {
	reply := make([]byte, 32+len(r.Children)*4)
	reply[0] = 1 // Reply type
	order.PutUint16(reply[2:4], r.Sequence)
	order.PutUint32(reply[4:8], uint32(len(r.Children)))
	order.PutUint32(reply[8:12], r.Root)
	order.PutUint32(reply[12:16], r.Parent)
	order.PutUint16(reply[16:18], r.NumChildren)
	for i, child := range r.Children {
		order.PutUint32(reply[32+i*4:], child)
	}
	return reply
}

// ParseQueryTreeReply parses a QueryTree reply.
func ParseQueryTreeReply(order binary.ByteOrder, b []byte) (*QueryTreeReply, error) {
	if len(b) < 32 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	numChildren := order.Uint16(b[16:18])
	if len(b) < 32+int(numChildren)*4 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	children := make([]uint32, numChildren)
	for i := 0; i < int(numChildren); i++ {
		children[i] = order.Uint32(b[32+i*4:])
	}
	r := &QueryTreeReply{
		Sequence:    order.Uint16(b[2:4]),
		Root:        order.Uint32(b[8:12]),
		Parent:      order.Uint32(b[12:16]),
		NumChildren: numChildren,
		Children:    children,
	}
	return r, nil
}

// AllocColorCellsReply represents a reply to an AllocColorCells request.
type AllocColorCellsReply struct {
	Sequence uint16   // Sequence number
	NPixels  uint16   // Number of pixels
	NMasks   uint16   // Number of masks
	Pixels   []uint32 // List of pixels
	Masks    []uint32 // List of masks
}

// EncodeMessage encodes the AllocColorCellsReply into a byte slice.
func (r *AllocColorCellsReply) EncodeMessage(order binary.ByteOrder) []byte {
	numPixels := len(r.Pixels)
	numMasks := len(r.Masks)
	reply := make([]byte, 32+(numPixels+numMasks)*4)
	reply[0] = 1 // Reply type
	// byte 1 is unused
	order.PutUint16(reply[2:4], r.Sequence)
	order.PutUint32(reply[4:8], uint32(numPixels+numMasks)) // Reply length
	order.PutUint16(reply[8:10], uint16(numPixels))
	order.PutUint16(reply[10:12], uint16(numMasks))
	// reply[12:32] is padding
	for i, pixel := range r.Pixels {
		order.PutUint32(reply[32+i*4:], pixel)
	}
	for i, mask := range r.Masks {
		order.PutUint32(reply[32+numPixels*4+i*4:], mask)
	}
	return reply
}

// ParseAllocColorCellsReply parses an AllocColorCells reply.
func ParseAllocColorCellsReply(order binary.ByteOrder, b []byte) (*AllocColorCellsReply, error) {
	if len(b) < 32 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	nPixels := order.Uint16(b[8:10])
	nMasks := order.Uint16(b[10:12])
	if len(b) < 32+int(nPixels)*4+int(nMasks)*4 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	pixels := make([]uint32, nPixels)
	masks := make([]uint32, nMasks)
	for i := 0; i < int(nPixels); i++ {
		pixels[i] = order.Uint32(b[32+i*4:])
	}
	for i := 0; i < int(nMasks); i++ {
		masks[i] = order.Uint32(b[32+int(nPixels)*4+i*4:])
	}
	r := &AllocColorCellsReply{
		Sequence: order.Uint16(b[2:4]),
		NPixels:  nPixels,
		NMasks:   nMasks,
		Pixels:   pixels,
		Masks:    masks,
	}
	return r, nil
}

// AllocColorPlanesReply represents a reply to an AllocColorPlanes request.
type AllocColorPlanesReply struct {
	Sequence  uint16   // Sequence number
	NPixels   uint16   // Number of pixels
	RedMask   uint32   // Red mask
	GreenMask uint32   // Green mask
	BlueMask  uint32   // Blue mask
	Pixels    []uint32 // List of pixels
}

// EncodeMessage encodes the AllocColorPlanesReply into a byte slice.
func (r *AllocColorPlanesReply) EncodeMessage(order binary.ByteOrder) []byte {
	numPixels := len(r.Pixels)
	reply := make([]byte, 32+numPixels*4)
	reply[0] = 1 // Reply type
	// byte 1 is unused
	order.PutUint16(reply[2:4], r.Sequence)
	order.PutUint32(reply[4:8], uint32(numPixels)) // Reply length
	order.PutUint16(reply[8:10], uint16(numPixels))
	// reply[10:12] is padding
	order.PutUint32(reply[12:16], r.RedMask)
	order.PutUint32(reply[16:20], r.GreenMask)
	order.PutUint32(reply[20:24], r.BlueMask)
	// reply[24:32] is padding
	for i, pixel := range r.Pixels {
		order.PutUint32(reply[32+i*4:], pixel)
	}
	return reply
}

// ParseAllocColorPlanesReply parses an AllocColorPlanes reply.
func ParseAllocColorPlanesReply(order binary.ByteOrder, b []byte) (*AllocColorPlanesReply, error) {
	if len(b) < 32 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	nPixels := order.Uint16(b[8:10])
	if len(b) < 32+int(nPixels)*4 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	pixels := make([]uint32, nPixels)
	for i := 0; i < int(nPixels); i++ {
		pixels[i] = order.Uint32(b[32+i*4:])
	}
	r := &AllocColorPlanesReply{
		Sequence:  order.Uint16(b[2:4]),
		NPixels:   nPixels,
		RedMask:   order.Uint32(b[12:16]),
		GreenMask: order.Uint32(b[16:20]),
		BlueMask:  order.Uint32(b[20:24]),
		Pixels:    pixels,
	}
	return r, nil
}

// ListExtensionsReply represents a reply to a ListExtensions request.
type ListExtensionsReply struct {
	Sequence uint16   // Sequence number
	NNames   byte     // Number of extension names
	Names    []string // List of extension names
}

// EncodeMessage encodes the ListExtensionsReply into a byte slice.
func (r *ListExtensionsReply) EncodeMessage(order binary.ByteOrder) []byte {
	var namesData []byte
	for _, name := range r.Names {
		namesData = append(namesData, byte(len(name)))
		namesData = append(namesData, []byte(name)...)
	}

	namesSize := len(namesData)
	padSize := (4 - (namesSize % 4)) % 4

	reply := make([]byte, 32+namesSize+padSize)
	reply[0] = 1 // Reply
	reply[1] = r.NNames
	order.PutUint16(reply[2:4], r.Sequence)
	order.PutUint32(reply[4:8], uint32((namesSize+padSize)/4)) // Reply length
	// reply[8:32] is padding
	copy(reply[32:], namesData)
	return reply
}

// ParseListExtensionsReply parses a ListExtensions reply.
func ParseListExtensionsReply(order binary.ByteOrder, b []byte) (*ListExtensionsReply, error) {
	if len(b) < 32 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	nNames := b[1]
	names := make([]string, nNames)
	offset := 32
	for i := 0; i < int(nNames); i++ {
		if len(b) < offset+1 {
			return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
		}
		length := int(b[offset])
		if len(b) < offset+1+length {
			return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
		}
		names[i] = string(b[offset+1 : offset+1+length])
		offset += 1 + length
	}
	r := &ListExtensionsReply{
		Sequence: order.Uint16(b[2:4]),
		NNames:   nNames,
		Names:    names,
	}
	return r, nil
}

// GetPointerControlReply represents a reply to a GetPointerControl request.
type GetPointerControlReply struct {
	Sequence         uint16 // Sequence number
	AccelNumerator   uint16 // Acceleration numerator
	AccelDenominator uint16 // Acceleration denominator
	Threshold        uint16 // Threshold
}

// EncodeMessage encodes the GetPointerControlReply into a byte slice.
func (r *GetPointerControlReply) EncodeMessage(order binary.ByteOrder) []byte {
	reply := make([]byte, 32)
	reply[0] = 1 // Reply type
	// byte 1 is unused
	order.PutUint16(reply[2:4], r.Sequence)
	order.PutUint32(reply[4:8], 0) // Reply length
	order.PutUint16(reply[8:10], r.AccelNumerator)
	order.PutUint16(reply[10:12], r.AccelDenominator)
	order.PutUint16(reply[12:14], r.Threshold)
	// reply[14:32] is padding
	return reply
}

// ParseGetPointerControlReply parses a GetPointerControl reply.
func ParseGetPointerControlReply(order binary.ByteOrder, b []byte) (*GetPointerControlReply, error) {
	if len(b) < 32 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	r := &GetPointerControlReply{
		Sequence:         order.Uint16(b[2:4]),
		AccelNumerator:   order.Uint16(b[8:10]),
		AccelDenominator: order.Uint16(b[10:12]),
		Threshold:        order.Uint16(b[12:14]),
	}
	return r, nil
}
