//go:build x11

package wire

import (
	"encoding/binary"
	"fmt"
)

// KeyEvent represents a KeyPress or KeyRelease event.
type KeyEvent struct {
	Opcode         byte   // KeyPress: 2, KeyRelease: 3
	Sequence       uint16 // Sequence number
	Detail         byte   // keycode
	Time           uint32 // Time of event in milliseconds
	Root           uint32 // Root window ID
	Event          uint32 // Event window ID
	Child          uint32 // Child window ID (or None)
	RootX, RootY   int16  // Pointer coordinates relative to root
	EventX, EventY int16  // Pointer coordinates relative to event window
	State          uint16 // Key/Button state mask
	SameScreen     bool   // True if event and root are on same screen
}

// EventCode returns the event code.
func (e *KeyEvent) EventCode() uint8 { return e.Opcode }

// EncodeMessage encodes the KeyEvent into a byte slice.
func (e *KeyEvent) EncodeMessage(order binary.ByteOrder) []byte {
	event := make([]byte, 32)
	event[0] = e.Opcode
	event[1] = e.Detail
	order.PutUint16(event[2:4], e.Sequence)
	order.PutUint32(event[4:8], e.Time)
	order.PutUint32(event[8:12], e.Root)
	order.PutUint32(event[12:16], e.Event)
	order.PutUint32(event[16:20], e.Child)
	order.PutUint16(event[20:22], uint16(e.RootX))
	order.PutUint16(event[22:24], uint16(e.RootY))
	order.PutUint16(event[24:26], uint16(e.EventX))
	order.PutUint16(event[26:28], uint16(e.EventY))
	order.PutUint16(event[28:30], e.State)
	event[30] = BoolToByte(e.SameScreen)
	// event[31] is unused
	return event
}

// ButtonPressEvent represents a ButtonPress event (opcode 4).
type ButtonPressEvent struct {
	Sequence       uint16 // Sequence number
	Detail         byte   // button code
	Time           uint32 // Time of event
	Root           uint32 // Root window ID
	Event          uint32 // Event window ID
	Child          uint32 // Child window ID
	RootX, RootY   int16  // Coordinates relative to root
	EventX, EventY int16  // Coordinates relative to event window
	State          uint16 // Key/Button state mask
	SameScreen     bool   // Same screen flag
}

// GraphicsExposureEvent represents a GraphicsExposure event (opcode 13).
type GraphicsExposureEvent struct {
	Sequence      uint16 // Sequence number
	Drawable      uint32 // Drawable ID
	X, Y          uint16 // Top-left coordinate of exposed area
	Width, Height uint16 // Dimensions of exposed area
	MinorOpcode   uint16 // Minor opcode of request causing event
	Count         uint16 // Number of subsequent GraphicsExposure events
	MajorOpcode   byte   // Major opcode of request causing event
}

// EventCode returns the event code.
func (e *GraphicsExposureEvent) EventCode() uint8 { return 13 }

// EncodeMessage encodes the GraphicsExposureEvent into a byte slice.
func (e *GraphicsExposureEvent) EncodeMessage(order binary.ByteOrder) []byte {
	event := make([]byte, 32)
	event[0] = 13 // GraphicsExposure event code
	// byte 1 is unused
	order.PutUint16(event[2:4], e.Sequence)
	order.PutUint32(event[4:8], e.Drawable)
	order.PutUint16(event[8:10], e.X)
	order.PutUint16(event[10:12], e.Y)
	order.PutUint16(event[12:14], e.Width)
	order.PutUint16(event[14:16], e.Height)
	order.PutUint16(event[16:18], e.MinorOpcode)
	order.PutUint16(event[18:20], e.Count)
	event[20] = e.MajorOpcode
	// event[21:32] is unused
	return event
}

// NoExposureEvent represents a NoExposure event (opcode 14).
type NoExposureEvent struct {
	Sequence    uint16 // Sequence number
	Drawable    uint32 // Drawable ID
	MinorOpcode uint16 // Minor opcode
	MajorOpcode byte   // Major opcode
}

// EventCode returns the event code.
func (e *NoExposureEvent) EventCode() uint8 { return 14 }

// EncodeMessage encodes the NoExposureEvent into a byte slice.
func (e *NoExposureEvent) EncodeMessage(order binary.ByteOrder) []byte {
	event := make([]byte, 32)
	event[0] = 14 // NoExposure event code
	// byte 1 is unused
	order.PutUint16(event[2:4], e.Sequence)
	order.PutUint32(event[4:8], e.Drawable)
	order.PutUint16(event[8:10], e.MinorOpcode)
	event[10] = e.MajorOpcode
	// event[11:32] is unused
	return event
}

// VisibilityNotifyEvent represents a VisibilityNotify event (opcode 15).
type VisibilityNotifyEvent struct {
	Sequence uint16 // Sequence number
	Window   uint32 // Window ID
	State    byte   // Visibility state (Unobscured, PartiallyObscured, FullyObscured)
}

// EventCode returns the event code.
func (e *VisibilityNotifyEvent) EventCode() uint8 { return 15 }

// EncodeMessage encodes the VisibilityNotifyEvent into a byte slice.
func (e *VisibilityNotifyEvent) EncodeMessage(order binary.ByteOrder) []byte {
	event := make([]byte, 32)
	event[0] = 15 // VisibilityNotify event code
	// byte 1 is unused
	order.PutUint16(event[2:4], e.Sequence)
	order.PutUint32(event[4:8], e.Window)
	event[8] = e.State
	// event[9:32] is unused
	return event
}

// CreateNotifyEvent represents a CreateNotify event (opcode 16).
type CreateNotifyEvent struct {
	Sequence         uint16 // Sequence number
	Parent           uint32 // Parent window ID
	Window           uint32 // Created window ID
	X, Y             int16  // Coordinates relative to parent
	Width, Height    uint16 // Dimensions
	BorderWidth      uint16 // Border width
	OverrideRedirect bool   // Override-redirect flag
}

// EventCode returns the event code.
func (e *CreateNotifyEvent) EventCode() uint8 { return 16 }

// EncodeMessage encodes the CreateNotifyEvent into a byte slice.
func (e *CreateNotifyEvent) EncodeMessage(order binary.ByteOrder) []byte {
	event := make([]byte, 32)
	event[0] = 16 // CreateNotify event code
	// byte 1 is unused
	order.PutUint16(event[2:4], e.Sequence)
	order.PutUint32(event[4:8], e.Parent)
	order.PutUint32(event[8:12], e.Window)
	order.PutUint16(event[12:14], uint16(e.X))
	order.PutUint16(event[14:16], uint16(e.Y))
	order.PutUint16(event[16:18], e.Width)
	order.PutUint16(event[18:20], e.Height)
	order.PutUint16(event[20:22], e.BorderWidth)
	event[22] = BoolToByte(e.OverrideRedirect)
	// byte 23 is unused
	return event
}

// DestroyNotifyEvent represents a DestroyNotify event (opcode 17).
type DestroyNotifyEvent struct {
	Sequence uint16 // Sequence number
	Event    uint32 // Event window ID
	Window   uint32 // Destroyed window ID
}

// EventCode returns the event code.
func (e *DestroyNotifyEvent) EventCode() uint8 { return 17 }

// EncodeMessage encodes the DestroyNotifyEvent into a byte slice.
func (e *DestroyNotifyEvent) EncodeMessage(order binary.ByteOrder) []byte {
	event := make([]byte, 32)
	event[0] = 17 // DestroyNotify event code
	// byte 1 is unused
	order.PutUint16(event[2:4], e.Sequence)
	order.PutUint32(event[4:8], e.Event)
	order.PutUint32(event[8:12], e.Window)
	// event[12:32] is unused
	return event
}

// UnmapNotifyEvent represents an UnmapNotify event (opcode 18).
type UnmapNotifyEvent struct {
	Sequence      uint16 // Sequence number
	Event         uint32 // Event window ID
	Window        uint32 // Unmapped window ID
	FromConfigure bool   // True if unmap was result of a resize
}

// EventCode returns the event code.
func (e *UnmapNotifyEvent) EventCode() uint8 { return 18 }

// EncodeMessage encodes the UnmapNotifyEvent into a byte slice.
func (e *UnmapNotifyEvent) EncodeMessage(order binary.ByteOrder) []byte {
	event := make([]byte, 32)
	event[0] = 18 // UnmapNotify event code
	// byte 1 is unused
	order.PutUint16(event[2:4], e.Sequence)
	order.PutUint32(event[4:8], e.Event)
	order.PutUint32(event[8:12], e.Window)
	event[12] = BoolToByte(e.FromConfigure)
	// event[13:32] is unused
	return event
}

// MapNotifyEvent represents a MapNotify event (opcode 19).
type MapNotifyEvent struct {
	Sequence         uint16 // Sequence number
	Event            uint32 // Event window ID
	Window           uint32 // Mapped window ID
	OverrideRedirect bool   // Override-redirect flag
}

// EventCode returns the event code.
func (e *MapNotifyEvent) EventCode() uint8 { return 19 }

// EncodeMessage encodes the MapNotifyEvent into a byte slice.
func (e *MapNotifyEvent) EncodeMessage(order binary.ByteOrder) []byte {
	event := make([]byte, 32)
	event[0] = 19 // MapNotify event code
	// byte 1 is unused
	order.PutUint16(event[2:4], e.Sequence)
	order.PutUint32(event[4:8], e.Event)
	order.PutUint32(event[8:12], e.Window)
	event[12] = BoolToByte(e.OverrideRedirect)
	// event[13:32] is unused
	return event
}

// MapRequestEvent represents a MapRequest event (opcode 20).
type MapRequestEvent struct {
	Sequence uint16 // Sequence number
	Parent   uint32 // Parent window ID
	Window   uint32 // Window ID requested to be mapped
}

// EventCode returns the event code.
func (e *MapRequestEvent) EventCode() uint8 { return 20 }

// EncodeMessage encodes the MapRequestEvent into a byte slice.
func (e *MapRequestEvent) EncodeMessage(order binary.ByteOrder) []byte {
	event := make([]byte, 32)
	event[0] = 20 // MapRequest event code
	// byte 1 is unused
	order.PutUint16(event[2:4], e.Sequence)
	order.PutUint32(event[4:8], e.Parent)
	order.PutUint32(event[8:12], e.Window)
	// event[12:32] is unused
	return event
}

// ReparentNotifyEvent represents a ReparentNotify event (opcode 21).
type ReparentNotifyEvent struct {
	Sequence         uint16 // Sequence number
	Event            uint32 // Event window ID
	Window           uint32 // Reparented window ID
	Parent           uint32 // New parent window ID
	X, Y             int16  // Coordinates relative to new parent
	OverrideRedirect bool   // Override-redirect flag
}

// EventCode returns the event code.
func (e *ReparentNotifyEvent) EventCode() uint8 { return 21 }

// EncodeMessage encodes the ReparentNotifyEvent into a byte slice.
func (e *ReparentNotifyEvent) EncodeMessage(order binary.ByteOrder) []byte {
	event := make([]byte, 32)
	event[0] = 21 // ReparentNotify event code
	// byte 1 is unused
	order.PutUint16(event[2:4], e.Sequence)
	order.PutUint32(event[4:8], e.Event)
	order.PutUint32(event[8:12], e.Window)
	order.PutUint32(event[12:16], e.Parent)
	order.PutUint16(event[16:18], uint16(e.X))
	order.PutUint16(event[18:20], uint16(e.Y))
	event[20] = BoolToByte(e.OverrideRedirect)
	// event[21:32] is unused
	return event
}

// ConfigureRequestEvent represents a ConfigureRequest event (opcode 23).
type ConfigureRequestEvent struct {
	Sequence      uint16 // Sequence number
	StackMode     byte   // Stack mode (Above, Below, etc.)
	Parent        uint32 // Parent window ID
	Window        uint32 // Window ID
	Sibling       uint32 // Sibling window ID
	X, Y          int16  // Requested coordinates
	Width, Height uint16 // Requested dimensions
	BorderWidth   uint16 // Requested border width
	ValueMask     uint16 // Mask indicating which values are requested
}

// EventCode returns the event code.
func (e *ConfigureRequestEvent) EventCode() uint8 { return 23 }

// EncodeMessage encodes the ConfigureRequestEvent into a byte slice.
func (e *ConfigureRequestEvent) EncodeMessage(order binary.ByteOrder) []byte {
	event := make([]byte, 32)
	event[0] = 23 // ConfigureRequest event code
	event[1] = e.StackMode
	order.PutUint16(event[2:4], e.Sequence)
	order.PutUint32(event[4:8], e.Parent)
	order.PutUint32(event[8:12], e.Window)
	order.PutUint32(event[12:16], e.Sibling)
	order.PutUint16(event[16:18], uint16(e.X))
	order.PutUint16(event[18:20], uint16(e.Y))
	order.PutUint16(event[20:22], e.Width)
	order.PutUint16(event[22:24], e.Height)
	order.PutUint16(event[24:26], e.BorderWidth)
	order.PutUint16(event[26:28], e.ValueMask)
	// event[28:32] is unused
	return event
}

// GravityNotifyEvent represents a GravityNotify event (opcode 24).
type GravityNotifyEvent struct {
	Sequence uint16 // Sequence number
	Event    uint32 // Event window ID
	Window   uint32 // Window ID
	X, Y     int16  // New coordinates
}

// EventCode returns the event code.
func (e *GravityNotifyEvent) EventCode() uint8 { return 24 }

// EncodeMessage encodes the GravityNotifyEvent into a byte slice.
func (e *GravityNotifyEvent) EncodeMessage(order binary.ByteOrder) []byte {
	event := make([]byte, 32)
	event[0] = 24 // GravityNotify event code
	// byte 1 is unused
	order.PutUint16(event[2:4], e.Sequence)
	order.PutUint32(event[4:8], e.Event)
	order.PutUint32(event[8:12], e.Window)
	order.PutUint16(event[12:14], uint16(e.X))
	order.PutUint16(event[14:16], uint16(e.Y))
	// event[16:32] is unused
	return event
}

// ResizeRequestEvent represents a ResizeRequest event (opcode 25).
type ResizeRequestEvent struct {
	Sequence      uint16 // Sequence number
	Window        uint32 // Window ID
	Width, Height uint16 // Requested dimensions
}

// EventCode returns the event code.
func (e *ResizeRequestEvent) EventCode() uint8 { return 25 }

// EncodeMessage encodes the ResizeRequestEvent into a byte slice.
func (e *ResizeRequestEvent) EncodeMessage(order binary.ByteOrder) []byte {
	event := make([]byte, 32)
	event[0] = 25 // ResizeRequest event code
	// byte 1 is unused
	order.PutUint16(event[2:4], e.Sequence)
	order.PutUint32(event[4:8], e.Window)
	order.PutUint16(event[8:10], e.Width)
	order.PutUint16(event[10:12], e.Height)
	// event[12:32] is unused
	return event
}

// CirculateNotifyEvent represents a CirculateNotify event (opcode 26).
type CirculateNotifyEvent struct {
	Sequence uint16 // Sequence number
	Event    uint32 // Event window ID
	Window   uint32 // Window ID
	Place    byte   // Place (PlaceOnTop, PlaceOnBottom)
}

// EventCode returns the event code.
func (e *CirculateNotifyEvent) EventCode() uint8 { return 26 }

// EncodeMessage encodes the CirculateNotifyEvent into a byte slice.
func (e *CirculateNotifyEvent) EncodeMessage(order binary.ByteOrder) []byte {
	event := make([]byte, 32)
	event[0] = 26 // CirculateNotify event code
	// byte 1 is unused
	order.PutUint16(event[2:4], e.Sequence)
	order.PutUint32(event[4:8], e.Event)
	order.PutUint32(event[8:12], e.Window)
	event[16] = e.Place
	// event[17:32] is unused
	return event
}

// CirculateRequestEvent represents a CirculateRequest event (opcode 27).
type CirculateRequestEvent struct {
	Sequence uint16 // Sequence number
	Parent   uint32 // Parent window ID
	Window   uint32 // Window ID
	Place    byte   // Place (PlaceOnTop, PlaceOnBottom)
}

// EventCode returns the event code.
func (e *CirculateRequestEvent) EventCode() uint8 { return 27 }

// EncodeMessage encodes the CirculateRequestEvent into a byte slice.
func (e *CirculateRequestEvent) EncodeMessage(order binary.ByteOrder) []byte {
	event := make([]byte, 32)
	event[0] = 27 // CirculateRequest event code
	// byte 1 is unused
	order.PutUint16(event[2:4], e.Sequence)
	order.PutUint32(event[4:8], e.Parent)
	order.PutUint32(event[8:12], e.Window)
	event[16] = e.Place
	// event[17:32] is unused
	return event
}

// PropertyNotifyEvent represents a PropertyNotify event (opcode 28).
type PropertyNotifyEvent struct {
	Sequence uint16 // Sequence number
	Window   uint32 // Window ID
	Atom     uint32 // Property atom
	Time     uint32 // Time of change
	State    byte   // State (PropertyNewValue, PropertyDelete)
}

// EventCode returns the event code.
func (e *PropertyNotifyEvent) EventCode() uint8 { return 28 }

// EncodeMessage encodes the PropertyNotifyEvent into a byte slice.
func (e *PropertyNotifyEvent) EncodeMessage(order binary.ByteOrder) []byte {
	event := make([]byte, 32)
	event[0] = 28 // PropertyNotify event code
	// byte 1 is unused
	order.PutUint16(event[2:4], e.Sequence)
	order.PutUint32(event[4:8], e.Window)
	order.PutUint32(event[8:12], e.Atom)
	order.PutUint32(event[12:16], e.Time)
	event[16] = e.State
	// event[17:32] is unused
	return event
}

// SelectionClearEvent represents a SelectionClear event (opcode 29).
type SelectionClearEvent struct {
	Sequence  uint16 // Sequence number
	Owner     uint32 // Window losing ownership
	Selection uint32 // Selection atom
	Time      uint32 // Last change time
}

// EventCode returns the event code.
func (e *SelectionClearEvent) EventCode() uint8 { return 29 }

// EncodeMessage encodes the SelectionClearEvent into a byte slice.
func (e *SelectionClearEvent) EncodeMessage(order binary.ByteOrder) []byte {
	event := make([]byte, 32)
	event[0] = 29 // SelectionClear event code
	// byte 1 is unused
	order.PutUint16(event[2:4], e.Sequence)
	order.PutUint32(event[4:8], e.Time)
	order.PutUint32(event[8:12], e.Owner)
	order.PutUint32(event[12:16], e.Selection)
	// event[16:32] is unused
	return event
}

// SelectionRequestEvent represents a SelectionRequest event (opcode 30).
type SelectionRequestEvent struct {
	Sequence  uint16 // Sequence number
	Owner     uint32 // Owner window ID
	Requestor uint32 // Requestor window ID
	Selection uint32 // Selection atom
	Target    uint32 // Target atom
	Property  uint32 // Property atom
	Time      uint32 // Request time
}

// EventCode returns the event code.
func (e *SelectionRequestEvent) EventCode() uint8 { return 30 }

// EncodeMessage encodes the SelectionRequestEvent into a byte slice.
func (e *SelectionRequestEvent) EncodeMessage(order binary.ByteOrder) []byte {
	event := make([]byte, 32)
	event[0] = 30 // SelectionRequest event code
	// byte 1 is unused
	order.PutUint16(event[2:4], e.Sequence)
	order.PutUint32(event[4:8], e.Time)
	order.PutUint32(event[8:12], e.Owner)
	order.PutUint32(event[12:16], e.Requestor)
	order.PutUint32(event[16:20], e.Selection)
	order.PutUint32(event[20:24], e.Target)
	order.PutUint32(event[24:28], e.Property)
	return event
}

// MappingNotifyEvent represents a MappingNotify event (opcode 34).
type MappingNotifyEvent struct {
	Sequence     uint16 // Sequence number
	Request      byte   // Request (MappingModifier, MappingKeyboard, MappingPointer)
	FirstKeycode byte   // First keycode changed
	Count        byte   // Number of keycodes changed
}

// EventCode returns the event code.
func (e *MappingNotifyEvent) EventCode() uint8 { return 34 }

// EncodeMessage encodes the MappingNotifyEvent into a byte slice.
func (e *MappingNotifyEvent) EncodeMessage(order binary.ByteOrder) []byte {
	event := make([]byte, 32)
	event[0] = 34 // MappingNotify event code
	// byte 1 is unused
	order.PutUint16(event[2:4], e.Sequence)
	event[4] = e.Request
	event[5] = e.FirstKeycode
	event[6] = e.Count
	// event[7:32] is unused
	return event
}

// GenericEventData represents a GenericEvent (opcode 35), used for extensions like XInput2.
type GenericEventData struct {
	Sequence  uint16 // Sequence number
	Extension byte   // Extension opcode
	EventType uint16 // Extension event type
	Length    uint32 // Length of event data
	EventData []byte // Raw event data
}

// EventCode returns the event code.
func (e *GenericEventData) EventCode() uint8 { return 35 }

// EncodeMessage encodes the GenericEventData into a byte slice.
func (e *GenericEventData) EncodeMessage(order binary.ByteOrder) []byte {
	event := make([]byte, 32)
	event[0] = 35 // GenericEvent event code
	event[1] = e.Extension
	order.PutUint16(event[2:4], e.Sequence)
	order.PutUint32(event[4:8], e.Length)
	order.PutUint16(event[8:10], e.EventType)
	copy(event[12:32], e.EventData)
	return event
}

// EncodeMessage encodes the DeviceMotionNotifyEvent into a byte slice.
func (e *DeviceMotionNotifyEvent) EncodeMessage(order binary.ByteOrder) []byte {
	buf := make([]byte, 32)
	buf[0] = e.BaseEventCode + DeviceMotionNotify
	buf[1] = 6 // DeviceMotionNotify
	order.PutUint16(buf[2:4], e.Sequence)
	order.PutUint32(buf[4:8], e.Time)
	order.PutUint32(buf[8:12], e.Root)
	order.PutUint32(buf[12:16], e.Event)
	order.PutUint32(buf[16:20], e.Child)
	order.PutUint16(buf[20:22], uint16(e.RootX))
	order.PutUint16(buf[22:24], uint16(e.RootY))
	order.PutUint16(buf[24:26], uint16(e.EventX))
	order.PutUint16(buf[26:28], uint16(e.EventY))
	order.PutUint16(buf[28:30], e.State)
	buf[30] = e.DeviceID
	buf[31] = e.Detail
	return buf
}

// EventCode returns the event code.
func (e *DeviceMotionNotifyEvent) EventCode() uint8 { return byte(XInputOpcode) }

// EncodeMessage encodes the ProximityInEvent into a byte slice.
func (e *ProximityInEvent) EncodeMessage(order binary.ByteOrder) []byte {
	buf := make([]byte, 32)
	buf[0] = e.BaseEventCode + ProximityIn
	buf[1] = 8 // ProximityIn
	order.PutUint16(buf[2:4], e.Sequence)
	order.PutUint32(buf[4:8], e.Time)
	order.PutUint32(buf[8:12], e.Root)
	order.PutUint32(buf[12:16], e.Event)
	order.PutUint32(buf[16:20], e.Child)
	order.PutUint16(buf[20:22], uint16(e.RootX))
	order.PutUint16(buf[22:24], uint16(e.RootY))
	order.PutUint16(buf[24:26], uint16(e.EventX))
	order.PutUint16(buf[26:28], uint16(e.EventY))
	order.PutUint16(buf[28:30], e.State)
	buf[30] = e.DeviceID
	buf[31] = e.Detail
	return buf
}

// EventCode returns the event code.
func (e *ProximityInEvent) EventCode() uint8 { return byte(XInputOpcode) }

// EncodeMessage encodes the ProximityOutEvent into a byte slice.
func (e *ProximityOutEvent) EncodeMessage(order binary.ByteOrder) []byte {
	buf := make([]byte, 32)
	buf[0] = e.BaseEventCode + ProximityOut
	buf[1] = 9 // ProximityOut
	order.PutUint16(buf[2:4], e.Sequence)
	order.PutUint32(buf[4:8], e.Time)
	order.PutUint32(buf[8:12], e.Root)
	order.PutUint32(buf[12:16], e.Event)
	order.PutUint32(buf[16:20], e.Child)
	order.PutUint16(buf[20:22], uint16(e.RootX))
	order.PutUint16(buf[22:24], uint16(e.RootY))
	order.PutUint16(buf[24:26], uint16(e.EventX))
	order.PutUint16(buf[26:28], uint16(e.EventY))
	order.PutUint16(buf[28:30], e.State)
	buf[30] = e.DeviceID
	buf[31] = e.Detail
	return buf
}

// ParseKeyEvent parses a KeyPress or KeyRelease event.
func ParseKeyEvent(buf []byte, order binary.ByteOrder) (*KeyEvent, error) {
	e := &KeyEvent{}
	e.Opcode = buf[0]
	e.Detail = buf[1]
	e.Sequence = order.Uint16(buf[2:4])
	e.Time = order.Uint32(buf[4:8])
	e.Root = order.Uint32(buf[8:12])
	e.Event = order.Uint32(buf[12:16])
	e.Child = order.Uint32(buf[16:20])
	e.RootX = int16(order.Uint16(buf[20:22]))
	e.RootY = int16(order.Uint16(buf[22:24]))
	e.EventX = int16(order.Uint16(buf[24:26]))
	e.EventY = int16(order.Uint16(buf[26:28]))
	e.State = order.Uint16(buf[28:30])
	e.SameScreen = ByteToBool(buf[30])
	return e, nil
}

// ParseButtonPressEvent parses a ButtonPress event.
func ParseButtonPressEvent(buf []byte, order binary.ByteOrder) (*ButtonPressEvent, error) {
	e := &ButtonPressEvent{}
	e.Detail = buf[1]
	e.Sequence = order.Uint16(buf[2:4])
	e.Time = order.Uint32(buf[4:8])
	e.Root = order.Uint32(buf[8:12])
	e.Event = order.Uint32(buf[12:16])
	e.Child = order.Uint32(buf[16:20])
	e.RootX = int16(order.Uint16(buf[20:22]))
	e.RootY = int16(order.Uint16(buf[22:24]))
	e.EventX = int16(order.Uint16(buf[24:26]))
	e.EventY = int16(order.Uint16(buf[26:28]))
	e.State = order.Uint16(buf[28:30])
	e.SameScreen = ByteToBool(buf[30])
	return e, nil
}

// ParseDeviceButtonReleaseEvent parses an XInput DeviceButtonRelease event.
func ParseDeviceButtonReleaseEvent(buf []byte, order binary.ByteOrder) (*DeviceButtonReleaseEvent, error) {
	e := &DeviceButtonReleaseEvent{}
	e.BaseEventCode = buf[0] - DeviceButtonRelease
	e.Sequence = order.Uint16(buf[2:4])
	e.Time = order.Uint32(buf[4:8])
	e.Root = order.Uint32(buf[8:12])
	e.Event = order.Uint32(buf[12:16])
	e.Child = order.Uint32(buf[16:20])
	e.RootX = int16(order.Uint16(buf[20:22]))
	e.RootY = int16(order.Uint16(buf[22:24]))
	e.EventX = int16(order.Uint16(buf[24:26]))
	e.EventY = int16(order.Uint16(buf[26:28]))
	e.State = order.Uint16(buf[28:30])
	e.DeviceID = buf[30]
	e.Button = buf[31]
	return e, nil
}

// ParseButtonReleaseEvent parses a ButtonRelease event.
func ParseButtonReleaseEvent(buf []byte, order binary.ByteOrder) (*ButtonReleaseEvent, error) {
	e := &ButtonReleaseEvent{}
	e.Detail = buf[1]
	e.Sequence = order.Uint16(buf[2:4])
	e.Time = order.Uint32(buf[4:8])
	e.Root = order.Uint32(buf[8:12])
	e.Event = order.Uint32(buf[12:16])
	e.Child = order.Uint32(buf[16:20])
	e.RootX = int16(order.Uint16(buf[20:22]))
	e.RootY = int16(order.Uint16(buf[22:24]))
	e.EventX = int16(order.Uint16(buf[24:26]))
	e.EventY = int16(order.Uint16(buf[26:28]))
	e.State = order.Uint16(buf[28:30])
	e.SameScreen = ByteToBool(buf[30])
	return e, nil
}

// ParseMotionNotifyEvent parses a MotionNotify event.
func ParseMotionNotifyEvent(buf []byte, order binary.ByteOrder) (*MotionNotifyEvent, error) {
	e := &MotionNotifyEvent{}
	e.Detail = buf[1]
	e.Sequence = order.Uint16(buf[2:4])
	e.Time = order.Uint32(buf[4:8])
	e.Root = order.Uint32(buf[8:12])
	e.Event = order.Uint32(buf[12:16])
	e.Child = order.Uint32(buf[16:20])
	e.RootX = int16(order.Uint16(buf[20:22]))
	e.RootY = int16(order.Uint16(buf[22:24]))
	e.EventX = int16(order.Uint16(buf[24:26]))
	e.EventY = int16(order.Uint16(buf[26:28]))
	e.State = order.Uint16(buf[28:30])
	e.SameScreen = ByteToBool(buf[30])
	return e, nil
}

// ParseEnterNotifyEvent parses an EnterNotify event.
func ParseEnterNotifyEvent(buf []byte, order binary.ByteOrder) (*EnterNotifyEvent, error) {
	e := &EnterNotifyEvent{}
	e.Detail = buf[1]
	e.Sequence = order.Uint16(buf[2:4])
	e.Time = order.Uint32(buf[4:8])
	e.Root = order.Uint32(buf[8:12])
	e.Event = order.Uint32(buf[12:16])
	e.Child = order.Uint32(buf[16:20])
	e.RootX = int16(order.Uint16(buf[20:22]))
	e.RootY = int16(order.Uint16(buf[22:24]))
	e.EventX = int16(order.Uint16(buf[24:26]))
	e.EventY = int16(order.Uint16(buf[26:28]))
	e.State = order.Uint16(buf[28:30])
	e.Mode = buf[30]
	e.SameScreen = (buf[31] & 1) != 0
	e.Focus = (buf[31] & 2) != 0
	return e, nil
}

// ParseLeaveNotifyEvent parses a LeaveNotify event.
func ParseLeaveNotifyEvent(buf []byte, order binary.ByteOrder) (*LeaveNotifyEvent, error) {
	e := &LeaveNotifyEvent{}
	e.Detail = buf[1]
	e.Sequence = order.Uint16(buf[2:4])
	e.Time = order.Uint32(buf[4:8])
	e.Root = order.Uint32(buf[8:12])
	e.Event = order.Uint32(buf[12:16])
	e.Child = order.Uint32(buf[16:20])
	e.RootX = int16(order.Uint16(buf[20:22]))
	e.RootY = int16(order.Uint16(buf[22:24]))
	e.EventX = int16(order.Uint16(buf[24:26]))
	e.EventY = int16(order.Uint16(buf[26:28]))
	e.State = order.Uint16(buf[28:30])
	e.Mode = buf[30]
	e.SameScreen = (buf[31] & 1) != 0
	e.Focus = (buf[31] & 2) != 0
	return e, nil
}

// ParseExposeEvent parses an Expose event.
func ParseExposeEvent(buf []byte, order binary.ByteOrder) (*ExposeEvent, error) {
	e := &ExposeEvent{}
	e.Sequence = order.Uint16(buf[2:4])
	e.Window = order.Uint32(buf[4:8])
	e.X = order.Uint16(buf[8:10])
	e.Y = order.Uint16(buf[10:12])
	e.Width = order.Uint16(buf[12:14])
	e.Height = order.Uint16(buf[14:16])
	e.Count = order.Uint16(buf[16:18])
	return e, nil
}

// ParseConfigureNotifyEvent parses a ConfigureNotify event.
func ParseConfigureNotifyEvent(buf []byte, order binary.ByteOrder) (*ConfigureNotifyEvent, error) {
	e := &ConfigureNotifyEvent{}
	e.Sequence = order.Uint16(buf[2:4])
	e.Event = order.Uint32(buf[4:8])
	e.Window = order.Uint32(buf[8:12])
	e.AboveSibling = order.Uint32(buf[12:16])
	e.X = int16(order.Uint16(buf[16:18]))
	e.Y = int16(order.Uint16(buf[18:20]))
	e.Width = order.Uint16(buf[20:22])
	e.Height = order.Uint16(buf[22:24])
	e.BorderWidth = order.Uint16(buf[24:26])
	e.OverrideRedirect = ByteToBool(buf[26])
	return e, nil
}

// ParseSelectionNotifyEvent parses a SelectionNotify event.
func ParseSelectionNotifyEvent(buf []byte, order binary.ByteOrder) (*SelectionNotifyEvent, error) {
	e := &SelectionNotifyEvent{}
	e.Sequence = order.Uint16(buf[2:4])
	e.Requestor = order.Uint32(buf[4:8])
	e.Selection = order.Uint32(buf[8:12])
	e.Target = order.Uint32(buf[12:16])
	e.Property = order.Uint32(buf[16:20])
	e.Time = order.Uint32(buf[20:24])
	return e, nil
}

// ParseColormapNotifyEvent parses a ColormapNotify event.
func ParseColormapNotifyEvent(buf []byte, order binary.ByteOrder) (*ColormapNotifyEvent, error) {
	e := &ColormapNotifyEvent{}
	e.Sequence = order.Uint16(buf[2:4])
	e.Window = order.Uint32(buf[4:8])
	e.Colormap = order.Uint32(buf[8:12])
	e.New = ByteToBool(buf[12])
	e.State = buf[13]
	return e, nil
}

// ParseClientMessageEvent parses a ClientMessage event.
func ParseClientMessageEvent(buf []byte, order binary.ByteOrder) (*ClientMessageEvent, error) {
	e := &ClientMessageEvent{}
	e.Format = buf[1]
	e.Sequence = order.Uint16(buf[2:4])
	e.Window = order.Uint32(buf[4:8])
	e.MessageType = order.Uint32(buf[8:12])
	copy(e.Data[:], buf[12:32])
	return e, nil
}

// ParseDeviceKeyPressEvent parses an XInput DeviceKeyPress event.
func ParseDeviceKeyPressEvent(buf []byte, order binary.ByteOrder) (*DeviceKeyPressEvent, error) {
	e := &DeviceKeyPressEvent{}
	e.BaseEventCode = buf[0] - DeviceKeyPress
	e.Sequence = order.Uint16(buf[2:4])
	e.Time = order.Uint32(buf[4:8])
	e.Root = order.Uint32(buf[8:12])
	e.Event = order.Uint32(buf[12:16])
	e.Child = order.Uint32(buf[16:20])
	e.RootX = int16(order.Uint16(buf[20:22]))
	e.RootY = int16(order.Uint16(buf[22:24]))
	e.EventX = int16(order.Uint16(buf[24:26]))
	e.EventY = int16(order.Uint16(buf[26:28]))
	e.State = order.Uint16(buf[28:30])
	e.DeviceID = buf[30]
	e.KeyCode = buf[31]
	return e, nil
}

// ParseDeviceKeyReleaseEvent parses an XInput DeviceKeyRelease event.
func ParseDeviceKeyReleaseEvent(buf []byte, order binary.ByteOrder) (*DeviceKeyReleaseEvent, error) {
	e := &DeviceKeyReleaseEvent{}
	e.BaseEventCode = buf[0] - DeviceKeyRelease
	e.Sequence = order.Uint16(buf[2:4])
	e.Time = order.Uint32(buf[4:8])
	e.Root = order.Uint32(buf[8:12])
	e.Event = order.Uint32(buf[12:16])
	e.Child = order.Uint32(buf[16:20])
	e.RootX = int16(order.Uint16(buf[20:22]))
	e.RootY = int16(order.Uint16(buf[22:24]))
	e.EventX = int16(order.Uint16(buf[24:26]))
	e.EventY = int16(order.Uint16(buf[26:28]))
	e.State = order.Uint16(buf[28:30])
	e.DeviceID = buf[30]
	e.KeyCode = buf[31]
	return e, nil
}

// ParseDeviceButtonPressEvent parses an XInput DeviceButtonPress event.
func ParseDeviceButtonPressEvent(buf []byte, order binary.ByteOrder) (*DeviceButtonPressEvent, error) {
	e := &DeviceButtonPressEvent{}
	e.BaseEventCode = buf[0] - DeviceButtonPress
	e.Sequence = order.Uint16(buf[2:4])
	e.Time = order.Uint32(buf[4:8])
	e.Root = order.Uint32(buf[8:12])
	e.Event = order.Uint32(buf[12:16])
	e.Child = order.Uint32(buf[16:20])
	e.RootX = int16(order.Uint16(buf[20:22]))
	e.RootY = int16(order.Uint16(buf[22:24]))
	e.EventX = int16(order.Uint16(buf[24:26]))
	e.EventY = int16(order.Uint16(buf[26:28]))
	e.State = order.Uint16(buf[28:30])
	e.DeviceID = buf[30]
	e.Detail = buf[31]
	return e, nil
}

// ParseGraphicsExposureEvent parses a GraphicsExposure event.
func ParseGraphicsExposureEvent(buf []byte, order binary.ByteOrder) (*GraphicsExposureEvent, error) {
	e := &GraphicsExposureEvent{}
	e.Sequence = order.Uint16(buf[2:4])
	e.Drawable = order.Uint32(buf[4:8])
	e.X = order.Uint16(buf[8:10])
	e.Y = order.Uint16(buf[10:12])
	e.Width = order.Uint16(buf[12:14])
	e.Height = order.Uint16(buf[14:16])
	e.MinorOpcode = order.Uint16(buf[16:18])
	e.Count = order.Uint16(buf[18:20])
	e.MajorOpcode = buf[20]
	return e, nil
}

// ParseNoExposureEvent parses a NoExposure event.
func ParseNoExposureEvent(buf []byte, order binary.ByteOrder) (*NoExposureEvent, error) {
	e := &NoExposureEvent{}
	e.Sequence = order.Uint16(buf[2:4])
	e.Drawable = order.Uint32(buf[4:8])
	e.MinorOpcode = order.Uint16(buf[8:10])
	e.MajorOpcode = buf[10]
	return e, nil
}

// ParseVisibilityNotifyEvent parses a VisibilityNotify event.
func ParseVisibilityNotifyEvent(buf []byte, order binary.ByteOrder) (*VisibilityNotifyEvent, error) {
	e := &VisibilityNotifyEvent{}
	e.Sequence = order.Uint16(buf[2:4])
	e.Window = order.Uint32(buf[4:8])
	e.State = buf[8]
	return e, nil
}

// ParseCreateNotifyEvent parses a CreateNotify event.
func ParseCreateNotifyEvent(buf []byte, order binary.ByteOrder) (*CreateNotifyEvent, error) {
	e := &CreateNotifyEvent{}
	e.Sequence = order.Uint16(buf[2:4])
	e.Parent = order.Uint32(buf[4:8])
	e.Window = order.Uint32(buf[8:12])
	e.X = int16(order.Uint16(buf[12:14]))
	e.Y = int16(order.Uint16(buf[14:16]))
	e.Width = order.Uint16(buf[16:18])
	e.Height = order.Uint16(buf[18:20])
	e.BorderWidth = order.Uint16(buf[20:22])
	e.OverrideRedirect = ByteToBool(buf[22])
	return e, nil
}

// ParseDestroyNotifyEvent parses a DestroyNotify event.
func ParseDestroyNotifyEvent(buf []byte, order binary.ByteOrder) (*DestroyNotifyEvent, error) {
	e := &DestroyNotifyEvent{}
	e.Sequence = order.Uint16(buf[2:4])
	e.Event = order.Uint32(buf[4:8])
	e.Window = order.Uint32(buf[8:12])
	return e, nil
}

// ParseUnmapNotifyEvent parses an UnmapNotify event.
func ParseUnmapNotifyEvent(buf []byte, order binary.ByteOrder) (*UnmapNotifyEvent, error) {
	e := &UnmapNotifyEvent{}
	e.Sequence = order.Uint16(buf[2:4])
	e.Event = order.Uint32(buf[4:8])
	e.Window = order.Uint32(buf[8:12])
	e.FromConfigure = ByteToBool(buf[12])
	return e, nil
}

// ParseMapNotifyEvent parses a MapNotify event.
func ParseMapNotifyEvent(buf []byte, order binary.ByteOrder) (*MapNotifyEvent, error) {
	e := &MapNotifyEvent{}
	e.Sequence = order.Uint16(buf[2:4])
	e.Event = order.Uint32(buf[4:8])
	e.Window = order.Uint32(buf[8:12])
	e.OverrideRedirect = ByteToBool(buf[12])
	return e, nil
}

// ParseMapRequestEvent parses a MapRequest event.
func ParseMapRequestEvent(buf []byte, order binary.ByteOrder) (*MapRequestEvent, error) {
	e := &MapRequestEvent{}
	e.Sequence = order.Uint16(buf[2:4])
	e.Parent = order.Uint32(buf[4:8])
	e.Window = order.Uint32(buf[8:12])
	return e, nil
}

// ParseReparentNotifyEvent parses a ReparentNotify event.
func ParseReparentNotifyEvent(buf []byte, order binary.ByteOrder) (*ReparentNotifyEvent, error) {
	e := &ReparentNotifyEvent{}
	e.Sequence = order.Uint16(buf[2:4])
	e.Event = order.Uint32(buf[4:8])
	e.Window = order.Uint32(buf[8:12])
	e.Parent = order.Uint32(buf[12:16])
	e.X = int16(order.Uint16(buf[16:18]))
	e.Y = int16(order.Uint16(buf[18:20]))
	e.OverrideRedirect = ByteToBool(buf[20])
	return e, nil
}

// ParseConfigureRequestEvent parses a ConfigureRequest event.
func ParseConfigureRequestEvent(buf []byte, order binary.ByteOrder) (*ConfigureRequestEvent, error) {
	e := &ConfigureRequestEvent{}
	e.StackMode = buf[1]
	e.Sequence = order.Uint16(buf[2:4])
	e.Parent = order.Uint32(buf[4:8])
	e.Window = order.Uint32(buf[8:12])
	e.Sibling = order.Uint32(buf[12:16])
	e.X = int16(order.Uint16(buf[16:18]))
	e.Y = int16(order.Uint16(buf[18:20]))
	e.Width = order.Uint16(buf[20:22])
	e.Height = order.Uint16(buf[22:24])
	e.BorderWidth = order.Uint16(buf[24:26])
	e.ValueMask = order.Uint16(buf[26:28])
	return e, nil
}

// ParseGravityNotifyEvent parses a GravityNotify event.
func ParseGravityNotifyEvent(buf []byte, order binary.ByteOrder) (*GravityNotifyEvent, error) {
	e := &GravityNotifyEvent{}
	e.Sequence = order.Uint16(buf[2:4])
	e.Event = order.Uint32(buf[4:8])
	e.Window = order.Uint32(buf[8:12])
	e.X = int16(order.Uint16(buf[12:14]))
	e.Y = int16(order.Uint16(buf[14:16]))
	return e, nil
}

// ParseResizeRequestEvent parses a ResizeRequest event.
func ParseResizeRequestEvent(buf []byte, order binary.ByteOrder) (*ResizeRequestEvent, error) {
	e := &ResizeRequestEvent{}
	e.Sequence = order.Uint16(buf[2:4])
	e.Window = order.Uint32(buf[4:8])
	e.Width = order.Uint16(buf[8:10])
	e.Height = order.Uint16(buf[10:12])
	return e, nil
}

// ParseCirculateNotifyEvent parses a CirculateNotify event.
func ParseCirculateNotifyEvent(buf []byte, order binary.ByteOrder) (*CirculateNotifyEvent, error) {
	e := &CirculateNotifyEvent{}
	e.Sequence = order.Uint16(buf[2:4])
	e.Event = order.Uint32(buf[4:8])
	e.Window = order.Uint32(buf[8:12])
	e.Place = buf[16]
	return e, nil
}

// ParseCirculateRequestEvent parses a CirculateRequest event.
func ParseCirculateRequestEvent(buf []byte, order binary.ByteOrder) (*CirculateRequestEvent, error) {
	e := &CirculateRequestEvent{}
	e.Sequence = order.Uint16(buf[2:4])
	e.Parent = order.Uint32(buf[4:8])
	e.Window = order.Uint32(buf[8:12])
	e.Place = buf[16]
	return e, nil
}

// ParsePropertyNotifyEvent parses a PropertyNotify event.
func ParsePropertyNotifyEvent(buf []byte, order binary.ByteOrder) (*PropertyNotifyEvent, error) {
	e := &PropertyNotifyEvent{}
	e.Sequence = order.Uint16(buf[2:4])
	e.Window = order.Uint32(buf[4:8])
	e.Atom = order.Uint32(buf[8:12])
	e.Time = order.Uint32(buf[12:16])
	e.State = buf[16]
	return e, nil
}

// ParseSelectionClearEvent parses a SelectionClear event.
func ParseSelectionClearEvent(buf []byte, order binary.ByteOrder) (*SelectionClearEvent, error) {
	e := &SelectionClearEvent{}
	e.Sequence = order.Uint16(buf[2:4])
	e.Time = order.Uint32(buf[4:8])
	e.Owner = order.Uint32(buf[8:12])
	e.Selection = order.Uint32(buf[12:16])
	return e, nil
}

// ParseSelectionRequestEvent parses a SelectionRequest event.
func ParseSelectionRequestEvent(buf []byte, order binary.ByteOrder) (*SelectionRequestEvent, error) {
	e := &SelectionRequestEvent{}
	e.Sequence = order.Uint16(buf[2:4])
	e.Time = order.Uint32(buf[4:8])
	e.Owner = order.Uint32(buf[8:12])
	e.Requestor = order.Uint32(buf[12:16])
	e.Selection = order.Uint32(buf[16:20])
	e.Target = order.Uint32(buf[20:24])
	e.Property = order.Uint32(buf[24:28])
	return e, nil
}

// ParseMappingNotifyEvent parses a MappingNotify event.
func ParseMappingNotifyEvent(buf []byte, order binary.ByteOrder) (*MappingNotifyEvent, error) {
	e := &MappingNotifyEvent{}
	e.Sequence = order.Uint16(buf[2:4])
	e.Request = buf[4]
	e.FirstKeycode = buf[5]
	e.Count = buf[6]
	return e, nil
}

// ParseGenericEvent parses a GenericEvent (XGE).
func ParseGenericEvent(buf []byte, order binary.ByteOrder) (*GenericEventData, error) {
	e := &GenericEventData{}
	e.Extension = buf[1]
	e.Sequence = order.Uint16(buf[2:4])
	e.Length = order.Uint32(buf[4:8])
	e.EventType = order.Uint16(buf[8:10])
	e.EventData = buf[12:32]
	return e, nil
}

// ParseDeviceMotionNotifyEvent parses an XInput DeviceMotionNotify event.
func ParseDeviceMotionNotifyEvent(buf []byte, order binary.ByteOrder) (*DeviceMotionNotifyEvent, error) {
	e := &DeviceMotionNotifyEvent{}
	e.BaseEventCode = buf[0] - DeviceMotionNotify
	e.Sequence = order.Uint16(buf[2:4])
	e.Time = order.Uint32(buf[4:8])
	e.Root = order.Uint32(buf[8:12])
	e.Event = order.Uint32(buf[12:16])
	e.Child = order.Uint32(buf[16:20])
	e.RootX = int16(order.Uint16(buf[20:22]))
	e.RootY = int16(order.Uint16(buf[22:24]))
	e.EventX = int16(order.Uint16(buf[24:26]))
	e.EventY = int16(order.Uint16(buf[26:28]))
	e.State = order.Uint16(buf[28:30])
	e.DeviceID = buf[30]
	e.Detail = buf[31]
	return e, nil
}

// ParseProximityInEvent parses an XInput ProximityIn event.
func ParseProximityInEvent(buf []byte, order binary.ByteOrder) (*ProximityInEvent, error) {
	e := &ProximityInEvent{}
	e.BaseEventCode = buf[0] - ProximityIn
	e.Sequence = order.Uint16(buf[2:4])
	e.Time = order.Uint32(buf[4:8])
	e.Root = order.Uint32(buf[8:12])
	e.Event = order.Uint32(buf[12:16])
	e.Child = order.Uint32(buf[16:20])
	e.RootX = int16(order.Uint16(buf[20:22]))
	e.RootY = int16(order.Uint16(buf[22:24]))
	e.EventX = int16(order.Uint16(buf[24:26]))
	e.EventY = int16(order.Uint16(buf[26:28]))
	e.State = order.Uint16(buf[28:30])
	e.DeviceID = buf[30]
	e.Detail = buf[31]
	return e, nil
}

// ParseProximityOutEvent parses an XInput ProximityOut event.
func ParseProximityOutEvent(buf []byte, order binary.ByteOrder) (*ProximityOutEvent, error) {
	e := &ProximityOutEvent{}
	e.BaseEventCode = buf[0] - ProximityOut
	e.Sequence = order.Uint16(buf[2:4])
	e.Time = order.Uint32(buf[4:8])
	e.Root = order.Uint32(buf[8:12])
	e.Event = order.Uint32(buf[12:16])
	e.Child = order.Uint32(buf[16:20])
	e.RootX = int16(order.Uint16(buf[20:22]))
	e.RootY = int16(order.Uint16(buf[22:24]))
	e.EventX = int16(order.Uint16(buf[24:26]))
	e.EventY = int16(order.Uint16(buf[26:28]))
	e.State = order.Uint16(buf[28:30])
	e.DeviceID = buf[30]
	e.Detail = buf[31]
	return e, nil
}

// Event is an interface that all X11 events implement.
type Event interface {
	EventCode() uint8
	// EncodeMessage encodes the event into a byte slice.
	EncodeMessage(order binary.ByteOrder) []byte
}

// ParseEvent parses an X11 event from a byte slice.
func ParseEvent(buf []byte, order binary.ByteOrder) (Event, error) {
	if len(buf) < 32 {
		return nil, fmt.Errorf("event message too short: %d", len(buf))
	}
	switch buf[0] {
	case KeyPress, KeyRelease:
		return ParseKeyEvent(buf, order)
	case ButtonPress:
		return ParseButtonPressEvent(buf, order)
	case ButtonRelease:
		return ParseButtonReleaseEvent(buf, order)
	case MotionNotify:
		return ParseMotionNotifyEvent(buf, order)
	case EnterNotify:
		return ParseEnterNotifyEvent(buf, order)
	case LeaveNotify:
		return ParseLeaveNotifyEvent(buf, order)
	case Expose:
		return ParseExposeEvent(buf, order)
	case ConfigureNotify:
		return ParseConfigureNotifyEvent(buf, order)
	case GraphicsExposure:
		return ParseGraphicsExposureEvent(buf, order)
	case NoExposure:
		return ParseNoExposureEvent(buf, order)
	case VisibilityNotify:
		return ParseVisibilityNotifyEvent(buf, order)
	case CreateNotify:
		return ParseCreateNotifyEvent(buf, order)
	case DestroyNotify:
		return ParseDestroyNotifyEvent(buf, order)
	case UnmapNotify:
		return ParseUnmapNotifyEvent(buf, order)
	case MapNotify:
		return ParseMapNotifyEvent(buf, order)
	case MapRequest:
		return ParseMapRequestEvent(buf, order)
	case ReparentNotify:
		return ParseReparentNotifyEvent(buf, order)
	case ConfigureRequest:
		return ParseConfigureRequestEvent(buf, order)
	case GravityNotify:
		return ParseGravityNotifyEvent(buf, order)
	case ResizeRequest:
		return ParseResizeRequestEvent(buf, order)
	case CirculateNotify:
		return ParseCirculateNotifyEvent(buf, order)
	case CirculateRequest:
		return ParseCirculateRequestEvent(buf, order)
	case PropertyNotify:
		return ParsePropertyNotifyEvent(buf, order)
	case SelectionClear:
		return ParseSelectionClearEvent(buf, order)
	case SelectionRequest:
		return ParseSelectionRequestEvent(buf, order)
	case SelectionNotify:
		return ParseSelectionNotifyEvent(buf, order)
	case ColormapNotifyCode:
		return ParseColormapNotifyEvent(buf, order)
	case ClientMessage:
		return ParseClientMessageEvent(buf, order)
	case MappingNotify:
		return ParseMappingNotifyEvent(buf, order)
	case GenericEvent:
		return ParseGenericEvent(buf, order)
	case byte(XInputOpcode), 66, 67, 68, 69, 70, 71, 72, 73:
		switch buf[1] {
		case DeviceKeyPress:
			return ParseDeviceKeyPressEvent(buf, order)
		case DeviceKeyRelease:
			return ParseDeviceKeyReleaseEvent(buf, order)
		case DeviceButtonPress:
			return ParseDeviceButtonPressEvent(buf, order)
		case DeviceButtonRelease:
			return ParseDeviceButtonReleaseEvent(buf, order)
		case DeviceMotionNotify:
			return ParseDeviceMotionNotifyEvent(buf, order)
		case ProximityIn:
			return ParseProximityInEvent(buf, order)
		case ProximityOut:
			return ParseProximityOutEvent(buf, order)
		}
	}
	return nil, fmt.Errorf("unknown event opcode: %d", buf[0])
}

// DeviceButtonReleaseEvent parses an XInput DeviceButtonRelease event.
func (e *DeviceButtonReleaseEvent) EncodeMessage(order binary.ByteOrder) []byte {
	buf := make([]byte, 32)
	buf[0] = e.BaseEventCode + DeviceButtonRelease
	buf[1] = DeviceButtonRelease
	order.PutUint16(buf[2:4], e.Sequence)
	order.PutUint32(buf[4:8], e.Time)
	order.PutUint32(buf[8:12], e.Root)
	order.PutUint32(buf[12:16], e.Event)
	order.PutUint32(buf[16:20], e.Child)
	order.PutUint16(buf[20:22], uint16(e.RootX))
	order.PutUint16(buf[22:24], uint16(e.RootY))
	order.PutUint16(buf[24:26], uint16(e.EventX))
	order.PutUint16(buf[26:28], uint16(e.EventY))
	order.PutUint16(buf[28:30], e.State)
	buf[30] = e.DeviceID
	buf[31] = e.Button
	return buf
}

// EventCode returns the event code.
func (e *ButtonPressEvent) EventCode() uint8 { return 4 }

// EncodeMessage encodes the ButtonPressEvent into a byte slice.
func (e *ButtonPressEvent) EncodeMessage(order binary.ByteOrder) []byte {
	event := make([]byte, 32)
	event[0] = 4 // ButtonPress event code
	event[1] = e.Detail
	order.PutUint16(event[2:4], e.Sequence)
	order.PutUint32(event[4:8], e.Time)
	order.PutUint32(event[8:12], e.Root)
	order.PutUint32(event[12:16], e.Event)
	order.PutUint32(event[16:20], e.Child)
	order.PutUint16(event[20:22], uint16(e.RootX))
	order.PutUint16(event[22:24], uint16(e.RootY))
	order.PutUint16(event[24:26], uint16(e.EventX))
	order.PutUint16(event[26:28], uint16(e.EventY))
	order.PutUint16(event[28:30], e.State)
	event[30] = BoolToByte(e.SameScreen)
	// event[31] is unused
	return event
}

// ButtonReleaseEvent represents a ButtonRelease event (opcode 5).
type ButtonReleaseEvent struct {
	Sequence       uint16 // Sequence number
	Detail         byte   // button code
	Time           uint32 // Time of event
	Root           uint32 // Root window ID
	Event          uint32 // Event window ID
	Child          uint32 // Child window ID
	RootX, RootY   int16  // Coordinates relative to root
	EventX, EventY int16  // Coordinates relative to event window
	State          uint16 // Key/Button state mask
	SameScreen     bool   // Same screen flag
}

// EventCode returns the event code.
func (e *ButtonReleaseEvent) EventCode() uint8 { return 5 }

// EncodeMessage encodes the ButtonReleaseEvent into a byte slice.
func (e *ButtonReleaseEvent) EncodeMessage(order binary.ByteOrder) []byte {
	event := make([]byte, 32)
	event[0] = 5 // ButtonRelease event code
	event[1] = e.Detail
	order.PutUint16(event[2:4], e.Sequence)
	order.PutUint32(event[4:8], e.Time)
	order.PutUint32(event[8:12], e.Root)
	order.PutUint32(event[12:16], e.Event)
	order.PutUint32(event[16:20], e.Child)
	order.PutUint16(event[20:22], uint16(e.RootX))
	order.PutUint16(event[22:24], uint16(e.RootY))
	order.PutUint16(event[24:26], uint16(e.EventX))
	order.PutUint16(event[26:28], uint16(e.EventY))
	order.PutUint16(event[28:30], e.State)
	event[30] = BoolToByte(e.SameScreen)
	// event[31] is unused
	return event
}

// MotionNotifyEvent represents a MotionNotify event (opcode 6).
type MotionNotifyEvent struct {
	Sequence       uint16 // Sequence number
	Detail         byte   // Detail (Normal or Hint)
	Time           uint32 // Time of event
	Root           uint32 // Root window ID
	Event          uint32 // Event window ID
	Child          uint32 // Child window ID
	RootX, RootY   int16  // Coordinates relative to root
	EventX, EventY int16  // Coordinates relative to event window
	State          uint16 // Key/Button state mask
	SameScreen     bool   // Same screen flag
}

// EventCode returns the event code.
func (e *MotionNotifyEvent) EventCode() uint8 { return 6 }

// EncodeMessage encodes the MotionNotifyEvent into a byte slice.
func (e *MotionNotifyEvent) EncodeMessage(order binary.ByteOrder) []byte {
	event := make([]byte, 32)
	event[0] = 6 // MotionNotify event code
	event[1] = e.Detail
	order.PutUint16(event[2:4], e.Sequence)
	order.PutUint32(event[4:8], e.Time)
	order.PutUint32(event[8:12], e.Root)
	order.PutUint32(event[12:16], e.Event)
	order.PutUint32(event[16:20], e.Child)
	order.PutUint16(event[20:22], uint16(e.RootX))
	order.PutUint16(event[22:24], uint16(e.RootY))
	order.PutUint16(event[24:26], uint16(e.EventX))
	order.PutUint16(event[26:28], uint16(e.EventY))
	order.PutUint16(event[28:30], e.State)
	event[30] = BoolToByte(e.SameScreen)
	// event[31] is unused
	return event
}

// EnterNotifyEvent represents an EnterNotify event (opcode 7).
type EnterNotifyEvent struct {
	Sequence       uint16 // Sequence number
	Detail         byte   // Detail (Ancestor, Virtual, Inferior, Nonlinear, NonlinearVirtual)
	Time           uint32 // Time of event
	Root           uint32 // Root window ID
	Event          uint32 // Event window ID
	Child          uint32 // Child window ID
	RootX, RootY   int16  // Coordinates relative to root
	EventX, EventY int16  // Coordinates relative to event window
	State          uint16 // Key/Button state mask
	Mode           byte   // Mode (Normal, Grab, Ungrab)
	SameScreen     bool   // Same screen flag
	Focus          bool   // Focus flag
}

// EventCode returns the event code.
func (e *EnterNotifyEvent) EventCode() uint8 { return 7 }

// EncodeMessage encodes the EnterNotifyEvent into a byte slice.
func (e *EnterNotifyEvent) EncodeMessage(order binary.ByteOrder) []byte {
	event := make([]byte, 32)
	event[0] = 7 // EnterNotify event code
	event[1] = e.Detail
	order.PutUint16(event[2:4], e.Sequence)
	order.PutUint32(event[4:8], e.Time)
	order.PutUint32(event[8:12], e.Root)
	order.PutUint32(event[12:16], e.Event)
	order.PutUint32(event[16:20], e.Child)
	order.PutUint16(event[20:22], uint16(e.RootX))
	order.PutUint16(event[22:24], uint16(e.RootY))
	order.PutUint16(event[24:26], uint16(e.EventX))
	order.PutUint16(event[26:28], uint16(e.EventY))
	order.PutUint16(event[28:30], e.State)
	event[30] = e.Mode
	var sameScreenFocusByte byte
	if e.SameScreen {
		sameScreenFocusByte |= 1
	}
	if e.Focus {
		sameScreenFocusByte |= 2
	}
	event[31] = sameScreenFocusByte
	return event
}

// LeaveNotifyEvent represents a LeaveNotify event (opcode 8).
type LeaveNotifyEvent struct {
	Sequence       uint16 // Sequence number
	Detail         byte   // Detail (Ancestor, Virtual, Inferior, Nonlinear, NonlinearVirtual)
	Time           uint32 // Time of event
	Root           uint32 // Root window ID
	Event          uint32 // Event window ID
	Child          uint32 // Child window ID
	RootX, RootY   int16  // Coordinates relative to root
	EventX, EventY int16  // Coordinates relative to event window
	State          uint16 // Key/Button state mask
	Mode           byte   // Mode (Normal, Grab, Ungrab)
	SameScreen     bool   // Same screen flag
	Focus          bool   // Focus flag
}

// EventCode returns the event code.
func (e *LeaveNotifyEvent) EventCode() uint8 { return 8 }

// EncodeMessage encodes the LeaveNotifyEvent into a byte slice.
func (e *LeaveNotifyEvent) EncodeMessage(order binary.ByteOrder) []byte {
	event := make([]byte, 32)
	event[0] = 8 // LeaveNotify event code
	event[1] = e.Detail
	order.PutUint16(event[2:4], e.Sequence)
	order.PutUint32(event[4:8], e.Time)
	order.PutUint32(event[8:12], e.Root)
	order.PutUint32(event[12:16], e.Event)
	order.PutUint32(event[16:20], e.Child)
	order.PutUint16(event[20:22], uint16(e.RootX))
	order.PutUint16(event[22:24], uint16(e.RootY))
	order.PutUint16(event[24:26], uint16(e.EventX))
	order.PutUint16(event[26:28], uint16(e.EventY))
	order.PutUint16(event[28:30], e.State)
	event[30] = e.Mode
	var sameScreenFocusByte byte
	if e.SameScreen {
		sameScreenFocusByte |= 1
	}
	if e.Focus {
		sameScreenFocusByte |= 2
	}
	event[31] = sameScreenFocusByte
	return event
}

// FocusInEvent represents a FocusIn event (opcode 9).
type FocusInEvent struct {
	Sequence uint16 // Sequence number
	Detail   byte   // Detail (Ancestor, Virtual, Inferior, Nonlinear, NonlinearVirtual, Pointer, PointerRoot, None)
	Window   uint32 // Event window ID
	Mode     byte   // Mode (Normal, Grab, Ungrab, WhileGrabbed)
}

// EventCode returns the event code.
func (e *FocusInEvent) EventCode() uint8 { return 9 }

// EncodeMessage encodes the FocusInEvent into a byte slice.
func (e *FocusInEvent) EncodeMessage(order binary.ByteOrder) []byte {
	event := make([]byte, 32)
	event[0] = 9 // FocusIn event code
	event[1] = e.Detail
	order.PutUint16(event[2:4], e.Sequence)
	order.PutUint32(event[4:8], e.Window)
	event[8] = e.Mode
	// event[9:32] is unused
	return event
}

// FocusOutEvent represents a FocusOut event (opcode 10).
type FocusOutEvent struct {
	Sequence uint16 // Sequence number
	Detail   byte   // Detail (Ancestor, Virtual, Inferior, Nonlinear, NonlinearVirtual, Pointer, PointerRoot, None)
	Window   uint32 // Event window ID
	Mode     byte   // Mode (Normal, Grab, Ungrab, WhileGrabbed)
}

// EventCode returns the event code.
func (e *FocusOutEvent) EventCode() uint8 { return 10 }

// EncodeMessage encodes the FocusOutEvent into a byte slice.
func (e *FocusOutEvent) EncodeMessage(order binary.ByteOrder) []byte {
	event := make([]byte, 32)
	event[0] = 10 // FocusOut event code
	event[1] = e.Detail
	order.PutUint16(event[2:4], e.Sequence)
	order.PutUint32(event[4:8], e.Window)
	event[8] = e.Mode
	// event[9:32] is unused
	return event
}

// ExposeEvent represents an Expose event (opcode 12).
type ExposeEvent struct {
	Sequence      uint16 // Sequence number
	Window        uint32 // Window ID
	X, Y          uint16 // Top-left coordinate of exposed area
	Width, Height uint16 // Dimensions of exposed area
	Count         uint16 // Number of subsequent Expose events
}

// EventCode returns the event code.
func (e *ExposeEvent) EventCode() uint8 { return 12 }

// EncodeMessage encodes the ExposeEvent into a byte slice.
func (e *ExposeEvent) EncodeMessage(order binary.ByteOrder) []byte {
	event := make([]byte, 32)
	event[0] = 12 // Expose event code
	// byte 1 is unused
	order.PutUint16(event[2:4], e.Sequence)
	order.PutUint32(event[4:8], e.Window)
	order.PutUint16(event[8:10], e.X)
	order.PutUint16(event[10:12], e.Y)
	order.PutUint16(event[12:14], e.Width)
	order.PutUint16(event[14:16], e.Height)
	order.PutUint16(event[16:18], e.Count)
	// event[18:32] is unused
	return event
}

// ConfigureNotifyEvent represents a ConfigureNotify event (opcode 22).
type ConfigureNotifyEvent struct {
	Sequence         uint16 // Sequence number
	Event            uint32 // Event window ID
	Window           uint32 // Configured window ID
	AboveSibling     uint32 // Sibling window ID
	X, Y             int16  // Coordinates
	Width, Height    uint16 // Dimensions
	BorderWidth      uint16 // Border width
	OverrideRedirect bool   // Override-redirect flag
}

// EventCode returns the event code.
func (e *ConfigureNotifyEvent) EventCode() uint8 { return 22 }

// EncodeMessage encodes the ConfigureNotifyEvent into a byte slice.
func (e *ConfigureNotifyEvent) EncodeMessage(order binary.ByteOrder) []byte {
	event := make([]byte, 32)
	event[0] = 22 // ConfigureNotify event code
	// byte 1 is unused
	order.PutUint16(event[2:4], e.Sequence)
	order.PutUint32(event[4:8], e.Event)
	order.PutUint32(event[8:12], e.Window)
	order.PutUint32(event[12:16], e.AboveSibling)
	order.PutUint16(event[16:18], uint16(e.X))
	order.PutUint16(event[18:20], uint16(e.Y))
	order.PutUint16(event[20:22], e.Width)
	order.PutUint16(event[22:24], e.Height)
	order.PutUint16(event[24:26], e.BorderWidth)
	event[26] = BoolToByte(e.OverrideRedirect)
	// byte 27 is unused
	return event
}

// SelectionNotifyEvent represents a SelectionNotify event (opcode 31).
type SelectionNotifyEvent struct {
	Sequence  uint16 // Sequence number
	Requestor uint32 // Requestor window ID
	Selection uint32 // Selection atom
	Target    uint32 // Target atom
	Property  uint32 // Property atom
	Time      uint32 // Time
}

// EventCode returns the event code.
func (e *SelectionNotifyEvent) EventCode() uint8 { return 31 }

// EncodeMessage encodes the SelectionNotifyEvent into a byte slice.
func (e *SelectionNotifyEvent) EncodeMessage(order binary.ByteOrder) []byte {
	event := make([]byte, 32)
	event[0] = 31 // SelectionNotify event code
	// byte 1 is unused
	order.PutUint16(event[2:4], e.Sequence)
	order.PutUint32(event[4:8], e.Requestor)
	order.PutUint32(event[8:12], e.Selection)
	order.PutUint32(event[12:16], e.Target)
	order.PutUint32(event[16:20], e.Property)
	order.PutUint32(event[20:24], e.Time)
	// event[24:32] is unused
	return event
}

// ColormapNotifyEvent represents a ColormapNotify event (opcode 32).
type ColormapNotifyEvent struct {
	Sequence uint16 // Sequence number
	Window   uint32 // Window ID
	Colormap uint32 // Colormap ID
	New      bool   // True if colormap attribute changed, False if colormap installed/uninstalled
	State    byte   // State (ColormapInstalled, ColormapUninstalled)
}

// EventCode returns the event code.
func (e *ColormapNotifyEvent) EventCode() uint8 { return ColormapNotifyCode }

// EncodeMessage encodes the ColormapNotifyEvent into a byte slice.
func (e *ColormapNotifyEvent) EncodeMessage(order binary.ByteOrder) []byte {
	event := make([]byte, 32)
	event[0] = ColormapNotifyCode // ColormapNotify event code
	// byte 1 is unused
	order.PutUint16(event[2:4], e.Sequence)
	order.PutUint32(event[4:8], e.Window)
	order.PutUint32(event[8:12], e.Colormap)
	event[12] = BoolToByte(e.New)
	event[13] = e.State
	// event[14:32] is unused
	return event
}

// ClientMessageEvent represents a ClientMessage event (opcode 33).
type ClientMessageEvent struct {
	Sequence    uint16   // Sequence number
	Format      byte     // Data format (8, 16, or 32)
	Window      uint32   // Window ID
	MessageType uint32   // Message type atom
	Data        [20]byte // Data
}

// EventCode returns the event code.
func (e *ClientMessageEvent) EventCode() uint8 { return 33 }

// EncodeMessage encodes the ClientMessageEvent into a byte slice.
func (e *ClientMessageEvent) EncodeMessage(order binary.ByteOrder) []byte {
	event := make([]byte, 32)
	event[0] = 33 // ClientMessage event code
	event[1] = e.Format
	order.PutUint16(event[2:4], e.Sequence)
	order.PutUint32(event[4:8], e.Window)
	order.PutUint32(event[8:12], e.MessageType)
	copy(event[12:32], e.Data[:])
	return event
}

// X11RawEvent implements messageEncoder for raw X11 event data.
type X11RawEvent struct {
	Data []byte
}

// EventCode returns the event code.
func (e *X11RawEvent) EventCode() uint8 { return e.Data[0] }

// EncodeMessage encodes the X11RawEvent into a byte slice.
func (e *X11RawEvent) EncodeMessage(order binary.ByteOrder) []byte {
	return e.Data
}

// DeviceKeyPressEvent is an XInput key press event.
type DeviceKeyPressEvent struct {
	BaseEventCode uint8  // Base event code
	DeviceID      byte   // Device ID
	Sequence      uint16 // Sequence number
	Time       uint32 // Time of event
	Root       uint32 // Root window ID
	Event      uint32 // Event window ID
	Child      uint32 // Child window ID
	RootX      int16  // Root X coordinate
	RootY      int16  // Root Y coordinate
	EventX     int16  // Event X coordinate
	EventY     int16  // Event Y coordinate
	State      uint16 // Modifier state
	SameScreen bool   // Same screen flag
	KeyCode    byte   // Keycode
}

// EventCode returns the event code.
func (e *DeviceKeyPressEvent) EventCode() uint8 { return byte(XInputOpcode) }

// EncodeMessage encodes the DeviceKeyPressEvent into a byte slice.
func (e *DeviceKeyPressEvent) EncodeMessage(order binary.ByteOrder) []byte {
	buf := make([]byte, 32)
	buf[0] = e.BaseEventCode + DeviceKeyPress
	buf[1] = DeviceKeyPress
	order.PutUint16(buf[2:4], e.Sequence)
	order.PutUint32(buf[4:8], e.Time)
	order.PutUint32(buf[8:12], e.Root)
	order.PutUint32(buf[12:16], e.Event)
	order.PutUint32(buf[16:20], e.Child)
	order.PutUint16(buf[20:22], uint16(e.RootX))
	order.PutUint16(buf[22:24], uint16(e.RootY))
	order.PutUint16(buf[24:26], uint16(e.EventX))
	order.PutUint16(buf[26:28], uint16(e.EventY))
	order.PutUint16(buf[28:30], e.State)
	buf[30] = e.DeviceID
	buf[31] = e.KeyCode
	return buf
}

// DeviceKeyReleaseEvent is an XInput key release event.
type DeviceKeyReleaseEvent struct {
	BaseEventCode uint8  // Base event code
	DeviceID      byte   // Device ID
	Sequence      uint16 // Sequence number
	Time       uint32 // Time of event
	Root       uint32 // Root window ID
	Event      uint32 // Event window ID
	Child      uint32 // Child window ID
	RootX      int16  // Root X coordinate
	RootY      int16  // Root Y coordinate
	EventX     int16  // Event X coordinate
	EventY     int16  // Event Y coordinate
	State      uint16 // Modifier state
	SameScreen bool   // Same screen flag
	KeyCode    byte   // Keycode
}

// EventCode returns the event code.
func (e *DeviceKeyReleaseEvent) EventCode() uint8 { return byte(XInputOpcode) }

// EncodeMessage encodes the DeviceKeyReleaseEvent into a byte slice.
func (e *DeviceKeyReleaseEvent) EncodeMessage(order binary.ByteOrder) []byte {
	buf := make([]byte, 32)
	buf[0] = e.BaseEventCode + DeviceKeyRelease
	buf[1] = DeviceKeyRelease
	order.PutUint16(buf[2:4], e.Sequence)
	order.PutUint32(buf[4:8], e.Time)
	order.PutUint32(buf[8:12], e.Root)
	order.PutUint32(buf[12:16], e.Event)
	order.PutUint32(buf[16:20], e.Child)
	order.PutUint16(buf[20:22], uint16(e.RootX))
	order.PutUint16(buf[22:24], uint16(e.RootY))
	order.PutUint16(buf[24:26], uint16(e.EventX))
	order.PutUint16(buf[26:28], uint16(e.EventY))
	order.PutUint16(buf[28:30], e.State)
	buf[30] = e.DeviceID
	buf[31] = e.KeyCode
	return buf
}

// DeviceButtonPressEvent is an XInput button press event.
type DeviceButtonPressEvent struct {
	BaseEventCode uint8  // Base event code
	DeviceID      byte   // Device ID
	Sequence      uint16 // Sequence number
	Time       uint32 // Time of event
	Root       uint32 // Root window ID
	Event      uint32 // Event window ID
	Child      uint32 // Child window ID
	RootX      int16  // Root X coordinate
	RootY      int16  // Root Y coordinate
	EventX     int16  // Event X coordinate
	EventY     int16  // Event Y coordinate
	State      uint16 // Modifier state
	SameScreen bool   // Same screen flag
	Detail     byte   // Button
}

// EventCode returns the event code.
func (e *DeviceButtonPressEvent) EventCode() uint8 { return byte(XInputOpcode) }

// SetSequence sets the sequence number for the DeviceButtonPressEvent.
func (e *DeviceButtonPressEvent) SetSequence(seq uint16) {
	e.Sequence = seq
}

// EncodeMessage encodes the DeviceButtonPressEvent into a byte slice.
func (e *DeviceButtonPressEvent) EncodeMessage(order binary.ByteOrder) []byte {
	buf := make([]byte, 32)
	buf[0] = e.BaseEventCode + DeviceButtonPress
	buf[1] = DeviceButtonPress
	order.PutUint16(buf[2:4], e.Sequence)
	order.PutUint32(buf[4:8], e.Time)
	order.PutUint32(buf[8:12], e.Root)
	order.PutUint32(buf[12:16], e.Event)
	order.PutUint32(buf[16:20], e.Child)
	order.PutUint16(buf[20:22], uint16(e.RootX))
	order.PutUint16(buf[22:24], uint16(e.RootY))
	order.PutUint16(buf[24:26], uint16(e.EventX))
	order.PutUint16(buf[26:28], uint16(e.EventY))
	order.PutUint16(buf[28:30], e.State)
	buf[30] = e.DeviceID
	buf[31] = e.Detail
	return buf
}

// DeviceButtonReleaseEvent represents an XInput button release event.
type DeviceButtonReleaseEvent struct {
	BaseEventCode uint8  // Base event code
	Sequence      uint16 // Sequence number
	DeviceID      byte   // Device ID
	Time       uint32 // Time of event
	Button     byte   // Button code
	Root       uint32 // Root window ID
	Event      uint32 // Event window ID
	Child      uint32 // Child window ID
	RootX      int16  // Root X coordinate
	RootY      int16  // Root Y coordinate
	EventX     int16  // Event X coordinate
	EventY     int16  // Event Y coordinate
	State      uint16 // Modifier state
	SameScreen bool   // Same screen flag
}

// EventCode returns the event code.
func (e *DeviceButtonReleaseEvent) EventCode() uint8 { return byte(XInputOpcode) }

// DeviceMotionNotifyEvent represents an XInput motion event.
type DeviceMotionNotifyEvent struct {
	BaseEventCode uint8  // Base event code
	Sequence      uint16 // Sequence number
	DeviceID      byte   // Device ID
	Time       uint32 // Time of event
	Detail     byte   // Detail
	Root       uint32 // Root window ID
	Event      uint32 // Event window ID
	Child      uint32 // Child window ID
	RootX      int16  // Root X coordinate
	RootY      int16  // Root Y coordinate
	EventX     int16  // Event X coordinate
	EventY     int16  // Event Y coordinate
	State      uint16 // Modifier state
	SameScreen bool   // Same screen flag
}

// ProximityInEvent represents an XInput proximity in event.
type ProximityInEvent struct {
	BaseEventCode uint8  // Base event code
	Sequence      uint16 // Sequence number
	DeviceID      byte   // Device ID
	Time       uint32 // Time of event
	Detail     byte   // Detail
	Root       uint32 // Root window ID
	Event      uint32 // Event window ID
	Child      uint32 // Child window ID
	RootX      int16  // Root X coordinate
	RootY      int16  // Root Y coordinate
	EventX     int16  // Event X coordinate
	EventY     int16  // Event Y coordinate
	State      uint16 // Modifier state
	SameScreen bool   // Same screen flag
}

// ProximityOutEvent represents an XInput proximity out event.
type ProximityOutEvent struct {
	BaseEventCode uint8  // Base event code
	Sequence      uint16 // Sequence number
	DeviceID      byte   // Device ID
	Time       uint32 // Time of event
	Detail     byte   // Detail
	Root       uint32 // Root window ID
	Event      uint32 // Event window ID
	Child      uint32 // Child window ID
	RootX      int16  // Root X coordinate
	RootY      int16  // Root Y coordinate
	EventX     int16  // Event X coordinate
	EventY     int16  // Event Y coordinate
	State      uint16 // Modifier state
	SameScreen bool   // Same screen flag
}

// EventCode returns the event code.
func (e *ProximityOutEvent) EventCode() uint8 { return byte(XInputOpcode) }
