//go:build x11

package x11

import (
	"encoding/binary"
)

// keyEvent implements messageEncoder for KeyPress and KeyRelease events.
type keyEvent struct {
	sequence       uint16
	detail         byte // keycode
	time           uint32
	root           uint32
	event          uint32
	child          uint32
	rootX, rootY   int16
	eventX, eventY int16
	state          uint16 // keyboard state
	sameScreen     bool
}

func (e *keyEvent) encodeMessage(order binary.ByteOrder) []byte {
	event := make([]byte, 32)
	// event[0] will be set to KeyPress (2) or KeyRelease (3) by the caller
	event[1] = e.detail
	order.PutUint16(event[2:4], e.sequence)
	order.PutUint32(event[4:8], e.time)
	order.PutUint32(event[8:12], e.root)
	order.PutUint32(event[12:16], e.event)
	order.PutUint32(event[16:20], e.child)
	order.PutUint16(event[20:22], uint16(e.rootX))
	order.PutUint16(event[22:24], uint16(e.rootY))
	order.PutUint16(event[24:26], uint16(e.eventX))
	order.PutUint16(event[26:28], uint16(e.eventY))
	order.PutUint16(event[28:30], e.state)
	event[30] = boolToByte(e.sameScreen)
	// event[31] is unused
	return event
}

// motionNotifyEvent implements messageEncoder for MotionNotify event.
type motionNotifyEvent struct {
	sequence       uint16
	detail         byte
	time           uint32
	root           uint32
	event          uint32
	child          uint32
	rootX, rootY   int16
	eventX, eventY int16
	state          uint16
	sameScreen     bool
}

func (e *motionNotifyEvent) encodeMessage(order binary.ByteOrder) []byte {
	event := make([]byte, 32)
	event[0] = 6 // MotionNotify event code
	event[1] = e.detail
	order.PutUint16(event[2:4], e.sequence)
	order.PutUint32(event[4:8], e.time)
	order.PutUint32(event[8:12], e.root)
	order.PutUint32(event[12:16], e.event)
	order.PutUint32(event[16:20], e.child)
	order.PutUint16(event[20:22], uint16(e.rootX))
	order.PutUint16(event[22:24], uint16(e.rootY))
	order.PutUint16(event[24:26], uint16(e.eventX))
	order.PutUint16(event[26:28], uint16(e.eventY))
	order.PutUint16(event[28:30], e.state)
	event[30] = boolToByte(e.sameScreen)
	// event[31] is unused
	return event
}

// exposeEvent implements messageEncoder for Expose event.
type exposeEvent struct {
	sequence      uint16
	window        uint32
	x, y          uint16
	width, height uint16
	count         uint16
}

func (e *exposeEvent) encodeMessage(order binary.ByteOrder) []byte {
	event := make([]byte, 32)
	event[0] = 12 // Expose event code
	// byte 1 is unused
	order.PutUint16(event[2:4], e.sequence)
	order.PutUint32(event[4:8], e.window)
	order.PutUint16(event[8:10], e.x)
	order.PutUint16(event[10:12], e.y)
	order.PutUint16(event[12:14], e.width)
	order.PutUint16(event[14:16], e.height)
	order.PutUint16(event[16:18], e.count)
	// event[18:32] is unused
	return event
}

// colormapNotifyEvent implements messageEncoder for ColormapNotify event.
type colormapNotifyEvent struct {
	sequence uint16
	window   uint32
	colormap uint32
	new      bool
	state    byte
}

func (e *colormapNotifyEvent) encodeMessage(order binary.ByteOrder) []byte {
	event := make([]byte, 32)
	event[0] = ColormapNotify // ColormapNotify event code
	// byte 1 is unused
	order.PutUint16(event[2:4], e.sequence)
	order.PutUint32(event[4:8], e.window)
	order.PutUint32(event[8:12], e.colormap)
	event[12] = boolToByte(e.new)
	event[13] = e.state
	// event[14:32] is unused
	return event
}

// configureNotifyEvent implements messageEncoder for ConfigureNotify event.
type configureNotifyEvent struct {
	sequence         uint16
	event            uint32
	window           uint32
	aboveSibling     uint32
	x, y             int16
	width, height    uint16
	borderWidth      uint16
	overrideRedirect bool
}

func (e *configureNotifyEvent) encodeMessage(order binary.ByteOrder) []byte {
	event := make([]byte, 32)
	event[0] = 22 // ConfigureNotify event code
	// byte 1 is unused
	order.PutUint16(event[2:4], e.sequence)
	order.PutUint32(event[4:8], e.event)
	order.PutUint32(event[8:12], e.window)
	order.PutUint32(event[12:16], e.aboveSibling)
	order.PutUint16(event[16:18], uint16(e.x))
	order.PutUint16(event[18:20], uint16(e.y))
	order.PutUint16(event[20:22], e.width)
	order.PutUint16(event[22:24], e.height)
	order.PutUint16(event[24:26], e.borderWidth)
	event[26] = boolToByte(e.overrideRedirect)
	// byte 27 is unused
	return event
}

// selectionNotifyEvent implements messageEncoder for SelectionNotify event.
type selectionNotifyEvent struct {
	sequence  uint16
	requestor uint32
	selection uint32
	target    uint32
	property  uint32
	time      uint32
}

func (e *selectionNotifyEvent) encodeMessage(order binary.ByteOrder) []byte {
	event := make([]byte, 32)
	event[0] = 31 // SelectionNotify event code
	// byte 1 is unused
	order.PutUint16(event[2:4], e.sequence)
	order.PutUint32(event[4:8], e.requestor)
	order.PutUint32(event[8:12], e.selection)
	order.PutUint32(event[12:16], e.target)
	order.PutUint32(event[16:20], e.property)
	order.PutUint32(event[20:24], e.time)
	// event[24:32] is unused
	return event
}

// clientMessageEvent implements messageEncoder for ClientMessage event.
type clientMessageEvent struct {
	sequence    uint16
	format      byte
	window      uint32
	messageType uint32
	data        [20]byte
}

func (e *clientMessageEvent) encodeMessage(order binary.ByteOrder) []byte {
	event := make([]byte, 32)
	event[0] = 33 // ClientMessage event code
	event[1] = e.format
	order.PutUint16(event[2:4], e.sequence)
	order.PutUint32(event[4:8], e.window)
	order.PutUint32(event[8:12], e.messageType)
	copy(event[12:32], e.data[:])
	return event
}

// x11RawEvent implements messageEncoder for raw X11 event data.
type x11RawEvent struct {
	data []byte
}

func (e *x11RawEvent) encodeMessage(order binary.ByteOrder) []byte {
	return e.data
}
