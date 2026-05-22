//go:build x11

package wire

import (
	"bytes"
	"encoding/binary"
)

// XInput minor opcodes from XIproto.h
const (
	XIAllDevices         = 0
	XIAllMasterDevices   = 1
	CorePointerDeviceID  = 2
	CoreKeyboardDeviceID = 3

	KeyClass      = 0
	ButtonClass   = 1
	ValuatorClass = 2

	KbdFeedbackClass    = 0
	PtrFeedbackClass    = 1
	IntFeedbackClass    = 2
	StringFeedbackClass = 3
	BellFeedbackClass   = 4
	LedFeedbackClass    = 5

	XGetExtensionVersion           = 1
	XListInputDevices              = 2
	XOpenDevice                    = 3
	XCloseDevice                   = 4
	XSetDeviceMode                 = 5
	XSelectExtensionEvent          = 6
	XGetSelectedExtensionEvents    = 7
	XChangeDeviceDontPropagateList = 8
	XGetDeviceDontPropagateList    = 9
	XGetDeviceMotionEvents         = 10
	XChangeKeyboardDevice          = 11
	XChangePointerDevice           = 12
	XGrabDevice                    = 13
	XUngrabDevice                  = 14
	XGrabDeviceKey                 = 15
	XUngrabDeviceKey               = 16
	XGrabDeviceButton              = 17
	XUngrabDeviceButton            = 18
	XAllowDeviceEvents             = 19
	XGetDeviceFocus                = 20
	XSetDeviceFocus                = 21
	XGetFeedbackControl            = 22
	XChangeFeedbackControl         = 23
	XGetDeviceKeyMapping           = 24
	XChangeDeviceKeyMapping        = 25
	XGetDeviceModifierMapping      = 26
	XSetDeviceModifierMapping      = 27
	XGetDeviceButtonMapping        = 28
	XSetDeviceButtonMapping        = 29
	XQueryDeviceState              = 30
	XSendExtensionEvent            = 31
	XDeviceBell                    = 32
	XSetDeviceValuators            = 33
	XGetDeviceControl              = 34
	XChangeDeviceControl           = 35
	XIQueryPointer                 = 40
	XIWarpPointer                  = 41
	XIChangeCursor                 = 42
	XIChangeHierarchy              = 43
	XISetClientPointer             = 44
	XIGetClientPointer             = 45
	XISelectEvents                 = 46
	XIQueryVersion                 = 47
	XIQueryDevice                  = 48
	XISetFocus                     = 49
	XIGetFocus                     = 50
	XIGrabDevice                   = 51
	XIUngrabDevice                 = 52
	XIAllowEvents                  = 53
	XIPassiveGrabDevice            = 54
	XIPassiveUngrabDevice          = 55
	XIListProperties               = 56
	XIChangeProperty               = 57
	XIDeleteProperty               = 58
	XIGetProperty                  = 59
	XIGetSelectedEvents            = 60
	XIBarrierReleasePointer        = 61

)

func ParseXInputRequest(order binary.ByteOrder, data byte, body []byte, seq uint16) (Request, error) {
	switch data {
	case XGetExtensionVersion:
		return ParseGetExtensionVersionRequest(order, body, seq)
	case XListInputDevices:
		return ParseListInputDevicesRequest(order, body, seq)
	case XOpenDevice:
		return ParseOpenDeviceRequest(order, body, seq)
	case XCloseDevice:
		return ParseCloseDeviceRequest(order, body, seq)
	case XSetDeviceMode:
		return ParseSetDeviceModeRequest(order, body, seq)
	case XSelectExtensionEvent:
		return ParseSelectExtensionEventRequest(order, body, seq)
	case XGetSelectedExtensionEvents:
		return ParseGetSelectedExtensionEventsRequest(order, body, seq)
	case XChangeDeviceDontPropagateList:
		return ParseChangeDeviceDontPropagateListRequest(order, body, seq)
	case XGetDeviceDontPropagateList:
		return ParseGetDeviceDontPropagateListRequest(order, body, seq)
	case XGetDeviceMotionEvents:
		return ParseGetDeviceMotionEventsRequest(order, body, seq)
	case XChangeKeyboardDevice:
		return ParseChangeKeyboardDeviceRequest(order, body, seq)
	case XChangePointerDevice:
		return ParseChangePointerDeviceRequest(order, body, seq)
	case XGrabDevice:
		return ParseGrabDeviceRequest(order, body, seq)
	case XUngrabDevice:
		return ParseUngrabDeviceRequest(order, body, seq)
	case XGrabDeviceKey:
		return ParseGrabDeviceKeyRequest(order, body, seq)
	case XUngrabDeviceKey:
		return ParseUngrabDeviceKeyRequest(order, body, seq)
	case XGrabDeviceButton:
		return ParseGrabDeviceButtonRequest(order, body, seq)
	case XUngrabDeviceButton:
		return ParseUngrabDeviceButtonRequest(order, body, seq)
	case XAllowDeviceEvents:
		return ParseAllowDeviceEventsRequest(order, body, seq)
	case XGetDeviceFocus:
		return ParseGetDeviceFocusRequest(order, body, seq)
	case XSetDeviceFocus:
		return ParseSetDeviceFocusRequest(order, body, seq)
	case XGetFeedbackControl:
		return ParseGetFeedbackControlRequest(order, body, seq)
	case XChangeFeedbackControl:
		return ParseChangeFeedbackControlRequest(order, body, seq)
	case XGetDeviceKeyMapping:
		return ParseGetDeviceKeyMappingRequest(order, body, seq)
	case XChangeDeviceKeyMapping:
		return ParseChangeDeviceKeyMappingRequest(order, body, seq)
	case XGetDeviceModifierMapping:
		return ParseGetDeviceModifierMappingRequest(order, body, seq)
	case XSetDeviceModifierMapping:
		return ParseSetDeviceModifierMappingRequest(order, body, seq)
	case XGetDeviceButtonMapping:
		return ParseGetDeviceButtonMappingRequest(order, body, seq)
	case XSetDeviceButtonMapping:
		return ParseSetDeviceButtonMappingRequest(order, body, seq)
	case XQueryDeviceState:
		return ParseQueryDeviceStateRequest(order, body, seq)
	case XSendExtensionEvent:
		return ParseSendExtensionEventRequest(order, body, seq)
	case XDeviceBell:
		return ParseDeviceBellRequest(order, body, seq)
	case XSetDeviceValuators:
		return ParseSetDeviceValuatorsRequest(order, body, seq)
	case XGetDeviceControl:
		return ParseGetDeviceControlRequest(order, body, seq)
	case XChangeDeviceControl:
		return ParseChangeDeviceControlRequest(order, body, seq)
	case XIQueryVersion:
		return ParseXIQueryVersionRequest(order, body, seq)
	case XIQueryPointer:
		return ParseXIQueryPointerRequest(order, body, seq)
	case XIWarpPointer:
		return ParseXIWarpPointerRequest(order, body, seq)
	case XIChangeCursor:
		return ParseXIChangeCursorRequest(order, body, seq)
	case XIChangeHierarchy:
		return ParseXIChangeHierarchyRequest(order, body, seq)
	case XISetClientPointer:
		return ParseXISetClientPointerRequest(order, body, seq)
	case XIGetClientPointer:
		return ParseXIGetClientPointerRequest(order, body, seq)
	case XISelectEvents:
		return ParseXISelectEventsRequest(order, body, seq)
	case XIQueryDevice:
		return ParseXIQueryDeviceRequest(order, body, seq)
	case XISetFocus:
		return ParseXISetFocusRequest(order, body, seq)
	case XIGetFocus:
		return ParseXIGetFocusRequest(order, body, seq)
	case XIGrabDevice:
		return ParseXIGrabDeviceRequest(order, body, seq)
	case XIUngrabDevice:
		return ParseXIUngrabDeviceRequest(order, body, seq)
	case XIAllowEvents:
		return ParseXIAllowEventsRequest(order, body, seq)
	case XIPassiveGrabDevice:
		return ParseXIPassiveGrabDeviceRequest(order, body, seq)
	case XIPassiveUngrabDevice:
		return ParseXIPassiveUngrabDeviceRequest(order, body, seq)
	case XIListProperties:
		return ParseXIListPropertiesRequest(order, body, seq)
	case XIChangeProperty:
		return ParseXIChangePropertyRequest(order, body, seq)
	case XIDeleteProperty:
		return ParseXIDeletePropertyRequest(order, body, seq)
	case XIGetProperty:
		return ParseXIGetPropertyRequest(order, body, seq)
	case XIGetSelectedEvents:
		return ParseXIGetSelectedEventsRequest(order, body, seq)
	case XIBarrierReleasePointer:
		return ParseXIBarrierReleasePointerRequest(order, body, seq)
	default:
		return nil, NewError(RequestErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: data})
	}
}

// GetExtensionVersion request
type GetExtensionVersionRequest struct {
	Name string
}

func (r *GetExtensionVersionRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	nameBytes := []byte(r.Name)
	length := uint16(2 + (len(nameBytes)+PadLen(len(nameBytes)))/4)

	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(XGetExtensionVersion)
	binary.Write(buf, order, length)
	binary.Write(buf, order, uint16(len(nameBytes)))
	buf.Write([]byte{0, 0}) // padding
	buf.Write(nameBytes)
	buf.Write(make([]byte, PadLen(len(nameBytes))))

	return buf.Bytes()
}

func (r *GetExtensionVersionRequest) OpCode() ReqCode {
	return XInputOpcode
}

func ParseGetExtensionVersionRequest(order binary.ByteOrder, body []byte, seq uint16) (*GetExtensionVersionRequest, error) {
	if len(body) < 4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XGetExtensionVersion})
	}
	length := int(order.Uint16(body[0:2]))
	if len(body) != 4+length+PadLen(length) {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XGetExtensionVersion})
	}
	return &GetExtensionVersionRequest{
		Name: string(body[4 : 4+length]),
	}, nil
}

// XIWarpPointer request
type XIWarpPointerRequest struct {
	DeviceID  uint16
	SrcWindow Window
	DstWindow Window
	SrcX      int32
	SrcY      int32
	SrcW      uint16
	SrcH      uint16
	DstX      int32
	DstY      int32
}

func (r *XIWarpPointerRequest) OpCode() ReqCode {
	return XInputOpcode
}

func (r *XIWarpPointerRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	length := uint16(9)

	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(XIWarpPointer)
	binary.Write(buf, order, length)

	binary.Write(buf, order, r.DeviceID)
	buf.Write([]byte{0, 0}) // padding
	binary.Write(buf, order, r.SrcWindow)
	binary.Write(buf, order, r.DstWindow)
	binary.Write(buf, order, r.SrcX)
	binary.Write(buf, order, r.SrcY)
	binary.Write(buf, order, r.SrcW)
	binary.Write(buf, order, r.SrcH)
	binary.Write(buf, order, r.DstX)
	binary.Write(buf, order, r.DstY)
	return buf.Bytes()
}

func ParseXIWarpPointerRequest(order binary.ByteOrder, body []byte, seq uint16) (*XIWarpPointerRequest, error) {
	if len(body) != 32 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XIWarpPointer})
	}
	// The protocol defines 'fp1616' fixed point numbers. We'll treat them as int32 for now,
	// effectively ignoring the fractional part by taking the integer part.
	return &XIWarpPointerRequest{
		DeviceID:  order.Uint16(body[0:2]),
		SrcWindow: Window(order.Uint32(body[4:8])),
		DstWindow: Window(order.Uint32(body[8:12])),
		SrcX:      int32(order.Uint32(body[12:16])),
		SrcY:      int32(order.Uint32(body[16:20])),
		SrcW:      order.Uint16(body[20:22]),
		SrcH:      order.Uint16(body[22:24]),
		DstX:      int32(order.Uint32(body[24:28])),
		DstY:      int32(order.Uint32(body[28:32])),
	}, nil
}

// XIChangeCursor request
type XIChangeCursorRequest struct {
	DeviceID uint16
	Window   Window
	Cursor   uint32
}

func (r *XIChangeCursorRequest) OpCode() ReqCode {
	return XInputOpcode
}

func (r *XIChangeCursorRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	length := uint16(4)

	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(XIChangeCursor)
	binary.Write(buf, order, length)

	binary.Write(buf, order, r.DeviceID)
	buf.Write([]byte{0, 0}) // padding
	binary.Write(buf, order, r.Window)
	binary.Write(buf, order, r.Cursor)
	return buf.Bytes()
}

func ParseXIChangeCursorRequest(order binary.ByteOrder, body []byte, seq uint16) (*XIChangeCursorRequest, error) {
	if len(body) != 12 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XIChangeCursor})
	}
	return &XIChangeCursorRequest{
		DeviceID: order.Uint16(body[0:2]),
		Window:   Window(order.Uint32(body[4:8])),
		Cursor:   order.Uint32(body[8:12]),
	}, nil
}

// XIChangeHierarchy request
type XIChangeHierarchyRequest struct {
	NumChanges uint16
	Changes    []XIChangeHierarchyChange
}

type XIChangeHierarchyChange interface {
	Op() uint16
}

type XIAnyHierarchyChange struct {
	Type   uint16
	Length uint16
}

type XIAddMaster struct {
	Type     uint16
	Length   uint16
	Name     string
	SendCore bool
	Enable   bool
}

func (c *XIAddMaster) Op() uint16 { return 1 }

type XIRemoveMaster struct {
	Type           uint16
	Length         uint16
	DeviceID       uint16
	ReturnMode     byte
	ReturnPointer  uint16
	ReturnKeyboard uint16
}

func (c *XIRemoveMaster) Op() uint16 { return 2 }

type XIAttachSlave struct {
	Type     uint16
	Length   uint16
	DeviceID uint16
	MasterID uint16
}

func (c *XIAttachSlave) Op() uint16 { return 3 }

type XIDetachSlave struct {
	Type     uint16
	Length   uint16
	DeviceID uint16
}

func (c *XIDetachSlave) Op() uint16 { return 4 }

func (r *XIChangeHierarchyRequest) OpCode() ReqCode {
	return XInputOpcode
}

func (c *XIDetachSlave) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, c.Type)
	binary.Write(buf, order, c.Length)
	binary.Write(buf, order, c.DeviceID)
	binary.Write(buf, order, uint16(0)) // padding
	return buf.Bytes()
}

func (r *XIChangeHierarchyRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)

	changesBytes := new(bytes.Buffer)
	for _, change := range r.Changes {
		switch c := change.(type) {
		case *XIDetachSlave:
			changesBytes.Write(c.EncodeMessage(order))
		}
	}
	length := uint16(2 + (changesBytes.Len())/4)

	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(XIChangeHierarchy)
	binary.Write(buf, order, length)

	binary.Write(buf, order, r.NumChanges)
	buf.Write([]byte{0, 0}) // padding
	buf.Write(changesBytes.Bytes())
	return buf.Bytes()
}

func ParseXIChangeHierarchyRequest(order binary.ByteOrder, body []byte, seq uint16) (*XIChangeHierarchyRequest, error) {
	if len(body) < 4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XIChangeHierarchy})
	}
	numChanges := order.Uint16(body[0:2])
	changes := make([]XIChangeHierarchyChange, 0, numChanges)
	offset := 4
	for i := 0; i < int(numChanges); i++ {
		if len(body) < offset+4 {
			return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XIChangeHierarchy})
		}
		changeType := order.Uint16(body[offset : offset+2])
		length := order.Uint16(body[offset+2 : offset+4])
		if len(body) < offset+int(length) {
			return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XIChangeHierarchy})
		}
		changeBody := body[offset : offset+int(length)]
		var change XIChangeHierarchyChange
		switch changeType {
		case 1: // XIAddMaster
			return nil, NewError(ImplementationErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XIChangeHierarchy})
		case 2: // XIRemoveMaster
			return nil, NewError(ImplementationErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XIChangeHierarchy})
		case 3: // XIAttachSlave
			if len(changeBody) != 8 {
				return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XIChangeHierarchy})
			}
			change = &XIAttachSlave{
				Type:     changeType,
				Length:   length,
				DeviceID: order.Uint16(changeBody[4:6]),
				MasterID: order.Uint16(changeBody[6:8]),
			}
		case 4: // XIDetachSlave
			if len(changeBody) != 8 {
				return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XIChangeHierarchy})
			}
			change = &XIDetachSlave{
				Type:     changeType,
				Length:   length,
				DeviceID: order.Uint16(changeBody[4:6]),
			}
		default:
			return nil, NewError(ValueErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XIChangeHierarchy})
		}
		changes = append(changes, change)
		offset += int(length)
	}
	return &XIChangeHierarchyRequest{
		NumChanges: numChanges,
		Changes:    changes,
	}, nil
}

// XISetClientPointer request
type XISetClientPointerRequest struct {
	DeviceID uint16
	Window   Window
}

func (r *XISetClientPointerRequest) OpCode() ReqCode {
	return XInputOpcode
}

func (r *XISetClientPointerRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	length := uint16(3)

	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(XISetClientPointer)
	binary.Write(buf, order, length)

	binary.Write(buf, order, r.DeviceID)
	buf.Write([]byte{0, 0}) // padding
	binary.Write(buf, order, r.Window)
	return buf.Bytes()
}

func ParseXISetClientPointerRequest(order binary.ByteOrder, body []byte, seq uint16) (*XISetClientPointerRequest, error) {
	if len(body) != 8 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XISetClientPointer})
	}
	return &XISetClientPointerRequest{
		DeviceID: order.Uint16(body[0:2]),
		Window:   Window(order.Uint32(body[4:8])),
	}, nil
}

// XIGetClientPointer request
type XIGetClientPointerRequest struct {
	Window Window
}

func (r *XIGetClientPointerRequest) OpCode() ReqCode {
	return XInputOpcode
}

func (r *XIGetClientPointerRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	length := uint16(2)

	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(XIGetClientPointer)
	binary.Write(buf, order, length)

	binary.Write(buf, order, r.Window)
	return buf.Bytes()
}

func ParseXIGetClientPointerRequest(order binary.ByteOrder, body []byte, seq uint16) (*XIGetClientPointerRequest, error) {
	if len(body) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XIGetClientPointer})
	}
	return &XIGetClientPointerRequest{
		Window: Window(order.Uint32(body[0:4])),
	}, nil
}

// XISelectEvents request
type XISelectEventsRequest struct {
	Window   Window
	NumMasks uint16
	Masks    []XIEventMask
}

type XIEventMask struct {
	DeviceID uint16
	MaskLen  uint16
	Mask     []uint32
}

func (r *XISelectEventsRequest) OpCode() ReqCode {
	return XInputOpcode
}

func (r *XISelectEventsRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)

	masksBytes := new(bytes.Buffer)
	for _, mask := range r.Masks {
		binary.Write(masksBytes, order, mask.DeviceID)
		binary.Write(masksBytes, order, mask.MaskLen)
		for _, m := range mask.Mask {
			binary.Write(masksBytes, order, m)
		}
	}
	length := uint16(3 + (masksBytes.Len())/4)

	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(XISelectEvents)
	binary.Write(buf, order, length)

	binary.Write(buf, order, r.Window)
	binary.Write(buf, order, r.NumMasks)
	buf.Write([]byte{0, 0}) // padding
	buf.Write(masksBytes.Bytes())
	return buf.Bytes()
}

func ParseXISelectEventsRequest(order binary.ByteOrder, body []byte, seq uint16) (*XISelectEventsRequest, error) {
	if len(body) < 8 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XISelectEvents})
	}
	window := Window(order.Uint32(body[0:4]))
	numMasks := order.Uint16(body[4:6])
	masks := make([]XIEventMask, 0, numMasks)
	offset := 8
	for i := 0; i < int(numMasks); i++ {
		if len(body) < offset+4 {
			return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XISelectEvents})
		}
		deviceID := order.Uint16(body[offset : offset+2])
		maskLen := order.Uint16(body[offset+2 : offset+4])
		maskBytes := int(maskLen) * 4
		if len(body) < offset+4+maskBytes {
			return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XISelectEvents})
		}
		mask := make([]uint32, maskLen)
		for j := 0; j < int(maskLen); j++ {
			mask[j] = order.Uint32(body[offset+4+j*4 : offset+8+j*4])
		}
		masks = append(masks, XIEventMask{
			DeviceID: deviceID,
			MaskLen:  maskLen,
			Mask:     mask,
		})
		offset += 4 + maskBytes
	}
	return &XISelectEventsRequest{
		Window:   window,
		NumMasks: numMasks,
		Masks:    masks,
	}, nil
}

// XIQueryDevice request
type XIQueryDeviceRequest struct {
	DeviceID uint16
}

func (r *XIQueryDeviceRequest) OpCode() ReqCode {
	return XInputOpcode
}

func (r *XIQueryDeviceRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	length := uint16(2)

	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(XIQueryDevice)
	binary.Write(buf, order, length)

	binary.Write(buf, order, r.DeviceID)
	buf.Write([]byte{0, 0}) // padding
	return buf.Bytes()
}

func ParseXIQueryDeviceRequest(order binary.ByteOrder, body []byte, seq uint16) (*XIQueryDeviceRequest, error) {
	if len(body) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XIQueryDevice})
	}
	return &XIQueryDeviceRequest{
		DeviceID: order.Uint16(body[0:2]),
	}, nil
}

// XISetFocus request
type XISetFocusRequest struct {
	DeviceID uint16
	Focus    Window
	Time     uint32
}

func (r *XISetFocusRequest) OpCode() ReqCode {
	return XInputOpcode
}

func (r *XISetFocusRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	length := uint16(4)

	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(XISetFocus)
	binary.Write(buf, order, length)

	binary.Write(buf, order, r.DeviceID)
	buf.Write([]byte{0, 0}) // padding
	binary.Write(buf, order, r.Focus)
	binary.Write(buf, order, r.Time)
	return buf.Bytes()
}

func ParseXISetFocusRequest(order binary.ByteOrder, body []byte, seq uint16) (*XISetFocusRequest, error) {
	if len(body) != 12 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XISetFocus})
	}
	return &XISetFocusRequest{
		DeviceID: order.Uint16(body[0:2]),
		Focus:    Window(order.Uint32(body[4:8])),
		Time:     order.Uint32(body[8:12]),
	}, nil
}

// XIGetFocus request
type XIGetFocusRequest struct {
	DeviceID uint16
}

func (r *XIGetFocusRequest) OpCode() ReqCode {
	return XInputOpcode
}

func (r *XIGetFocusRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	length := uint16(2)

	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(XIGetFocus)
	binary.Write(buf, order, length)

	binary.Write(buf, order, r.DeviceID)
	buf.Write([]byte{0, 0}) // padding
	return buf.Bytes()
}

func ParseXIGetFocusRequest(order binary.ByteOrder, body []byte, seq uint16) (*XIGetFocusRequest, error) {
	if len(body) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XIGetFocus})
	}
	return &XIGetFocusRequest{
		DeviceID: order.Uint16(body[0:2]),
	}, nil
}

// XIGrabDevice request
type XIGrabDeviceRequest struct {
	DeviceID         uint16
	GrabWindow       Window
	Time             uint32
	Cursor           uint32
	GrabMode         byte
	PairedDeviceMode byte
	OwnerEvents      bool
	MaskLen          uint16
	Mask             []byte
}

func (r *XIGrabDeviceRequest) OpCode() ReqCode {
	return XInputOpcode
}

func (r *XIGrabDeviceRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	length := uint16(7 + len(r.Mask)/4)

	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(XIGrabDevice)
	binary.Write(buf, order, length)

	binary.Write(buf, order, r.DeviceID)
	buf.Write([]byte{0, 0}) // padding
	binary.Write(buf, order, r.GrabWindow)
	binary.Write(buf, order, r.Time)
	binary.Write(buf, order, r.Cursor)
	buf.WriteByte(r.GrabMode)
	buf.WriteByte(r.PairedDeviceMode)
	if r.OwnerEvents {
		buf.WriteByte(1)
	} else {
		buf.WriteByte(0)
	}
	buf.WriteByte(0) // padding
	binary.Write(buf, order, r.MaskLen)
	buf.Write([]byte{0, 0}) // padding
	buf.Write(r.Mask)
	return buf.Bytes()
}

func ParseXIGrabDeviceRequest(order binary.ByteOrder, body []byte, seq uint16) (*XIGrabDeviceRequest, error) {
	if len(body) < 24 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XIGrabDevice})
	}
	maskLen := order.Uint16(body[20:22])
	if len(body) != 24+int(maskLen)*4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XIGrabDevice})
	}
	return &XIGrabDeviceRequest{
		DeviceID:         order.Uint16(body[0:2]),
		GrabWindow:       Window(order.Uint32(body[4:8])),
		Time:             order.Uint32(body[8:12]),
		Cursor:           order.Uint32(body[12:16]),
		GrabMode:         body[16],
		PairedDeviceMode: body[17],
		OwnerEvents:      body[18] != 0,
		MaskLen:          maskLen,
		Mask:             body[24:],
	}, nil
}

// XIUngrabDevice request
type XIUngrabDeviceRequest struct {
	DeviceID uint16
	Time     uint32
}

func (r *XIUngrabDeviceRequest) OpCode() ReqCode {
	return XInputOpcode
}

func (r *XIUngrabDeviceRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	length := uint16(3)

	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(XIUngrabDevice)
	binary.Write(buf, order, length)

	binary.Write(buf, order, r.DeviceID)
	buf.Write([]byte{0, 0}) // padding
	binary.Write(buf, order, r.Time)
	return buf.Bytes()
}

func ParseXIUngrabDeviceRequest(order binary.ByteOrder, body []byte, seq uint16) (*XIUngrabDeviceRequest, error) {
	if len(body) != 8 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XIUngrabDevice})
	}
	return &XIUngrabDeviceRequest{
		DeviceID: order.Uint16(body[0:2]),
		Time:     order.Uint32(body[4:8]),
	}, nil
}

// XIAllowEvents request
type XIAllowEventsRequest struct {
	DeviceID   uint16
	EventMode  byte
	Time       uint32
	TouchID    uint32
	GrabWindow Window
}

func (r *XIAllowEventsRequest) OpCode() ReqCode {
	return XInputOpcode
}

func (r *XIAllowEventsRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	length := uint16(5)

	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(XIAllowEvents)
	binary.Write(buf, order, length)

	binary.Write(buf, order, r.DeviceID)
	buf.WriteByte(r.EventMode)
	buf.WriteByte(0) // padding
	binary.Write(buf, order, r.Time)
	binary.Write(buf, order, r.TouchID)
	binary.Write(buf, order, r.GrabWindow)
	return buf.Bytes()
}

func ParseXIAllowEventsRequest(order binary.ByteOrder, body []byte, seq uint16) (*XIAllowEventsRequest, error) {
	if len(body) != 16 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XIAllowEvents})
	}
	return &XIAllowEventsRequest{
		DeviceID:   order.Uint16(body[0:2]),
		EventMode:  body[2],
		Time:       order.Uint32(body[4:8]),
		TouchID:    order.Uint32(body[8:12]),
		GrabWindow: Window(order.Uint32(body[12:16])),
	}, nil
}

// XIPassiveGrabDevice request
type XIPassiveGrabDeviceRequest struct {
	DeviceID         uint16
	GrabWindow       Window
	Time             uint32
	Cursor           uint32
	Detail           uint32
	NumModifiers     uint16
	MaskLen          uint16
	GrabType         byte
	GrabMode         byte
	PairedDeviceMode byte
	OwnerEvents      bool
	Mask             []byte
	Modifiers        []byte
}

func (r *XIPassiveGrabDeviceRequest) OpCode() ReqCode {
	return XInputOpcode
}

func (r *XIPassiveGrabDeviceRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	length := uint16(8 + len(r.Mask)/4 + len(r.Modifiers)/4)

	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(XIPassiveGrabDevice)
	binary.Write(buf, order, length)

	binary.Write(buf, order, r.DeviceID)
	buf.Write([]byte{0, 0}) // padding
	binary.Write(buf, order, r.GrabWindow)
	binary.Write(buf, order, r.Time)
	binary.Write(buf, order, r.Cursor)
	binary.Write(buf, order, r.Detail)
	binary.Write(buf, order, r.NumModifiers)
	binary.Write(buf, order, r.MaskLen)
	buf.WriteByte(r.GrabType)
	buf.WriteByte(r.GrabMode)
	buf.WriteByte(r.PairedDeviceMode)
	if r.OwnerEvents {
		buf.WriteByte(1)
	} else {
		buf.WriteByte(0)
	}
	buf.Write(r.Mask)
	buf.Write(r.Modifiers)
	return buf.Bytes()
}

func ParseXIPassiveGrabDeviceRequest(order binary.ByteOrder, body []byte, seq uint16) (*XIPassiveGrabDeviceRequest, error) {
	if len(body) < 28 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XIPassiveGrabDevice})
	}
	numModifiers := order.Uint16(body[20:22])
	maskLen := order.Uint16(body[22:24])
	expectedLen := 28 + int(maskLen)*4 + int(numModifiers)*4
	if len(body) != expectedLen {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XIPassiveGrabDevice})
	}

	mask := body[28 : 28+int(maskLen)*4]
	modifiers := body[28+int(maskLen)*4:]

	return &XIPassiveGrabDeviceRequest{
		DeviceID:         order.Uint16(body[0:2]),
		GrabWindow:       Window(order.Uint32(body[4:8])),
		Time:             order.Uint32(body[8:12]),
		Cursor:           order.Uint32(body[12:16]),
		Detail:           order.Uint32(body[16:20]),
		NumModifiers:     numModifiers,
		MaskLen:          maskLen,
		GrabType:         body[24],
		GrabMode:         body[25],
		PairedDeviceMode: body[26],
		OwnerEvents:      body[27] != 0,
		Mask:             mask,
		Modifiers:        modifiers,
	}, nil
}

// XIGrabModifierInfo structure
type XIGrabModifierInfo struct {
	Status    byte
	Modifiers uint32
}

// XIPassiveGrabDevice reply
type XIPassiveGrabDeviceReply struct {
	Sequence     uint16
	NumModifiers uint16
	Modifiers    []XIGrabModifierInfo
}

func (r *XIPassiveGrabDeviceReply) EncodeMessage(order binary.ByteOrder) []byte {
	totalLen := 32 + int(r.NumModifiers)*8
	lengthField := (totalLen - 32) / 4

	buf := make([]byte, totalLen)
	buf[0] = 1 // Reply
	order.PutUint16(buf[2:4], r.Sequence)
	order.PutUint32(buf[4:8], uint32(lengthField))
	order.PutUint16(buf[8:10], r.NumModifiers)
	// pad0 (10-32) is 0

	offset := 32
	for _, mod := range r.Modifiers {
		buf[offset] = mod.Status
		order.PutUint32(buf[offset+4:offset+8], mod.Modifiers)
		offset += 8
	}
	return buf
}

// XIPassiveUngrabDevice request
type XIPassiveUngrabDeviceRequest struct {
	DeviceID     uint16
	GrabWindow   Window
	Detail       uint32
	NumModifiers uint16
	GrabType     byte
	Modifiers    []byte
}

func (r *XIPassiveUngrabDeviceRequest) OpCode() ReqCode {
	return XInputOpcode
}

func (r *XIPassiveUngrabDeviceRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	length := uint16(5 + len(r.Modifiers)/4)

	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(XIPassiveUngrabDevice)
	binary.Write(buf, order, length)

	binary.Write(buf, order, r.DeviceID)
	buf.Write([]byte{0, 0}) // padding
	binary.Write(buf, order, r.GrabWindow)
	binary.Write(buf, order, r.Detail)
	binary.Write(buf, order, r.NumModifiers)
	buf.WriteByte(r.GrabType)
	buf.WriteByte(0) // padding
	buf.Write(r.Modifiers)
	return buf.Bytes()
}

func ParseXIPassiveUngrabDeviceRequest(order binary.ByteOrder, body []byte, seq uint16) (*XIPassiveUngrabDeviceRequest, error) {
	if len(body) < 16 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XIPassiveUngrabDevice})
	}
	numModifiers := order.Uint16(body[12:14])
	if len(body) != 16+int(numModifiers)*4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XIPassiveUngrabDevice})
	}
	return &XIPassiveUngrabDeviceRequest{
		DeviceID:     order.Uint16(body[0:2]),
		GrabWindow:   Window(order.Uint32(body[4:8])),
		Detail:       order.Uint32(body[8:12]),
		NumModifiers: numModifiers,
		GrabType:     body[14],
		Modifiers:    body[16:],
	}, nil
}

// XIListProperties request
type XIListPropertiesRequest struct {
	DeviceID uint16
}

func (r *XIListPropertiesRequest) OpCode() ReqCode {
	return XInputOpcode
}

func (r *XIListPropertiesRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	length := uint16(2)

	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(XIListProperties)
	binary.Write(buf, order, length)

	binary.Write(buf, order, r.DeviceID)
	buf.Write([]byte{0, 0}) // padding
	return buf.Bytes()
}

func ParseXIListPropertiesRequest(order binary.ByteOrder, body []byte, seq uint16) (*XIListPropertiesRequest, error) {
	if len(body) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XIListProperties})
	}
	return &XIListPropertiesRequest{
		DeviceID: order.Uint16(body[0:2]),
	}, nil
}

// XIChangeProperty request
type XIChangePropertyRequest struct {
	DeviceID uint16
	Mode     byte
	Format   byte
	Property uint32
	Type     uint32
	NumItems uint32
	Data     []byte
}

func (r *XIChangePropertyRequest) OpCode() ReqCode {
	return XInputOpcode
}

func (r *XIChangePropertyRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	length := uint16(5 + (len(r.Data)+PadLen(len(r.Data)))/4)

	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(XIChangeProperty)
	binary.Write(buf, order, length)

	binary.Write(buf, order, r.DeviceID)
	buf.WriteByte(r.Mode)
	buf.WriteByte(r.Format)
	binary.Write(buf, order, r.Property)
	binary.Write(buf, order, r.Type)
	binary.Write(buf, order, r.NumItems)
	buf.Write(r.Data)
	buf.Write(make([]byte, PadLen(len(r.Data))))
	return buf.Bytes()
}

func pad(i int) int {
	return (i + 3) & ^3
}

func ParseXIChangePropertyRequest(order binary.ByteOrder, body []byte, seq uint16) (*XIChangePropertyRequest, error) {
	if len(body) < 16 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XIChangeProperty})
	}
	format := body[3]
	numItems := order.Uint32(body[12:16])
	var dataLen int
	switch format {
	case 8:
		dataLen = int(numItems)
	case 16:
		dataLen = int(numItems) * 2
	case 32:
		dataLen = int(numItems) * 4
	default:
		return nil, NewError(ValueErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XIChangeProperty})
	}
	if len(body) != 16+pad(dataLen) {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XIChangeProperty})
	}
	return &XIChangePropertyRequest{
		DeviceID: order.Uint16(body[0:2]),
		Mode:     body[2],
		Format:   format,
		Property: order.Uint32(body[4:8]),
		Type:     order.Uint32(body[8:12]),
		NumItems: numItems,
		Data:     body[16 : 16+dataLen],
	}, nil
}

// XIDeleteProperty request
type XIDeletePropertyRequest struct {
	DeviceID uint16
	Property uint32
}

func (r *XIDeletePropertyRequest) OpCode() ReqCode {
	return XInputOpcode
}

func (r *XIDeletePropertyRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	length := uint16(3)

	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(XIDeleteProperty)
	binary.Write(buf, order, length)

	binary.Write(buf, order, r.DeviceID)
	buf.Write([]byte{0, 0}) // padding
	binary.Write(buf, order, r.Property)
	return buf.Bytes()
}

func ParseXIDeletePropertyRequest(order binary.ByteOrder, body []byte, seq uint16) (*XIDeletePropertyRequest, error) {
	if len(body) != 8 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XIDeleteProperty})
	}
	return &XIDeletePropertyRequest{
		DeviceID: order.Uint16(body[0:2]),
		Property: order.Uint32(body[4:8]),
	}, nil
}

// XIGetProperty request
type XIGetPropertyRequest struct {
	DeviceID uint16
	Delete   bool
	Property uint32
	Type     uint32
	Offset   uint32
	Len      uint32
}

func (r *XIGetPropertyRequest) OpCode() ReqCode {
	return XInputOpcode
}

func (r *XIGetPropertyRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	length := uint16(6)

	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(XIGetProperty)
	binary.Write(buf, order, length)

	binary.Write(buf, order, r.DeviceID)
	if r.Delete {
		buf.WriteByte(1)
	} else {
		buf.WriteByte(0)
	}
	buf.WriteByte(0) // padding
	binary.Write(buf, order, r.Property)
	binary.Write(buf, order, r.Type)
	binary.Write(buf, order, r.Offset)
	binary.Write(buf, order, r.Len)
	return buf.Bytes()
}

func ParseXIGetPropertyRequest(order binary.ByteOrder, body []byte, seq uint16) (*XIGetPropertyRequest, error) {
	if len(body) != 20 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XIGetProperty})
	}
	return &XIGetPropertyRequest{
		DeviceID: order.Uint16(body[0:2]),
		Delete:   body[2] != 0,
		Property: order.Uint32(body[4:8]),
		Type:     order.Uint32(body[8:12]),
		Offset:   order.Uint32(body[12:16]),
		Len:      order.Uint32(body[16:20]),
	}, nil
}

// XIGetSelectedEvents request
type XIGetSelectedEventsRequest struct {
	Window Window
}

func (r *XIGetSelectedEventsRequest) OpCode() ReqCode {
	return XInputOpcode
}

func (r *XIGetSelectedEventsRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	length := uint16(2)

	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(XIGetSelectedEvents)
	binary.Write(buf, order, length)

	binary.Write(buf, order, r.Window)
	return buf.Bytes()
}

func ParseXIGetSelectedEventsRequest(order binary.ByteOrder, body []byte, seq uint16) (*XIGetSelectedEventsRequest, error) {
	if len(body) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XIGetSelectedEvents})
	}
	return &XIGetSelectedEventsRequest{
		Window: Window(order.Uint32(body[0:4])),
	}, nil
}

// XIBarrierReleasePointer request
type XIBarrierReleasePointerRequest struct {
	NumBarriers uint32
	Barriers    []XIBarrier
}

type XIBarrier struct {
	Barrier uint32
	EventID uint32
}

func (r *XIBarrierReleasePointerRequest) OpCode() ReqCode {
	return XInputOpcode
}

func (r *XIBarrierReleasePointerRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	length := uint16(2 + len(r.Barriers)*2)

	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(XIBarrierReleasePointer)
	binary.Write(buf, order, length)

	binary.Write(buf, order, r.NumBarriers)
	for _, barrier := range r.Barriers {
		binary.Write(buf, order, barrier.Barrier)
		binary.Write(buf, order, barrier.EventID)
	}
	return buf.Bytes()
}

func ParseXIBarrierReleasePointerRequest(order binary.ByteOrder, body []byte, seq uint16) (*XIBarrierReleasePointerRequest, error) {
	if len(body) < 4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XIBarrierReleasePointer})
	}
	numBarriers := order.Uint32(body[0:4])
	if len(body) != 4+int(numBarriers)*8 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XIBarrierReleasePointer})
	}
	barriers := make([]XIBarrier, numBarriers)
	for i := 0; i < int(numBarriers); i++ {
		offset := 4 + i*8
		barriers[i] = XIBarrier{
			Barrier: order.Uint32(body[offset : offset+4]),
			EventID: order.Uint32(body[offset+4 : offset+8]),
		}
	}
	return &XIBarrierReleasePointerRequest{
		NumBarriers: numBarriers,
		Barriers:    barriers,
	}, nil
}

// GetExtensionVersion reply
type GetExtensionVersionReply struct {
	Sequence     uint16
	MajorVersion uint16
	MinorVersion uint16
}

type GetDeviceMotionEventsReply struct {
	Sequence uint16
	NEvents  uint32
	Events   []TimeCoord
}

type ChangeKeyboardDeviceReply struct {
	Sequence uint16
	Status   byte
}

func (r *GetDeviceMotionEventsReply) EncodeMessage(order binary.ByteOrder) []byte {
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

func (r *ChangeKeyboardDeviceReply) EncodeMessage(order binary.ByteOrder) []byte {
	reply := make([]byte, 32)
	reply[0] = 1 // Reply
	reply[1] = r.Status
	order.PutUint16(reply[2:4], r.Sequence)
	order.PutUint32(reply[4:8], 0)
	return reply
}

func (r *ChangePointerDeviceReply) EncodeMessage(order binary.ByteOrder) []byte {
	reply := make([]byte, 32)
	reply[0] = 1 // Reply
	reply[1] = r.Status
	order.PutUint16(reply[2:4], r.Sequence)
	order.PutUint32(reply[4:8], 0)
	return reply
}

type ChangePointerDeviceReply struct {
	Sequence uint16
	Status   byte
}

func (r *GetExtensionVersionReply) EncodeMessage(order binary.ByteOrder) []byte {
	reply := make([]byte, 32)
	reply[0] = 1 // Reply
	reply[1] = 1 // Present
	order.PutUint16(reply[2:4], r.Sequence)
	order.PutUint32(reply[4:8], 0) // length
	order.PutUint16(reply[8:10], r.MajorVersion)
	order.PutUint16(reply[10:12], r.MinorVersion)
	return reply
}

func ParseGetExtensionVersionReply(order binary.ByteOrder, b []byte) (*GetExtensionVersionReply, error) {
	if len(b) < 32 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	r := &GetExtensionVersionReply{
		Sequence:     order.Uint16(b[2:4]),
		MajorVersion: order.Uint16(b[8:10]),
		MinorVersion: order.Uint16(b[10:12]),
	}
	return r, nil
}

// ListInputDevices request
type ListInputDevicesRequest struct{}

func (r *ListInputDevicesRequest) OpCode() ReqCode {
	return XInputOpcode
}

func (r *ListInputDevicesRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	length := uint16(1)

	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(XListInputDevices)
	binary.Write(buf, order, length)

	return buf.Bytes()
}

func ParseListInputDevicesRequest(order binary.ByteOrder, body []byte, seq uint16) (*ListInputDevicesRequest, error) {
	if len(body) != 0 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XListInputDevices})
	}
	return &ListInputDevicesRequest{}, nil
}

// OpenDevice request
type OpenDeviceRequest struct {
	DeviceID byte
}

func (r *OpenDeviceRequest) OpCode() ReqCode {
	return XInputOpcode
}

func (r *OpenDeviceRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	length := uint16(2)

	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(XOpenDevice)
	binary.Write(buf, order, length)
	buf.WriteByte(r.DeviceID)
	buf.Write([]byte{0, 0, 0}) // padding

	return buf.Bytes()
}

func ParseOpenDeviceRequest(order binary.ByteOrder, body []byte, seq uint16) (*OpenDeviceRequest, error) {
	if len(body) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XOpenDevice})
	}
	return &OpenDeviceRequest{
		DeviceID: body[0],
	}, nil
}

// QueryDeviceState reply
type QueryDeviceStateReply struct {
	Sequence  uint16
	NumEvents uint16
	Classes   []InputClassInfo
}

func (r *QueryDeviceStateReply) EncodeMessage(order binary.ByteOrder) []byte {
	var classBytes []byte
	for _, c := range r.Classes {
		classBytes = append(classBytes, c.EncodeMessage(order)...)
	}
	length := (len(classBytes) + 3) / 4

	reply := make([]byte, 32+len(classBytes))
	reply[0] = 1 // Reply
	order.PutUint16(reply[2:4], r.Sequence)
	order.PutUint32(reply[4:8], uint32(length))
	reply[8] = byte(len(r.Classes))
	copy(reply[32:], classBytes)
	return reply
}

func parseInputClassInfo(order binary.ByteOrder, b []byte) (InputClassInfo, int) {
	classID := b[0]
	length := int(b[1])
	switch classID {
	case KeyClass:
		return &KeyClassInfo{
			NumKeys:    order.Uint16(b[2:4]),
			MinKeycode: b[4],
			MaxKeycode: b[5],
		}, length
	case ButtonClass:
		info := &ButtonClassInfo{
			NumButtons: order.Uint16(b[2:4]),
		}
		copy(info.State[:], b[8:40])
		return info, length
	case ValuatorClass:
		numAxes := b[2]
		axes := make([]ValuatorAxisInfo, numAxes)
		for i := 0; i < int(numAxes); i++ {
			axes[i] = ValuatorAxisInfo{
				Resolution: order.Uint32(b[8+i*12:]),
				Min:        int32(order.Uint32(b[8+i*12+4:])),
				Max:        int32(order.Uint32(b[8+i*12+8:])),
			}
		}
		return &ValuatorClassInfo{
			NumAxes:    numAxes,
			Mode:       b[3],
			MotionSize: order.Uint32(b[4:8]),
			Axes:       axes,
		}, length
	}
	return nil, 0
}

func ParseQueryDeviceStateReply(order binary.ByteOrder, b []byte) (*QueryDeviceStateReply, error) {
	if len(b) < 32 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	numClasses := b[8]
	classes := make([]InputClassInfo, numClasses)
	offset := 32
	for i := 0; i < int(numClasses); i++ {
		if len(b) < offset+2 {
			return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
		}
		class, length := parseInputClassInfo(order, b[offset:])
		if len(b) < offset+length {
			return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
		}
		classes[i] = class
		offset += length
	}
	r := &QueryDeviceStateReply{
		Sequence:  order.Uint16(b[2:4]),
		NumEvents: uint16(numClasses),
		Classes:   classes,
	}
	return r, nil
}

// GetDeviceButtonMapping reply
type GetDeviceButtonMappingReply struct {
	Sequence uint16
	Map      []byte
}

func (r *GetDeviceButtonMappingReply) EncodeMessage(order binary.ByteOrder) []byte {
	length := len(r.Map)
	reply := make([]byte, 32+length)
	reply[0] = 1 // Reply
	reply[1] = byte(length)
	order.PutUint16(reply[2:4], r.Sequence)
	order.PutUint32(reply[4:8], uint32((length+3)/4))
	copy(reply[32:], r.Map)
	return reply
}

func ParseGetDeviceButtonMappingReply(order binary.ByteOrder, b []byte) (*GetDeviceButtonMappingReply, error) {
	if len(b) < 32 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	length := b[1]
	if len(b) < 32+int(length) {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	r := &GetDeviceButtonMappingReply{
		Sequence: order.Uint16(b[2:4]),
		Map:      b[32 : 32+length],
	}
	return r, nil
}

// GetDeviceModifierMapping reply
type GetDeviceModifierMappingReply struct {
	Sequence          uint16
	NumKeycodesPerMod byte
	Keycodes          []byte
}

func (r *GetDeviceModifierMappingReply) EncodeMessage(order binary.ByteOrder) []byte {
	length := len(r.Keycodes)
	reply := make([]byte, 32+length)
	reply[0] = 1 // Reply
	reply[1] = r.NumKeycodesPerMod
	order.PutUint16(reply[2:4], r.Sequence)
	order.PutUint32(reply[4:8], uint32((length+3)/4))
	copy(reply[32:], r.Keycodes)
	return reply
}

func ParseGetDeviceModifierMappingReply(order binary.ByteOrder, b []byte) (*GetDeviceModifierMappingReply, error) {
	if len(b) < 32 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	numKeycodesPerMod := b[1]
	if len(b) < 32+int(numKeycodesPerMod)*8 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	keycodes := b[32 : 32+int(numKeycodesPerMod)*8]
	r := &GetDeviceModifierMappingReply{
		Sequence:          order.Uint16(b[2:4]),
		NumKeycodesPerMod: numKeycodesPerMod,
		Keycodes:          keycodes,
	}
	return r, nil
}

// GetFeedbackControl reply
type GetFeedbackControlReply struct {
	ReplyType byte
	Unused    byte
	Sequence  uint16
	Length    uint32
	NumEvents uint16
	Padding   [22]byte
	Feedbacks []FeedbackState
}

func (r *GetFeedbackControlReply) EncodeMessage(order binary.ByteOrder) []byte {
	var feedbackBytes []byte
	for _, f := range r.Feedbacks {
		feedbackBytes = append(feedbackBytes, f.EncodeMessage(order)...)
	}
	length := (len(feedbackBytes) + 3) / 4

	reply := make([]byte, 32+len(feedbackBytes))
	reply[0] = 1 // Reply
	order.PutUint16(reply[2:4], r.Sequence)
	order.PutUint32(reply[4:8], uint32(length))
	order.PutUint16(reply[8:10], r.NumEvents)
	copy(reply[32:], feedbackBytes)
	return reply
}

func ParseGetFeedbackControlReply(order binary.ByteOrder, b []byte) (*GetFeedbackControlReply, error) {
	if len(b) < 32 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	numEvents := order.Uint16(b[8:10])
	feedbacks := make([]FeedbackState, numEvents)
	offset := 32
	for i := 0; i < int(numEvents); i++ {
		classID := b[offset]
		length := int(order.Uint16(b[offset+2 : offset+4]))
		switch classID {
		case KbdFeedbackClass:
			state := &KbdFeedbackState{
				ClassID:          classID,
				ID:               b[offset+1],
				Len:              uint16(length),
				Pitch:            order.Uint16(b[offset+4:]),
				Duration:         order.Uint16(b[offset+6:]),
				LedMask:          order.Uint32(b[offset+8:]),
				LedValues:        order.Uint32(b[offset+12:]),
				GlobalAutoRepeat: b[offset+16] != 0,
				Click:            b[offset+17],
				Percent:          b[offset+18],
			}
			copy(state.AutoRepeats[:], b[offset+19:offset+51])
			feedbacks[i] = state
		case PtrFeedbackClass:
			feedbacks[i] = &PtrFeedbackState{
				ClassID:    classID,
				ID:         b[offset+1],
				Len:        uint16(length),
				AccelNum:   order.Uint16(b[offset+4:]),
				AccelDenom: order.Uint16(b[offset+6:]),
				Threshold:  order.Uint16(b[offset+8:]),
			}
		}
		offset += length
	}
	r := &GetFeedbackControlReply{
		Sequence:  order.Uint16(b[2:4]),
		NumEvents: numEvents,
		Feedbacks: feedbacks,
	}
	return r, nil
}

type FeedbackState interface {
	EncodeMessage(order binary.ByteOrder) []byte
}

type KbdFeedbackState struct {
	ClassID          byte
	ID               byte
	Len              uint16
	Pitch            uint16
	Duration         uint16
	LedMask          uint32
	LedValues        uint32
	GlobalAutoRepeat bool
	Click            byte
	Percent          byte
	AutoRepeats      [32]byte
}

func (f *KbdFeedbackState) EncodeMessage(order binary.ByteOrder) []byte {
	buf := make([]byte, 44)
	buf[0] = f.ClassID
	buf[1] = f.ID
	order.PutUint16(buf[2:4], f.Len)
	order.PutUint16(buf[4:6], f.Pitch)
	order.PutUint16(buf[6:8], f.Duration)
	order.PutUint32(buf[8:12], f.LedMask)
	order.PutUint32(buf[12:16], f.LedValues)
	if f.GlobalAutoRepeat {
		buf[16] = 1
	} else {
		buf[16] = 0
	}
	buf[17] = f.Click
	buf[18] = f.Percent
	copy(buf[19:], f.AutoRepeats[:])
	return buf
}

type PtrFeedbackState struct {
	ClassID    byte
	ID         byte
	Len        uint16
	AccelNum   uint16
	AccelDenom uint16
	Threshold  uint16
}

func (f *PtrFeedbackState) EncodeMessage(order binary.ByteOrder) []byte {
	buf := make([]byte, 12)
	buf[0] = f.ClassID
	buf[1] = f.ID
	order.PutUint16(buf[2:4], f.Len)
	order.PutUint16(buf[4:6], f.AccelNum)
	order.PutUint16(buf[6:8], f.AccelDenom)
	order.PutUint16(buf[8:10], f.Threshold)
	return buf
}

// GetDeviceFocus reply
type GetDeviceFocusReply struct {
	ReplyType byte
	Unused    byte
	Sequence  uint16
	Length    uint32
	Focus     uint32
	Time      uint32
	RevertTo  byte
	Padding   [15]byte
}

func (r *GetDeviceFocusReply) EncodeMessage(order binary.ByteOrder) []byte {
	reply := make([]byte, 32)
	reply[0] = 1 // Reply
	order.PutUint16(reply[2:4], r.Sequence)
	order.PutUint32(reply[4:8], 0) // length
	order.PutUint32(reply[8:12], r.Focus)
	order.PutUint32(reply[12:16], r.Time)
	reply[16] = r.RevertTo
	return reply
}

func ParseGetDeviceFocusReply(order binary.ByteOrder, b []byte) (*GetDeviceFocusReply, error) {
	if len(b) < 32 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	r := &GetDeviceFocusReply{
		Sequence: order.Uint16(b[2:4]),
		Focus:    order.Uint32(b[8:12]),
		Time:     order.Uint32(b[12:16]),
		RevertTo: b[16],
	}
	return r, nil
}

// OpenDevice reply
type OpenDeviceReply struct {
	Sequence uint16
	Classes  []InputClassInfo
}

func (r *OpenDeviceReply) EncodeMessage(order binary.ByteOrder) []byte {
	classesBuf := new(bytes.Buffer)
	for _, class := range r.Classes {
		classesBuf.Write(class.EncodeMessage(order))
	}
	classesBytes := classesBuf.Bytes()

	reply := make([]byte, 32+len(classesBytes))
	reply[0] = 1 // Reply
	reply[1] = byte(len(r.Classes))
	order.PutUint16(reply[2:4], r.Sequence)
	order.PutUint32(reply[4:8], uint32((len(classesBytes)+3)/4)) // length
	copy(reply[32:], classesBytes)
	return reply
}

func ParseOpenDeviceReply(order binary.ByteOrder, b []byte) (*OpenDeviceReply, error) {
	if len(b) < 32 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	numClasses := b[1]
	classes := make([]InputClassInfo, numClasses)
	offset := 32
	for i := 0; i < int(numClasses); i++ {
		if len(b) < offset+2 {
			return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
		}
		class, length := parseInputClassInfo(order, b[offset:])
		if len(b) < offset+length {
			return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
		}
		classes[i] = class
		offset += length
	}
	r := &OpenDeviceReply{
		Sequence: order.Uint16(b[2:4]),
		Classes:  classes,
	}
	return r, nil
}

// SetDeviceMode request
type SetDeviceModeRequest struct {
	DeviceID byte
	Mode     byte
}

func (r *SetDeviceModeRequest) OpCode() ReqCode {
	return XInputOpcode
}

func (r *SetDeviceModeRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	length := uint16(2)

	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(XSetDeviceMode)
	binary.Write(buf, order, length)
	buf.WriteByte(r.DeviceID)
	buf.WriteByte(r.Mode)
	buf.Write([]byte{0, 0}) // padding

	return buf.Bytes()
}

func ParseSetDeviceModeRequest(order binary.ByteOrder, body []byte, seq uint16) (*SetDeviceModeRequest, error) {
	if len(body) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XSetDeviceMode})
	}
	return &SetDeviceModeRequest{
		DeviceID: body[0],
		Mode:     body[1],
	}, nil
}

// SetDeviceMode reply
type SetDeviceModeReply struct {
	Sequence uint16
	Status   byte
}

func (r *SetDeviceModeReply) EncodeMessage(order binary.ByteOrder) []byte {
	reply := make([]byte, 32)
	reply[0] = 1 // Reply
	reply[1] = r.Status
	order.PutUint16(reply[2:4], r.Sequence)
	order.PutUint32(reply[4:8], 0) // length
	return reply
}

func ParseSetDeviceModeReply(order binary.ByteOrder, b []byte) (*SetDeviceModeReply, error) {
	if len(b) < 32 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	r := &SetDeviceModeReply{
		Sequence: order.Uint16(b[2:4]),
		Status:   b[1],
	}
	return r, nil
}

// SetDeviceValuators request
type SetDeviceValuatorsRequest struct {
	DeviceID      byte
	FirstValuator byte
	NumValuators  byte
	Valuators     []int32
}

func (r *SetDeviceValuatorsRequest) OpCode() ReqCode {
	return XInputOpcode
}

func (r *SetDeviceValuatorsRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	length := uint16(2 + len(r.Valuators))

	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(XSetDeviceValuators)
	binary.Write(buf, order, length)

	buf.WriteByte(r.DeviceID)
	buf.WriteByte(r.FirstValuator)
	buf.WriteByte(byte(len(r.Valuators)))
	buf.WriteByte(0) // padding
	for _, v := range r.Valuators {
		binary.Write(buf, order, v)
	}

	return buf.Bytes()
}

func ParseSetDeviceValuatorsRequest(order binary.ByteOrder, body []byte, seq uint16) (*SetDeviceValuatorsRequest, error) {
	if len(body) < 4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XSetDeviceValuators})
	}
	numValuators := body[2]
	if len(body) != 4+int(numValuators)*4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XSetDeviceValuators})
	}
	valuators := make([]int32, numValuators)
	for i := 0; i < int(numValuators); i++ {
		valuators[i] = int32(order.Uint32(body[4+i*4 : 8+i*4]))
	}
	return &SetDeviceValuatorsRequest{
		DeviceID:      body[0],
		FirstValuator: body[1],
		NumValuators:  numValuators,
		Valuators:     valuators,
	}, nil
}

// SetDeviceValuators reply
type SetDeviceValuatorsReply struct {
	Sequence uint16
	Status   byte
}

func (r *SetDeviceValuatorsReply) EncodeMessage(order binary.ByteOrder) []byte {
	reply := make([]byte, 32)
	reply[0] = 1 // Reply
	reply[1] = r.Status
	order.PutUint16(reply[2:4], r.Sequence)
	order.PutUint32(reply[4:8], 0) // length
	return reply
}

func ParseSetDeviceValuatorsReply(order binary.ByteOrder, b []byte) (*SetDeviceValuatorsReply, error) {
	if len(b) < 32 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	r := &SetDeviceValuatorsReply{
		Sequence: order.Uint16(b[2:4]),
		Status:   b[1],
	}
	return r, nil
}

// Device Control constants
const (
	DeviceResolution = 1
)

// DeviceControl interfaces
type DeviceControlState interface {
	EncodeMessage(order binary.ByteOrder) []byte
}

type DeviceControl interface {
	EncodeMessage(order binary.ByteOrder) []byte
}

type DeviceResolutionState struct {
	NumValuators   byte
	Resolutions    []uint32
	MinResolutions []uint32
	MaxResolutions []uint32
}

func (s *DeviceResolutionState) EncodeMessage(order binary.ByteOrder) []byte {
	length := 8 + int(s.NumValuators)*12
	buf := new(bytes.Buffer)
	buf.Grow(length)
	binary.Write(buf, order, uint16(DeviceResolution))
	binary.Write(buf, order, uint16(length))
	buf.WriteByte(s.NumValuators)
	buf.Write([]byte{0, 0, 0}) // padding
	for _, res := range s.Resolutions {
		binary.Write(buf, order, res)
	}
	for _, res := range s.MinResolutions {
		binary.Write(buf, order, res)
	}
	for _, res := range s.MaxResolutions {
		binary.Write(buf, order, res)
	}
	return buf.Bytes()
}

type DeviceResolutionControl struct {
	FirstValuator byte
	NumValuators  byte
	Resolutions   []uint32
}

func (c *DeviceResolutionControl) EncodeMessage(order binary.ByteOrder) []byte {
	length := 8 + int(c.NumValuators)*4
	buf := new(bytes.Buffer)
	buf.Grow(length)
	binary.Write(buf, order, uint16(DeviceResolution))
	binary.Write(buf, order, uint16(length))
	buf.WriteByte(c.FirstValuator)
	buf.WriteByte(c.NumValuators)
	buf.Write([]byte{0, 0}) // padding
	for _, res := range c.Resolutions {
		binary.Write(buf, order, res)
	}
	return buf.Bytes()
}

// GetDeviceControl request
type GetDeviceControlRequest struct {
	DeviceID byte
	Control  uint16
}

func (r *GetDeviceControlRequest) OpCode() ReqCode {
	return XInputOpcode
}

func (r *GetDeviceControlRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	length := uint16(2)

	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(XGetDeviceControl)
	binary.Write(buf, order, length)

	buf.WriteByte(r.DeviceID)
	buf.WriteByte(0) // padding
	binary.Write(buf, order, r.Control)

	return buf.Bytes()
}

func ParseGetDeviceControlRequest(order binary.ByteOrder, body []byte, seq uint16) (*GetDeviceControlRequest, error) {
	if len(body) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XGetDeviceControl})
	}
	return &GetDeviceControlRequest{
		DeviceID: body[0],
		Control:  order.Uint16(body[2:4]),
	}, nil
}

// GetDeviceControl reply
type GetDeviceControlReply struct {
	Sequence uint16
	Control  DeviceControlState
}

func (r *GetDeviceControlReply) EncodeMessage(order binary.ByteOrder) []byte {
	controlBytes := r.Control.EncodeMessage(order)
	reply := make([]byte, 32+len(controlBytes))
	reply[0] = 1 // Reply
	order.PutUint16(reply[2:4], r.Sequence)
	order.PutUint32(reply[4:8], uint32((len(controlBytes)+3)/4)) // length
	copy(reply[32:], controlBytes)
	return reply
}

func ParseGetDeviceControlReply(order binary.ByteOrder, b []byte) (*GetDeviceControlReply, error) {
	if len(b) < 32 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	if len(b) < 34 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	controlID := order.Uint16(b[32:34])
	var control DeviceControlState
	switch controlID {
	case DeviceResolution:
		if len(b) < 40+int(b[36])*12 {
			return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
		}
		numValuators := b[36]
		resolutions := make([]uint32, numValuators)
		minResolutions := make([]uint32, numValuators)
		maxResolutions := make([]uint32, numValuators)
		for i := 0; i < int(numValuators); i++ {
			resolutions[i] = order.Uint32(b[40+i*4:])
			minResolutions[i] = order.Uint32(b[40+int(numValuators)*4+i*4:])
			maxResolutions[i] = order.Uint32(b[40+int(numValuators)*8+i*4:])
		}
		control = &DeviceResolutionState{
			NumValuators:   numValuators,
			Resolutions:    resolutions,
			MinResolutions: minResolutions,
			MaxResolutions: maxResolutions,
		}
	default:
		// Do nothing
	}
	r := &GetDeviceControlReply{
		Sequence: order.Uint16(b[2:4]),
		Control:  control,
	}
	return r, nil
}

// ChangeDeviceControl request
type ChangeDeviceControlRequest struct {
	DeviceID byte
	Control  DeviceControl
}

func (r *ChangeDeviceControlRequest) OpCode() ReqCode {
	return XInputOpcode
}

func (r *ChangeDeviceControlRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	controlBytes := r.Control.EncodeMessage(order)
	length := uint16(1 + (len(controlBytes)+PadLen(len(controlBytes)))/4)

	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(XChangeDeviceControl)
	binary.Write(buf, order, length)

	buf.WriteByte(r.DeviceID)
	buf.WriteByte(0) // padding
	buf.Write(controlBytes)
	buf.Write(make([]byte, PadLen(len(controlBytes))))

	return buf.Bytes()
}

func ParseChangeDeviceControlRequest(order binary.ByteOrder, body []byte, seq uint16) (*ChangeDeviceControlRequest, error) {
	if len(body) < 4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XChangeDeviceControl})
	}
	controlID := order.Uint16(body[2:4])
	if controlID != DeviceResolution {
		return nil, NewError(ValueErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XChangeDeviceControl})
	}
	if len(body) < 10 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XChangeDeviceControl})
	}
	length := order.Uint16(body[4:6])
	firstValuator := body[6]
	numValuators := body[7]
	expectedControlLength := uint16(8) + uint16(numValuators)*4
	if length != expectedControlLength {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XChangeDeviceControl})
	}
	expectedBodyLength := 2 + int(length)
	if len(body) != expectedBodyLength {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XChangeDeviceControl})
	}
	resolutions := make([]uint32, numValuators)
	for i := 0; i < int(numValuators); i++ {
		start := 10 + i*4
		resolutions[i] = order.Uint32(body[start : start+4])
	}
	return &ChangeDeviceControlRequest{
		DeviceID: body[0],
		Control: &DeviceResolutionControl{
			FirstValuator: firstValuator,
			NumValuators:  numValuators,
			Resolutions:   resolutions,
		},
	}, nil
}

// ChangeDeviceControl reply
type ChangeDeviceControlReply struct {
	Sequence uint16
	Status   byte
}

func (r *ChangeDeviceControlReply) EncodeMessage(order binary.ByteOrder) []byte {
	reply := make([]byte, 32)
	reply[0] = 1 // Reply
	reply[1] = r.Status
	order.PutUint16(reply[2:4], r.Sequence)
	order.PutUint32(reply[4:8], 0)
	return reply
}

func ParseChangeDeviceControlReply(order binary.ByteOrder, b []byte) (*ChangeDeviceControlReply, error) {
	if len(b) < 32 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	r := &ChangeDeviceControlReply{
		Sequence: order.Uint16(b[2:4]),
		Status:   b[1],
	}
	return r, nil
}

// GetSelectedExtensionEvents request
type GetSelectedExtensionEventsRequest struct {
	Window uint32
}

func (r *GetSelectedExtensionEventsRequest) OpCode() ReqCode {
	return XInputOpcode
}

func ParseGetSelectedExtensionEventsRequest(order binary.ByteOrder, body []byte, seq uint16) (*GetSelectedExtensionEventsRequest, error) {
	if len(body) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XGetSelectedExtensionEvents})
	}
	return &GetSelectedExtensionEventsRequest{
		Window: order.Uint32(body[0:4]),
	}, nil
}

// GetSelectedExtensionEvents reply
type GetSelectedExtensionEventsReply struct {
	Sequence          uint16
	ThisClientClasses []uint32
	AllClientsClasses []uint32
}

func (r *GetSelectedExtensionEventsReply) EncodeMessage(order binary.ByteOrder) []byte {
	thisClientLen := len(r.ThisClientClasses)
	allClientsLen := len(r.AllClientsClasses)
	length := (thisClientLen + allClientsLen) * 4
	reply := make([]byte, 32+length)
	reply[0] = 1 // Reply
	order.PutUint16(reply[2:4], r.Sequence)
	order.PutUint32(reply[4:8], uint32(length/4))
	order.PutUint16(reply[8:10], uint16(thisClientLen))
	order.PutUint16(reply[10:12], uint16(allClientsLen))
	offset := 32
	for _, class := range r.ThisClientClasses {
		order.PutUint32(reply[offset:offset+4], class)
		offset += 4
	}
	for _, class := range r.AllClientsClasses {
		order.PutUint32(reply[offset:offset+4], class)
		offset += 4
	}
	return reply
}

func ParseGetSelectedExtensionEventsReply(order binary.ByteOrder, b []byte) (*GetSelectedExtensionEventsReply, error) {
	if len(b) < 32 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	thisClientLen := order.Uint16(b[8:10])
	allClientsLen := order.Uint16(b[10:12])
	if len(b) < 32+int(thisClientLen)*4+int(allClientsLen)*4 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	thisClientClasses := make([]uint32, thisClientLen)
	allClientsClasses := make([]uint32, allClientsLen)
	offset := 32
	for i := 0; i < int(thisClientLen); i++ {
		thisClientClasses[i] = order.Uint32(b[offset : offset+4])
		offset += 4
	}
	for i := 0; i < int(allClientsLen); i++ {
		allClientsClasses[i] = order.Uint32(b[offset : offset+4])
		offset += 4
	}
	r := &GetSelectedExtensionEventsReply{
		Sequence:          order.Uint16(b[2:4]),
		ThisClientClasses: thisClientClasses,
		AllClientsClasses: allClientsClasses,
	}
	return r, nil
}

// ChangeDeviceDontPropagateList request
type ChangeDeviceDontPropagateListRequest struct {
	Window  uint32
	Mode    byte
	Classes []uint32
}

func (r *ChangeDeviceDontPropagateListRequest) OpCode() ReqCode {
	return XInputOpcode
}

func ParseChangeDeviceDontPropagateListRequest(order binary.ByteOrder, body []byte, seq uint16) (*ChangeDeviceDontPropagateListRequest, error) {
	if len(body) < 8 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XChangeDeviceDontPropagateList})
	}
	numClasses := order.Uint16(body[4:6])
	if len(body) != 8+int(numClasses)*4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XChangeDeviceDontPropagateList})
	}
	classes := make([]uint32, numClasses)
	for i := 0; i < int(numClasses); i++ {
		classes[i] = order.Uint32(body[8+i*4 : 12+i*4])
	}
	return &ChangeDeviceDontPropagateListRequest{
		Window:  order.Uint32(body[0:4]),
		Mode:    body[6],
		Classes: classes,
	}, nil
}

// GetDeviceDontPropagateList request
type GetDeviceDontPropagateListRequest struct {
	Window uint32
}

func (r *GetDeviceDontPropagateListRequest) OpCode() ReqCode {
	return XInputOpcode
}

func ParseGetDeviceDontPropagateListRequest(order binary.ByteOrder, body []byte, seq uint16) (*GetDeviceDontPropagateListRequest, error) {
	if len(body) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XGetDeviceDontPropagateList})
	}
	return &GetDeviceDontPropagateListRequest{
		Window: order.Uint32(body[0:4]),
	}, nil
}

// GetDeviceDontPropagateList reply
type GetDeviceDontPropagateListReply struct {
	Sequence uint16
	Classes  []uint32
}

func (r *GetDeviceDontPropagateListReply) EncodeMessage(order binary.ByteOrder) []byte {
	length := len(r.Classes) * 4
	reply := make([]byte, 32+length)
	reply[0] = 1 // Reply
	order.PutUint16(reply[2:4], r.Sequence)
	order.PutUint32(reply[4:8], uint32(length/4))
	order.PutUint16(reply[8:10], uint16(len(r.Classes)))
	offset := 32
	for _, class := range r.Classes {
		order.PutUint32(reply[offset:offset+4], class)
		offset += 4
	}
	return reply
}

func ParseGetDeviceDontPropagateListReply(order binary.ByteOrder, b []byte) (*GetDeviceDontPropagateListReply, error) {
	if len(b) < 32 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	numClasses := order.Uint16(b[8:10])
	if len(b) < 32+int(numClasses)*4 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	classes := make([]uint32, numClasses)
	offset := 32
	for i := 0; i < int(numClasses); i++ {
		classes[i] = order.Uint32(b[offset : offset+4])
		offset += 4
	}
	r := &GetDeviceDontPropagateListReply{
		Sequence: order.Uint16(b[2:4]),
		Classes:  classes,
	}
	return r, nil
}

// AllowDeviceEvents request
type AllowDeviceEventsRequest struct {
	Time     uint32
	DeviceID byte
	Mode     byte
}

func (r *AllowDeviceEventsRequest) OpCode() ReqCode {
	return XInputOpcode
}

func (r *AllowDeviceEventsRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	length := uint16(3)

	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(XAllowDeviceEvents)
	binary.Write(buf, order, length)

	binary.Write(buf, order, r.Time)
	buf.WriteByte(r.DeviceID)
	buf.WriteByte(r.Mode)
	buf.Write([]byte{0, 0}) // padding

	return buf.Bytes()
}

func ParseAllowDeviceEventsRequest(order binary.ByteOrder, body []byte, seq uint16) (*AllowDeviceEventsRequest, error) {
	if len(body) != 8 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XAllowDeviceEvents})
	}
	return &AllowDeviceEventsRequest{
		Time:     order.Uint32(body[0:4]),
		DeviceID: body[4],
		Mode:     body[5],
	}, nil
}

// CloseDevice request
type CloseDeviceRequest struct {
	DeviceID byte
}

func (r *CloseDeviceRequest) OpCode() ReqCode {
	return XInputOpcode
}

func ParseCloseDeviceRequest(order binary.ByteOrder, body []byte, seq uint16) (*CloseDeviceRequest, error) {
	if len(body) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XCloseDevice})
	}
	return &CloseDeviceRequest{
		DeviceID: body[0],
	}, nil
}

// CloseDevice reply
type CloseDeviceReply struct {
	Sequence uint16
}

func (r *CloseDeviceReply) EncodeMessage(order binary.ByteOrder) []byte {
	reply := make([]byte, 32)
	reply[0] = 1 // Reply
	order.PutUint16(reply[2:4], r.Sequence)
	order.PutUint32(reply[4:8], 0) // length
	return reply
}

func ParseCloseDeviceReply(order binary.ByteOrder, b []byte) (*CloseDeviceReply, error) {
	if len(b) < 32 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	r := &CloseDeviceReply{
		Sequence: order.Uint16(b[2:4]),
	}
	return r, nil
}

// GrabDevice request
type GrabDeviceRequest struct {
	DeviceID        byte
	GrabWindow      uint32
	Time            uint32
	OwnerEvents     bool
	ThisDeviceMode  byte
	OtherDeviceMode byte
	NumClasses      uint16
	Classes         []uint32
}

func (r *GrabDeviceRequest) OpCode() ReqCode {
	return XInputOpcode
}

func ParseGrabDeviceRequest(order binary.ByteOrder, body []byte, seq uint16) (*GrabDeviceRequest, error) {
	if len(body) < 16 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XGrabDevice})
	}
	numClasses := order.Uint16(body[12:14])
	if len(body) != 16+int(numClasses)*4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XGrabDevice})
	}
	classes := make([]uint32, numClasses)
	for i := 0; i < int(numClasses); i++ {
		classes[i] = order.Uint32(body[16+i*4 : 20+i*4])
	}
	return &GrabDeviceRequest{
		GrabWindow:      order.Uint32(body[0:4]),
		Time:            order.Uint32(body[4:8]),
		DeviceID:        body[8],
		OwnerEvents:     body[9] != 0,
		ThisDeviceMode:  body[10],
		OtherDeviceMode: body[11],
		NumClasses:      numClasses,
		Classes:         classes,
	}, nil
}

// GrabDevice reply
type GrabDeviceReply struct {
	Sequence uint16
	Status   byte
}

func (r *GrabDeviceReply) EncodeMessage(order binary.ByteOrder) []byte {
	reply := make([]byte, 32)
	reply[0] = 1 // Reply
	reply[1] = r.Status
	order.PutUint16(reply[2:4], r.Sequence)
	order.PutUint32(reply[4:8], 0) // length
	return reply
}

func ParseGrabDeviceReply(order binary.ByteOrder, b []byte) (*GrabDeviceReply, error) {
	if len(b) < 32 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	r := &GrabDeviceReply{
		Sequence: order.Uint16(b[2:4]),
		Status:   b[1],
	}
	return r, nil
}

// UngrabDevice request
type UngrabDeviceRequest struct {
	DeviceID byte
	Time     uint32
}

func (r *UngrabDeviceRequest) OpCode() ReqCode {
	return XInputOpcode
}

func ParseUngrabDeviceRequest(order binary.ByteOrder, body []byte, seq uint16) (*UngrabDeviceRequest, error) {
	if len(body) != 8 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XUngrabDevice})
	}
	return &UngrabDeviceRequest{
		Time:     order.Uint32(body[4:8]),
		DeviceID: body[0],
	}, nil
}

// ListInputDevices reply
type DeviceInfo struct {
	Header        DeviceHeader
	Classes       []InputClassInfo
	EventMasks    map[uint32]uint32   // window ID -> event mask (XI 1.x)
	XI2EventMasks map[uint32][]uint32 // window ID -> event masks (XI 2.x)
}

func (d *DeviceInfo) DeepCopy() *DeviceInfo {
	if d == nil {
		return nil
	}
	newInfo := &DeviceInfo{
		Header:        d.Header,
		Classes:       make([]InputClassInfo, len(d.Classes)),
		EventMasks:    make(map[uint32]uint32),
		XI2EventMasks: make(map[uint32][]uint32),
	}
	copy(newInfo.Classes, d.Classes)
	for k, v := range d.EventMasks {
		newInfo.EventMasks[k] = v
	}
	for k, v := range d.XI2EventMasks {
		masks := make([]uint32, len(v))
		copy(masks, v)
		newInfo.XI2EventMasks[k] = masks
	}
	return newInfo
}

func (d DeviceInfo) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	buf.WriteByte(d.Header.DeviceID)
	buf.WriteByte(d.Header.Use)
	binary.Write(buf, order, d.Header.DeviceType)
	buf.WriteByte(d.Header.NumClasses)
	buf.WriteByte(byte(len(d.Header.Name)))
	buf.WriteString(d.Header.Name)
	for _, class := range d.Classes {
		buf.Write(class.EncodeMessage(order))
	}
	return buf.Bytes()
}

type ListInputDevicesReply struct {
	Sequence uint16
	Devices  []*DeviceInfo
	NDevices byte
}

type DeviceHeader struct {
	DeviceID   byte
	DeviceType Atom
	NumClasses byte
	Use        byte // 0: IsXPointer, 1: IsXKeyboard, 2: IsXExtensionDevice
	Name       string
}

type InputClassInfo interface {
	EncodeMessage(order binary.ByteOrder) []byte
	ClassID() byte
	Length() int
}

type KeyClassInfo struct {
	NumKeys    uint16
	MinKeycode byte
	MaxKeycode byte
}

func (c *KeyClassInfo) ClassID() byte { return 0 }
func (c *KeyClassInfo) Length() int   { return 8 }
func (c *KeyClassInfo) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	buf.WriteByte(c.ClassID())
	buf.WriteByte(byte(c.Length()))
	binary.Write(buf, order, c.NumKeys)
	buf.WriteByte(c.MinKeycode)
	buf.WriteByte(c.MaxKeycode)
	buf.Write([]byte{0, 0}) // padding
	return buf.Bytes()
}

type ButtonClassInfo struct {
	NumButtons uint16
	State      [32]byte
}

func (c *ButtonClassInfo) ClassID() byte { return 1 }
func (c *ButtonClassInfo) Length() int   { return 8 + 32 }
func (c *ButtonClassInfo) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	buf.WriteByte(c.ClassID())
	buf.WriteByte(byte(c.Length()))
	binary.Write(buf, order, c.NumButtons)
	buf.Write([]byte{0, 0, 0, 0}) // padding
	buf.Write(c.State[:])
	return buf.Bytes()
}

type ValuatorClassInfo struct {
	NumAxes    byte
	Mode       byte
	MotionSize uint32
	Axes       []ValuatorAxisInfo
}

type ValuatorAxisInfo struct {
	Min        int32
	Max        int32
	Resolution uint32
	Value      int32
}

func (c *ValuatorClassInfo) ClassID() byte { return 2 }
func (c *ValuatorClassInfo) Length() int {
	return 8 + len(c.Axes)*12
}
func (c *ValuatorClassInfo) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	buf.WriteByte(c.ClassID())
	buf.WriteByte(byte(c.Length()))
	buf.WriteByte(c.NumAxes)
	buf.WriteByte(c.Mode)
	binary.Write(buf, order, c.MotionSize)
	for _, axis := range c.Axes {
		binary.Write(buf, order, axis.Resolution)
		binary.Write(buf, order, axis.Min)
		binary.Write(buf, order, axis.Max)
	}
	return buf.Bytes()
}

func (r *ListInputDevicesReply) EncodeMessage(order binary.ByteOrder) []byte {
	var devicesData []byte
	for _, dev := range r.Devices {
		devicesData = append(devicesData, dev.EncodeMessage(order)...)
	}
	p := (4 - (len(devicesData) % 4)) % 4
	if p == 4 {
		p = 0
	}
	finalDeviceData := make([]byte, len(devicesData)+p)
	copy(finalDeviceData, devicesData)
	reply := make([]byte, 32+len(finalDeviceData))
	reply[0] = 1 // Reply
	reply[8] = byte(len(r.Devices))
	order.PutUint16(reply[2:4], r.Sequence)
	order.PutUint32(reply[4:8], uint32((len(finalDeviceData)+3)/4)) // length
	copy(reply[32:], finalDeviceData)
	return reply
}

func ParseListInputDevicesReply(order binary.ByteOrder, b []byte) (*ListInputDevicesReply, error) {
	if len(b) < 32 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	nDevices := b[8]
	devices := make([]*DeviceInfo, nDevices)
	offset := 32
	for i := 0; i < int(nDevices); i++ {
		if len(b) < offset+8 {
			return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
		}
		nameLen := int(b[offset+7])
		if len(b) < offset+8+nameLen {
			return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
		}
		name := string(b[offset+8 : offset+8+nameLen])
		header := DeviceHeader{
			DeviceID:   b[offset],
			DeviceType: Atom(order.Uint32(b[offset+2 : offset+6])),
			NumClasses: b[offset+6],
			Use:        b[offset+1],
			Name:       name,
		}
		offset += 8 + nameLen + PadLen(nameLen)
		classes := make([]InputClassInfo, header.NumClasses)
		for j := 0; j < int(header.NumClasses); j++ {
			if len(b) < offset+2 {
				return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
			}
			class, length := parseInputClassInfo(order, b[offset:])
			if len(b) < offset+length {
				return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
			}
			classes[j] = class
			offset += length
		}
		devices[i] = &DeviceInfo{
			Header:  header,
			Classes: classes,
		}
	}
	return &ListInputDevicesReply{
		Sequence: order.Uint16(b[2:4]),
		Devices:  devices,
		NDevices: nDevices,
	}, nil
}

func ParseGetDeviceMotionEventsReply(order binary.ByteOrder, b []byte) (*GetDeviceMotionEventsReply, error) {
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
	r := &GetDeviceMotionEventsReply{
		Sequence: order.Uint16(b[2:4]),
		NEvents:  nEvents,
		Events:   events,
	}
	return r, nil
}

func ParseChangeKeyboardDeviceReply(order binary.ByteOrder, b []byte) (*ChangeKeyboardDeviceReply, error) {
	if len(b) < 32 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	r := &ChangeKeyboardDeviceReply{
		Sequence: order.Uint16(b[2:4]),
		Status:   b[1],
	}
	return r, nil
}

func ParseChangePointerDeviceReply(order binary.ByteOrder, b []byte) (*ChangePointerDeviceReply, error) {
	if len(b) < 32 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	r := &ChangePointerDeviceReply{
		Sequence: order.Uint16(b[2:4]),
		Status:   b[1],
	}
	return r, nil
}

//
// NEWLY IMPLEMENTED REQUESTS START HERE
//

// SelectExtensionEvent request
type SelectExtensionEventRequest struct {
	Window  Window
	Classes []uint32
}

func (r *SelectExtensionEventRequest) OpCode() ReqCode {
	return XInputOpcode
}

func (r *SelectExtensionEventRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	length := uint16(3 + len(r.Classes))

	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(XSelectExtensionEvent)
	binary.Write(buf, order, length)

	binary.Write(buf, order, r.Window)
	binary.Write(buf, order, uint16(len(r.Classes)))
	buf.Write([]byte{0, 0}) // padding
	for _, class := range r.Classes {
		binary.Write(buf, order, class)
	}

	return buf.Bytes()
}

func ParseSelectExtensionEventRequest(order binary.ByteOrder, body []byte, seq uint16) (*SelectExtensionEventRequest, error) {
	if len(body) < 8 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XSelectExtensionEvent})
	}
	numClasses := order.Uint16(body[4:6])
	if len(body) != 8+int(numClasses)*4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XSelectExtensionEvent})
	}
	classes := make([]uint32, numClasses)
	for i := 0; i < int(numClasses); i++ {
		classes[i] = order.Uint32(body[8+i*4 : 12+i*4])
	}
	return &SelectExtensionEventRequest{
		Window:  Window(order.Uint32(body[0:4])),
		Classes: classes,
	}, nil
}

// GetDeviceMotionEvents request
type GetDeviceMotionEventsRequest struct {
	Start    uint32
	Stop     uint32
	DeviceID byte
}

func (r *GetDeviceMotionEventsRequest) OpCode() ReqCode {
	return XInputOpcode
}

func (r *GetDeviceMotionEventsRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	length := uint16(4)

	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(XGetDeviceMotionEvents)
	binary.Write(buf, order, length)

	binary.Write(buf, order, r.Start)
	binary.Write(buf, order, r.Stop)
	buf.WriteByte(r.DeviceID)
	buf.Write([]byte{0, 0, 0}) // padding

	return buf.Bytes()
}

func ParseGetDeviceMotionEventsRequest(order binary.ByteOrder, body []byte, seq uint16) (*GetDeviceMotionEventsRequest, error) {
	if len(body) != 12 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XGetDeviceMotionEvents})
	}
	return &GetDeviceMotionEventsRequest{
		Start:    order.Uint32(body[0:4]),
		Stop:     order.Uint32(body[4:8]),
		DeviceID: body[8],
	}, nil
}

// ChangeKeyboardDevice request
type ChangeKeyboardDeviceRequest struct {
	DeviceID byte
}

func (r *ChangeKeyboardDeviceRequest) OpCode() ReqCode {
	return XInputOpcode
}

func (r *ChangeKeyboardDeviceRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	length := uint16(2)

	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(XChangeKeyboardDevice)
	binary.Write(buf, order, length)

	buf.WriteByte(r.DeviceID)
	buf.Write([]byte{0, 0, 0}) // padding

	return buf.Bytes()
}

func ParseChangeKeyboardDeviceRequest(order binary.ByteOrder, body []byte, seq uint16) (*ChangeKeyboardDeviceRequest, error) {
	if len(body) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XChangeKeyboardDevice})
	}
	return &ChangeKeyboardDeviceRequest{
		DeviceID: body[0],
	}, nil
}

// ChangePointerDevice request
type ChangePointerDeviceRequest struct {
	XAxis    byte
	YAxis    byte
	DeviceID byte
}

func (r *ChangePointerDeviceRequest) OpCode() ReqCode {
	return XInputOpcode
}

func (r *ChangePointerDeviceRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	length := uint16(2)

	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(XChangePointerDevice)
	binary.Write(buf, order, length)

	buf.WriteByte(r.XAxis)
	buf.WriteByte(r.YAxis)
	buf.WriteByte(r.DeviceID)
	buf.WriteByte(0) // padding

	return buf.Bytes()
}

func ParseChangePointerDeviceRequest(order binary.ByteOrder, body []byte, seq uint16) (*ChangePointerDeviceRequest, error) {
	if len(body) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XChangePointerDevice})
	}
	return &ChangePointerDeviceRequest{
		XAxis:    body[0],
		YAxis:    body[1],
		DeviceID: body[2],
	}, nil
}

// GrabDeviceKey request
type GrabDeviceKeyRequest struct {
	GrabWindow      Window
	Modifiers       uint16
	Key             byte
	DeviceID        byte
	OwnerEvents     bool
	ThisDeviceMode  byte
	OtherDeviceMode byte
	NumClasses      uint16
	Classes         []uint32
}

func (r *GrabDeviceKeyRequest) OpCode() ReqCode {
	return XInputOpcode
}

func (r *GrabDeviceKeyRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	length := uint16(5 + len(r.Classes))

	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(XGrabDeviceKey)
	binary.Write(buf, order, length)

	binary.Write(buf, order, r.GrabWindow)
	binary.Write(buf, order, uint16(len(r.Classes)))
	if r.OwnerEvents {
		buf.WriteByte(1)
	} else {
		buf.WriteByte(0)
	}
	buf.WriteByte(r.ThisDeviceMode)
	buf.WriteByte(r.OtherDeviceMode)
	buf.WriteByte(r.DeviceID)
	binary.Write(buf, order, r.Modifiers)
	buf.WriteByte(r.Key)
	for _, class := range r.Classes {
		binary.Write(buf, order, class)
	}

	return buf.Bytes()
}

func ParseGrabDeviceKeyRequest(order binary.ByteOrder, body []byte, seq uint16) (*GrabDeviceKeyRequest, error) {
	if len(body) < 13 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XGrabDeviceKey})
	}
	numClasses := order.Uint16(body[4:6])
	if len(body) != 13+int(numClasses)*4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XGrabDeviceKey})
	}
	classes := make([]uint32, numClasses)
	for i := 0; i < int(numClasses); i++ {
		classes[i] = order.Uint32(body[13+i*4 : 17+i*4])
	}
	return &GrabDeviceKeyRequest{
		GrabWindow:      Window(order.Uint32(body[0:4])),
		NumClasses:      numClasses,
		OwnerEvents:     body[6] != 0,
		ThisDeviceMode:  body[7],
		OtherDeviceMode: body[8],
		DeviceID:        body[9],
		Modifiers:       order.Uint16(body[10:12]),
		Key:             body[12],
		Classes:         classes,
	}, nil
}

// UngrabDeviceKey request
type UngrabDeviceKeyRequest struct {
	GrabWindow Window
	Modifiers  uint16
	Key        byte
	DeviceID   byte
}

func (r *UngrabDeviceKeyRequest) OpCode() ReqCode {
	return XInputOpcode
}

func (r *UngrabDeviceKeyRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	length := uint16(4)

	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(XUngrabDeviceKey)
	binary.Write(buf, order, length)

	binary.Write(buf, order, r.GrabWindow)
	binary.Write(buf, order, r.Modifiers)
	buf.WriteByte(r.DeviceID)
	buf.WriteByte(r.Key)
	buf.Write([]byte{0, 0, 0, 0}) // padding

	return buf.Bytes()
}

func ParseUngrabDeviceKeyRequest(order binary.ByteOrder, body []byte, seq uint16) (*UngrabDeviceKeyRequest, error) {
	if len(body) != 12 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XUngrabDeviceKey})
	}
	return &UngrabDeviceKeyRequest{
		GrabWindow: Window(order.Uint32(body[0:4])),
		Modifiers:  order.Uint16(body[4:6]),
		Key:        body[7],
		DeviceID:   body[6],
	}, nil
}

// GrabDeviceButton request
type GrabDeviceButtonRequest struct {
	GrabWindow      Window
	Modifiers       uint16
	Button          byte
	DeviceID        byte
	OwnerEvents     bool
	ThisDeviceMode  byte
	OtherDeviceMode byte
	NumClasses      uint16
	Classes         []uint32
}

func (r *GrabDeviceButtonRequest) OpCode() ReqCode {
	return XInputOpcode
}

func (r *GrabDeviceButtonRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	length := uint16(5 + len(r.Classes))

	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(XGrabDeviceButton)
	binary.Write(buf, order, length)

	binary.Write(buf, order, r.GrabWindow)
	binary.Write(buf, order, uint16(len(r.Classes)))
	if r.OwnerEvents {
		buf.WriteByte(1)
	} else {
		buf.WriteByte(0)
	}
	buf.WriteByte(r.ThisDeviceMode)
	buf.WriteByte(r.OtherDeviceMode)
	buf.WriteByte(r.DeviceID)
	binary.Write(buf, order, r.Modifiers)
	buf.WriteByte(r.Button)
	for _, class := range r.Classes {
		binary.Write(buf, order, class)
	}

	return buf.Bytes()
}

func ParseGrabDeviceButtonRequest(order binary.ByteOrder, body []byte, seq uint16) (*GrabDeviceButtonRequest, error) {
	if len(body) < 13 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XGrabDeviceButton})
	}
	numClasses := order.Uint16(body[4:6])
	expectedLen := 13 + int(numClasses)*4
	if len(body) != expectedLen {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XGrabDeviceButton})
	}
	classes := make([]uint32, numClasses)
	for i := 0; i < int(numClasses); i++ {
		classes[i] = order.Uint32(body[13+i*4 : 17+i*4])
	}
	return &GrabDeviceButtonRequest{
		GrabWindow:      Window(order.Uint32(body[0:4])),
		NumClasses:      numClasses,
		OwnerEvents:     body[6] != 0,
		ThisDeviceMode:  body[7],
		OtherDeviceMode: body[8],
		DeviceID:        body[9],
		Modifiers:       order.Uint16(body[10:12]),
		Button:          body[12],
		Classes:         classes,
	}, nil
}

// UngrabDeviceButton request
type UngrabDeviceButtonRequest struct {
	GrabWindow Window
	Modifiers  uint16
	Button     byte
	DeviceID   byte
}

func (r *UngrabDeviceButtonRequest) OpCode() ReqCode {
	return XInputOpcode
}

func (r *UngrabDeviceButtonRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	length := uint16(4)

	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(XUngrabDeviceButton)
	binary.Write(buf, order, length)

	binary.Write(buf, order, r.GrabWindow)
	binary.Write(buf, order, r.Modifiers)
	buf.WriteByte(r.DeviceID)
	buf.WriteByte(r.Button)
	buf.Write([]byte{0, 0, 0, 0}) // padding

	return buf.Bytes()
}

func ParseUngrabDeviceButtonRequest(order binary.ByteOrder, body []byte, seq uint16) (*UngrabDeviceButtonRequest, error) {
	if len(body) != 12 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XUngrabDeviceButton})
	}
	return &UngrabDeviceButtonRequest{
		GrabWindow: Window(order.Uint32(body[0:4])),
		Modifiers:  order.Uint16(body[4:6]),
		Button:     body[7],
		DeviceID:   body[6],
	}, nil
}

// GetDeviceFocus request
type GetDeviceFocusRequest struct {
	DeviceID byte
}

func (r *GetDeviceFocusRequest) OpCode() ReqCode {
	return XInputOpcode
}

func (r *GetDeviceFocusRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	length := uint16(2)

	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(XGetDeviceFocus)
	binary.Write(buf, order, length)

	buf.WriteByte(r.DeviceID)
	buf.Write([]byte{0, 0, 0}) // padding

	return buf.Bytes()
}

func ParseGetDeviceFocusRequest(order binary.ByteOrder, body []byte, seq uint16) (*GetDeviceFocusRequest, error) {
	if len(body) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XGetDeviceFocus})
	}
	return &GetDeviceFocusRequest{
		DeviceID: body[0],
	}, nil
}

// SetDeviceFocus request
type SetDeviceFocusRequest struct {
	Focus    Window
	Time     uint32
	RevertTo byte
	DeviceID byte
}

func (r *SetDeviceFocusRequest) OpCode() ReqCode {
	return XInputOpcode
}

func (r *SetDeviceFocusRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	length := uint16(4)

	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(XSetDeviceFocus)
	binary.Write(buf, order, length)

	binary.Write(buf, order, r.Focus)
	binary.Write(buf, order, r.Time)
	buf.WriteByte(r.RevertTo)
	buf.WriteByte(r.DeviceID)
	buf.Write([]byte{0, 0}) // padding

	return buf.Bytes()
}

func ParseSetDeviceFocusRequest(order binary.ByteOrder, body []byte, seq uint16) (*SetDeviceFocusRequest, error) {
	if len(body) != 12 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XSetDeviceFocus})
	}
	return &SetDeviceFocusRequest{
		Focus:    Window(order.Uint32(body[0:4])),
		Time:     order.Uint32(body[4:8]),
		RevertTo: body[8],
		DeviceID: body[9],
	}, nil
}

// GetFeedbackControl request
type GetFeedbackControlRequest struct {
	DeviceID byte
}

func (r *GetFeedbackControlRequest) OpCode() ReqCode {
	return XInputOpcode
}

func (r *GetFeedbackControlRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	length := uint16(2)

	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(XGetFeedbackControl)
	binary.Write(buf, order, length)

	buf.WriteByte(r.DeviceID)
	buf.Write([]byte{0, 0, 0}) // padding

	return buf.Bytes()
}

func ParseGetFeedbackControlRequest(order binary.ByteOrder, body []byte, seq uint16) (*GetFeedbackControlRequest, error) {
	if len(body) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XGetFeedbackControl})
	}
	return &GetFeedbackControlRequest{
		DeviceID: body[0],
	}, nil
}

// ChangeFeedbackControl request
type ChangeFeedbackControlRequest struct {
	Mask      uint32
	DeviceID  byte
	ControlID byte
	Control   []byte
}

func (r *ChangeFeedbackControlRequest) OpCode() ReqCode {
	return XInputOpcode
}

func (r *ChangeFeedbackControlRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	length := uint16(3 + (len(r.Control)+PadLen(len(r.Control)))/4)

	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(XChangeFeedbackControl)
	binary.Write(buf, order, length)

	binary.Write(buf, order, r.Mask)
	buf.WriteByte(r.DeviceID)
	buf.WriteByte(r.ControlID)
	buf.Write([]byte{0, 0}) // padding
	buf.Write(r.Control)
	buf.Write(make([]byte, PadLen(len(r.Control))))

	return buf.Bytes()
}

func ParseChangeFeedbackControlRequest(order binary.ByteOrder, body []byte, seq uint16) (*ChangeFeedbackControlRequest, error) {
	if len(body) < 8 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XChangeFeedbackControl})
	}
	return &ChangeFeedbackControlRequest{
		Mask:      order.Uint32(body[0:4]),
		DeviceID:  body[4],
		ControlID: body[5],
		Control:   body[8:],
	}, nil
}

// GetDeviceKeyMapping request
type GetDeviceKeyMappingRequest struct {
	DeviceID byte
	FirstKey byte
	Count    byte
}

func (r *GetDeviceKeyMappingRequest) OpCode() ReqCode {
	return XInputOpcode
}

func (r *GetDeviceKeyMappingRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	length := uint16(2)

	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(XGetDeviceKeyMapping)
	binary.Write(buf, order, length)

	buf.WriteByte(r.DeviceID)
	buf.WriteByte(r.FirstKey)
	buf.WriteByte(r.Count)
	buf.WriteByte(0) // padding

	return buf.Bytes()
}

func ParseGetDeviceKeyMappingRequest(order binary.ByteOrder, body []byte, seq uint16) (*GetDeviceKeyMappingRequest, error) {
	if len(body) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XGetDeviceKeyMapping})
	}
	return &GetDeviceKeyMappingRequest{
		DeviceID: body[0],
		FirstKey: body[1],
		Count:    body[2],
	}, nil
}

// GetDeviceKeyMapping reply
type GetDeviceKeyMappingReply struct {
	Sequence          uint16
	KeysymsPerKeycode byte
	Keysyms           []uint32
}

func (r *GetDeviceKeyMappingReply) EncodeMessage(order binary.ByteOrder) []byte {
	length := len(r.Keysyms) * 4
	reply := make([]byte, 32+length)
	reply[0] = 1 // Reply
	reply[1] = byte(XGetDeviceKeyMapping)
	order.PutUint16(reply[2:4], r.Sequence)
	order.PutUint32(reply[4:8], uint32(length/4))
	reply[8] = r.KeysymsPerKeycode
	offset := 32
	for _, keysym := range r.Keysyms {
		order.PutUint32(reply[offset:offset+4], keysym)
		offset += 4
	}
	return reply
}

func ParseGetDeviceKeyMappingReply(order binary.ByteOrder, b []byte) (*GetDeviceKeyMappingReply, error) {
	if len(b) < 32 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	keysymsPerKeycode := b[8]
	length := order.Uint32(b[4:8])
	if len(b) < 32+int(length)*4 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	keysyms := make([]uint32, length)
	offset := 32
	for i := 0; i < int(length); i++ {
		keysyms[i] = order.Uint32(b[offset : offset+4])
		offset += 4
	}
	r := &GetDeviceKeyMappingReply{
		Sequence:          order.Uint16(b[2:4]),
		KeysymsPerKeycode: keysymsPerKeycode,
		Keysyms:           keysyms,
	}
	return r, nil
}

// ChangeDeviceKeyMapping request
type ChangeDeviceKeyMappingRequest struct {
	DeviceID          byte
	FirstKey          byte
	KeysymsPerKeycode byte
	KeycodeCount      byte
	Keysyms           []uint32
}

func (r *ChangeDeviceKeyMappingRequest) OpCode() ReqCode {
	return XInputOpcode
}

func (r *ChangeDeviceKeyMappingRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	length := uint16(2 + len(r.Keysyms))

	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(XChangeDeviceKeyMapping)
	binary.Write(buf, order, length)

	buf.WriteByte(r.DeviceID)
	buf.WriteByte(r.FirstKey)
	buf.WriteByte(r.KeysymsPerKeycode)
	buf.WriteByte(r.KeycodeCount)
	for _, keysym := range r.Keysyms {
		binary.Write(buf, order, keysym)
	}

	return buf.Bytes()
}

func ParseChangeDeviceKeyMappingRequest(order binary.ByteOrder, body []byte, seq uint16) (*ChangeDeviceKeyMappingRequest, error) {
	if len(body) < 4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XChangeDeviceKeyMapping})
	}
	keycodeCount := body[3]
	keysymsPerKeycode := body[2]
	expectedLen := 4 + int(keycodeCount)*int(keysymsPerKeycode)*4
	if len(body) != expectedLen {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XChangeDeviceKeyMapping})
	}
	keysyms := make([]uint32, int(keycodeCount)*int(keysymsPerKeycode))
	for i := range keysyms {
		keysyms[i] = order.Uint32(body[4+i*4 : 8+i*4])
	}
	return &ChangeDeviceKeyMappingRequest{
		DeviceID:          body[0],
		FirstKey:          body[1],
		KeysymsPerKeycode: keysymsPerKeycode,
		KeycodeCount:      keycodeCount,
		Keysyms:           keysyms,
	}, nil
}

// GetDeviceModifierMapping request
type GetDeviceModifierMappingRequest struct {
	DeviceID byte
}

func (r *GetDeviceModifierMappingRequest) OpCode() ReqCode {
	return XInputOpcode
}

func (r *GetDeviceModifierMappingRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	length := uint16(2)

	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(XGetDeviceModifierMapping)
	binary.Write(buf, order, length)

	buf.WriteByte(r.DeviceID)
	buf.Write([]byte{0, 0, 0}) // padding

	return buf.Bytes()
}

func ParseGetDeviceModifierMappingRequest(order binary.ByteOrder, body []byte, seq uint16) (*GetDeviceModifierMappingRequest, error) {
	if len(body) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XGetDeviceModifierMapping})
	}
	return &GetDeviceModifierMappingRequest{
		DeviceID: body[0],
	}, nil
}

// SetDeviceModifierMapping request
type SetDeviceModifierMappingRequest struct {
	DeviceID byte
	Keycodes []byte
}

func (r *SetDeviceModifierMappingRequest) OpCode() ReqCode {
	return XInputOpcode
}

func (r *SetDeviceModifierMappingRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	length := uint16(2 + (len(r.Keycodes)+PadLen(len(r.Keycodes)))/4)

	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(XSetDeviceModifierMapping)
	binary.Write(buf, order, length)

	buf.WriteByte(r.DeviceID)
	buf.WriteByte(byte(len(r.Keycodes) / 8))
	buf.Write([]byte{0, 0}) // padding
	buf.Write(r.Keycodes)
	buf.Write(make([]byte, PadLen(len(r.Keycodes))))

	return buf.Bytes()
}

func ParseSetDeviceModifierMappingRequest(order binary.ByteOrder, body []byte, seq uint16) (*SetDeviceModifierMappingRequest, error) {
	if len(body) < 4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XSetDeviceModifierMapping})
	}
	numKeycodesPerModifier := body[1]
	// There are always 8 modifiers.
	expectedLen := 4 + int(numKeycodesPerModifier)*8
	if len(body) != expectedLen {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XSetDeviceModifierMapping})
	}
	return &SetDeviceModifierMappingRequest{
		DeviceID: body[0],
		Keycodes: body[4:],
	}, nil
}

// SetDeviceModifierMapping reply
type SetDeviceModifierMappingReply struct {
	ReplyType byte
	Unused    byte
	Sequence  uint16
	Length    uint32
	Status    byte
	Padding   [23]byte
}

func (r *SetDeviceModifierMappingReply) EncodeMessage(order binary.ByteOrder) []byte {
	reply := make([]byte, 32)
	reply[0] = 1 // Reply
	reply[1] = byte(XSetDeviceModifierMapping)
	order.PutUint16(reply[2:4], r.Sequence)
	order.PutUint32(reply[4:8], 0)
	reply[8] = r.Status
	return reply
}

func ParseSetDeviceModifierMappingReply(order binary.ByteOrder, b []byte) (*SetDeviceModifierMappingReply, error) {
	if len(b) < 32 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	r := &SetDeviceModifierMappingReply{
		Sequence: order.Uint16(b[2:4]),
		Status:   b[8],
	}
	return r, nil
}

// GetDeviceButtonMapping request
type GetDeviceButtonMappingRequest struct {
	DeviceID byte
}

func (r *GetDeviceButtonMappingRequest) OpCode() ReqCode {
	return XInputOpcode
}

func (r *GetDeviceButtonMappingRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	length := uint16(2)

	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(XGetDeviceButtonMapping)
	binary.Write(buf, order, length)

	buf.WriteByte(r.DeviceID)
	buf.Write([]byte{0, 0, 0}) // padding

	return buf.Bytes()
}

func ParseGetDeviceButtonMappingRequest(order binary.ByteOrder, body []byte, seq uint16) (*GetDeviceButtonMappingRequest, error) {
	if len(body) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XGetDeviceButtonMapping})
	}
	return &GetDeviceButtonMappingRequest{
		DeviceID: body[0],
	}, nil
}

// SetDeviceButtonMapping request
type SetDeviceButtonMappingRequest struct {
	DeviceID byte
	Map      []byte
}

func (r *SetDeviceButtonMappingRequest) OpCode() ReqCode {
	return XInputOpcode
}

func (r *SetDeviceButtonMappingRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	length := uint16((4 + len(r.Map) + PadLen(len(r.Map))) / 4)

	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(XSetDeviceButtonMapping)
	binary.Write(buf, order, length)

	buf.WriteByte(r.DeviceID)
	buf.WriteByte(byte(len(r.Map)))
	buf.Write([]byte{0, 0}) // padding
	buf.Write(r.Map)
	buf.Write(make([]byte, PadLen(len(r.Map))))

	return buf.Bytes()
}

func ParseSetDeviceButtonMappingRequest(order binary.ByteOrder, body []byte, seq uint16) (*SetDeviceButtonMappingRequest, error) {
	if len(body) < 4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XSetDeviceButtonMapping})
	}
	map_size := body[1]
	expectedLen := 4 + int(map_size)
	if len(body) != expectedLen+PadLen(expectedLen) {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XSetDeviceButtonMapping})
	}
	return &SetDeviceButtonMappingRequest{
		DeviceID: body[0],
		Map:      body[4:expectedLen],
	}, nil
}

// SetDeviceButtonMapping reply
type SetDeviceButtonMappingReply struct {
	ReplyType byte
	Unused    byte
	Sequence  uint16
	Length    uint32
	Status    byte
	Padding   [23]byte
}

func (r *SetDeviceButtonMappingReply) EncodeMessage(order binary.ByteOrder) []byte {
	reply := make([]byte, 32)
	reply[0] = 1 // Reply
	reply[1] = r.Status
	order.PutUint16(reply[2:4], r.Sequence)
	order.PutUint32(reply[4:8], 0)
	return reply
}

func ParseSetDeviceButtonMappingReply(order binary.ByteOrder, b []byte) (*SetDeviceButtonMappingReply, error) {
	if len(b) < 32 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	r := &SetDeviceButtonMappingReply{
		Sequence: order.Uint16(b[2:4]),
		Status:   b[1],
	}
	return r, nil
}

// QueryDeviceState request
type QueryDeviceStateRequest struct {
	DeviceID byte
}

func (r *QueryDeviceStateRequest) OpCode() ReqCode {
	return XInputOpcode
}

func (r *QueryDeviceStateRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	length := uint16(2)

	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(XQueryDeviceState)
	binary.Write(buf, order, length)

	buf.WriteByte(r.DeviceID)
	buf.Write([]byte{0, 0, 0}) // padding

	return buf.Bytes()
}

func ParseQueryDeviceStateRequest(order binary.ByteOrder, body []byte, seq uint16) (*QueryDeviceStateRequest, error) {
	if len(body) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XQueryDeviceState})
	}
	return &QueryDeviceStateRequest{
		DeviceID: body[0],
	}, nil
}

// SendExtensionEvent request
type SendExtensionEventRequest struct {
	Destination Window
	DeviceID    byte
	Propagate   bool
	NumClasses  uint16
	NumEvents   byte
	Events      []byte
	Classes     []uint32
}

func (r *SendExtensionEventRequest) OpCode() ReqCode {
	return XInputOpcode
}

func (r *SendExtensionEventRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	length := uint16(4 + len(r.Events)/4 + len(r.Classes))

	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(XSendExtensionEvent)
	binary.Write(buf, order, length)

	binary.Write(buf, order, r.Destination)
	binary.Write(buf, order, uint16(len(r.Classes)))
	buf.WriteByte(byte(len(r.Events) / 32))
	buf.WriteByte(r.DeviceID)
	if r.Propagate {
		buf.WriteByte(1)
	} else {
		buf.WriteByte(0)
	}
	buf.Write([]byte{0, 0, 0}) // padding
	buf.Write(r.Events)
	for _, class := range r.Classes {
		binary.Write(buf, order, class)
	}

	return buf.Bytes()
}

func ParseSendExtensionEventRequest(order binary.ByteOrder, body []byte, seq uint16) (*SendExtensionEventRequest, error) {
	// Base length before events and classes
	fixedBaseLen := 12 // 4 (Destination) + 2 (NumClasses) + 1 (NumEvents) + 1 (DeviceID) + 1 (Propagate) + 3 (Padding)

	if len(body) < fixedBaseLen {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XSendExtensionEvent})
	}

	destination := Window(order.Uint32(body[0:4]))
	numClasses := order.Uint16(body[4:6])
	numEvents := body[6]
	deviceID := body[7]
	propagate := body[8] != 0

	// Calculate expected total length
	expectedLen := fixedBaseLen + int(numEvents)*32 + int(numClasses)*4
	if len(body) != expectedLen {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XSendExtensionEvent})
	}

	eventsStart := fixedBaseLen // Events start after the fixed part (including padding)
	eventsEnd := eventsStart + int(numEvents)*32
	events := body[eventsStart:eventsEnd]

	classesStart := eventsEnd
	classes := make([]uint32, numClasses)
	for i := 0; i < int(numClasses); i++ {
		classes[i] = order.Uint32(body[classesStart+i*4 : classesStart+(i+1)*4])
	}

	return &SendExtensionEventRequest{
		Destination: destination,
		DeviceID:    deviceID,
		Propagate:   propagate,
		NumClasses:  numClasses,
		NumEvents:   numEvents,
		Events:      events,
		Classes:     classes,
	}, nil
}

// DeviceBell request
type DeviceBellRequest struct {
	DeviceID      byte
	FeedbackID    byte
	FeedbackClass byte
	Percent       byte
}

func (r *DeviceBellRequest) OpCode() ReqCode {
	return XInputOpcode
}

func (r *DeviceBellRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	length := uint16(2)

	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(XDeviceBell)
	binary.Write(buf, order, length)

	buf.WriteByte(r.DeviceID)
	buf.WriteByte(r.FeedbackID)
	buf.WriteByte(r.FeedbackClass)
	buf.WriteByte(r.Percent)

	return buf.Bytes()
}

func ParseDeviceBellRequest(order binary.ByteOrder, body []byte, seq uint16) (*DeviceBellRequest, error) {
	if len(body) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XDeviceBell})
	}
	return &DeviceBellRequest{
		DeviceID:      body[0],
		FeedbackID:    body[1],
		FeedbackClass: body[2],
		Percent:       body[3],
	}, nil
}

//
// XInput 2.0 requests
//

// XIQueryVersion request
type XIQueryVersionRequest struct {
	MajorVersion uint16
	MinorVersion uint16
}

func (r *XIQueryVersionRequest) OpCode() ReqCode {
	return XInputOpcode
}

func ParseXIQueryVersionRequest(order binary.ByteOrder, body []byte, seq uint16) (*XIQueryVersionRequest, error) {
	if len(body) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XIQueryVersion})
	}
	return &XIQueryVersionRequest{
		MajorVersion: order.Uint16(body[0:2]),
		MinorVersion: order.Uint16(body[2:4]),
	}, nil
}

// XIGrabDevice reply
type XIGrabDeviceReply struct {
	Sequence uint16
	Status   byte
}

func (r *XIGrabDeviceReply) EncodeMessage(order binary.ByteOrder) []byte {
	reply := make([]byte, 32)
	reply[0] = 1 // Reply
	reply[1] = r.Status
	order.PutUint16(reply[2:4], r.Sequence)
	order.PutUint32(reply[4:8], 0) // length
	return reply
}

// XIQueryVersion reply
type XIQueryVersionReply struct {
	Sequence     uint16
	MajorVersion uint16
	MinorVersion uint16
}

func (r *XIQueryVersionReply) EncodeMessage(order binary.ByteOrder) []byte {
	reply := make([]byte, 32)
	reply[0] = 1 // Reply
	order.PutUint16(reply[2:4], r.Sequence)
	order.PutUint32(reply[4:8], 0) // length
	order.PutUint16(reply[8:10], r.MajorVersion)
	order.PutUint16(reply[10:12], r.MinorVersion)
	return reply
}

// ModifierInfo structure
type ModifierInfo struct {
	Base      uint32
	Latched   uint32
	Locked    uint32
	Effective uint32
}

// GroupInfo structure
type GroupInfo struct {
	Base      byte
	Latched   byte
	Locked    byte
	Effective byte
}

// XIDeviceEvent represents an XI 2.x DeviceEvent.
type XIDeviceEvent struct {
	Sequence  uint16
	EventType uint16
	DeviceID  uint16
	Time      uint32
	Detail    uint32
	Root      uint32
	Event     uint32
	Child     uint32
	RootX     int32 // FP1616
	RootY     int32 // FP1616
	EventX    int32 // FP1616
	EventY    int32 // FP1616
	Buttons   []uint32
	Valuators []float64
	SourceID  uint16
	Mods      ModifierInfo
	Group     GroupInfo
}

// XIRawEvent represents an XI 2.x RawEvent.
type XIRawEvent struct {
	Sequence       uint16
	EventType      uint16
	DeviceID       uint16
	Time           uint32
	Detail         uint32
	SourceID       uint16
	ValuatorsMask  []uint32 // Bitmask of valuators
	ValuatorValues []float64
	RawValues      []float64
}

func DoubleToFP3232(v float64) (int32, uint32) {
	integral := int32(v)
	fractional := uint32((v - float64(integral)) * (1 << 32))
	return integral, fractional
}

func (e *XIRawEvent) EncodeMessage(order binary.ByteOrder) []byte {
	// Fixed part: 28 bytes (header 12 + body 16)
	// GenericEvent Header (12) + time(4) + detail(4) + sourceid(2) + valuators_len(2) + flags(4)

	valuatorsLen := len(e.ValuatorsMask)
	maskBytes := valuatorsLen * 4

	// Count set bits
	numValuators := 0
	for _, m := range e.ValuatorsMask {
		for i := 0; i < 32; i++ {
			if (m & (1 << i)) != 0 {
				numValuators++
			}
		}
	}

	valuesBytes := numValuators * 8 // 2 * 4 bytes for FP3232

	totalLen := 28 + maskBytes + valuesBytes*2 // Values and RawValues
	lengthField := (totalLen - 32) / 4

	buf := new(bytes.Buffer)
	buf.Grow(totalLen)

	// Header (GenericEvent)
	buf.WriteByte(35) // GenericEvent
	buf.WriteByte(byte(XInputOpcode))
	binary.Write(buf, order, e.Sequence)
	binary.Write(buf, order, uint32(lengthField))
	binary.Write(buf, order, e.EventType)
	binary.Write(buf, order, e.DeviceID)

	// Body
	binary.Write(buf, order, e.Time)
	binary.Write(buf, order, e.Detail)
	binary.Write(buf, order, e.SourceID)
	binary.Write(buf, order, uint16(valuatorsLen))
	binary.Write(buf, order, uint32(0)) // flags (0 for now)

	// Mask
	for _, m := range e.ValuatorsMask {
		binary.Write(buf, order, m)
	}

	// ValuatorValues
	for _, v := range e.ValuatorValues {
		integral, fractional := DoubleToFP3232(v)
		binary.Write(buf, order, integral)
		binary.Write(buf, order, fractional)
	}

	// RawValues
	for _, v := range e.RawValues {
		integral, fractional := DoubleToFP3232(v)
		binary.Write(buf, order, integral)
		binary.Write(buf, order, fractional)
	}

	return buf.Bytes()
}

func (e *XIDeviceEvent) EncodeMessage(order binary.ByteOrder) []byte {
	// Fixed part: 76 bytes
	// Header (GenericEvent): 12 bytes. But DeviceEvent struct overlaps.
	// Wire format:
	// type(1)=35, extension(1), sequence(2), length(4), evtype(2), deviceid(2), time(4), detail(4), root(4), event(4), child(4),
	// root_x(4), root_y(4), event_x(4), event_y(4), buttons_len(2), valuators_len(2), sourceid(2), pad0(2)
	// mods(16), group(4)
	// = 76 bytes.

	buttonsLen := 0
	if len(e.Buttons) > 0 {
		buttonsLen = len(e.Buttons) * 4
	}
	// Valuators mask + values? No, valuators_len is bitmask len (in 4-byte units).
	// We assume no valuators for now.
	valuatorsLen := 0

	totalLen := 76 + buttonsLen + valuatorsLen
	lengthField := (totalLen - 32) / 4

	buf := make([]byte, totalLen)
	buf[0] = 35 // GenericEvent
	buf[1] = byte(XInputOpcode)
	order.PutUint16(buf[2:4], e.Sequence)
	order.PutUint32(buf[4:8], uint32(lengthField))
	order.PutUint16(buf[8:10], e.EventType)
	order.PutUint16(buf[10:12], e.DeviceID)
	order.PutUint32(buf[12:16], e.Time)
	order.PutUint32(buf[16:20], e.Detail)
	order.PutUint32(buf[20:24], e.Root)
	order.PutUint32(buf[24:28], e.Event)
	order.PutUint32(buf[28:32], e.Child)
	order.PutUint32(buf[32:36], uint32(e.RootX))
	order.PutUint32(buf[36:40], uint32(e.RootY))
	order.PutUint32(buf[40:44], uint32(e.EventX))
	order.PutUint32(buf[44:48], uint32(e.EventY))
	order.PutUint16(buf[48:50], uint16(buttonsLen/4))
	order.PutUint16(buf[50:52], 0) // Valuators len
	order.PutUint16(buf[52:54], e.SourceID)
	// pad0 (54-56) is 0

	// Mods (16 bytes)
	order.PutUint32(buf[56:60], e.Mods.Base)
	order.PutUint32(buf[60:64], e.Mods.Latched)
	order.PutUint32(buf[64:68], e.Mods.Locked)
	order.PutUint32(buf[68:72], e.Mods.Effective)

	// Group (4 bytes)
	buf[72] = e.Group.Base
	buf[73] = e.Group.Latched
	buf[74] = e.Group.Locked
	buf[75] = e.Group.Effective

	if buttonsLen > 0 {
		offset := 76
		for _, b := range e.Buttons {
			order.PutUint32(buf[offset:offset+4], b)
			offset += 4
		}
	}

	return buf
}

// XIQueryPointer request
type XIQueryPointerRequest struct {
	Window   Window
	DeviceID uint16
}

func (r *XIQueryPointerRequest) OpCode() ReqCode {
	return XInputOpcode
}

func (r *XIQueryPointerRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	length := uint16(3)

	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(XIQueryPointer)
	binary.Write(buf, order, length)

	binary.Write(buf, order, r.Window)
	binary.Write(buf, order, r.DeviceID)
	buf.Write([]byte{0, 0}) // padding
	return buf.Bytes()
}

func ParseXIQueryPointerRequest(order binary.ByteOrder, body []byte, seq uint16) (*XIQueryPointerRequest, error) {
	if len(body) != 8 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: XInputOpcode, Minor: XIQueryPointer})
	}
	return &XIQueryPointerRequest{
		Window:   Window(order.Uint32(body[0:4])),
		DeviceID: order.Uint16(body[4:6]),
	}, nil
}

// XIQueryPointer reply
type XIQueryPointerReply struct {
	Sequence   uint16
	Root       Window
	Child      Window
	RootX      int32 // FP1616
	RootY      int32 // FP1616
	WinX       int32 // FP1616
	WinY       int32 // FP1616
	SameScreen bool
	Mods       ModifierInfo
	Group      GroupInfo
	Buttons    []uint32
}

func (r *XIQueryPointerReply) EncodeMessage(order binary.ByteOrder) []byte {
	buttonsLen := len(r.Buttons) * 4
	totalLen := 56 + buttonsLen
	lengthField := (totalLen - 32) / 4

	buf := make([]byte, totalLen)
	buf[0] = 1 // Reply
	order.PutUint16(buf[2:4], r.Sequence)
	order.PutUint32(buf[4:8], uint32(lengthField))

	order.PutUint32(buf[8:12], uint32(r.Root))
	order.PutUint32(buf[12:16], uint32(r.Child))
	order.PutUint32(buf[16:20], uint32(r.RootX))
	order.PutUint32(buf[20:24], uint32(r.RootY))
	order.PutUint32(buf[24:28], uint32(r.WinX))
	order.PutUint32(buf[28:32], uint32(r.WinY))

	if r.SameScreen {
		buf[32] = 1
	}
	// pad0 (33)
	order.PutUint16(buf[34:36], uint16(len(r.Buttons)))

	// Mods (16 bytes)
	order.PutUint32(buf[36:40], r.Mods.Base)
	order.PutUint32(buf[40:44], r.Mods.Latched)
	order.PutUint32(buf[44:48], r.Mods.Locked)
	order.PutUint32(buf[48:52], r.Mods.Effective)

	// Group (4 bytes)
	buf[52] = r.Group.Base
	buf[53] = r.Group.Latched
	buf[54] = r.Group.Locked
	buf[55] = r.Group.Effective

	if len(r.Buttons) > 0 {
		offset := 56
		for _, b := range r.Buttons {
			order.PutUint32(buf[offset:offset+4], b)
			offset += 4
		}
	}

	return buf
}

func ParseXIGrabDeviceReply(order binary.ByteOrder, b []byte) (*XIGrabDeviceReply, error) {
	if len(b) < 32 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	r := &XIGrabDeviceReply{
		Sequence: order.Uint16(b[2:4]),
		Status:   b[1],
	}
	return r, nil
}

func ParseXIQueryVersionReply(order binary.ByteOrder, b []byte) (*XIQueryVersionReply, error) {
	if len(b) < 32 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	r := &XIQueryVersionReply{
		Sequence:     order.Uint16(b[2:4]),
		MajorVersion: order.Uint16(b[8:10]),
		MinorVersion: order.Uint16(b[10:12]),
	}
	return r, nil
}

func ParseXIPassiveGrabDeviceReply(order binary.ByteOrder, b []byte) (*XIPassiveGrabDeviceReply, error) {
	if len(b) < 32 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	numModifiers := order.Uint16(b[8:10])
	if len(b) < 32+int(numModifiers)*8 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	modifiers := make([]XIGrabModifierInfo, numModifiers)
	offset := 32
	for i := 0; i < int(numModifiers); i++ {
		modifiers[i] = XIGrabModifierInfo{
			Status:    b[offset],
			Modifiers: order.Uint32(b[offset+4 : offset+8]),
		}
		offset += 8
	}

	r := &XIPassiveGrabDeviceReply{
		Sequence:     order.Uint16(b[2:4]),
		NumModifiers: numModifiers,
		Modifiers:    modifiers,
	}
	return r, nil
}

func ParseXIQueryPointerReply(order binary.ByteOrder, b []byte) (*XIQueryPointerReply, error) {
	if len(b) < 56 {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}
	buttonsLen := int(order.Uint16(b[34:36])) * 4
	if len(b) < 56+buttonsLen {
		return nil, NewError(LengthErrorCode, 0, 0, Opcodes{Major: 0, Minor: 0})
	}

	r := &XIQueryPointerReply{
		Sequence:   order.Uint16(b[2:4]),
		Root:       Window(order.Uint32(b[8:12])),
		Child:      Window(order.Uint32(b[12:16])),
		RootX:      int32(order.Uint32(b[16:20])),
		RootY:      int32(order.Uint32(b[20:24])),
		WinX:       int32(order.Uint32(b[24:28])),
		WinY:       int32(order.Uint32(b[28:32])),
		SameScreen: b[32] != 0,
		Mods: ModifierInfo{
			Base:      order.Uint32(b[36:40]),
			Latched:   order.Uint32(b[40:44]),
			Locked:    order.Uint32(b[44:48]),
			Effective: order.Uint32(b[48:52]),
		},
		Group: GroupInfo{
			Base:      b[52],
			Latched:   b[53],
			Locked:    b[54],
			Effective: b[55],
		},
	}

	if buttonsLen > 0 {
		r.Buttons = make([]uint32, buttonsLen/4)
		offset := 56
		for i := 0; i < int(buttonsLen/4); i++ {
			r.Buttons[i] = order.Uint32(b[offset : offset+4])
			offset += 4
		}
	}

	return r, nil
}
