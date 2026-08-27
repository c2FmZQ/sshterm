//go:build x11

package wire

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// Request is an interface implemented by all X11 request structs.
type Request interface {
	// OpCode returns the request opcode.
	OpCode() ReqCode
}

// PadLen returns the number of padding bytes needed to align n bytes to a 4-byte boundary.
func PadLen(n int) int {
	return (4 - n%4) % 4
}

// ParseRequest parses an X11 request from the given raw bytes.
// It determines the request type based on the opcode in the header and dispatches to the appropriate parsing function.
func ParseRequest(order binary.ByteOrder, raw []byte, seq uint16, bigRequestsEnabled bool) (Request, error) {
	var reqHeader [4]byte
	if n := copy(reqHeader[:], raw); n != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: 0, Minor: 0})
	}

	length := uint32(order.Uint16(reqHeader[2:4]))
	opcode := ReqCode(reqHeader[0])
	bodyOffset := 4
	if bigRequestsEnabled && length == 0 {
		if len(raw) < 8 {
			return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: opcode, Minor: 0})
		}
		length = order.Uint32(raw[4:8])
		bodyOffset = 8
	}

	if uint64(length)*4 != uint64(len(raw)) {
		debugf("X11: ParseRequest(%x...) length=%d, %d != %d", reqHeader, length, 4*length, len(raw))
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: opcode, Minor: 0})
	}

	data := reqHeader[1]
	body := raw[bodyOffset:]

	if opcode == BigRequestsOpcode {
		return ParseEnableBigRequestsRequest(order, raw, seq)
	}
	if opcode == XInputOpcode {
		return ParseXInputRequest(order, data, body, seq)
	}

	switch opcode {
	case CreateWindow:
		return ParseCreateWindowRequest(order, data, body, seq)

	case ChangeWindowAttributes:
		return ParseChangeWindowAttributesRequest(order, body, seq)

	case GetWindowAttributes:
		return ParseGetWindowAttributesRequest(order, body, seq)

	case DestroyWindow:
		return ParseDestroyWindowRequest(order, body, seq)

	case DestroySubwindows:
		return ParseDestroySubwindowsRequest(order, body, seq)

	case ChangeSaveSet:
		return ParseChangeSaveSetRequest(order, data, body, seq)

	case ReparentWindow:
		return ParseReparentWindowRequest(order, body, seq)

	case MapWindow:
		return ParseMapWindowRequest(order, body, seq)

	case MapSubwindows:
		return ParseMapSubwindowsRequest(order, body, seq)

	case UnmapWindow:
		return ParseUnmapWindowRequest(order, body, seq)

	case UnmapSubwindows:
		return ParseUnmapSubwindowsRequest(order, body, seq)

	case ConfigureWindow:
		return ParseConfigureWindowRequest(order, body, seq)

	case CirculateWindow:
		return ParseCirculateWindowRequest(order, data, body, seq)

	case GetGeometry:
		return ParseGetGeometryRequest(order, body, seq)

	case QueryTree:
		return ParseQueryTreeRequest(order, body, seq)

	case InternAtom:
		return ParseInternAtomRequest(order, data, body, seq)

	case GetAtomName:
		return ParseGetAtomNameRequest(order, body, seq)

	case ChangeProperty:
		return ParseChangePropertyRequest(order, body, seq)

	case DeleteProperty:
		return ParseDeletePropertyRequest(order, body, seq)

	case GetProperty:
		return ParseGetPropertyRequest(order, data, body, seq)

	case ListProperties:
		return ParseListPropertiesRequest(order, body, seq)

	case SetSelectionOwner:
		return ParseSetSelectionOwnerRequest(order, body, seq)

	case GetSelectionOwner:
		return ParseGetSelectionOwnerRequest(order, body, seq)

	case ConvertSelection:
		return ParseConvertSelectionRequest(order, body, seq)

	case SendEvent:
		return ParseSendEventRequest(order, data, body, seq)

	case GrabPointer:
		return ParseGrabPointerRequest(order, data, body, seq)

	case UngrabPointer:
		return ParseUngrabPointerRequest(order, body, seq)

	case GrabButton:
		return ParseGrabButtonRequest(order, data, body, seq)

	case UngrabButton:
		return ParseUngrabButtonRequest(order, data, body, seq)

	case ChangeActivePointerGrab:
		return ParseChangeActivePointerGrabRequest(order, body, seq)

	case GrabKeyboard:
		return ParseGrabKeyboardRequest(order, data, body, seq)

	case UngrabKeyboard:
		return ParseUngrabKeyboardRequest(order, body, seq)

	case GrabKey:
		return ParseGrabKeyRequest(order, data, body, seq)

	case UngrabKey:
		return ParseUngrabKeyRequest(order, data, body, seq)

	case AllowEvents:
		return ParseAllowEventsRequest(order, data, body, seq)

	case GrabServer:
		return ParseGrabServerRequest(order, body, seq)

	case UngrabServer:
		return ParseUngrabServerRequest(order, body, seq)

	case QueryPointer:
		return ParseQueryPointerRequest(order, body, seq)

	case GetMotionEvents:
		return ParseGetMotionEventsRequest(order, body, seq)

	case TranslateCoords:
		return ParseTranslateCoordsRequest(order, body, seq)

	case WarpPointer:
		return ParseWarpPointerRequest(order, body, seq)

	case SetInputFocus:
		return ParseSetInputFocusRequest(order, data, body, seq)

	case GetInputFocus:
		return ParseGetInputFocusRequest(order, body, seq)

	case QueryKeymap:
		return ParseQueryKeymapRequest(order, body, seq)

	case OpenFont:
		return ParseOpenFontRequest(order, body, seq)

	case CloseFont:
		return ParseCloseFontRequest(order, body, seq)

	case QueryFont:
		return ParseQueryFontRequest(order, body, seq)

	case QueryTextExtents:
		return ParseQueryTextExtentsRequest(order, data, body, seq)

	case ListFonts:
		return ParseListFontsRequest(order, body, seq)

	case ListFontsWithInfo:
		return ParseListFontsWithInfoRequest(order, body, seq)

	case SetFontPath:
		return ParseSetFontPathRequest(order, body, seq)

	case GetFontPath:
		return ParseGetFontPathRequest(order, body, seq)

	case CreatePixmap:
		return ParseCreatePixmapRequest(order, data, body, seq)

	case FreePixmap:
		return ParseFreePixmapRequest(order, body, seq)

	case CreateGC:
		return ParseCreateGCRequest(order, body, seq)

	case ChangeGC:
		return ParseChangeGCRequest(order, body, seq)

	case CopyGC:
		return ParseCopyGCRequest(order, body, seq)

	case SetDashes:
		return ParseSetDashesRequest(order, body, seq)

	case SetClipRectangles:
		return ParseSetClipRectanglesRequest(order, data, body, seq)

	case FreeGC:
		return ParseFreeGCRequest(order, body, seq)

	case ClearArea:
		return ParseClearAreaRequest(order, body, seq)

	case CopyArea:
		return ParseCopyAreaRequest(order, body, seq)

	case PolyPoint:
		return ParsePolyPointRequest(order, data, body, seq)

	case PolyLine:
		return ParsePolyLineRequest(order, data, body, seq)

	case PolySegment:
		return ParsePolySegmentRequest(order, body, seq)

	case PolyRectangle:
		return ParsePolyRectangleRequest(order, body, seq)

	case PolyArc:
		return ParsePolyArcRequest(order, body, seq)

	case FillPoly:
		return ParseFillPolyRequest(order, body, seq)

	case PolyFillRectangle:
		return ParsePolyFillRectangleRequest(order, body, seq)

	case PolyFillArc:
		return ParsePolyFillArcRequest(order, body, seq)

	case PutImage:
		return ParsePutImageRequest(order, data, body, seq)

	case GetImage:
		return ParseGetImageRequest(order, data, body, seq)

	case PolyText8:
		return ParsePolyText8Request(order, body, seq)

	case PolyText16:
		return ParsePolyText16Request(order, body, seq)

	case ImageText8:
		return ParseImageText8Request(order, data, body, seq)

	case ImageText16:
		return ParseImageText16Request(order, data, body, seq)

	case CreateColormap:
		return ParseCreateColormapRequest(order, data, body, seq)

	case FreeColormap:
		return ParseFreeColormapRequest(order, body, seq)

	case CopyColormapAndFree:
		return ParseCopyColormapAndFreeRequest(order, body, seq)

	case InstallColormap:
		return ParseInstallColormapRequest(order, body, seq)

	case UninstallColormap:
		return ParseUninstallColormapRequest(order, body, seq)

	case ListInstalledColormaps:
		return ParseListInstalledColormapsRequest(order, body, seq)

	case AllocColor:
		return ParseAllocColorRequest(order, body, seq)

	case AllocNamedColor:
		return ParseAllocNamedColorRequest(order, body, seq)

	case FreeColors:
		return ParseFreeColorsRequest(order, body, seq)

	case StoreColors:
		return ParseStoreColorsRequest(order, body, seq)

	case StoreNamedColor:
		return ParseStoreNamedColorRequest(order, data, body, seq)

	case QueryColors:
		return ParseQueryColorsRequest(order, body, seq)

	case LookupColor:
		return ParseLookupColorRequest(order, body, seq)

	case CreateGlyphCursor:
		return ParseCreateGlyphCursorRequest(order, body, seq)

	case FreeCursor:
		return ParseFreeCursorRequest(order, body, seq)

	case RecolorCursor:
		return ParseRecolorCursorRequest(order, body, seq)

	case QueryBestSize:
		return ParseQueryBestSizeRequest(order, body, seq)

	case QueryExtension:
		return ParseQueryExtensionRequest(order, body, seq)

	case Bell:
		if len(body) != 0 {
			return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: Bell, Minor: 0})
		}
		return ParseBellRequest(data, seq)

	case SetPointerMapping:
		return ParseSetPointerMappingRequest(order, data, body, seq)

	case GetPointerMapping:
		return ParseGetPointerMappingRequest(order, body, seq)

	case GetKeyboardMapping:
		return ParseGetKeyboardMappingRequest(order, body, seq)

	case ChangeKeyboardMapping:
		return ParseChangeKeyboardMappingRequest(order, data, body, seq)

	case ChangeKeyboardControl:
		return ParseChangeKeyboardControlRequest(order, body, seq)

	case GetKeyboardControl:
		return ParseGetKeyboardControlRequest(order, body, seq)

	case SetScreenSaver:
		return ParseSetScreenSaverRequest(order, body, seq)

	case GetScreenSaver:
		return ParseGetScreenSaverRequest(order, body, seq)

	case ChangeHosts:
		return ParseChangeHostsRequest(order, data, body, seq)

	case ListHosts:
		return ParseListHostsRequest(order, body, seq)

	case SetAccessControl:
		return ParseSetAccessControlRequest(order, data, body, seq)

	case SetCloseDownMode:
		return ParseSetCloseDownModeRequest(order, data, body, seq)

	case KillClient:
		return ParseKillClientRequest(order, body, seq)

	case RotateProperties:
		return ParseRotatePropertiesRequest(order, body, seq)

	case ForceScreenSaver:
		return ParseForceScreenSaverRequest(order, data, body, seq)

	case SetModifierMapping:
		return ParseSetModifierMappingRequest(order, data, body, seq)

	case GetModifierMapping:
		return ParseGetModifierMappingRequest(order, body, seq)

	case NoOperation:
		return ParseNoOperationRequest(order, body, seq)

	case AllocColorCells:
		return ParseAllocColorCellsRequest(order, data, body, seq)

	case AllocColorPlanes:
		return ParseAllocColorPlanesRequest(order, data, body, seq)

	case CreateCursor:
		return ParseCreateCursorRequest(order, body, seq)

	case CopyPlane:
		return ParseCopyPlaneRequest(order, body, seq)

	case ListExtensions:
		return ParseListExtensionsRequest(order, raw, seq)

	case ChangePointerControl:
		return ParseChangePointerControlRequest(order, body, seq)

	case GetPointerControl:
		return ParseGetPointerControlRequest(order, body, seq)

	default:
		return nil, fmt.Errorf("x11: unhandled opcode %d", opcode)
	}
}

// auxiliary data structures

// WindowAttributes represents the attributes of a window.
// Used in CreateWindow and ChangeWindowAttributes requests.
type WindowAttributes struct {
	BackgroundPixmap  Pixmap
	BackgroundPixel   uint32
	BorderPixmap      Pixmap
	BorderPixel       uint32
	BitGravity        uint32
	WinGravity        uint32
	BackingStore      uint32
	BackingPlanes     uint32
	BackingPixel      uint32
	OverrideRedirect  bool
	SaveUnder         bool
	EventMask         uint32
	DontPropagateMask uint32
	Colormap          Colormap
	Cursor            Cursor

	// Not part of value-mask, but part of window state
	Class              uint32
	MapIsInstalled     bool
	MapState           uint32
	BackgroundPixelSet bool
}

// encode serializes the window attributes to a byte slice based on the value mask.
func (wa *WindowAttributes) encode(order binary.ByteOrder, valueMask uint32) []byte {
	buf := new(bytes.Buffer)
	if valueMask&CWBackPixmap != 0 {
		binary.Write(buf, order, wa.BackgroundPixmap)
	}
	if valueMask&CWBackPixel != 0 {
		binary.Write(buf, order, wa.BackgroundPixel)
	}
	if valueMask&CWBorderPixmap != 0 {
		binary.Write(buf, order, wa.BorderPixmap)
	}
	if valueMask&CWBorderPixel != 0 {
		binary.Write(buf, order, wa.BorderPixel)
	}
	if valueMask&CWBitGravity != 0 {
		binary.Write(buf, order, wa.BitGravity)
	}
	if valueMask&CWWinGravity != 0 {
		binary.Write(buf, order, wa.WinGravity)
	}
	if valueMask&CWBackingStore != 0 {
		binary.Write(buf, order, wa.BackingStore)
	}
	if valueMask&CWBackingPlanes != 0 {
		binary.Write(buf, order, wa.BackingPlanes)
	}
	if valueMask&CWBackingPixel != 0 {
		binary.Write(buf, order, wa.BackingPixel)
	}
	if valueMask&CWOverrideRedirect != 0 {
		var v uint32
		if wa.OverrideRedirect {
			v = 1
		}
		binary.Write(buf, order, v)
	}
	if valueMask&CWSaveUnder != 0 {
		var v uint32
		if wa.SaveUnder {
			v = 1
		}
		binary.Write(buf, order, v)
	}
	if valueMask&CWEventMask != 0 {
		binary.Write(buf, order, wa.EventMask)
	}
	if valueMask&CWDontPropagate != 0 {
		binary.Write(buf, order, wa.DontPropagateMask)
	}
	if valueMask&CWColormap != 0 {
		binary.Write(buf, order, wa.Colormap)
	}
	if valueMask&CWCursor != 0 {
		binary.Write(buf, order, wa.Cursor)
	}
	return buf.Bytes()
}

// PolyTextItem is an interface for items in a PolyText request.
type PolyTextItem interface {
	isPolyTextItem()
}

// PolyText8String represents a string item in a PolyText8 request.
type PolyText8String struct {
	Delta int8   // Delta to apply to the current X coordinate.
	Str   []byte // String to draw.
}

func (PolyText8String) isPolyTextItem() {}

// PolyText16String represents a string item in a PolyText16 request.
type PolyText16String struct {
	Delta int8     // Delta to apply to the current X coordinate.
	Str   []uint16 // String to draw (16-bit characters).
}

func (PolyText16String) isPolyTextItem() {}

// PolyTextFont represents a font change item in a PolyText request.
type PolyTextFont struct {
	Font Font // New font ID.
}

func (PolyTextFont) isPolyTextItem() {}

// request messages

// CreateWindowRequest represents a CreateWindow request.
//
//	1     1                               opcode
//	1     DEPTH                           depth
//	2     8+n                             request length
//	4     WINDOW                          wid
//	4     WINDOW                          parent
//	2     INT16                           x
//	2     INT16                           y
//	2     CARD16                          width
//	2     CARD16                          height
//	2     CARD16                          border-width
//	2     { InputOutput, InputOnly,       class
//	      CopyFromParent }
//	4     VISUALID                        visual
//	4     BITMASK                         value-mask
//	4n    LISTofVALUE                     value-list
type CreateWindowRequest struct {
	Depth       uint8
	Drawable    Window
	Parent      Window
	X           int16
	Y           int16
	Width       uint16
	Height      uint16
	BorderWidth uint16
	Class       uint16
	Visual      VisualID
	ValueMask   uint32
	Values      WindowAttributes
}

func (r *CreateWindowRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(r.Depth)
	valuesBytes := r.Values.encode(order, r.ValueMask)
	length := uint16(8 + len(valuesBytes)/4)
	binary.Write(buf, order, length)
	binary.Write(buf, order, r.Drawable)
	binary.Write(buf, order, r.Parent)
	binary.Write(buf, order, r.X)
	binary.Write(buf, order, r.Y)
	binary.Write(buf, order, r.Width)
	binary.Write(buf, order, r.Height)
	binary.Write(buf, order, r.BorderWidth)
	binary.Write(buf, order, r.Class)
	binary.Write(buf, order, r.Visual)
	binary.Write(buf, order, r.ValueMask)
	buf.Write(valuesBytes)
	return buf.Bytes()
}

func (CreateWindowRequest) OpCode() ReqCode { return CreateWindow }

// ParseCreateWindowRequest parses a CreateWindow request.
func ParseCreateWindowRequest(order binary.ByteOrder, data byte, requestBody []byte, seq uint16) (*CreateWindowRequest, error) {
	if len(requestBody) < 28 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: CreateWindow, Minor: 0})
	}
	req := &CreateWindowRequest{}
	req.Depth = data
	req.Drawable = Window(order.Uint32(requestBody[0:4]))
	req.Parent = Window(order.Uint32(requestBody[4:8]))
	req.X = int16(order.Uint16(requestBody[8:10]))
	req.Y = int16(order.Uint16(requestBody[10:12]))
	req.Width = order.Uint16(requestBody[12:14])
	req.Height = order.Uint16(requestBody[14:16])
	req.BorderWidth = order.Uint16(requestBody[16:18])
	req.Class = order.Uint16(requestBody[18:20])
	req.Visual = VisualID(order.Uint32(requestBody[20:24]))
	req.ValueMask = order.Uint32(requestBody[24:28])
	values, bytesRead, err := ParseWindowAttributes(order, req.ValueMask, requestBody[28:], seq)
	if err != nil {
		return nil, err
	}
	if len(requestBody) != 28+bytesRead {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: CreateWindow, Minor: 0})
	}
	req.Values = values
	return req, nil
}

// ChangeWindowAttributesRequest represents a ChangeWindowAttributes request.
//
//	1     2                               opcode
//	1                                     unused
//	2     3+n                             request length
//	4     WINDOW                          window
//	4     BITMASK                         value-mask
//	4n    LISTofVALUE                     value-list
type ChangeWindowAttributesRequest struct {
	Window    Window
	ValueMask uint32
	Values    WindowAttributes
}

func (r *ChangeWindowAttributesRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(0)
	valuesBytes := r.Values.encode(order, r.ValueMask)
	length := uint16(3 + len(valuesBytes)/4)
	binary.Write(buf, order, length)
	binary.Write(buf, order, r.Window)
	binary.Write(buf, order, r.ValueMask)
	buf.Write(valuesBytes)
	return buf.Bytes()
}

func (ChangeWindowAttributesRequest) OpCode() ReqCode { return ChangeWindowAttributes }

// ParseChangeWindowAttributesRequest parses a ChangeWindowAttributes request.
func ParseChangeWindowAttributesRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*ChangeWindowAttributesRequest, error) {
	if len(requestBody) < 8 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: ChangeWindowAttributes, Minor: 0})
	}
	req := &ChangeWindowAttributesRequest{}
	req.Window = Window(order.Uint32(requestBody[0:4]))
	req.ValueMask = order.Uint32(requestBody[4:8])
	values, bytesRead, err := ParseWindowAttributes(order, req.ValueMask, requestBody[8:], seq)
	if err != nil {
		return nil, err
	}
	if len(requestBody) != 8+bytesRead {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: ChangeWindowAttributes, Minor: 0})
	}
	req.Values = values
	return req, nil
}

// GetWindowAttributesRequest represents a GetWindowAttributes request.
type GetWindowAttributesRequest struct {
	Window Window
}

func (r *GetWindowAttributesRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(0)
	binary.Write(buf, order, uint16(2)) // length
	binary.Write(buf, order, r.Window)
	return buf.Bytes()
}

func (GetWindowAttributesRequest) OpCode() ReqCode { return GetWindowAttributes }

// ParseGetWindowAttributesRequest parses a GetWindowAttributes request.
//
//	1     3                               opcode
//	1                                     unused
//	2     2                               request length
//	4     WINDOW                          window
func ParseGetWindowAttributesRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*GetWindowAttributesRequest, error) {
	if len(requestBody) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: GetWindowAttributes, Minor: 0})
	}
	req := &GetWindowAttributesRequest{}
	req.Window = Window(order.Uint32(requestBody[0:4]))
	return req, nil
}

// DestroyWindowRequest represents a DestroyWindow request.
type DestroyWindowRequest struct {
	Window Window
}

func (r *DestroyWindowRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(0)
	binary.Write(buf, order, uint16(2)) // length
	binary.Write(buf, order, r.Window)
	return buf.Bytes()
}

func (DestroyWindowRequest) OpCode() ReqCode { return DestroyWindow }

// ParseDestroyWindowRequest parses a DestroyWindow request.
//
//	1     4                               opcode
//	1                                     unused
//	2     2                               request length
//	4     WINDOW                          window
func ParseDestroyWindowRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*DestroyWindowRequest, error) {
	if len(requestBody) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: DestroyWindow, Minor: 0})
	}
	req := &DestroyWindowRequest{}
	req.Window = Window(order.Uint32(requestBody[0:4]))
	return req, nil
}

// DestroySubwindowsRequest represents a DestroySubwindows request.
type DestroySubwindowsRequest struct {
	Window Window
}

func (r *DestroySubwindowsRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(0)
	binary.Write(buf, order, uint16(2)) // length
	binary.Write(buf, order, r.Window)
	return buf.Bytes()
}

func (DestroySubwindowsRequest) OpCode() ReqCode { return DestroySubwindows }

// ParseDestroySubwindowsRequest parses a DestroySubwindows request.
//
//	1     5                               opcode
//	1                                     unused
//	2     2                               request length
//	4     WINDOW                          window
func ParseDestroySubwindowsRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*DestroySubwindowsRequest, error) {
	if len(requestBody) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: DestroySubwindows, Minor: 0})
	}
	req := &DestroySubwindowsRequest{}
	req.Window = Window(order.Uint32(requestBody[0:4]))
	return req, nil
}

// ChangeSaveSetRequest represents a ChangeSaveSet request.
type ChangeSaveSetRequest struct {
	Window Window
	Mode   byte
}

func (r *ChangeSaveSetRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(r.Mode)
	binary.Write(buf, order, uint16(2)) // length
	binary.Write(buf, order, r.Window)
	return buf.Bytes()
}

func (ChangeSaveSetRequest) OpCode() ReqCode { return ChangeSaveSet }

// ParseChangeSaveSetRequest parses a ChangeSaveSet request.
//
//	1     6                               opcode
//	1     { Insert, Delete }              mode
//	2     2                               request length
//	4     WINDOW                          window
func ParseChangeSaveSetRequest(order binary.ByteOrder, data byte, requestBody []byte, seq uint16) (*ChangeSaveSetRequest, error) {
	if len(requestBody) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: ChangeSaveSet, Minor: 0})
	}
	req := &ChangeSaveSetRequest{}
	req.Window = Window(order.Uint32(requestBody[0:4]))
	req.Mode = data
	return req, nil
}

// ReparentWindowRequest represents a ReparentWindow request.
type ReparentWindowRequest struct {
	Window Window
	Parent Window
	X      int16
	Y      int16
}

func (r *ReparentWindowRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(0)
	binary.Write(buf, order, uint16(4)) // length
	binary.Write(buf, order, r.Window)
	binary.Write(buf, order, r.Parent)
	binary.Write(buf, order, r.X)
	binary.Write(buf, order, r.Y)
	return buf.Bytes()
}

func (ReparentWindowRequest) OpCode() ReqCode { return ReparentWindow }

// ParseReparentWindowRequest parses a ReparentWindow request.
//
//	1     7                               opcode
//	1                                     unused
//	2     4                               request length
//	4     WINDOW                          window
//	4     WINDOW                          parent
//	2     INT16                           x
//	2     INT16                           y
func ParseReparentWindowRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*ReparentWindowRequest, error) {
	if len(requestBody) != 12 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: ReparentWindow, Minor: 0})
	}
	req := &ReparentWindowRequest{}
	req.Window = Window(order.Uint32(requestBody[0:4]))
	req.Parent = Window(order.Uint32(requestBody[4:8]))
	req.X = int16(order.Uint16(requestBody[8:10]))
	req.Y = int16(order.Uint16(requestBody[10:12]))
	return req, nil
}

// MapWindowRequest represents a MapWindow request.
type MapWindowRequest struct {
	Window Window
}

func (r *MapWindowRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(0)
	binary.Write(buf, order, uint16(2)) // length
	binary.Write(buf, order, r.Window)
	return buf.Bytes()
}

func (MapWindowRequest) OpCode() ReqCode { return MapWindow }

// ParseMapWindowRequest parses a MapWindow request.
//
//	1     8                               opcode
//	1                                     unused
//	2     2                               request length
//	4     WINDOW                          window
func ParseMapWindowRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*MapWindowRequest, error) {
	if len(requestBody) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: MapWindow, Minor: 0})
	}
	req := &MapWindowRequest{}
	req.Window = Window(order.Uint32(requestBody[0:4]))
	return req, nil
}

type MapSubwindowsRequest struct {
	Window Window
}

func (r *MapSubwindowsRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(0)
	binary.Write(buf, order, uint16(2)) // length
	binary.Write(buf, order, r.Window)
	return buf.Bytes()
}

func (MapSubwindowsRequest) OpCode() ReqCode { return MapSubwindows }

/*
MapSubwindows

1     9                               opcode
1                                     unused
2     2                               request length
4     WINDOW                          window
*/
func ParseMapSubwindowsRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*MapSubwindowsRequest, error) {
	if len(requestBody) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: MapSubwindows, Minor: 0})
	}
	req := &MapSubwindowsRequest{}
	req.Window = Window(order.Uint32(requestBody[0:4]))
	return req, nil
}

type UnmapWindowRequest struct {
	Window Window
}

func (r *UnmapWindowRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(0)
	binary.Write(buf, order, uint16(2)) // length
	binary.Write(buf, order, r.Window)
	return buf.Bytes()
}

func (UnmapWindowRequest) OpCode() ReqCode { return UnmapWindow }

/*
UnmapWindow

1     10                              opcode
1                                     unused
2     2                               request length
4     WINDOW                          window
*/
func ParseUnmapWindowRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*UnmapWindowRequest, error) {
	if len(requestBody) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: UnmapWindow, Minor: 0})
	}
	req := &UnmapWindowRequest{}
	req.Window = Window(order.Uint32(requestBody[0:4]))
	return req, nil
}

type UnmapSubwindowsRequest struct {
	Window Window
}

func (r *UnmapSubwindowsRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(0)
	binary.Write(buf, order, uint16(2)) // length
	binary.Write(buf, order, r.Window)
	return buf.Bytes()
}

func (UnmapSubwindowsRequest) OpCode() ReqCode { return UnmapSubwindows }

/*
UnmapSubwindows

1     11                              opcode
1                                     unused
2     2                               request length
4     WINDOW                          window
*/
func ParseUnmapSubwindowsRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*UnmapSubwindowsRequest, error) {
	if len(requestBody) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: UnmapSubwindows, Minor: 0})
	}
	req := &UnmapSubwindowsRequest{}
	req.Window = Window(order.Uint32(requestBody[0:4]))
	return req, nil
}

type ConfigureWindowRequest struct {
	Window    Window
	ValueMask uint16
	Values    []uint32
}

func (r *ConfigureWindowRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(0)
	binary.Write(buf, order, uint16(3+len(r.Values))) // length
	binary.Write(buf, order, r.Window)
	binary.Write(buf, order, r.ValueMask)
	buf.Write([]byte{0, 0}) // unused
	for _, v := range r.Values {
		binary.Write(buf, order, v)
	}
	return buf.Bytes()
}

func (ConfigureWindowRequest) OpCode() ReqCode { return ConfigureWindow }

/*
ConfigureWindow

1     12                              opcode
1                                     unused
2     3+n                             request length
4     WINDOW                          window
2     BITMASK                         value-mask
2                                     unused
4n    LISTofVALUE                     value-list
*/
func ParseConfigureWindowRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*ConfigureWindowRequest, error) {
	if len(requestBody) < 8 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: ConfigureWindow, Minor: 0})
	}
	req := &ConfigureWindowRequest{}
	req.Window = Window(order.Uint32(requestBody[0:4]))
	req.ValueMask = order.Uint16(requestBody[4:6])
	numValues := 0
	for i := 0; i < 16; i++ {
		if (req.ValueMask & (1 << i)) != 0 {
			numValues++
		}
	}
	if len(requestBody) != 8+numValues*4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: ConfigureWindow, Minor: 0})
	}

	for i := 8; i < len(requestBody); i += 4 {
		req.Values = append(req.Values, order.Uint32(requestBody[i:i+4]))
	}
	return req, nil
}

/*
CirculateWindow

1     13                              opcode
1     { RaiseLowest, LowerHighest }   direction
2     2                               request length
4     WINDOW                          window
*/
type CirculateWindowRequest struct {
	Window    Window
	Direction byte
}

func (r *CirculateWindowRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(r.Direction)
	binary.Write(buf, order, uint16(2)) // length
	binary.Write(buf, order, r.Window)
	return buf.Bytes()
}

func (CirculateWindowRequest) OpCode() ReqCode { return CirculateWindow }

func ParseCirculateWindowRequest(order binary.ByteOrder, data byte, requestBody []byte, seq uint16) (*CirculateWindowRequest, error) {
	if len(requestBody) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: CirculateWindow, Minor: 0})
	}
	req := &CirculateWindowRequest{}
	req.Window = Window(order.Uint32(requestBody[0:4]))
	req.Direction = data
	return req, nil
}

/*
GetGeometry

1     14                              opcode
1                                     unused
2     2                               request length
4     DRAWABLE                        drawable
*/
type GetGeometryRequest struct {
	Drawable Drawable
}

func (r *GetGeometryRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(0)
	binary.Write(buf, order, uint16(2)) // length
	binary.Write(buf, order, r.Drawable)
	return buf.Bytes()
}

func (GetGeometryRequest) OpCode() ReqCode { return GetGeometry }

func ParseGetGeometryRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*GetGeometryRequest, error) {
	if len(requestBody) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: GetGeometry, Minor: 0})
	}
	req := &GetGeometryRequest{}
	req.Drawable = Drawable(order.Uint32(requestBody[0:4]))
	return req, nil
}

/*
QueryTree

1     15                              opcode
1                                     unused
2     2                               request length
4     WINDOW                          window
*/
type QueryTreeRequest struct {
	Window Window
}

func (r *QueryTreeRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(0)
	binary.Write(buf, order, uint16(2)) // length
	binary.Write(buf, order, r.Window)
	return buf.Bytes()
}

func (QueryTreeRequest) OpCode() ReqCode { return QueryTree }

func ParseQueryTreeRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*QueryTreeRequest, error) {
	if len(requestBody) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: QueryTree, Minor: 0})
	}
	req := &QueryTreeRequest{}
	req.Window = Window(order.Uint32(requestBody[0:4]))
	return req, nil
}

type InternAtomRequest struct {
	Name         string
	OnlyIfExists bool
}

func (r *InternAtomRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, r.OpCode())
	if r.OnlyIfExists {
		buf.WriteByte(1)
	} else {
		buf.WriteByte(0)
	}
	binary.Write(buf, order, uint16(2+(len(r.Name)+PadLen(len(r.Name)))/4)) // length
	binary.Write(buf, order, uint16(len(r.Name)))
	buf.Write([]byte{0, 0}) // unused
	buf.WriteString(r.Name)
	buf.Write(make([]byte, PadLen(len(r.Name))))
	return buf.Bytes()
}

func (InternAtomRequest) OpCode() ReqCode { return InternAtom }

/*
InternAtom

1     16                              opcode
1     BOOL                            only-if-exists
2     2+(n+p)/4                       request length
2     CARD16                          n
2                                     unused
n     STRING8                         name
p                                     padding
*/
func ParseInternAtomRequest(order binary.ByteOrder, data byte, requestBody []byte, seq uint16) (*InternAtomRequest, error) {
	if len(requestBody) < 4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: InternAtom, Minor: 0})
	}
	req := &InternAtomRequest{}
	req.OnlyIfExists = data != 0
	nameLen := order.Uint16(requestBody[0:2])
	paddedLen := 4 + int(nameLen) + PadLen(int(nameLen))
	if len(requestBody) != paddedLen {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: InternAtom, Minor: 0})
	}
	req.Name = string(requestBody[4 : 4+nameLen])
	return req, nil
}

/*
GetAtomName

1     17                              opcode
1                                     unused
2     2                               request length
4     ATOM                            atom
*/
type GetAtomNameRequest struct {
	Atom Atom
}

func (r *GetAtomNameRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(0)
	binary.Write(buf, order, uint16(2)) // length
	binary.Write(buf, order, r.Atom)
	return buf.Bytes()
}

func (GetAtomNameRequest) OpCode() ReqCode { return GetAtomName }

func ParseGetAtomNameRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*GetAtomNameRequest, error) {
	if len(requestBody) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: GetAtomName, Minor: 0})
	}
	req := &GetAtomNameRequest{}
	req.Atom = Atom(order.Uint32(requestBody[0:4]))
	return req, nil
}

/*
ChangeProperty

1     18                              opcode
1     { Replace, Prepend, Append }    mode
2     6+(n+p)/4                       request length
4     WINDOW                          window
4     ATOM                            property
4     ATOM                            type
1     8, 16, or 32                    format
3                                     unused
4     CARD32                          n
n                                     LISTofBYTE, LISTofCARD16,

	or LISTofCARD32

p                                     padding
*/
type ChangePropertyRequest struct {
	Window   Window
	Property Atom
	Type     Atom
	Format   byte
	Data     []byte
}

func (r *ChangePropertyRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(0)
	binary.Write(buf, order, uint16(6+(len(r.Data)+PadLen(len(r.Data)))/4)) // length
	binary.Write(buf, order, r.Window)
	binary.Write(buf, order, r.Property)
	binary.Write(buf, order, r.Type)
	buf.WriteByte(r.Format)
	buf.Write([]byte{0, 0, 0}) // unused
	binary.Write(buf, order, uint32(len(r.Data)))
	buf.Write(r.Data)
	buf.Write(make([]byte, PadLen(len(r.Data))))
	return buf.Bytes()
}

func (ChangePropertyRequest) OpCode() ReqCode { return ChangeProperty }

func ParseChangePropertyRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*ChangePropertyRequest, error) {
	if len(requestBody) < 20 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: ChangeProperty, Minor: 0})
	}
	req := &ChangePropertyRequest{}
	req.Window = Window(order.Uint32(requestBody[0:4]))
	req.Property = Atom(order.Uint32(requestBody[4:8]))
	req.Type = Atom(order.Uint32(requestBody[8:12]))
	req.Format = requestBody[12]
	nElements := order.Uint32(requestBody[16:20])

	var dataLen int
	switch req.Format {
	case 8:
		dataLen = int(nElements)
	case 16:
		dataLen = int(nElements) * 2
	case 32:
		dataLen = int(nElements) * 4
	default:
		return nil, NewError(ValueErrorCode, seq, uint32(req.Format), Opcodes{Major: ChangeProperty, Minor: 0})
	}

	if len(requestBody) < 20+dataLen {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: ChangeProperty, Minor: 0})
	}
	req.Data = requestBody[20 : 20+dataLen]
	return req, nil
}

/*
DeleteProperty

1     19                              opcode
1                                     unused
2     3                               request length
4     WINDOW                          window
4     ATOM                            property
*/
type DeletePropertyRequest struct {
	Window   Window
	Property Atom
}

func (r *DeletePropertyRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(0)
	binary.Write(buf, order, uint16(3)) // length
	binary.Write(buf, order, r.Window)
	binary.Write(buf, order, r.Property)
	return buf.Bytes()
}

func (DeletePropertyRequest) OpCode() ReqCode { return DeleteProperty }

func ParseDeletePropertyRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*DeletePropertyRequest, error) {
	if len(requestBody) != 8 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: DeleteProperty, Minor: 0})
	}
	req := &DeletePropertyRequest{}
	req.Window = Window(order.Uint32(requestBody[0:4]))
	req.Property = Atom(order.Uint32(requestBody[4:8]))
	return req, nil
}

/*
GetProperty

1     20                              opcode
1     BOOL                            delete
2     6                               request length
4     WINDOW                          window
4     ATOM                            property
4     ATOM                            type
4     CARD32                          long-offset
4     CARD32                          long-length
*/
type GetPropertyRequest struct {
	Window   Window
	Property Atom
	Type     Atom
	Delete   bool
	Offset   uint32
	Length   uint32
}

func (r *GetPropertyRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, r.OpCode())
	if r.Delete {
		buf.WriteByte(1)
	} else {
		buf.WriteByte(0)
	}
	binary.Write(buf, order, uint16(6)) // length
	binary.Write(buf, order, r.Window)
	binary.Write(buf, order, r.Property)
	binary.Write(buf, order, r.Type)
	binary.Write(buf, order, r.Offset)
	binary.Write(buf, order, r.Length)
	return buf.Bytes()
}

func (GetPropertyRequest) OpCode() ReqCode { return GetProperty }

func ParseGetPropertyRequest(order binary.ByteOrder, data byte, requestBody []byte, seq uint16) (*GetPropertyRequest, error) {
	if len(requestBody) != 20 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: GetProperty, Minor: 0})
	}
	req := &GetPropertyRequest{}
	req.Delete = data != 0
	req.Window = Window(order.Uint32(requestBody[0:4]))
	req.Property = Atom(order.Uint32(requestBody[4:8]))
	req.Type = Atom(order.Uint32(requestBody[8:12]))
	req.Offset = order.Uint32(requestBody[12:16])
	req.Length = order.Uint32(requestBody[16:20])
	return req, nil
}

/*
ListProperties

1     21                              opcode
1                                     unused
2     2                               request length
4     WINDOW                          window
*/
type ListPropertiesRequest struct {
	Window Window
}

func (r *ListPropertiesRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(0)
	binary.Write(buf, order, uint16(2)) // length
	binary.Write(buf, order, r.Window)
	return buf.Bytes()
}

func (ListPropertiesRequest) OpCode() ReqCode { return ListProperties }

func ParseListPropertiesRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*ListPropertiesRequest, error) {
	if len(requestBody) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: ListProperties, Minor: 0})
	}
	req := &ListPropertiesRequest{}
	req.Window = Window(order.Uint32(requestBody[0:4]))
	return req, nil
}

/*
SetSelectionOwner

1     22                              opcode
1                                     unused
2     4                               request length
4     WINDOW                          owner
4     ATOM                            selection
4     TIMESTAMP                       time
*/
type SetSelectionOwnerRequest struct {
	Owner     Window
	Selection Atom
	Time      Timestamp
}

func (r *SetSelectionOwnerRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(0)
	binary.Write(buf, order, uint16(4)) // length
	binary.Write(buf, order, r.Owner)
	binary.Write(buf, order, r.Selection)
	binary.Write(buf, order, r.Time)
	return buf.Bytes()
}

func (SetSelectionOwnerRequest) OpCode() ReqCode { return SetSelectionOwner }

func ParseSetSelectionOwnerRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*SetSelectionOwnerRequest, error) {
	if len(requestBody) != 12 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: SetSelectionOwner, Minor: 0})
	}
	req := &SetSelectionOwnerRequest{}
	req.Owner = Window(order.Uint32(requestBody[0:4]))
	req.Selection = Atom(order.Uint32(requestBody[4:8]))
	req.Time = Timestamp(order.Uint32(requestBody[8:12]))
	return req, nil
}

/*
GetSelectionOwner

1     23                              opcode
1                                     unused
2     2                               request length
4     ATOM                            selection
*/
type GetSelectionOwnerRequest struct {
	Selection Atom
}

func (r *GetSelectionOwnerRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(0)
	binary.Write(buf, order, uint16(2)) // length
	binary.Write(buf, order, r.Selection)
	return buf.Bytes()
}

func (GetSelectionOwnerRequest) OpCode() ReqCode { return GetSelectionOwner }

func ParseGetSelectionOwnerRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*GetSelectionOwnerRequest, error) {
	if len(requestBody) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: GetSelectionOwner, Minor: 0})
	}
	req := &GetSelectionOwnerRequest{}
	req.Selection = Atom(order.Uint32(requestBody[0:4]))
	return req, nil
}

/*
ConvertSelection

1     24                              opcode
1                                     unused
2     6                               request length
4     WINDOW                          requestor
4     ATOM                            selection
4     ATOM                            target
4     ATOM                            property
4     TIMESTAMP                       time
*/
type ConvertSelectionRequest struct {
	Requestor Window
	Selection Atom
	Target    Atom
	Property  Atom
	Time      Timestamp
}

func (r *ConvertSelectionRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(0)
	binary.Write(buf, order, uint16(6)) // length
	binary.Write(buf, order, r.Requestor)
	binary.Write(buf, order, r.Selection)
	binary.Write(buf, order, r.Target)
	binary.Write(buf, order, r.Property)
	binary.Write(buf, order, r.Time)
	return buf.Bytes()
}

func (ConvertSelectionRequest) OpCode() ReqCode { return ConvertSelection }

func ParseConvertSelectionRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*ConvertSelectionRequest, error) {
	if len(requestBody) != 20 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: ConvertSelection, Minor: 0})
	}
	req := &ConvertSelectionRequest{}
	req.Requestor = Window(order.Uint32(requestBody[0:4]))
	req.Selection = Atom(order.Uint32(requestBody[4:8]))
	req.Target = Atom(order.Uint32(requestBody[8:12]))
	req.Property = Atom(order.Uint32(requestBody[12:16]))
	req.Time = Timestamp(order.Uint32(requestBody[16:20]))
	return req, nil
}

/*
SendEvent

1     25                              opcode
1     BOOL                            propagate
2     12                              request length
4     WINDOW                          destination
4     EVENT-MASK                      event-mask
32    any                             event
*/
type SendEventRequest struct {
	Propagate   bool
	Destination Window
	EventMask   uint32
	EventData   []byte
}

func (r *SendEventRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, r.OpCode())
	if r.Propagate {
		buf.WriteByte(1)
	} else {
		buf.WriteByte(0)
	}
	binary.Write(buf, order, uint16(11)) // length
	binary.Write(buf, order, r.Destination)
	binary.Write(buf, order, r.EventMask)
	buf.Write(r.EventData)
	return buf.Bytes()
}

func (SendEventRequest) OpCode() ReqCode { return SendEvent }

func ParseSendEventRequest(order binary.ByteOrder, propagate byte, requestBody []byte, seq uint16) (*SendEventRequest, error) {
	if len(requestBody) != 40 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: SendEvent, Minor: 0})
	}
	req := &SendEventRequest{}
	req.Propagate = propagate != 0
	req.Destination = Window(order.Uint32(requestBody[0:4]))
	req.EventMask = order.Uint32(requestBody[4:8])
	req.EventData = requestBody[8:40]
	return req, nil
}

/*
GrabPointer

1     26                              opcode
1     BOOL                            owner-events
2     6                               request length
4     WINDOW                          grab-window
2     EVENT-MASK                      event-mask
1     { Asynchronous, Synchronous }   pointer-mode
1     { Asynchronous, Synchronous }   keyboard-mode
4     WINDOW                          confine-to
4     CURSOR                          cursor
4     TIMESTAMP                       time
*/
type GrabPointerRequest struct {
	OwnerEvents  bool
	GrabWindow   Window
	EventMask    uint16
	PointerMode  byte
	KeyboardMode byte
	ConfineTo    Window
	Cursor       Cursor
	Time         Timestamp
}

func (r *GrabPointerRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, r.OpCode())
	if r.OwnerEvents {
		buf.WriteByte(1)
	} else {
		buf.WriteByte(0)
	}
	binary.Write(buf, order, uint16(6)) // length
	binary.Write(buf, order, r.GrabWindow)
	binary.Write(buf, order, r.EventMask)
	buf.WriteByte(r.PointerMode)
	buf.WriteByte(r.KeyboardMode)
	binary.Write(buf, order, r.ConfineTo)
	binary.Write(buf, order, r.Cursor)
	binary.Write(buf, order, r.Time)
	return buf.Bytes()
}

func (GrabPointerRequest) OpCode() ReqCode { return GrabPointer }

func ParseGrabPointerRequest(order binary.ByteOrder, data byte, requestBody []byte, seq uint16) (*GrabPointerRequest, error) {
	if len(requestBody) != 20 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: GrabPointer, Minor: 0})
	}
	req := &GrabPointerRequest{}
	req.OwnerEvents = data != 0
	req.GrabWindow = Window(order.Uint32(requestBody[0:4]))
	req.EventMask = order.Uint16(requestBody[4:6])
	req.PointerMode = requestBody[6]
	req.KeyboardMode = requestBody[7]
	req.ConfineTo = Window(order.Uint32(requestBody[8:12]))
	req.Cursor = Cursor(order.Uint32(requestBody[12:16]))
	req.Time = Timestamp(order.Uint32(requestBody[16:20]))
	return req, nil
}

/*
UngrabPointer

1     27                              opcode
1                                     unused
2     2                               request length
4     TIMESTAMP                       time
*/
type UngrabPointerRequest struct {
	Time Timestamp
}

func (r *UngrabPointerRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(0)
	binary.Write(buf, order, uint16(2)) // length
	binary.Write(buf, order, r.Time)
	return buf.Bytes()
}

func (UngrabPointerRequest) OpCode() ReqCode { return UngrabPointer }

func ParseUngrabPointerRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*UngrabPointerRequest, error) {
	if len(requestBody) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: UngrabPointer, Minor: 0})
	}
	req := &UngrabPointerRequest{}
	req.Time = Timestamp(order.Uint32(requestBody[0:4]))
	return req, nil
}

/*
GrabButton

1     28                              opcode
1     BOOL                            owner-events
2     6                               request length
4     WINDOW                          grab-window
2     EVENT-MASK                      event-mask
1     { Asynchronous, Synchronous }   pointer-mode
1     { Asynchronous, Synchronous }   keyboard-mode
4     WINDOW                          confine-to
4     CURSOR                          cursor
1     BUTTON or AnyButton             button
1                                     unused
2     KEYMASK or AnyModifier          modifiers
*/
type GrabButtonRequest struct {
	OwnerEvents  bool
	GrabWindow   Window
	EventMask    uint16
	PointerMode  byte
	KeyboardMode byte
	ConfineTo    Window
	Cursor       Cursor
	Button       byte
	Modifiers    uint16
}

func (r *GrabButtonRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, r.OpCode())
	if r.OwnerEvents {
		buf.WriteByte(1)
	} else {
		buf.WriteByte(0)
	}
	binary.Write(buf, order, uint16(6)) // length
	binary.Write(buf, order, r.GrabWindow)
	binary.Write(buf, order, r.EventMask)
	buf.WriteByte(r.PointerMode)
	buf.WriteByte(r.KeyboardMode)
	binary.Write(buf, order, r.ConfineTo)
	binary.Write(buf, order, r.Cursor)
	buf.WriteByte(r.Button)
	buf.WriteByte(0) // unused
	binary.Write(buf, order, r.Modifiers)
	return buf.Bytes()
}

func (GrabButtonRequest) OpCode() ReqCode { return GrabButton }

func ParseGrabButtonRequest(order binary.ByteOrder, data byte, requestBody []byte, seq uint16) (*GrabButtonRequest, error) {
	if len(requestBody) != 20 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: GrabButton, Minor: 0})
	}
	req := &GrabButtonRequest{}
	req.OwnerEvents = data != 0
	req.GrabWindow = Window(order.Uint32(requestBody[0:4]))
	req.EventMask = order.Uint16(requestBody[4:6])
	req.PointerMode = requestBody[6]
	req.KeyboardMode = requestBody[7]
	req.ConfineTo = Window(order.Uint32(requestBody[8:12]))
	req.Cursor = Cursor(order.Uint32(requestBody[12:16]))
	req.Button = requestBody[16]
	req.Modifiers = order.Uint16(requestBody[18:20])
	return req, nil
}

/*
UngrabButton

1     29                              opcode
1     BUTTON or AnyButton             button
2     3                               request length
4     WINDOW                          grab-window
2                                     unused
2     KEYMASK or AnyModifier          modifiers
*/
type UngrabButtonRequest struct {
	GrabWindow Window
	Button     byte
	Modifiers  uint16
}

func (r *UngrabButtonRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(r.Button)
	binary.Write(buf, order, uint16(3)) // length
	binary.Write(buf, order, r.GrabWindow)
	buf.Write([]byte{0, 0}) // unused
	binary.Write(buf, order, r.Modifiers)
	return buf.Bytes()
}

func (UngrabButtonRequest) OpCode() ReqCode { return UngrabButton }

func ParseUngrabButtonRequest(order binary.ByteOrder, data byte, requestBody []byte, seq uint16) (*UngrabButtonRequest, error) {
	if len(requestBody) != 8 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: UngrabButton, Minor: 0})
	}
	req := &UngrabButtonRequest{}
	req.Button = data
	req.GrabWindow = Window(order.Uint32(requestBody[0:4]))
	req.Modifiers = order.Uint16(requestBody[6:8])
	return req, nil
}

/*
ChangeActivePointerGrab

1     30                              opcode
1                                     unused
2     4                               request length
4     CURSOR                          cursor
4     TIMESTAMP                       time
2     EVENT-MASK                      event-mask
2                                     unused
*/
type ChangeActivePointerGrabRequest struct {
	Cursor    Cursor
	Time      Timestamp
	EventMask uint16
}

func (r *ChangeActivePointerGrabRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(0)
	binary.Write(buf, order, uint16(4)) // length
	binary.Write(buf, order, r.Cursor)
	binary.Write(buf, order, r.Time)
	binary.Write(buf, order, r.EventMask)
	buf.Write([]byte{0, 0}) // unused
	return buf.Bytes()
}

func (ChangeActivePointerGrabRequest) OpCode() ReqCode { return ChangeActivePointerGrab }

func ParseChangeActivePointerGrabRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*ChangeActivePointerGrabRequest, error) {
	if len(requestBody) != 12 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: ChangeActivePointerGrab, Minor: 0})
	}
	req := &ChangeActivePointerGrabRequest{}
	req.Cursor = Cursor(order.Uint32(requestBody[0:4]))
	req.Time = Timestamp(order.Uint32(requestBody[4:8]))
	req.EventMask = order.Uint16(requestBody[8:10])
	return req, nil
}

/*
GrabKeyboard

1     31                              opcode
1     BOOL                            owner-events
2     4                               request length
4     WINDOW                          grab-window
4     TIMESTAMP                       time
1     { Asynchronous, Synchronous }   pointer-mode
1     { Asynchronous, Synchronous }   keyboard-mode
2                                     unused
*/
type GrabKeyboardRequest struct {
	OwnerEvents  bool
	GrabWindow   Window
	Time         Timestamp
	PointerMode  byte
	KeyboardMode byte
}

func (r *GrabKeyboardRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, r.OpCode())
	if r.OwnerEvents {
		buf.WriteByte(1)
	} else {
		buf.WriteByte(0)
	}
	binary.Write(buf, order, uint16(4)) // length
	binary.Write(buf, order, r.GrabWindow)
	binary.Write(buf, order, r.Time)
	buf.WriteByte(r.PointerMode)
	buf.WriteByte(r.KeyboardMode)
	buf.Write([]byte{0, 0}) // unused
	return buf.Bytes()
}

func (GrabKeyboardRequest) OpCode() ReqCode { return GrabKeyboard }

func ParseGrabKeyboardRequest(order binary.ByteOrder, data byte, requestBody []byte, seq uint16) (*GrabKeyboardRequest, error) {
	if len(requestBody) != 12 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: GrabKeyboard, Minor: 0})
	}
	req := &GrabKeyboardRequest{}
	req.OwnerEvents = data != 0
	req.GrabWindow = Window(order.Uint32(requestBody[0:4]))
	req.Time = Timestamp(order.Uint32(requestBody[4:8]))
	req.PointerMode = requestBody[8]
	req.KeyboardMode = requestBody[9]
	return req, nil
}

/*
UngrabKeyboard

1     32                              opcode
1                                     unused
2     2                               request length
4     TIMESTAMP                       time
*/
type UngrabKeyboardRequest struct {
	Time Timestamp
}

func (r *UngrabKeyboardRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(0)
	binary.Write(buf, order, uint16(2)) // length
	binary.Write(buf, order, r.Time)
	return buf.Bytes()
}

func (UngrabKeyboardRequest) OpCode() ReqCode { return UngrabKeyboard }

func ParseUngrabKeyboardRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*UngrabKeyboardRequest, error) {
	if len(requestBody) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: UngrabKeyboard, Minor: 0})
	}
	req := &UngrabKeyboardRequest{}
	req.Time = Timestamp(order.Uint32(requestBody[0:4]))
	return req, nil
}

/*
GrabKey

1     33                              opcode
1     BOOL                            owner-events
2     4                               request length
4     WINDOW                          grab-window
2     KEYMASK or AnyModifier          modifiers
1     KEYCODE or AnyKey               key
1     { Asynchronous, Synchronous }   pointer-mode
1     { Asynchronous, Synchronous }   keyboard-mode
3                                     unused
*/
type GrabKeyRequest struct {
	OwnerEvents  bool
	GrabWindow   Window
	Modifiers    uint16
	Key          KeyCode
	PointerMode  byte
	KeyboardMode byte
}

func (r *GrabKeyRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, r.OpCode())
	if r.OwnerEvents {
		buf.WriteByte(1)
	} else {
		buf.WriteByte(0)
	}
	binary.Write(buf, order, uint16(4)) // length
	binary.Write(buf, order, r.GrabWindow)
	binary.Write(buf, order, r.Modifiers)
	buf.WriteByte(byte(r.Key))
	buf.WriteByte(r.PointerMode)
	buf.WriteByte(r.KeyboardMode)
	buf.Write([]byte{0, 0, 0}) // unused
	return buf.Bytes()
}

func (GrabKeyRequest) OpCode() ReqCode { return GrabKey }

func ParseGrabKeyRequest(order binary.ByteOrder, data byte, requestBody []byte, seq uint16) (*GrabKeyRequest, error) {
	if len(requestBody) != 12 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: GrabKey, Minor: 0})
	}
	req := &GrabKeyRequest{}
	req.OwnerEvents = data != 0
	req.GrabWindow = Window(order.Uint32(requestBody[0:4]))
	req.Modifiers = order.Uint16(requestBody[4:6])
	req.Key = KeyCode(requestBody[6])
	req.PointerMode = requestBody[7]
	req.KeyboardMode = requestBody[8]
	return req, nil
}

/*
UngrabKey

1     34                              opcode
1     KEYCODE or AnyKey               key
2     3                               request length
4     WINDOW                          grab-window
2     KEYMASK or AnyModifier          modifiers
2                                     unused
*/
type UngrabKeyRequest struct {
	GrabWindow Window
	Modifiers  uint16
	Key        KeyCode
}

func (r *UngrabKeyRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(byte(r.Key))
	binary.Write(buf, order, uint16(3)) // length
	binary.Write(buf, order, r.GrabWindow)
	binary.Write(buf, order, r.Modifiers)
	buf.Write([]byte{0, 0}) // unused
	return buf.Bytes()
}

func (UngrabKeyRequest) OpCode() ReqCode { return UngrabKey }

func ParseUngrabKeyRequest(order binary.ByteOrder, data byte, requestBody []byte, seq uint16) (*UngrabKeyRequest, error) {
	if len(requestBody) != 8 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: UngrabKey, Minor: 0})
	}
	req := &UngrabKeyRequest{}
	req.Key = KeyCode(data)
	req.GrabWindow = Window(order.Uint32(requestBody[0:4]))
	req.Modifiers = order.Uint16(requestBody[4:6])
	return req, nil
}

/*
AllowEvents

1     35                              opcode
1     { AsyncPointer, SyncPointer,    mode

	ReplayPointer, AsyncKeyboard,
	SyncKeyboard, ReplayKeyboard,
	AsyncBoth, SyncBoth }

2     2                               request length
4     TIMESTAMP                       time
*/
type AllowEventsRequest struct {
	Mode byte
	Time Timestamp
}

func (r *AllowEventsRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(r.Mode)
	binary.Write(buf, order, uint16(2)) // length
	binary.Write(buf, order, r.Time)
	return buf.Bytes()
}

func (AllowEventsRequest) OpCode() ReqCode { return AllowEvents }

func ParseAllowEventsRequest(order binary.ByteOrder, data byte, requestBody []byte, seq uint16) (*AllowEventsRequest, error) {
	if len(requestBody) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: AllowEvents, Minor: 0})
	}
	req := &AllowEventsRequest{}
	req.Mode = data
	req.Time = Timestamp(order.Uint32(requestBody[0:4]))
	return req, nil
}

/*
GrabServer

1     36                              opcode
1                                     unused
2     1                               request length
*/
type GrabServerRequest struct{}

func (r *GrabServerRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(0)
	binary.Write(buf, order, uint16(1)) // length
	return buf.Bytes()
}

func (GrabServerRequest) OpCode() ReqCode { return GrabServer }

func ParseGrabServerRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*GrabServerRequest, error) {
	return &GrabServerRequest{}, nil
}

/*
UngrabServer

1     37                              opcode
1                                     unused
2     1                               request length
*/
type UngrabServerRequest struct{}

func (r *UngrabServerRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(0)
	binary.Write(buf, order, uint16(1)) // length
	return buf.Bytes()
}

func (UngrabServerRequest) OpCode() ReqCode { return UngrabServer }

func ParseUngrabServerRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*UngrabServerRequest, error) {
	return &UngrabServerRequest{}, nil
}

/*
QueryPointer

1     38                              opcode
1                                     unused
2     2                               request length
4     WINDOW                          window
*/
type QueryPointerRequest struct {
	Drawable Drawable
}

func (r *QueryPointerRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(0)
	binary.Write(buf, order, uint16(2)) // length
	binary.Write(buf, order, r.Drawable)
	return buf.Bytes()
}

func (QueryPointerRequest) OpCode() ReqCode { return QueryPointer }

func ParseQueryPointerRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*QueryPointerRequest, error) {
	if len(requestBody) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: QueryPointer, Minor: 0})
	}
	req := &QueryPointerRequest{}
	req.Drawable = Drawable(order.Uint32(requestBody[0:4]))
	return req, nil
}

/*
GetMotionEvents

1     39                              opcode
1                                     unused
2     4                               request length
4     WINDOW                          window
4     TIMESTAMP                       start
4     TIMESTAMP                       stop
*/
type GetMotionEventsRequest struct {
	Window Window
	Start  Timestamp
	Stop   Timestamp
}

func (r *GetMotionEventsRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(0)
	binary.Write(buf, order, uint16(4)) // length
	binary.Write(buf, order, r.Window)
	binary.Write(buf, order, r.Start)
	binary.Write(buf, order, r.Stop)
	return buf.Bytes()
}

func (GetMotionEventsRequest) OpCode() ReqCode { return GetMotionEvents }

func ParseGetMotionEventsRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*GetMotionEventsRequest, error) {
	if len(requestBody) != 12 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: GetMotionEvents, Minor: 0})
	}
	req := &GetMotionEventsRequest{}
	req.Window = Window(order.Uint32(requestBody[0:4]))
	req.Start = Timestamp(order.Uint32(requestBody[4:8]))
	req.Stop = Timestamp(order.Uint32(requestBody[8:12]))
	return req, nil
}

/*
TranslateCoordinates

1     40                              opcode
1                                     unused
2     4                               request length
4     WINDOW                          src-window
4     WINDOW                          dst-window
2     INT16                           src-x
2     INT16                           src-y
*/
type TranslateCoordsRequest struct {
	SrcWindow Window
	DstWindow Window
	SrcX      int16
	SrcY      int16
}

func (r *TranslateCoordsRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(0)
	binary.Write(buf, order, uint16(4)) // length
	binary.Write(buf, order, r.SrcWindow)
	binary.Write(buf, order, r.DstWindow)
	binary.Write(buf, order, r.SrcX)
	binary.Write(buf, order, r.SrcY)
	return buf.Bytes()
}

func (TranslateCoordsRequest) OpCode() ReqCode { return TranslateCoords }

func ParseTranslateCoordsRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*TranslateCoordsRequest, error) {
	if len(requestBody) != 12 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: TranslateCoords, Minor: 0})
	}
	req := &TranslateCoordsRequest{}
	req.SrcWindow = Window(order.Uint32(requestBody[0:4]))
	req.DstWindow = Window(order.Uint32(requestBody[4:8]))
	req.SrcX = int16(order.Uint16(requestBody[8:10]))
	req.SrcY = int16(order.Uint16(requestBody[10:12]))
	return req, nil
}

/*
WarpPointer

1     41                              opcode
1                                     unused
2     5                               request length
4     WINDOW                          src-window
4     WINDOW                          dst-window
2     INT16                           src-x
2     INT16                           src-y
2     CARD16                          src-width
2     CARD16                          src-height
2     INT16                           dst-x
2     INT16                           dst-y
*/
type WarpPointerRequest struct {
	SrcWindow uint32
	DstWindow uint32
	SrcX      int16
	SrcY      int16
	SrcWidth  uint16
	SrcHeight uint16
	DstX      int16
	DstY      int16
}

func (r *WarpPointerRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(0)
	binary.Write(buf, order, uint16(6)) // length
	binary.Write(buf, order, r.SrcWindow)
	binary.Write(buf, order, r.DstWindow)
	binary.Write(buf, order, r.SrcX)
	binary.Write(buf, order, r.SrcY)
	binary.Write(buf, order, r.SrcWidth)
	binary.Write(buf, order, r.SrcHeight)
	binary.Write(buf, order, r.DstX)
	binary.Write(buf, order, r.DstY)
	return buf.Bytes()
}

func (WarpPointerRequest) OpCode() ReqCode { return WarpPointer }

func ParseWarpPointerRequest(order binary.ByteOrder, payload []byte, seq uint16) (*WarpPointerRequest, error) {
	if len(payload) != 20 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: WarpPointer, Minor: 0})
	}
	req := &WarpPointerRequest{}
	req.SrcWindow = order.Uint32(payload[0:4])
	req.DstWindow = order.Uint32(payload[4:8])
	req.SrcX = int16(order.Uint16(payload[8:10]))
	req.SrcY = int16(order.Uint16(payload[10:12]))
	req.SrcWidth = order.Uint16(payload[12:14])
	req.SrcHeight = order.Uint16(payload[14:16])
	req.DstX = int16(order.Uint16(payload[16:18]))
	req.DstY = int16(order.Uint16(payload[18:20]))
	return req, nil
}

/*
SetInputFocus

1     42                              opcode
1     { None, PointerRoot, Parent,    revert-to

	FollowKeyboard }

2     3                               request length
4     WINDOW                          focus
4     TIMESTAMP                       time
*/
type SetInputFocusRequest struct {
	Focus    Window
	RevertTo byte
	Time     Timestamp
}

func (r *SetInputFocusRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(r.RevertTo)
	binary.Write(buf, order, uint16(3)) // length
	binary.Write(buf, order, r.Focus)
	binary.Write(buf, order, r.Time)
	return buf.Bytes()
}

func (SetInputFocusRequest) OpCode() ReqCode { return SetInputFocus }

func ParseSetInputFocusRequest(order binary.ByteOrder, data byte, requestBody []byte, seq uint16) (*SetInputFocusRequest, error) {
	if len(requestBody) != 8 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: SetInputFocus, Minor: 0})
	}
	req := &SetInputFocusRequest{}
	req.RevertTo = data
	req.Focus = Window(order.Uint32(requestBody[0:4]))
	req.Time = Timestamp(order.Uint32(requestBody[4:8]))
	return req, nil
}

/*
GetInputFocus

1     43                              opcode
1                                     unused
2     1                               request length
*/
type GetInputFocusRequest struct{}

func (r *GetInputFocusRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(0)
	binary.Write(buf, order, uint16(1)) // length
	return buf.Bytes()
}

func (GetInputFocusRequest) OpCode() ReqCode { return GetInputFocus }

func ParseGetInputFocusRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*GetInputFocusRequest, error) {
	return &GetInputFocusRequest{}, nil
}

/*
QueryKeymap

1     44                              opcode
1                                     unused
2     1                               request length
*/
type QueryKeymapRequest struct{}

func (r *QueryKeymapRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(0)
	binary.Write(buf, order, uint16(1)) // length
	return buf.Bytes()
}

func (QueryKeymapRequest) OpCode() ReqCode { return QueryKeymap }

func ParseQueryKeymapRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*QueryKeymapRequest, error) {
	return &QueryKeymapRequest{}, nil
}

/*
OpenFont

1     45                              opcode
1                                     unused
2     3+(n+p)/4                       request length
4     FONT                            fid
2     CARD16                          n
2                                     unused
n     STRING8                         name
p                                     padding
*/
type OpenFontRequest struct {
	Fid  Font
	Name string
}

func (r *OpenFontRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(0)
	binary.Write(buf, order, uint16(3+(len(r.Name)+PadLen(len(r.Name)))/4))
	binary.Write(buf, order, r.Fid)
	binary.Write(buf, order, uint16(len(r.Name)))
	buf.Write([]byte{0, 0}) // unused
	buf.WriteString(r.Name)
	buf.Write(make([]byte, PadLen(len(r.Name))))
	return buf.Bytes()
}

func (OpenFontRequest) OpCode() ReqCode { return OpenFont }

func ParseOpenFontRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*OpenFontRequest, error) {
	if len(requestBody) < 8 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: OpenFont, Minor: 0})
	}
	req := &OpenFontRequest{}
	req.Fid = Font(order.Uint32(requestBody[0:4]))
	nameLen := int(order.Uint16(requestBody[4:6]))
	paddedLen := 8 + nameLen + PadLen(8+nameLen)
	if len(requestBody) != paddedLen {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: OpenFont, Minor: 0})
	}
	req.Name = string(requestBody[8 : 8+nameLen])
	return req, nil
}

/*
CloseFont

1     46                              opcode
1                                     unused
2     2                               request length
4     FONT                            font
*/
type CloseFontRequest struct {
	Fid Font
}

func (r *CloseFontRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(0)
	binary.Write(buf, order, uint16(2)) // length
	binary.Write(buf, order, r.Fid)
	return buf.Bytes()
}

func (CloseFontRequest) OpCode() ReqCode { return CloseFont }

func ParseCloseFontRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*CloseFontRequest, error) {
	if len(requestBody) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: CloseFont, Minor: 0})
	}
	req := &CloseFontRequest{}
	req.Fid = Font(order.Uint32(requestBody[0:4]))
	return req, nil
}

/*
QueryFont

1     47                              opcode
1                                     unused
2     2                               request length
4     FONTABLE                        font
*/
type QueryFontRequest struct {
	Fid Font
}

func (r *QueryFontRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(0)
	binary.Write(buf, order, uint16(2)) // length
	binary.Write(buf, order, r.Fid)
	return buf.Bytes()
}

func (QueryFontRequest) OpCode() ReqCode { return QueryFont }

func ParseQueryFontRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*QueryFontRequest, error) {
	if len(requestBody) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: QueryFont, Minor: 0})
	}
	req := &QueryFontRequest{}
	req.Fid = Font(order.Uint32(requestBody[0:4]))
	return req, nil
}

/*
QueryTextExtents

1     48                              opcode
1     BOOL                            oddLength
2     2+2n/4                          request length
4     FONTABLE                        font
2n    LISTofCHAR2B                    string
*/
type QueryTextExtentsRequest struct {
	Fid  Font
	Text []uint16
}

func (r *QueryTextExtentsRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, r.OpCode())
	oddLength := len(r.Text)%2 != 0
	if oddLength {
		buf.WriteByte(1)
	} else {
		buf.WriteByte(0)
	}
	binary.Write(buf, order, uint16(2+(len(r.Text)*2+PadLen(len(r.Text)*2))/4))
	binary.Write(buf, order, r.Fid)
	for _, c := range r.Text {
		binary.Write(buf, order, c)
	}
	buf.Write(make([]byte, PadLen(len(r.Text)*2)))
	return buf.Bytes()
}

func (QueryTextExtentsRequest) OpCode() ReqCode { return QueryTextExtents }

func ParseQueryTextExtentsRequest(order binary.ByteOrder, data byte, requestBody []byte, seq uint16) (*QueryTextExtentsRequest, error) {
	if len(requestBody) < 4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: QueryTextExtents, Minor: 0})
	}
	oddLength := data != 0
	var n int
	if oddLength {
		if (len(requestBody)-4)%4 != 2 {
			return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: QueryTextExtents, Minor: 0})
		}
		n = (len(requestBody) - 4 - 2) / 2
	} else {
		if (len(requestBody)-4)%4 != 0 {
			return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: QueryTextExtents, Minor: 0})
		}
		n = (len(requestBody) - 4) / 2
	}
	if n%2 != 0 != oddLength {
		// As per spec, the oddLength flag is just a hint. The true
		// length is derived from the request length field, which we
		// have already validated. We can ignore a mismatch here.
	}

	req := &QueryTextExtentsRequest{}
	req.Fid = Font(order.Uint32(requestBody[0:4]))
	for i := 0; i < n; i++ {
		req.Text = append(req.Text, order.Uint16(requestBody[4+i*2:4+(i+1)*2]))
	}
	return req, nil
}

/*
ListFonts

1     49                              opcode
1                                     unused
2     2+(n+p)/4                       request length
2     CARD16                          max-names
2     CARD16                          n
n     STRING8                         pattern
p                                     padding
*/
type ListFontsRequest struct {
	MaxNames uint16
	Pattern  string
}

func (r *ListFontsRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(0)
	binary.Write(buf, order, uint16(2+(len(r.Pattern)+PadLen(len(r.Pattern)))/4))
	binary.Write(buf, order, r.MaxNames)
	binary.Write(buf, order, uint16(len(r.Pattern)))
	buf.WriteString(r.Pattern)
	buf.Write(make([]byte, PadLen(len(r.Pattern))))
	return buf.Bytes()
}

func (ListFontsRequest) OpCode() ReqCode { return ListFonts }

func ParseListFontsRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*ListFontsRequest, error) {
	if len(requestBody) < 4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: ListFonts, Minor: 0})
	}
	req := &ListFontsRequest{}
	req.MaxNames = order.Uint16(requestBody[0:2])
	nameLen := int(order.Uint16(requestBody[2:4]))
	paddedLen := 4 + nameLen + PadLen(nameLen)
	if len(requestBody) != paddedLen {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: ListFonts, Minor: 0})
	}
	req.Pattern = string(requestBody[4 : 4+nameLen])
	return req, nil
}

/*
ListFontsWithInfo

1     50                              opcode
1                                     unused
2     2+(n+p)/4                       request length
2     CARD16                          max-names
2     CARD16                          n
n     STRING8                         pattern
p                                     padding
*/
type ListFontsWithInfoRequest struct {
	MaxNames uint16
	Pattern  string
}

func (r *ListFontsWithInfoRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(0)
	binary.Write(buf, order, uint16(2+(len(r.Pattern)+PadLen(len(r.Pattern)))/4))
	binary.Write(buf, order, r.MaxNames)
	binary.Write(buf, order, uint16(len(r.Pattern)))
	buf.WriteString(r.Pattern)
	buf.Write(make([]byte, PadLen(len(r.Pattern))))
	return buf.Bytes()
}

func (ListFontsWithInfoRequest) OpCode() ReqCode { return ListFontsWithInfo }

func ParseListFontsWithInfoRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*ListFontsWithInfoRequest, error) {
	if len(requestBody) < 4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: ListFontsWithInfo, Minor: 0})
	}
	req := &ListFontsWithInfoRequest{}
	req.MaxNames = order.Uint16(requestBody[0:2])
	nameLen := int(order.Uint16(requestBody[2:4]))
	paddedLen := 4 + nameLen + PadLen(nameLen)
	if len(requestBody) != paddedLen {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: ListFontsWithInfo, Minor: 0})
	}
	req.Pattern = string(requestBody[4 : 4+nameLen])
	return req, nil
}

/*
SetFontPath

1     51                              opcode
1                                     unused
2     2+(n+p)/4                       request length
2     CARD16                          number of paths
2                                     unused
n                                     LISTofSTR
p                                     padding
*/
type SetFontPathRequest struct {
	NumPaths uint16
	Paths    []string
}

func (SetFontPathRequest) OpCode() ReqCode { return SetFontPath }

func ParseSetFontPathRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*SetFontPathRequest, error) {
	if len(requestBody) < 4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: SetFontPath, Minor: 0})
	}
	req := &SetFontPathRequest{}
	req.NumPaths = order.Uint16(requestBody[0:2])
	pathsData := requestBody[4:]
	pathsLen := 0
	tempPathsData := pathsData
	for i := 0; i < int(req.NumPaths); i++ {
		if len(tempPathsData) == 0 {
			return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: SetFontPath, Minor: 0})
		}
		pathLen := int(tempPathsData[0])
		tempPathsData = tempPathsData[1:]
		pathsLen++
		if len(tempPathsData) < pathLen {
			return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: SetFontPath, Minor: 0})
		}
		req.Paths = append(req.Paths, string(tempPathsData[:pathLen]))
		tempPathsData = tempPathsData[pathLen:]
		pathsLen += pathLen
	}
	paddedLen := pathsLen + PadLen(pathsLen)
	if len(pathsData) != paddedLen {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: SetFontPath, Minor: 0})
	}
	return req, nil
}

/*
GetFontPath

1     52                              opcode
1                                     unused
2     1                               request length
*/
type GetFontPathRequest struct{}

func (GetFontPathRequest) OpCode() ReqCode { return GetFontPath }

func ParseGetFontPathRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*GetFontPathRequest, error) {
	return &GetFontPathRequest{}, nil
}

/*
CreatePixmap

1     53                              opcode
1     DEPTH                           depth
2     4                               request length
4     PIXMAP                          pid
4     DRAWABLE                        drawable
2     CARD16                          width
2     CARD16                          height
*/
type CreatePixmapRequest struct {
	Pid      Pixmap
	Drawable Drawable
	Width    uint16
	Height   uint16
	Depth    byte
}

func (CreatePixmapRequest) OpCode() ReqCode { return CreatePixmap }

func ParseCreatePixmapRequest(order binary.ByteOrder, data byte, payload []byte, seq uint16) (*CreatePixmapRequest, error) {
	if len(payload) != 12 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: CreatePixmap, Minor: 0})
	}
	req := &CreatePixmapRequest{}
	req.Depth = data
	req.Pid = Pixmap(order.Uint32(payload[0:4]))
	req.Drawable = Drawable(order.Uint32(payload[4:8]))
	req.Width = order.Uint16(payload[8:10])
	req.Height = order.Uint16(payload[10:12])
	return req, nil
}

/*
FreePixmap

1     54                              opcode
1                                     unused
2     2                               request length
4     PIXMAP                          pixmap
*/
type FreePixmapRequest struct {
	Pid Pixmap
}

func (FreePixmapRequest) OpCode() ReqCode { return FreePixmap }

func ParseFreePixmapRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*FreePixmapRequest, error) {
	if len(requestBody) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: FreePixmap, Minor: 0})
	}
	req := &FreePixmapRequest{}
	req.Pid = Pixmap(order.Uint32(requestBody[0:4]))
	return req, nil
}

/*
CreateGC

1     55                              opcode
1                                     unused
2     4+n                             request length
4     GCONTEXT                        cid
4     DRAWABLE                        drawable
4     BITMASK                         value-mask
4n    LISTofVALUE                     value-list
*/
type CreateGCRequest struct {
	Cid       GContext
	Drawable  Drawable
	ValueMask uint32
	Values    GC
}

func (CreateGCRequest) OpCode() ReqCode { return CreateGC }

func ParseCreateGCRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*CreateGCRequest, error) {
	if len(requestBody) < 12 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: CreateGC, Minor: 0})
	}
	req := &CreateGCRequest{}
	req.Cid = GContext(order.Uint32(requestBody[0:4]))
	req.Drawable = Drawable(order.Uint32(requestBody[4:8]))
	req.ValueMask = order.Uint32(requestBody[8:12])
	values, _, err := ParseGCValues(order, req.ValueMask, requestBody[12:], seq)
	if err != nil {
		return nil, err
	}
	req.Values = values
	return req, nil
}

/*
ChangeGC

1     56                              opcode
1                                     unused
2     3+n                             request length
4     GCONTEXT                        gc
4     BITMASK                         value-mask
4n    LISTofVALUE                     value-list
*/
type ChangeGCRequest struct {
	Gc        GContext
	ValueMask uint32
	Values    GC
}

func (ChangeGCRequest) OpCode() ReqCode { return ChangeGC }

func ParseChangeGCRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*ChangeGCRequest, error) {
	if len(requestBody) < 8 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: ChangeGC, Minor: 0})
	}
	req := &ChangeGCRequest{}
	req.Gc = GContext(order.Uint32(requestBody[0:4]))
	req.ValueMask = order.Uint32(requestBody[4:8])
	values, _, err := ParseGCValues(order, req.ValueMask, requestBody[8:], seq)
	if err != nil {
		return nil, err
	}
	req.Values = values
	return req, nil
}

/*
CopyGC

1     57                              opcode
1                                     unused
2     4                               request length
4     GCONTEXT                        src-gc
4     GCONTEXT                        dst-gc
4     BITMASK                         value-mask
*/
type CopyGCRequest struct {
	SrcGC     GContext
	DstGC     GContext
	ValueMask uint32
}

func (CopyGCRequest) OpCode() ReqCode { return CopyGC }

func ParseCopyGCRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*CopyGCRequest, error) {
	if len(requestBody) != 12 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: CopyGC, Minor: 0})
	}
	req := &CopyGCRequest{}
	req.SrcGC = GContext(order.Uint32(requestBody[0:4]))
	req.DstGC = GContext(order.Uint32(requestBody[4:8]))
	req.ValueMask = order.Uint32(requestBody[8:12])
	return req, nil
}

/*
SetDashes

1     58                              opcode
1                                     unused
2     3+(n+p)/4                       request length
4     GCONTEXT                        gc
2     CARD16                          dash-offset
2     CARD16                          n
n     LISTofCARD8                     dashes
p                                     padding
*/
type SetDashesRequest struct {
	GC         GContext
	DashOffset uint16
	Dashes     []byte
}

func (SetDashesRequest) OpCode() ReqCode { return SetDashes }

func ParseSetDashesRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*SetDashesRequest, error) {
	if len(requestBody) < 8 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: SetDashes, Minor: 0})
	}
	req := &SetDashesRequest{}
	req.GC = GContext(order.Uint32(requestBody[0:4]))
	req.DashOffset = order.Uint16(requestBody[4:6])
	nDashes := int(order.Uint16(requestBody[6:8]))
	paddedLen := 8 + nDashes + PadLen(8+nDashes)
	if len(requestBody) != paddedLen {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: SetDashes, Minor: 0})
	}
	req.Dashes = requestBody[8 : 8+nDashes]
	return req, nil
}

/*
SetClipRectangles

1     59                              opcode
1     { UnSorted, YSorted,            ordering

	YXSorted, YXBanded }

2     3+2n                            request length
4     GCONTEXT                        gc
2     INT16                           clip-x-origin
2     INT16                           clip-y-origin
8n    LISTofRECTANGLE                 rectangles
*/
type SetClipRectanglesRequest struct {
	GC         GContext
	ClippingX  int16
	ClippingY  int16
	Rectangles []Rectangle
	Ordering   byte
}

func (SetClipRectanglesRequest) OpCode() ReqCode { return SetClipRectangles }

func ParseSetClipRectanglesRequest(order binary.ByteOrder, data byte, requestBody []byte, seq uint16) (*SetClipRectanglesRequest, error) {
	if len(requestBody) < 8 || len(requestBody)%8 != 0 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: SetClipRectangles, Minor: 0})
	}
	req := &SetClipRectanglesRequest{}
	req.Ordering = data
	req.GC = GContext(order.Uint32(requestBody[0:4]))
	req.ClippingX = int16(order.Uint16(requestBody[4:6]))
	req.ClippingY = int16(order.Uint16(requestBody[6:8]))
	numRects := (len(requestBody) - 8) / 8
	for i := 0; i < numRects; i++ {
		offset := 8 + i*8
		rect := Rectangle{
			X:      int16(order.Uint16(requestBody[offset : offset+2])),
			Y:      int16(order.Uint16(requestBody[offset+2 : offset+4])),
			Width:  order.Uint16(requestBody[offset+4 : offset+6]),
			Height: order.Uint16(requestBody[offset+6 : offset+8]),
		}
		req.Rectangles = append(req.Rectangles, rect)
	}
	return req, nil
}

/*
FreeGC

1     60                              opcode
1                                     unused
2     2                               request length
4     GCONTEXT                        gc
*/
type FreeGCRequest struct {
	GC GContext
}

func (FreeGCRequest) OpCode() ReqCode { return FreeGC }

func ParseFreeGCRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*FreeGCRequest, error) {
	if len(requestBody) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: FreeGC, Minor: 0})
	}
	req := &FreeGCRequest{}
	req.GC = GContext(order.Uint32(requestBody[0:4]))
	return req, nil
}

/*
ClearArea

1     61                              opcode
1     BOOL                            exposures
2     4                               request length
4     WINDOW                          window
2     INT16                           x
2     INT16                           y
2     CARD16                          width
2     CARD16                          height
*/
type ClearAreaRequest struct {
	Exposures bool
	Window    Window
	X         int16
	Y         int16
	Width     uint16
	Height    uint16
}

func (ClearAreaRequest) OpCode() ReqCode { return ClearArea }

func ParseClearAreaRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*ClearAreaRequest, error) {
	if len(requestBody) != 12 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: ClearArea, Minor: 0})
	}
	req := &ClearAreaRequest{}
	req.Window = Window(order.Uint32(requestBody[0:4]))
	req.X = int16(order.Uint16(requestBody[4:6]))
	req.Y = int16(order.Uint16(requestBody[6:8]))
	req.Width = order.Uint16(requestBody[8:10])
	req.Height = order.Uint16(requestBody[10:12])
	return req, nil
}

/*
CopyArea

1     62                              opcode
1                                     unused
2     7                               request length
4     DRAWABLE                        src-drawable
4     DRAWABLE                        dst-drawable
4     GCONTEXT                        gc
2     INT16                           src-x
2     INT16                           src-y
2     INT16                           dst-x
2     INT16                           dst-y
2     CARD16                          width
2     CARD16                          height
*/
type CopyAreaRequest struct {
	SrcDrawable Drawable
	DstDrawable Drawable
	Gc          GContext
	SrcX        int16
	SrcY        int16
	DstX        int16
	DstY        int16
	Width       uint16
	Height      uint16
}

func (CopyAreaRequest) OpCode() ReqCode { return CopyArea }

func ParseCopyAreaRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*CopyAreaRequest, error) {
	if len(requestBody) != 24 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: CopyArea, Minor: 0})
	}
	req := &CopyAreaRequest{}
	req.SrcDrawable = Drawable(order.Uint32(requestBody[0:4]))
	req.DstDrawable = Drawable(order.Uint32(requestBody[4:8]))
	req.Gc = GContext(order.Uint32(requestBody[8:12]))
	req.SrcX = int16(order.Uint16(requestBody[12:14]))
	req.SrcY = int16(order.Uint16(requestBody[14:16]))
	req.DstX = int16(order.Uint16(requestBody[16:18]))
	req.DstY = int16(order.Uint16(requestBody[18:20]))
	req.Width = order.Uint16(requestBody[20:22])
	req.Height = order.Uint16(requestBody[22:24])
	return req, nil
}

/*
PolyPoint

1     64                              opcode
1     { Origin, Previous }            coordinate-mode
2     3+n                             request length
4     DRAWABLE                        drawable
4     GCONTEXT                        gc
4n    LISTofPOINT                     points
*/
type PolyPointRequest struct {
	CoordinateMode byte
	Drawable       Drawable
	Gc             GContext
	Coordinates    []uint32
}

func (r *PolyPointRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(r.CoordinateMode)
	n := len(r.Coordinates)
	length := uint16(3 + n/2)
	binary.Write(buf, order, length)
	binary.Write(buf, order, r.Drawable)
	binary.Write(buf, order, r.Gc)
	for _, c := range r.Coordinates {
		binary.Write(buf, order, uint16(c))
	}
	return buf.Bytes()
}

func (PolyPointRequest) OpCode() ReqCode { return PolyPoint }

func ParsePolyPointRequest(order binary.ByteOrder, data byte, requestBody []byte, seq uint16) (*PolyPointRequest, error) {
	if len(requestBody) < 8 || (len(requestBody)-8)%4 != 0 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: PolyPoint, Minor: 0})
	}
	req := &PolyPointRequest{}
	req.CoordinateMode = data
	req.Drawable = Drawable(order.Uint32(requestBody[0:4]))
	req.Gc = GContext(order.Uint32(requestBody[4:8]))
	numPoints := (len(requestBody) - 8) / 4
	for i := 0; i < numPoints; i++ {
		offset := 8 + i*4
		x := int32(int16(order.Uint16(requestBody[offset : offset+2])))
		y := int32(int16(order.Uint16(requestBody[offset+2 : offset+4])))
		req.Coordinates = append(req.Coordinates, uint32(x), uint32(y))
	}
	return req, nil
}

/*
PolyLine

1     65                              opcode
1     { Origin, Previous }            coordinate-mode
2     3+n                             request length
4     DRAWABLE                        drawable
4     GCONTEXT                        gc
4n    LISTofPOINT                     points
*/
type PolyLineRequest struct {
	CoordinateMode byte
	Drawable       Drawable
	Gc             GContext
	Coordinates    []uint32
}

func (r *PolyLineRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(r.CoordinateMode)
	n := len(r.Coordinates)
	length := uint16(3 + n/2)
	binary.Write(buf, order, length)
	binary.Write(buf, order, r.Drawable)
	binary.Write(buf, order, r.Gc)
	for _, c := range r.Coordinates {
		binary.Write(buf, order, uint16(c))
	}
	return buf.Bytes()
}

func (PolyLineRequest) OpCode() ReqCode { return PolyLine }

func ParsePolyLineRequest(order binary.ByteOrder, data byte, requestBody []byte, seq uint16) (*PolyLineRequest, error) {
	if len(requestBody) < 8 || (len(requestBody)-8)%4 != 0 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: PolyLine, Minor: 0})
	}
	req := &PolyLineRequest{}
	req.CoordinateMode = data
	req.Drawable = Drawable(order.Uint32(requestBody[0:4]))
	req.Gc = GContext(order.Uint32(requestBody[4:8]))
	numPoints := (len(requestBody) - 8) / 4
	for i := 0; i < numPoints; i++ {
		offset := 8 + i*4
		x := int32(int16(order.Uint16(requestBody[offset : offset+2])))
		y := int32(int16(order.Uint16(requestBody[offset+2 : offset+4])))
		req.Coordinates = append(req.Coordinates, uint32(x), uint32(y))
	}
	return req, nil
}

/*
PolySegment

1     66                              opcode
1                                     unused
2     3+2n                            request length
4     DRAWABLE                        drawable
4     GCONTEXT                        gc
8n    LISTofSEGMENT                   segments
*/
type PolySegmentRequest struct {
	Drawable Drawable
	Gc       GContext
	Segments []uint32
}

func (PolySegmentRequest) OpCode() ReqCode { return PolySegment }

func ParsePolySegmentRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*PolySegmentRequest, error) {
	if len(requestBody) < 8 || (len(requestBody)-8)%8 != 0 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: PolySegment, Minor: 0})
	}
	req := &PolySegmentRequest{}
	req.Drawable = Drawable(order.Uint32(requestBody[0:4]))
	req.Gc = GContext(order.Uint32(requestBody[4:8]))
	numSegments := (len(requestBody) - 8) / 8
	for i := 0; i < numSegments; i++ {
		offset := 8 + i*8
		x1 := int32(int16(order.Uint16(requestBody[offset : offset+2])))
		y1 := int32(int16(order.Uint16(requestBody[offset+2 : offset+4])))
		x2 := int32(int16(order.Uint16(requestBody[offset+4 : offset+6])))
		y2 := int32(int16(order.Uint16(requestBody[offset+6 : offset+8])))
		req.Segments = append(req.Segments, uint32(x1), uint32(y1), uint32(x2), uint32(y2))
	}
	return req, nil
}

/*
PolyRectangle

1     67                              opcode
1                                     unused
2     3+2n                            request length
4     DRAWABLE                        drawable
4     GCONTEXT                        gc
8n    LISTofRECTANGLE                 rectangles
*/
type PolyRectangleRequest struct {
	Drawable   Drawable
	Gc         GContext
	Rectangles []uint32
}

func (PolyRectangleRequest) OpCode() ReqCode { return PolyRectangle }

func ParsePolyRectangleRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*PolyRectangleRequest, error) {
	if len(requestBody) < 8 || (len(requestBody)-8)%8 != 0 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: PolyRectangle, Minor: 0})
	}
	req := &PolyRectangleRequest{}
	req.Drawable = Drawable(order.Uint32(requestBody[0:4]))
	req.Gc = GContext(order.Uint32(requestBody[4:8]))
	numRects := (len(requestBody) - 8) / 8
	for i := 0; i < numRects; i++ {
		offset := 8 + i*8
		x := int32(int16(order.Uint16(requestBody[offset : offset+2])))
		y := int32(int16(order.Uint16(requestBody[offset+2 : offset+4])))
		width := uint32(order.Uint16(requestBody[offset+4 : offset+6]))
		height := uint32(order.Uint16(requestBody[offset+6 : offset+8]))
		req.Rectangles = append(req.Rectangles, uint32(x), uint32(y), width, height)
	}
	return req, nil
}

/*
PolyArc

1     68                              opcode
1                                     unused
2     3+3n                            request length
4     DRAWABLE                        drawable
4     GCONTEXT                        gc
12n   LISTofARC                       arcs
*/
type PolyArcRequest struct {
	Drawable Drawable
	Gc       GContext
	Arcs     []uint32
}

func (PolyArcRequest) OpCode() ReqCode { return PolyArc }

func ParsePolyArcRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*PolyArcRequest, error) {
	if len(requestBody) < 8 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: PolyArc, Minor: 0})
	}
	req := &PolyArcRequest{}
	req.Drawable = Drawable(order.Uint32(requestBody[0:4]))
	req.Gc = GContext(order.Uint32(requestBody[4:8]))
	numArcs := (len(requestBody) - 8) / 12
	for i := 0; i < numArcs; i++ {
		offset := 8 + i*12
		x := int32(int16(order.Uint16(requestBody[offset : offset+2])))
		y := int32(int16(order.Uint16(requestBody[offset+2 : offset+4])))
		width := uint32(order.Uint16(requestBody[offset+4 : offset+6]))
		height := uint32(order.Uint16(requestBody[offset+6 : offset+8]))
		angle1 := int32(int16(order.Uint16(requestBody[offset+8 : offset+10])))
		angle2 := int32(int16(order.Uint16(requestBody[offset+10 : offset+12])))
		req.Arcs = append(req.Arcs, uint32(x), uint32(y), width, height, uint32(angle1), uint32(angle2))
	}
	return req, nil
}

/*
FillPoly

1     69                              opcode
1                                     unused
2     4+n                             request length
4     DRAWABLE                        drawable
4     GCONTEXT                        gc
1     { Complex, Nonconvex, Convex }  shape
1     { Origin, Previous }            coordinate-mode
2                                     unused
4n    LISTofPOINT                     points
*/
type FillPolyRequest struct {
	Drawable       Drawable
	Gc             GContext
	Shape          byte
	CoordinateMode byte
	Coordinates    []uint32
}

func (r *FillPolyRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(0)
	n := len(r.Coordinates)
	length := uint16(4 + n/2)
	binary.Write(buf, order, length)
	binary.Write(buf, order, r.Drawable)
	binary.Write(buf, order, r.Gc)
	buf.WriteByte(r.Shape)
	buf.WriteByte(r.CoordinateMode)
	buf.Write([]byte{0, 0})
	for _, c := range r.Coordinates {
		binary.Write(buf, order, uint16(c))
	}
	return buf.Bytes()
}

func (FillPolyRequest) OpCode() ReqCode { return FillPoly }

func ParseFillPolyRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*FillPolyRequest, error) {
	if len(requestBody) < 12 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: FillPoly, Minor: 0})
	}
	req := &FillPolyRequest{}
	req.Drawable = Drawable(order.Uint32(requestBody[0:4]))
	req.Gc = GContext(order.Uint32(requestBody[4:8]))
	req.Shape = requestBody[8]
	req.CoordinateMode = requestBody[9]
	numPoints := (len(requestBody) - 12) / 4
	for i := 0; i < numPoints; i++ {
		offset := 12 + i*4
		x := int32(int16(order.Uint16(requestBody[offset : offset+2])))
		y := int32(int16(order.Uint16(requestBody[offset+2 : offset+4])))
		req.Coordinates = append(req.Coordinates, uint32(x), uint32(y))
	}
	return req, nil
}

/*
PolyFillRectangle

1     70                              opcode
1                                     unused
2     3+2n                            request length
4     DRAWABLE                        drawable
4     GCONTEXT                        gc
8n    LISTofRECTANGLE                 rectangles
*/
type PolyFillRectangleRequest struct {
	Drawable   Drawable
	Gc         GContext
	Rectangles []uint32
}

func (PolyFillRectangleRequest) OpCode() ReqCode { return PolyFillRectangle }

func ParsePolyFillRectangleRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*PolyFillRectangleRequest, error) {
	if len(requestBody) < 8 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: PolyFillRectangle, Minor: 0})
	}
	req := &PolyFillRectangleRequest{}
	req.Drawable = Drawable(order.Uint32(requestBody[0:4]))
	req.Gc = GContext(order.Uint32(requestBody[4:8]))
	numRects := (len(requestBody) - 8) / 8
	for i := 0; i < numRects; i++ {
		offset := 8 + i*8
		x := int32(int16(order.Uint16(requestBody[offset : offset+2])))
		y := int32(int16(order.Uint16(requestBody[offset+2 : offset+4])))
		width := uint32(order.Uint16(requestBody[offset+4 : offset+6]))
		height := uint32(order.Uint16(requestBody[offset+6 : offset+8]))
		req.Rectangles = append(req.Rectangles, uint32(x), uint32(y), width, height)
	}
	return req, nil
}

/*
PolyFillArc

1     71                              opcode
1                                     unused
2     3+3n                            request length
4     DRAWABLE                        drawable
4     GCONTEXT                        gc
12n   LISTofARC                       arcs
*/
type PolyFillArcRequest struct {
	Drawable Drawable
	Gc       GContext
	Arcs     []uint32
}

func (PolyFillArcRequest) OpCode() ReqCode { return PolyFillArc }

func ParsePolyFillArcRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*PolyFillArcRequest, error) {
	if len(requestBody) < 8 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: PolyFillArc, Minor: 0})
	}
	req := &PolyFillArcRequest{}
	req.Drawable = Drawable(order.Uint32(requestBody[0:4]))
	req.Gc = GContext(order.Uint32(requestBody[4:8]))
	numArcs := (len(requestBody) - 8) / 12
	for i := 0; i < numArcs; i++ {
		offset := 8 + i*12
		x := int32(int16(order.Uint16(requestBody[offset : offset+2])))
		y := int32(int16(order.Uint16(requestBody[offset+2 : offset+4])))
		width := uint32(order.Uint16(requestBody[offset+4 : offset+6]))
		height := uint32(order.Uint16(requestBody[offset+6 : offset+8]))
		angle1 := int32(int16(order.Uint16(requestBody[offset+8 : offset+10])))
		angle2 := int32(int16(order.Uint16(requestBody[offset+10 : offset+12])))
		req.Arcs = append(req.Arcs, uint32(x), uint32(y), width, height, uint32(angle1), uint32(angle2))
	}
	return req, nil
}

/*
PutImage

1     72                              opcode
1     { Bitmap, XYPixmap, ZPixmap }   format
2     6+(n+p)/4                       request length
4     DRAWABLE                        drawable
4     GCONTEXT                        gc
2     CARD16                          width
2     CARD16                          height
2     INT16                           dst-x
2     INT16                           dst-y
1     CARD8                           left-pad
1     CARD8                           depth
2                                     unused
n     LISTofBYTE                      data
p                                     padding
*/
type PutImageRequest struct {
	Drawable Drawable
	Gc       GContext
	Width    uint16
	Height   uint16
	DstX     int16
	DstY     int16
	LeftPad  byte
	Depth    byte
	Format   byte
	Data     []byte
}

func (PutImageRequest) OpCode() ReqCode { return PutImage }

func ParsePutImageRequest(order binary.ByteOrder, data byte, requestBody []byte, seq uint16) (*PutImageRequest, error) {
	if len(requestBody) < 20 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: PutImage, Minor: 0})
	}
	req := &PutImageRequest{}
	req.Format = data
	req.Drawable = Drawable(order.Uint32(requestBody[0:4]))
	req.Gc = GContext(order.Uint32(requestBody[4:8]))
	req.Width = order.Uint16(requestBody[8:10])
	req.Height = order.Uint16(requestBody[10:12])
	req.DstX = int16(order.Uint16(requestBody[12:14]))
	req.DstY = int16(order.Uint16(requestBody[14:16]))
	req.LeftPad = requestBody[16]
	req.Depth = requestBody[17]
	req.Data = requestBody[20:]
	return req, nil
}

/*
GetImage

1     73                              opcode
1     { XYPixmap, ZPixmap }           format
2     5                               request length
4     DRAWABLE                        drawable
2     INT16                           x
2     INT16                           y
2     CARD16                          width
2     CARD16                          height
4     CARD32                          plane-mask
*/
type GetImageRequest struct {
	Drawable  Drawable
	X         int16
	Y         int16
	Width     uint16
	Height    uint16
	PlaneMask uint32
	Format    byte
}

func (GetImageRequest) OpCode() ReqCode { return GetImage }

func ParseGetImageRequest(order binary.ByteOrder, data byte, requestBody []byte, seq uint16) (*GetImageRequest, error) {
	if len(requestBody) != 16 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: GetImage, Minor: 0})
	}
	req := &GetImageRequest{}
	req.Format = data
	req.Drawable = Drawable(order.Uint32(requestBody[0:4]))
	req.X = int16(order.Uint16(requestBody[4:6]))
	req.Y = int16(order.Uint16(requestBody[6:8]))
	req.Width = order.Uint16(requestBody[8:10])
	req.Height = order.Uint16(requestBody[10:12])
	req.PlaneMask = order.Uint32(requestBody[12:16])
	return req, nil
}

/*
PolyText8

1     74                              opcode
1                                     unused
2     4+(n+p)/4                       request length
4     DRAWABLE                        drawable
4     GCONTEXT                        gc
2     INT16                           x
2     INT16                           y
n     LISTofTEXTITEM8                 items
p                                     padding
*/
type PolyText8Request struct {
	Drawable Drawable
	GC       GContext
	X, Y     int16
	Items    []PolyTextItem
}

func (PolyText8Request) OpCode() ReqCode { return PolyText8 }

func (r *PolyText8Request) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)

	itemsBytes := new(bytes.Buffer)
	for _, item := range r.Items {
		switch i := item.(type) {
		case PolyText8String:
			itemsBytes.WriteByte(byte(len(i.Str)))
			itemsBytes.WriteByte(byte(i.Delta))
			itemsBytes.Write(i.Str)
		case PolyTextFont:
			itemsBytes.WriteByte(255)
			binary.Write(itemsBytes, order, i.Font)
		}
	}
	length := uint16(4 + (itemsBytes.Len()+PadLen(itemsBytes.Len()))/4)

	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(0)
	binary.Write(buf, order, length)

	binary.Write(buf, order, r.Drawable)
	binary.Write(buf, order, r.GC)
	binary.Write(buf, order, r.X)
	binary.Write(buf, order, r.Y)
	buf.Write(itemsBytes.Bytes())
	buf.Write(make([]byte, PadLen(itemsBytes.Len())))
	return buf.Bytes()
}

func ParsePolyText8Request(order binary.ByteOrder, data []byte, seq uint16) (*PolyText8Request, error) {
	var req PolyText8Request
	if len(data) < 12 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: PolyText8, Minor: 0})
	}
	req.Drawable = Drawable(order.Uint32(data[0:4]))
	req.GC = GContext(order.Uint32(data[4:8]))
	req.X = int16(order.Uint16(data[8:10]))
	req.Y = int16(order.Uint16(data[10:12]))

	i := 12
	for i < len(data) {
		if i+1 > len(data) {
			break
		}
		length := int(data[i])
		if length == 0 { // Invalid length, must be padding
			break
		}
		if length == 255 {
			itemSize := 5
			if i+itemSize > len(data) {
				break
			}
			font := Font(order.Uint32(data[i+1 : i+5]))
			req.Items = append(req.Items, PolyTextFont{Font: font})
			i += itemSize
		} else {
			itemSize := 2 + length
			if i+itemSize > len(data) {
				break
			}
			delta := int8(data[i+1])
			str := data[i+2 : i+2+length]
			req.Items = append(req.Items, PolyText8String{Delta: delta, Str: str})
			i += itemSize
		}
	}
	return &req, nil
}

/*
PolyText16

1     75                              opcode
1                                     unused
2     4+(n+p)/4                       request length
4     DRAWABLE                        drawable
4     GCONTEXT                        gc
2     INT16                           x
2     INT16                           y
n     LISTofTEXTITEM16                items
p                                     padding
*/
type PolyText16Request struct {
	Drawable Drawable
	GC       GContext
	X, Y     int16
	Items    []PolyTextItem
}

func (PolyText16Request) OpCode() ReqCode { return PolyText16 }

func (r *PolyText16Request) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)

	itemsBytes := new(bytes.Buffer)
	for _, item := range r.Items {
		switch i := item.(type) {
		case PolyText16String:
			itemsBytes.WriteByte(byte(len(i.Str)))
			itemsBytes.WriteByte(byte(i.Delta))
			for _, c := range i.Str {
				binary.Write(itemsBytes, order, c)
			}
		case PolyTextFont:
			itemsBytes.WriteByte(255)
			binary.Write(itemsBytes, order, i.Font)
		}
	}
	length := uint16(4 + (itemsBytes.Len()+PadLen(itemsBytes.Len()))/4)

	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(0)
	binary.Write(buf, order, length)

	binary.Write(buf, order, r.Drawable)
	binary.Write(buf, order, r.GC)
	binary.Write(buf, order, r.X)
	binary.Write(buf, order, r.Y)
	buf.Write(itemsBytes.Bytes())
	buf.Write(make([]byte, PadLen(itemsBytes.Len())))
	return buf.Bytes()
}

func ParsePolyText16Request(order binary.ByteOrder, data []byte, seq uint16) (*PolyText16Request, error) {
	var req PolyText16Request
	if len(data) < 12 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: PolyText16, Minor: 0})
	}
	req.Drawable = Drawable(order.Uint32(data[0:4]))
	req.GC = GContext(order.Uint32(data[4:8]))
	req.X = int16(order.Uint16(data[8:10]))
	req.Y = int16(order.Uint16(data[10:12]))

	i := 12
	for i < len(data) {
		if i+1 > len(data) {
			break
		}
		length := int(data[i])
		if length == 0 { // Invalid length, must be padding
			break
		}
		if length == 255 {
			itemSize := 5
			if i+itemSize > len(data) {
				break
			}
			font := Font(order.Uint32(data[i+1 : i+5]))
			req.Items = append(req.Items, PolyTextFont{Font: font})
			i += itemSize
		} else {
			itemSize := 2 + length*2
			if i+itemSize > len(data) {
				break
			}

			delta := int8(data[i+1])
			var str []uint16
			for j := 0; j < length; j++ {
				str = append(str, order.Uint16(data[i+2+j*2:i+2+(j+1)*2]))
			}
			req.Items = append(req.Items, PolyText16String{Delta: delta, Str: str})
			i += itemSize
		}
	}
	return &req, nil
}

/*
ImageText8

1     76                              opcode
1     n                               length of string
2     4+(n+p)/4                       request length
4     DRAWABLE                        drawable
4     GCONTEXT                        gc
2     INT16                           x
2     INT16                           y
n     STRING8                         string
p                                     padding
*/
type ImageText8Request struct {
	Drawable Drawable
	Gc       GContext
	X        int16
	Y        int16
	Text     []byte
}

func (ImageText8Request) OpCode() ReqCode { return ImageText8 }

func (r *ImageText8Request) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	length := uint16(4 + (len(r.Text)+PadLen(len(r.Text)))/4)

	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(byte(len(r.Text)))
	binary.Write(buf, order, length)

	binary.Write(buf, order, r.Drawable)
	binary.Write(buf, order, r.Gc)
	binary.Write(buf, order, r.X)
	binary.Write(buf, order, r.Y)
	buf.Write(r.Text)
	buf.Write(make([]byte, PadLen(len(r.Text))))
	return buf.Bytes()
}

func ParseImageText8Request(order binary.ByteOrder, data byte, requestBody []byte, seq uint16) (*ImageText8Request, error) {
	n := int(data)
	paddedLen := 12 + n + PadLen(n)
	if len(requestBody) != paddedLen {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: ImageText8, Minor: 0})
	}
	req := &ImageText8Request{}
	req.Drawable = Drawable(order.Uint32(requestBody[0:4]))
	req.Gc = GContext(order.Uint32(requestBody[4:8]))
	req.X = int16(order.Uint16(requestBody[8:10]))
	req.Y = int16(order.Uint16(requestBody[10:12]))
	req.Text = requestBody[12 : 12+n]
	return req, nil
}

/*
ImageText16

1     77                              opcode
1     n                               length of string
2     4+(2n+p)/4                      request length
4     DRAWABLE                        drawable
4     GCONTEXT                        gc
2     INT16                           x
2     INT16                           y
2n    STRING16                        string
p                                     padding
*/
type ImageText16Request struct {
	Drawable Drawable
	Gc       GContext
	X        int16
	Y        int16
	Text     []uint16
}

func (ImageText16Request) OpCode() ReqCode { return ImageText16 }

func (r *ImageText16Request) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	length := uint16(4 + (len(r.Text)*2+PadLen(len(r.Text)*2))/4)

	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(byte(len(r.Text)))
	binary.Write(buf, order, length)

	binary.Write(buf, order, r.Drawable)
	binary.Write(buf, order, r.Gc)
	binary.Write(buf, order, r.X)
	binary.Write(buf, order, r.Y)
	for _, c := range r.Text {
		binary.Write(buf, order, c)
	}
	buf.Write(make([]byte, PadLen(len(r.Text)*2)))
	return buf.Bytes()
}

func ParseImageText16Request(order binary.ByteOrder, data byte, requestBody []byte, seq uint16) (*ImageText16Request, error) {
	n := int(data)
	paddedLen := 12 + 2*n + PadLen(12+2*n)
	if len(requestBody) != paddedLen {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: ImageText16, Minor: 0})
	}
	req := &ImageText16Request{}
	req.Drawable = Drawable(order.Uint32(requestBody[0:4]))
	req.Gc = GContext(order.Uint32(requestBody[4:8]))
	req.X = int16(order.Uint16(requestBody[8:10]))
	req.Y = int16(order.Uint16(requestBody[10:12]))
	for i := 0; i < n; i++ {
		req.Text = append(req.Text, order.Uint16(requestBody[12+i*2:12+(i+1)*2]))
	}
	return req, nil
}

/*
CreateColormap

1     78                              opcode
1     { None, All }                   alloc
2     4                               request length
4     COLORMAP                        mid
4     WINDOW                          window
4     VISUALID                        visual
*/
type CreateColormapRequest struct {
	Alloc  byte
	Mid    Colormap
	Window Window
	Visual VisualID
}

func (CreateColormapRequest) OpCode() ReqCode { return CreateColormap }

func ParseCreateColormapRequest(order binary.ByteOrder, data byte, payload []byte, seq uint16) (*CreateColormapRequest, error) {
	if len(payload) != 12 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: CreateColormap, Minor: 0})
	}
	req := &CreateColormapRequest{}
	req.Alloc = data
	req.Mid = Colormap(order.Uint32(payload[0:4]))
	req.Window = Window(order.Uint32(payload[4:8]))
	req.Visual = VisualID(order.Uint32(payload[8:12]))
	return req, nil
}

/*
FreeColormap

1     79                              opcode
1                                     unused
2     2                               request length
4     COLORMAP                        cmap
*/
type FreeColormapRequest struct {
	Cmap Colormap
}

func (FreeColormapRequest) OpCode() ReqCode { return FreeColormap }

func ParseFreeColormapRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*FreeColormapRequest, error) {
	if len(requestBody) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: FreeColormap, Minor: 0})
	}
	req := &FreeColormapRequest{}
	req.Cmap = Colormap(order.Uint32(requestBody[0:4]))
	return req, nil
}

/*
CopyColormapAndFree

1     80                              opcode
1                                     unused
2     3                               request length
4     COLORMAP                        mid
4     COLORMAP                        src-cmap
*/
type CopyColormapAndFreeRequest struct {
	Mid     Colormap
	SrcCmap Colormap
}

func (CopyColormapAndFreeRequest) OpCode() ReqCode { return CopyColormapAndFree }

func ParseCopyColormapAndFreeRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*CopyColormapAndFreeRequest, error) {
	if len(requestBody) != 8 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: CopyColormapAndFree, Minor: 0})
	}
	req := &CopyColormapAndFreeRequest{}
	req.Mid = Colormap(order.Uint32(requestBody[0:4]))
	req.SrcCmap = Colormap(order.Uint32(requestBody[4:8]))
	return req, nil
}

/*
InstallColormap

1     81                              opcode
1                                     unused
2     2                               request length
4     COLORMAP                        cmap
*/
type InstallColormapRequest struct {
	Cmap Colormap
}

func (InstallColormapRequest) OpCode() ReqCode { return InstallColormap }

func ParseInstallColormapRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*InstallColormapRequest, error) {
	if len(requestBody) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: InstallColormap, Minor: 0})
	}
	req := &InstallColormapRequest{}
	req.Cmap = Colormap(order.Uint32(requestBody[0:4]))
	return req, nil
}

/*
UninstallColormap

1     82                              opcode
1                                     unused
2     2                               request length
4     COLORMAP                        cmap
*/
type UninstallColormapRequest struct {
	Cmap Colormap
}

func (UninstallColormapRequest) OpCode() ReqCode { return UninstallColormap }

func ParseUninstallColormapRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*UninstallColormapRequest, error) {
	if len(requestBody) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: UninstallColormap, Minor: 0})
	}
	req := &UninstallColormapRequest{}
	req.Cmap = Colormap(order.Uint32(requestBody[0:4]))
	return req, nil
}

/*
ListInstalledColormaps

1     83                              opcode
1                                     unused
2     2                               request length
4     WINDOW                          window
*/
type ListInstalledColormapsRequest struct {
	Window Window
}

func (ListInstalledColormapsRequest) OpCode() ReqCode { return ListInstalledColormaps }

func ParseListInstalledColormapsRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*ListInstalledColormapsRequest, error) {
	if len(requestBody) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: ListInstalledColormaps, Minor: 0})
	}
	req := &ListInstalledColormapsRequest{}
	req.Window = Window(order.Uint32(requestBody[0:4]))
	return req, nil
}

/*
AllocColor

1     84                              opcode
1                                     unused
2     4                               request length
4     COLORMAP                        cmap
2     CARD16                          red
2     CARD16                          green
2     CARD16                          blue
2                                     unused
*/
type AllocColorRequest struct {
	Cmap  Colormap
	Red   uint16
	Green uint16
	Blue  uint16
}

func (AllocColorRequest) OpCode() ReqCode { return AllocColor }

func ParseAllocColorRequest(order binary.ByteOrder, payload []byte, seq uint16) (*AllocColorRequest, error) {
	if len(payload) != 12 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: AllocColor, Minor: 0})
	}
	req := &AllocColorRequest{}
	req.Cmap = Colormap(order.Uint32(payload[0:4]))
	req.Red = order.Uint16(payload[4:6])
	req.Green = order.Uint16(payload[6:8])
	req.Blue = order.Uint16(payload[8:10])
	return req, nil
}

type AllocNamedColorRequest struct {
	Cmap Colormap
	Name []byte
}

func (AllocNamedColorRequest) OpCode() ReqCode { return AllocNamedColor }

/*
AllocNamedColor

1     85                              opcode
1                                     unused
2     3+(n+p)/4                       request length
4     COLORMAP                        cmap
2     CARD16                          n
2                                     unused
n     STRING8                         name
p                                     padding
*/
func ParseAllocNamedColorRequest(order binary.ByteOrder, payload []byte, seq uint16) (*AllocNamedColorRequest, error) {
	if len(payload) < 8 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: AllocNamedColor, Minor: 0})
	}
	req := &AllocNamedColorRequest{}
	req.Cmap = Colormap(order.Uint32(payload[0:4]))
	nameLen := order.Uint16(payload[4:6])
	paddedLen := 8 + int(nameLen) + PadLen(8+int(nameLen))
	if len(payload) != paddedLen {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: AllocNamedColor, Minor: 0})
	}
	req.Name = payload[8 : 8+nameLen]
	return req, nil
}

type FreeColorsRequest struct {
	Cmap      Colormap
	PlaneMask uint32
	Pixels    []uint32
}

func (FreeColorsRequest) OpCode() ReqCode { return FreeColors }

/*
FreeColors

	1     88                              opcode
	1                                     unused
	2     3+n                             request length
	4     COLORMAP                        cmap
	4     CARD32                          plane-mask
	4n     LISTofCARD32                   pixels
*/
func ParseFreeColorsRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*FreeColorsRequest, error) {
	if len(requestBody) < 8 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: FreeColors, Minor: 0})
	}
	req := &FreeColorsRequest{}
	req.Cmap = Colormap(order.Uint32(requestBody[0:4]))
	req.PlaneMask = order.Uint32(requestBody[4:8])
	numPixels := (len(requestBody) - 8) / 4
	if len(requestBody) < 8+numPixels*4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: FreeColors, Minor: 0})
	}
	for i := 0; i < numPixels; i++ {
		offset := 8 + i*4
		req.Pixels = append(req.Pixels, order.Uint32(requestBody[offset:offset+4]))
	}
	return req, nil
}

type StoreColorsRequest struct {
	Cmap  Colormap
	Items []XColorItem
}

func (StoreColorsRequest) OpCode() ReqCode { return StoreColors }

/*
StoreColors

1     89                              opcode
1                                     unused
2     2+3n                            request length
4     COLORMAP                        cmap
12n   LISTofCOLORITEM                 items
*/
func ParseStoreColorsRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*StoreColorsRequest, error) {
	if len(requestBody) < 4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: StoreColors, Minor: 0})
	}
	req := &StoreColorsRequest{}
	req.Cmap = Colormap(order.Uint32(requestBody[0:4]))
	numItems := (len(requestBody) - 4) / 12
	for i := 0; i < numItems; i++ {
		offset := 4 + i*12
		item := XColorItem{
			Pixel: order.Uint32(requestBody[offset : offset+4]),
			Red:   order.Uint16(requestBody[offset+4 : offset+6]),
			Green: order.Uint16(requestBody[offset+6 : offset+8]),
			Blue:  order.Uint16(requestBody[offset+8 : offset+10]),
			Flags: requestBody[offset+10],
		}
		req.Items = append(req.Items, item)
	}
	return req, nil
}

type StoreNamedColorRequest struct {
	Cmap  Colormap
	Pixel uint32
	Name  string
	Flags byte
}

func (StoreNamedColorRequest) OpCode() ReqCode { return StoreNamedColor }

/*
StoreNamedColor

1     90                              opcode
1     BITMASK                         flags
2     4+(n+p)/4                       request length
4     COLORMAP                        cmap
4     CARD32                          pixel
2     CARD16                          n
2                                     unused
n     STRING8                         name
p                                     padding
*/
func ParseStoreNamedColorRequest(order binary.ByteOrder, data byte, requestBody []byte, seq uint16) (*StoreNamedColorRequest, error) {
	if len(requestBody) < 12 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: StoreNamedColor, Minor: 0})
	}
	req := &StoreNamedColorRequest{}
	req.Cmap = Colormap(order.Uint32(requestBody[0:4]))
	req.Pixel = order.Uint32(requestBody[4:8])
	nameLen := order.Uint16(requestBody[8:10])
	if len(requestBody) < 12+int(nameLen) {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: StoreNamedColor, Minor: 0})
	}
	req.Name = string(requestBody[12 : 12+nameLen])
	req.Flags = data
	return req, nil
}

type QueryColorsRequest struct {
	Cmap   uint32
	Pixels []uint32
}

func (QueryColorsRequest) OpCode() ReqCode { return QueryColors }

/*
QueryColors

1     91                              opcode
1                                     unused
2     2+n                             request length
4     COLORMAP                        cmap
4n    LISTofCARD32                    pixels
*/
func ParseQueryColorsRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*QueryColorsRequest, error) {
	if len(requestBody) < 4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: QueryColors, Minor: 0})
	}
	req := &QueryColorsRequest{}
	req.Cmap = order.Uint32(requestBody[0:4])
	numPixels := (len(requestBody) - 4) / 4
	for i := 0; i < numPixels; i++ {
		offset := 4 + i*4
		req.Pixels = append(req.Pixels, order.Uint32(requestBody[offset:offset+4]))
	}
	return req, nil
}

type LookupColorRequest struct {
	Cmap Colormap
	Name string
}

func (LookupColorRequest) OpCode() ReqCode { return LookupColor }

/*
LookupColor

1     92                              opcode
1                                     unused
2     3+(n+p)/4                       request length
4     COLORMAP                        cmap
2     CARD16                          n
2                                     unused
n     STRING8                         name
p                                     padding
*/
func ParseLookupColorRequest(order binary.ByteOrder, payload []byte, seq uint16) (*LookupColorRequest, error) {
	if len(payload) < 8 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: LookupColor, Minor: 0})
	}
	req := &LookupColorRequest{}
	req.Cmap = Colormap(order.Uint32(payload[0:4]))
	nameLen := order.Uint16(payload[4:6])
	paddedLen := 8 + int(nameLen) + PadLen(int(nameLen))
	if len(payload) != paddedLen {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: LookupColor, Minor: 0})
	}
	req.Name = string(payload[8 : 8+nameLen])
	return req, nil
}

type CreateGlyphCursorRequest struct {
	Cid        Cursor
	SourceFont Font
	MaskFont   Font
	SourceChar uint16
	MaskChar   uint16
	ForeColor  [3]uint16
	BackColor  [3]uint16
}

func (CreateGlyphCursorRequest) OpCode() ReqCode { return CreateGlyphCursor }

/*
CreateGlyphCursor

1     94                              opcode
1                                     unused
2     8                               request length
4     CURSOR                          cid
4     FONT                            source-font
4     FONT                            mask-font
2     CARD16                          source-char
2     CARD16                          mask-char
2     CARD16                          fore-red
2     CARD16                          fore-green
2     CARD16                          fore-blue
2     CARD16                          back-red
2     CARD16                          back-green
2     CARD16                          back-blue
*/
func ParseCreateGlyphCursorRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*CreateGlyphCursorRequest, error) {
	if len(requestBody) != 28 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: CreateGlyphCursor, Minor: 0})
	}
	req := &CreateGlyphCursorRequest{}
	req.Cid = Cursor(order.Uint32(requestBody[0:4]))
	req.SourceFont = Font(order.Uint32(requestBody[4:8]))
	req.MaskFont = Font(order.Uint32(requestBody[8:12]))
	req.SourceChar = order.Uint16(requestBody[12:14])
	req.MaskChar = order.Uint16(requestBody[14:16])
	req.ForeColor[0] = order.Uint16(requestBody[16:18])
	req.ForeColor[1] = order.Uint16(requestBody[18:20])
	req.ForeColor[2] = order.Uint16(requestBody[20:22])
	req.BackColor[0] = order.Uint16(requestBody[22:24])
	req.BackColor[1] = order.Uint16(requestBody[24:26])
	req.BackColor[2] = order.Uint16(requestBody[26:28])
	return req, nil
}

type FreeCursorRequest struct {
	Cursor Cursor
}

func (FreeCursorRequest) OpCode() ReqCode { return FreeCursor }

/*
FreeCursor

1     95                              opcode
1                                     unused
2     2                               request length
4     CURSOR                          cursor
*/
func ParseFreeCursorRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*FreeCursorRequest, error) {
	if len(requestBody) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: FreeCursor, Minor: 0})
	}
	req := &FreeCursorRequest{}
	req.Cursor = Cursor(order.Uint32(requestBody[0:4]))
	return req, nil
}

type RecolorCursorRequest struct {
	Cursor    Cursor
	ForeColor [3]uint16
	BackColor [3]uint16
}

func (RecolorCursorRequest) OpCode() ReqCode { return RecolorCursor }

/*
RecolorCursor

1     96                              opcode
1                                     unused
2     5                               request length
4     CURSOR                          cursor
2     CARD16                          fore-red
2     CARD16                          fore-green
2     CARD16                          fore-blue
2     CARD16                          back-red
2     CARD16                          back-green
2     CARD16                          back-blue
*/
func ParseRecolorCursorRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*RecolorCursorRequest, error) {
	if len(requestBody) != 16 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: RecolorCursor, Minor: 0})
	}
	req := &RecolorCursorRequest{}
	req.Cursor = Cursor(order.Uint32(requestBody[0:4]))
	req.ForeColor[0] = order.Uint16(requestBody[4:6])
	req.ForeColor[1] = order.Uint16(requestBody[6:8])
	req.ForeColor[2] = order.Uint16(requestBody[8:10])
	req.BackColor[0] = order.Uint16(requestBody[10:12])
	req.BackColor[1] = order.Uint16(requestBody[12:14])
	req.BackColor[2] = order.Uint16(requestBody[14:16])
	return req, nil
}

type QueryBestSizeRequest struct {
	Class    byte
	Drawable Drawable
	Width    uint16
	Height   uint16
}

func (QueryBestSizeRequest) OpCode() ReqCode { return QueryBestSize }

/*
QueryBestSize

1     97                              opcode
1     { Cursor, Tile, Stipple }       class
2     3                               request length
4     DRAWABLE                        drawable
2     CARD16                          width
2     CARD16                          height
*/
func ParseQueryBestSizeRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*QueryBestSizeRequest, error) {
	if len(requestBody) != 8 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: QueryBestSize, Minor: 0})
	}
	req := &QueryBestSizeRequest{}
	req.Drawable = Drawable(order.Uint32(requestBody[0:4]))
	req.Width = order.Uint16(requestBody[4:6])
	req.Height = order.Uint16(requestBody[6:8])
	return req, nil
}

type QueryExtensionRequest struct {
	Name string
}

func (QueryExtensionRequest) OpCode() ReqCode { return QueryExtension }

/*
QueryExtension

1     98                              opcode
1                                     unused
2     2+(n+p)/4                       request length
2     CARD16                          n
2                                     unused
n     STRING8                         name
p                                     padding
*/
func ParseQueryExtensionRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*QueryExtensionRequest, error) {
	if len(requestBody) < 4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: QueryExtension, Minor: 0})
	}
	req := &QueryExtensionRequest{}
	nameLen := order.Uint16(requestBody[0:2])
	paddedLen := 4 + int(nameLen) + PadLen(int(nameLen))
	if len(requestBody) != paddedLen {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: QueryExtension, Minor: 0})
	}
	req.Name = string(requestBody[4 : 4+nameLen])
	return req, nil
}

type BellRequest struct {
	Percent int8
}

func (BellRequest) OpCode() ReqCode { return Bell }

/*
Bell

1     102                             opcode
1     INT8                            percent
2     1                               request length
*/
func ParseBellRequest(requestBody byte, seq uint16) (*BellRequest, error) {
	req := &BellRequest{}
	req.Percent = int8(requestBody)
	return req, nil
}

type SetPointerMappingRequest struct {
	Map []byte
}

func (r *SetPointerMappingRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	n := len(r.Map)
	paddedLen := n + PadLen(n)
	length := uint16(1 + paddedLen/4)

	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(byte(n))
	binary.Write(buf, order, length)
	buf.Write(r.Map)
	buf.Write(make([]byte, PadLen(n)))
	return buf.Bytes()
}

func (SetPointerMappingRequest) OpCode() ReqCode { return SetPointerMapping }

/*
SetPointerMapping

1     116                             opcode
1     n                               length of map
2     1+n/4                           request length
n     LISTofBYTE                      map
*/
func ParseSetPointerMappingRequest(order binary.ByteOrder, data byte, requestBody []byte, seq uint16) (*SetPointerMappingRequest, error) {
	req := &SetPointerMappingRequest{}
	mapLen := int(data)
	if len(requestBody) < mapLen {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: SetPointerMapping, Minor: 0})
	}
	req.Map = requestBody[:mapLen]
	return req, nil
}

type GetPointerMappingRequest struct{}

func (r *GetPointerMappingRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(0)
	binary.Write(buf, order, uint16(1))
	return buf.Bytes()
}

func (GetPointerMappingRequest) OpCode() ReqCode { return GetPointerMapping }

/*
GetPointerMapping

1     117                             opcode
1                                     unused
2     1                               request length
*/
func ParseGetPointerMappingRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*GetPointerMappingRequest, error) {
	return &GetPointerMappingRequest{}, nil
}

type GetPointerControlRequest struct{}

func (r *GetPointerControlRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(0)
	binary.Write(buf, order, uint16(1))
	return buf.Bytes()
}

func (GetPointerControlRequest) OpCode() ReqCode { return GetPointerControl }

/*
GetPointerControl

1     106                             opcode
1                                     unused
2     1                               request length
*/
func ParseGetPointerControlRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*GetPointerControlRequest, error) {
	return &GetPointerControlRequest{}, nil
}

type GetKeyboardMappingRequest struct {
	FirstKeyCode KeyCode
	Count        byte
}

func (GetKeyboardMappingRequest) OpCode() ReqCode { return GetKeyboardMapping }

/*
GetKeyboardMapping

1     101                             opcode
1                                     unused
2     2                               request length
1     KEYCODE                         first-keycode
1     CARD8                           count
2                                     unused
*/
func ParseGetKeyboardMappingRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*GetKeyboardMappingRequest, error) {
	if len(requestBody) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: GetKeyboardMapping, Minor: 0})
	}
	req := &GetKeyboardMappingRequest{}
	req.FirstKeyCode = KeyCode(requestBody[0])
	req.Count = requestBody[1]
	return req, nil
}

type ChangeKeyboardMappingRequest struct {
	KeyCodeCount      byte
	FirstKeyCode      KeyCode
	KeySymsPerKeyCode byte
	KeySyms           []uint32
}

func (ChangeKeyboardMappingRequest) OpCode() ReqCode { return ChangeKeyboardMapping }

/*
ChangeKeyboardMapping

1     100                             opcode
1     CARD8                           keycode-count
2     2+n*m                           request length
1     KEYCODE                         first-keycode
1     CARD8                           keysyms-per-keycode
2                                     unused
4nm   LISTofKEYSYM                    keysyms
*/
func ParseChangeKeyboardMappingRequest(order binary.ByteOrder, data byte, requestBody []byte, seq uint16) (*ChangeKeyboardMappingRequest, error) {
	if len(requestBody) < 4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: ChangeKeyboardMapping, Minor: 0})
	}
	req := &ChangeKeyboardMappingRequest{}
	req.KeyCodeCount = data
	req.FirstKeyCode = KeyCode(requestBody[0])
	req.KeySymsPerKeyCode = requestBody[1]
	numKeySyms := int(req.KeyCodeCount) * int(req.KeySymsPerKeyCode)
	if len(requestBody) < 4+numKeySyms*4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: ChangeKeyboardMapping, Minor: 0})
	}
	for i := 0; i < numKeySyms; i++ {
		offset := 4 + i*4
		req.KeySyms = append(req.KeySyms, order.Uint32(requestBody[offset:offset+4]))
	}
	return req, nil
}

type ChangeKeyboardControlRequest struct {
	ValueMask uint32
	Values    KeyboardControl
}

func (ChangeKeyboardControlRequest) OpCode() ReqCode { return ChangeKeyboardControl }

/*
ChangeKeyboardControl

1     103                             opcode
1                                     unused
2     2+n                             request length
4     BITMASK                         value-mask
4n    LISTofVALUE                     value-list
*/
func ParseChangeKeyboardControlRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*ChangeKeyboardControlRequest, error) {
	if len(requestBody) < 4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: ChangeKeyboardControl, Minor: 0})
	}
	req := &ChangeKeyboardControlRequest{}
	req.ValueMask = order.Uint32(requestBody[0:4])
	values, _, err := ParseKeyboardControl(order, req.ValueMask, requestBody[4:], seq)
	if err != nil {
		return nil, err
	}
	req.Values = values
	return req, nil
}

type GetKeyboardControlRequest struct{}

func (GetKeyboardControlRequest) OpCode() ReqCode { return GetKeyboardControl }

/*
GetKeyboardControl

1     104                             opcode
1                                     unused
2     1                               request length
*/
func ParseGetKeyboardControlRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*GetKeyboardControlRequest, error) {
	return &GetKeyboardControlRequest{}, nil
}

type SetScreenSaverRequest struct {
	Timeout     int16
	Interval    int16
	PreferBlank byte
	AllowExpose byte
}

func (SetScreenSaverRequest) OpCode() ReqCode { return SetScreenSaver }

/*
SetScreenSaver

1     107                             opcode
1                                     unused
2     3                               request length
2     INT16                           timeout
2     INT16                           interval
1     { No, Yes, Default }            prefer-blanking
1     { No, Yes, Default }            allow-exposures
2                                     unused
*/
func ParseSetScreenSaverRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*SetScreenSaverRequest, error) {
	if len(requestBody) != 8 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: SetScreenSaver, Minor: 0})
	}
	req := &SetScreenSaverRequest{}
	req.Timeout = int16(order.Uint16(requestBody[0:2]))
	req.Interval = int16(order.Uint16(requestBody[2:4]))
	req.PreferBlank = requestBody[4]
	req.AllowExpose = requestBody[5]
	return req, nil
}

type GetScreenSaverRequest struct{}

func (GetScreenSaverRequest) OpCode() ReqCode { return GetScreenSaver }

/*
GetScreenSaver

1     108                             opcode
1                                     unused
2     1                               request length
*/
func ParseGetScreenSaverRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*GetScreenSaverRequest, error) {
	return &GetScreenSaverRequest{}, nil
}

type ChangeHostsRequest struct {
	Mode byte
	Host Host
}

func (ChangeHostsRequest) OpCode() ReqCode { return ChangeHosts }

/*
ChangeHosts

1     109                             opcode
1     { Insert, Delete }              mode
2     2+(n+p)/4                       request length
1     { Internet, DECnet, Chaos,      family

	ServerInterpreted,
	InternetV6 }

1                                     unused
2     CARD16                          n, length of address
n     LISTofBYTE                      address
p                                     padding
*/
func ParseChangeHostsRequest(order binary.ByteOrder, data byte, requestBody []byte, seq uint16) (*ChangeHostsRequest, error) {
	if len(requestBody) < 4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: ChangeHosts, Minor: 0})
	}
	req := &ChangeHostsRequest{}
	req.Mode = data
	family := requestBody[0]
	addressLen := order.Uint16(requestBody[2:4])
	if len(requestBody) < 4+int(addressLen) {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: ChangeHosts, Minor: 0})
	}
	req.Host = Host{
		Family: family,
		Data:   requestBody[4 : 4+addressLen],
	}
	return req, nil
}

type ListHostsRequest struct{}

func (ListHostsRequest) OpCode() ReqCode { return ListHosts }

/*
ListHosts

1     110                             opcode
1                                     unused
2     1                               request length
*/
func ParseListHostsRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*ListHostsRequest, error) {
	return &ListHostsRequest{}, nil
}

type SetAccessControlRequest struct {
	Mode byte
}

func (SetAccessControlRequest) OpCode() ReqCode { return SetAccessControl }

/*
SetAccessControl

1     111                             opcode
1     { Enable, Disable }             mode
2     1                               request length
*/
func ParseSetAccessControlRequest(order binary.ByteOrder, data byte, requestBody []byte, seq uint16) (*SetAccessControlRequest, error) {
	req := &SetAccessControlRequest{}
	req.Mode = data
	return req, nil
}

type SetCloseDownModeRequest struct {
	Mode byte
}

func (SetCloseDownModeRequest) OpCode() ReqCode { return SetCloseDownMode }

/*
SetCloseDownMode

1     112                             opcode
1     { Destroy, RetainPermanent,     mode

	RetainTemporary }

2     1                               request length
*/
func ParseSetCloseDownModeRequest(order binary.ByteOrder, data byte, requestBody []byte, seq uint16) (*SetCloseDownModeRequest, error) {
	req := &SetCloseDownModeRequest{}
	req.Mode = data
	return req, nil
}

type KillClientRequest struct {
	Resource uint32
}

func (KillClientRequest) OpCode() ReqCode { return KillClient }

/*
KillClient

1     113                             opcode
1                                     unused
2     2                               request length
4     CARD32                          resource
*/
func ParseKillClientRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*KillClientRequest, error) {
	if len(requestBody) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: KillClient, Minor: 0})
	}
	req := &KillClientRequest{}
	req.Resource = order.Uint32(requestBody[0:4])
	return req, nil
}

type RotatePropertiesRequest struct {
	Window Window
	Delta  int16
	Atoms  []Atom
}

func (RotatePropertiesRequest) OpCode() ReqCode { return RotateProperties }

/*
RotateProperties

1     114                             opcode
1                                     unused
2     3+n                             request length
4     WINDOW                          window
2     CARD16                          n
2     INT16                           delta
4n    LISTofATOM                      properties
*/
func ParseRotatePropertiesRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*RotatePropertiesRequest, error) {
	if len(requestBody) < 8 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: RotateProperties, Minor: 0})
	}
	req := &RotatePropertiesRequest{}
	req.Window = Window(order.Uint32(requestBody[0:4]))
	numAtoms := order.Uint16(requestBody[4:6])
	req.Delta = int16(order.Uint16(requestBody[6:8]))
	if len(requestBody) < 8+int(numAtoms)*4 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: RotateProperties, Minor: 0})
	}
	for i := 0; i < int(numAtoms); i++ {
		offset := 8 + i*4
		req.Atoms = append(req.Atoms, Atom(order.Uint32(requestBody[offset:offset+4])))
	}
	return req, nil
}

type ForceScreenSaverRequest struct {
	Mode byte
}

func (ForceScreenSaverRequest) OpCode() ReqCode { return ForceScreenSaver }

/*
ForceScreenSaver

1     115                             opcode
1     { Activate, Reset }             mode
2     1                               request length
*/
func ParseForceScreenSaverRequest(order binary.ByteOrder, data byte, requestBody []byte, seq uint16) (*ForceScreenSaverRequest, error) {
	req := &ForceScreenSaverRequest{}
	req.Mode = data
	return req, nil
}

type SetModifierMappingRequest struct {
	KeyCodesPerModifier byte
	KeyCodes            []KeyCode
}

func (r *SetModifierMappingRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(r.KeyCodesPerModifier)
	length := uint16(1 + len(r.KeyCodes)/4)
	binary.Write(buf, order, length)
	for _, kc := range r.KeyCodes {
		buf.WriteByte(byte(kc))
	}
	return buf.Bytes()
}

func (SetModifierMappingRequest) OpCode() ReqCode { return SetModifierMapping }

/*
SetModifierMapping

1     118                             opcode
1     CARD8                           keycodes-per-modifier
2     1+2n                            request length
8n    LISTofKEYCODE                   keycodes
*/
func ParseSetModifierMappingRequest(order binary.ByteOrder, data byte, requestBody []byte, seq uint16) (*SetModifierMappingRequest, error) {
	req := &SetModifierMappingRequest{}
	req.KeyCodesPerModifier = data
	req.KeyCodes = make([]KeyCode, 0, 8*int(req.KeyCodesPerModifier))
	if len(requestBody) != cap(req.KeyCodes) {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: SetModifierMapping, Minor: 0})
	}
	for i := 0; i < len(requestBody); i++ {
		req.KeyCodes = append(req.KeyCodes, KeyCode(requestBody[i]))
	}
	return req, nil
}

type GetModifierMappingRequest struct{}

func (r *GetModifierMappingRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(0)
	binary.Write(buf, order, uint16(1))
	return buf.Bytes()
}

func (GetModifierMappingRequest) OpCode() ReqCode { return GetModifierMapping }

/*
GetModifierMapping

1     119                             opcode
1                                     unused
2     1                               request length
*/
func ParseGetModifierMappingRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*GetModifierMappingRequest, error) {
	return &GetModifierMappingRequest{}, nil
}

func ParseKeyboardControl(order binary.ByteOrder, valueMask uint32, valuesData []byte, seq uint16) (KeyboardControl, int, error) {
	kc := KeyboardControl{}
	offset := 0
	if valueMask&KBKeyClickPercent != 0 {
		if len(valuesData) < offset+4 {
			return kc, 0, NewError(LengthErrorCode, seq, 0, Opcodes{Major: ChangeKeyboardControl, Minor: 0})
		}
		kc.KeyClickPercent = int32(order.Uint32(valuesData[offset : offset+4]))
		offset += 4
	}
	if valueMask&KBBellPercent != 0 {
		if len(valuesData) < offset+4 {
			return kc, 0, NewError(LengthErrorCode, seq, 0, Opcodes{Major: ChangeKeyboardControl, Minor: 0})
		}
		kc.BellPercent = int32(order.Uint32(valuesData[offset : offset+4]))
		offset += 4
	}
	if valueMask&KBBellPitch != 0 {
		if len(valuesData) < offset+4 {
			return kc, 0, NewError(LengthErrorCode, seq, 0, Opcodes{Major: ChangeKeyboardControl, Minor: 0})
		}
		kc.BellPitch = int32(order.Uint32(valuesData[offset : offset+4]))
		offset += 4
	}
	if valueMask&KBBellDuration != 0 {
		if len(valuesData) < offset+4 {
			return kc, 0, NewError(LengthErrorCode, seq, 0, Opcodes{Major: ChangeKeyboardControl, Minor: 0})
		}
		kc.BellDuration = int32(order.Uint32(valuesData[offset : offset+4]))
		offset += 4
	}
	if valueMask&KBLed != 0 {
		if len(valuesData) < offset+4 {
			return kc, 0, NewError(LengthErrorCode, seq, 0, Opcodes{Major: ChangeKeyboardControl, Minor: 0})
		}
		kc.Led = order.Uint32(valuesData[offset : offset+4])
		offset += 4
	}
	if valueMask&KBLedMode != 0 {
		if len(valuesData) < offset+4 {
			return kc, 0, NewError(LengthErrorCode, seq, 0, Opcodes{Major: ChangeKeyboardControl, Minor: 0})
		}
		kc.LedMode = order.Uint32(valuesData[offset : offset+4])
		offset += 4
	}
	if valueMask&KBKey != 0 {
		if len(valuesData) < offset+4 {
			return kc, 0, NewError(LengthErrorCode, seq, 0, Opcodes{Major: ChangeKeyboardControl, Minor: 0})
		}
		kc.Key = KeyCode(valuesData[offset])
		offset += 4
	}
	if valueMask&KBAutoRepeatMode != 0 {
		if len(valuesData) < offset+4 {
			return kc, 0, NewError(LengthErrorCode, seq, 0, Opcodes{Major: ChangeKeyboardControl, Minor: 0})
		}
		kc.AutoRepeatMode = order.Uint32(valuesData[offset : offset+4])
		offset += 4
	}
	return kc, offset, nil
}

type NoOperationRequest struct{}

func (NoOperationRequest) OpCode() ReqCode { return NoOperation }

/*
NoOperation

1     127                             opcode
1                                     unused
2     1                               request length
*/
func ParseNoOperationRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*NoOperationRequest, error) {
	return &NoOperationRequest{}, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func ParseGCValues(order binary.ByteOrder, valueMask uint32, valuesData []byte, seq uint16) (GC, int, error) {
	// http://www.x.org/releases/X11R7.6/doc/xproto/x11protocol.html#requests:CreateGC
	gc := GC{
		Function:          FunctionCopy,
		PlaneMask:         ^uint32(0),
		Foreground:        0,
		Background:        1,
		LineWidth:         0,
		LineStyle:         LineStyleSolid,
		CapStyle:          CapStyleButt,
		JoinStyle:         JoinStyleMiter,
		FillStyle:         FillStyleSolid,
		FillRule:          FillRuleEvenOdd,
		Tile:              0, // pixmap of unspecified size filled with foreground pixel
		Stipple:           0, // pixmap of unspecified size filled with ones
		TileStipXOrigin:   0,
		TileStipYOrigin:   0,
		Font:              0, // server-dependent
		SubwindowMode:     SubwindowModeClipByChildren,
		GraphicsExposures: 1, // true
		ClipXOrigin:       0,
		ClipYOrigin:       0,
		ClipMask:          0, // no clip mask
		DashOffset:        0,
		Dashes:            4,
		ArcMode:           ArcModePieSlice,
	}
	offset := 0
	if valueMask&GCFunction != 0 {
		if len(valuesData) < offset+4 {
			return gc, 0, NewError(LengthErrorCode, seq, 0, Opcodes{Major: CreateGC, Minor: 0})
		}
		gc.Function = order.Uint32(valuesData[offset : offset+4])
		offset += 4
	}
	if valueMask&GCPlaneMask != 0 {
		if len(valuesData) < offset+4 {
			return gc, 0, NewError(LengthErrorCode, seq, 0, Opcodes{Major: CreateGC, Minor: 0})
		}
		gc.PlaneMask = order.Uint32(valuesData[offset : offset+4])
		offset += 4
	}
	if valueMask&GCForeground != 0 {
		if len(valuesData) < offset+4 {
			return gc, 0, NewError(LengthErrorCode, seq, 0, Opcodes{Major: CreateGC, Minor: 0})
		}
		gc.Foreground = order.Uint32(valuesData[offset : offset+4])
		offset += 4
	}
	if valueMask&GCBackground != 0 {
		if len(valuesData) < offset+4 {
			return gc, 0, NewError(LengthErrorCode, seq, 0, Opcodes{Major: CreateGC, Minor: 0})
		}
		gc.Background = order.Uint32(valuesData[offset : offset+4])
		offset += 4
	}
	if valueMask&GCLineWidth != 0 {
		if len(valuesData) < offset+4 {
			return gc, 0, NewError(LengthErrorCode, seq, 0, Opcodes{Major: CreateGC, Minor: 0})
		}
		gc.LineWidth = order.Uint32(valuesData[offset : offset+4])
		offset += 4
	}
	if valueMask&GCLineStyle != 0 {
		if len(valuesData) < offset+4 {
			return gc, 0, NewError(LengthErrorCode, seq, 0, Opcodes{Major: CreateGC, Minor: 0})
		}
		gc.LineStyle = order.Uint32(valuesData[offset : offset+4])
		offset += 4
	}
	if valueMask&GCCapStyle != 0 {
		if len(valuesData) < offset+4 {
			return gc, 0, NewError(LengthErrorCode, seq, 0, Opcodes{Major: CreateGC, Minor: 0})
		}
		gc.CapStyle = order.Uint32(valuesData[offset : offset+4])
		offset += 4
	}
	if valueMask&GCJoinStyle != 0 {
		if len(valuesData) < offset+4 {
			return gc, 0, NewError(LengthErrorCode, seq, 0, Opcodes{Major: CreateGC, Minor: 0})
		}
		gc.JoinStyle = order.Uint32(valuesData[offset : offset+4])
		offset += 4
	}
	if valueMask&GCFillStyle != 0 {
		if len(valuesData) < offset+4 {
			return gc, 0, NewError(LengthErrorCode, seq, 0, Opcodes{Major: CreateGC, Minor: 0})
		}
		gc.FillStyle = order.Uint32(valuesData[offset : offset+4])
		offset += 4
	}
	if valueMask&GCFillRule != 0 {
		if len(valuesData) < offset+4 {
			return gc, 0, NewError(LengthErrorCode, seq, 0, Opcodes{Major: CreateGC, Minor: 0})
		}
		gc.FillRule = order.Uint32(valuesData[offset : offset+4])
		offset += 4
	}
	if valueMask&GCTile != 0 {
		if len(valuesData) < offset+4 {
			return gc, 0, NewError(LengthErrorCode, seq, 0, Opcodes{Major: CreateGC, Minor: 0})
		}
		gc.Tile = order.Uint32(valuesData[offset : offset+4])
		offset += 4
	}
	if valueMask&GCStipple != 0 {
		if len(valuesData) < offset+4 {
			return gc, 0, NewError(LengthErrorCode, seq, 0, Opcodes{Major: CreateGC, Minor: 0})
		}
		gc.Stipple = order.Uint32(valuesData[offset : offset+4])
		offset += 4
	}
	if valueMask&GCTileStipXOrigin != 0 {
		if len(valuesData) < offset+4 {
			return gc, 0, NewError(LengthErrorCode, seq, 0, Opcodes{Major: CreateGC, Minor: 0})
		}
		gc.TileStipXOrigin = order.Uint32(valuesData[offset : offset+4])
		offset += 4
	}
	if valueMask&GCTileStipYOrigin != 0 {
		if len(valuesData) < offset+4 {
			return gc, 0, NewError(LengthErrorCode, seq, 0, Opcodes{Major: CreateGC, Minor: 0})
		}
		gc.TileStipYOrigin = order.Uint32(valuesData[offset : offset+4])
		offset += 4
	}
	if valueMask&GCFont != 0 {
		if len(valuesData) < offset+4 {
			return gc, 0, NewError(LengthErrorCode, seq, 0, Opcodes{Major: CreateGC, Minor: 0})
		}
		gc.Font = order.Uint32(valuesData[offset : offset+4])
		offset += 4
	}
	if valueMask&GCSubwindowMode != 0 {
		if len(valuesData) < offset+4 {
			return gc, 0, NewError(LengthErrorCode, seq, 0, Opcodes{Major: CreateGC, Minor: 0})
		}
		gc.SubwindowMode = order.Uint32(valuesData[offset : offset+4])
		offset += 4
	}
	if valueMask&GCGraphicsExposures != 0 {
		if len(valuesData) < offset+4 {
			return gc, 0, NewError(LengthErrorCode, seq, 0, Opcodes{Major: CreateGC, Minor: 0})
		}
		gc.GraphicsExposures = order.Uint32(valuesData[offset : offset+4])
		offset += 4
	}
	if valueMask&GCClipXOrigin != 0 {
		if len(valuesData) < offset+4 {
			return gc, 0, NewError(LengthErrorCode, seq, 0, Opcodes{Major: CreateGC, Minor: 0})
		}
		gc.ClipXOrigin = int32(order.Uint32(valuesData[offset : offset+4]))
		offset += 4
	}
	if valueMask&GCClipYOrigin != 0 {
		if len(valuesData) < offset+4 {
			return gc, 0, NewError(LengthErrorCode, seq, 0, Opcodes{Major: CreateGC, Minor: 0})
		}
		gc.ClipYOrigin = int32(order.Uint32(valuesData[offset : offset+4]))
		offset += 4
	}
	if valueMask&GCClipMask != 0 {
		if len(valuesData) < offset+4 {
			return gc, 0, NewError(LengthErrorCode, seq, 0, Opcodes{Major: CreateGC, Minor: 0})
		}
		gc.ClipMask = order.Uint32(valuesData[offset : offset+4])
		offset += 4
	}
	if valueMask&GCDashOffset != 0 {
		if len(valuesData) < offset+4 {
			return gc, 0, NewError(LengthErrorCode, seq, 0, Opcodes{Major: CreateGC, Minor: 0})
		}
		gc.DashOffset = order.Uint32(valuesData[offset : offset+4])
		offset += 4
	}
	if valueMask&GCDashes != 0 {
		if len(valuesData) < offset+4 {
			return gc, 0, NewError(LengthErrorCode, seq, 0, Opcodes{Major: CreateGC, Minor: 0})
		}
		gc.Dashes = order.Uint32(valuesData[offset : offset+4])
		offset += 4
	}
	if valueMask&GCArcMode != 0 {
		if len(valuesData) < offset+4 {
			return gc, 0, NewError(LengthErrorCode, seq, 0, Opcodes{Major: CreateGC, Minor: 0})
		}
		gc.ArcMode = order.Uint32(valuesData[offset : offset+4])
		offset += 4
	}
	return gc, offset, nil
}

func ParseWindowAttributes(order binary.ByteOrder, valueMask uint32, valuesData []byte, seq uint16) (WindowAttributes, int, error) {
	wa := WindowAttributes{}
	offset := 0
	if valueMask&CWBackPixmap != 0 {
		if len(valuesData) < offset+4 {
			return wa, 0, NewError(LengthErrorCode, seq, 0, Opcodes{Major: CreateWindow, Minor: 0})
		}
		wa.BackgroundPixmap = Pixmap(order.Uint32(valuesData[offset : offset+4]))
		offset += 4
	}
	if valueMask&CWBackPixel != 0 {
		if len(valuesData) < offset+4 {
			return wa, 0, NewError(LengthErrorCode, seq, 0, Opcodes{Major: CreateWindow, Minor: 0})
		}
		wa.BackgroundPixel = order.Uint32(valuesData[offset : offset+4])
		wa.BackgroundPixelSet = true
		offset += 4
	}
	if valueMask&CWBorderPixmap != 0 {
		if len(valuesData) < offset+4 {
			return wa, 0, NewError(LengthErrorCode, seq, 0, Opcodes{Major: CreateWindow, Minor: 0})
		}
		wa.BorderPixmap = Pixmap(order.Uint32(valuesData[offset : offset+4]))
		offset += 4
	}
	if valueMask&CWBorderPixel != 0 {
		if len(valuesData) < offset+4 {
			return wa, 0, NewError(LengthErrorCode, seq, 0, Opcodes{Major: CreateWindow, Minor: 0})
		}
		wa.BorderPixel = order.Uint32(valuesData[offset : offset+4])
		offset += 4
	}
	if valueMask&CWBitGravity != 0 {
		if len(valuesData) < offset+4 {
			return wa, 0, NewError(LengthErrorCode, seq, 0, Opcodes{Major: CreateWindow, Minor: 0})
		}
		wa.BitGravity = order.Uint32(valuesData[offset : offset+4])
		offset += 4
	}
	if valueMask&CWWinGravity != 0 {
		if len(valuesData) < offset+4 {
			return wa, 0, NewError(LengthErrorCode, seq, 0, Opcodes{Major: CreateWindow, Minor: 0})
		}
		wa.WinGravity = order.Uint32(valuesData[offset : offset+4])
		offset += 4
	}
	if valueMask&CWBackingStore != 0 {
		if len(valuesData) < offset+4 {
			return wa, 0, NewError(LengthErrorCode, seq, 0, Opcodes{Major: CreateWindow, Minor: 0})
		}
		wa.BackingStore = order.Uint32(valuesData[offset : offset+4])
		offset += 4
	}
	if valueMask&CWBackingPlanes != 0 {
		if len(valuesData) < offset+4 {
			return wa, 0, NewError(LengthErrorCode, seq, 0, Opcodes{Major: CreateWindow, Minor: 0})
		}
		wa.BackingPlanes = order.Uint32(valuesData[offset : offset+4])
		offset += 4
	}
	if valueMask&CWBackingPixel != 0 {
		if len(valuesData) < offset+4 {
			return wa, 0, NewError(LengthErrorCode, seq, 0, Opcodes{Major: CreateWindow, Minor: 0})
		}
		wa.BackingPixel = order.Uint32(valuesData[offset : offset+4])
		offset += 4
	}
	if valueMask&CWOverrideRedirect != 0 {
		if len(valuesData) < offset+4 {
			return wa, 0, NewError(LengthErrorCode, seq, 0, Opcodes{Major: CreateWindow, Minor: 0})
		}
		wa.OverrideRedirect = order.Uint32(valuesData[offset:offset+4]) != 0
		offset += 4
	}
	if valueMask&CWSaveUnder != 0 {
		if len(valuesData) < offset+4 {
			return wa, 0, NewError(LengthErrorCode, seq, 0, Opcodes{Major: CreateWindow, Minor: 0})
		}
		wa.SaveUnder = order.Uint32(valuesData[offset:offset+4]) != 0
		offset += 4
	}
	if valueMask&CWEventMask != 0 {
		if len(valuesData) < offset+4 {
			return wa, 0, NewError(LengthErrorCode, seq, 0, Opcodes{Major: CreateWindow, Minor: 0})
		}
		wa.EventMask = order.Uint32(valuesData[offset : offset+4])
		offset += 4
	}
	if valueMask&CWDontPropagate != 0 {
		if len(valuesData) < offset+4 {
			return wa, 0, NewError(LengthErrorCode, seq, 0, Opcodes{Major: CreateWindow, Minor: 0})
		}
		wa.DontPropagateMask = order.Uint32(valuesData[offset : offset+4])
		offset += 4
	}
	if valueMask&CWColormap != 0 {
		if len(valuesData) < offset+4 {
			return wa, 0, NewError(LengthErrorCode, seq, 0, Opcodes{Major: CreateWindow, Minor: 0})
		}
		wa.Colormap = Colormap(order.Uint32(valuesData[offset : offset+4]))
		offset += 4
	}
	if valueMask&CWCursor != 0 {
		if len(valuesData) < offset+4 {
			return wa, 0, NewError(LengthErrorCode, seq, 0, Opcodes{Major: CreateWindow, Minor: 0})
		}
		wa.Cursor = Cursor(order.Uint32(valuesData[offset : offset+4]))
		offset += 4
	}
	return wa, offset, nil
}

// AllocColorCells: 86
type AllocColorCellsRequest struct {
	Contiguous bool
	Cmap       Colormap
	Colors     uint16
	Planes     uint16
}

func (r *AllocColorCellsRequest) OpCode() ReqCode { return AllocColorCells }

/*
AllocColorCells

	1     86                              opcode
	1     BOOL                            contiguous
	2     3                               request length
	4     COLORMAP                        cmap
	2     CARD16                          colors
	2     CARD16                          planes
*/
func ParseAllocColorCellsRequest(order binary.ByteOrder, data byte, body []byte, seq uint16) (*AllocColorCellsRequest, error) {
	if len(body) != 8 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: AllocColorCells, Minor: 0})
	}
	req := &AllocColorCellsRequest{}
	req.Contiguous = data != 0
	req.Cmap = Colormap(order.Uint32(body[0:4]))
	req.Colors = order.Uint16(body[4:6])
	req.Planes = order.Uint16(body[6:8])
	return req, nil
}

// AllocColorPlanes: 87
type AllocColorPlanesRequest struct {
	Contiguous bool
	Cmap       Colormap
	Colors     uint16
	Reds       uint16
	Greens     uint16
	Blues      uint16
}

func (r *AllocColorPlanesRequest) OpCode() ReqCode { return AllocColorPlanes }

/*
AllocColorPlanes

	1     87                              opcode
	1     BOOL                            contiguous
	2     4                               request length
	4     COLORMAP                        cmap
	2     CARD16                          colors
	2     CARD16                          reds
	2     CARD16                          greens
	2     CARD16                          blues
*/
func ParseAllocColorPlanesRequest(order binary.ByteOrder, data byte, body []byte, seq uint16) (*AllocColorPlanesRequest, error) {
	if len(body) != 12 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: AllocColorPlanes, Minor: 0})
	}
	req := &AllocColorPlanesRequest{}
	req.Contiguous = data != 0
	req.Cmap = Colormap(order.Uint32(body[0:4]))
	req.Colors = order.Uint16(body[4:6])
	req.Reds = order.Uint16(body[6:8])
	req.Greens = order.Uint16(body[8:10])
	req.Blues = order.Uint16(body[10:12])
	return req, nil
}

// ReqCodeCreateCursor:
type CreateCursorRequest struct {
	Cid       Cursor
	Source    Pixmap
	Mask      Pixmap
	ForeRed   uint16
	ForeGreen uint16
	ForeBlue  uint16
	BackRed   uint16
	BackGreen uint16
	BackBlue  uint16
	X         uint16
	Y         uint16
}

func (r *CreateCursorRequest) OpCode() ReqCode { return CreateCursor }

/*
CreateCursor

1     93                              opcode
1                                     unused
2     8                               request length
4     CURSOR                          cid
4     PIXMAP                          source
4     PIXMAP                          mask
2     CARD16                          fore-red
2     CARD16                          fore-green
2     CARD16                          fore-blue
2     CARD16                          back-red
2     CARD16                          back-green
2     CARD16                          back-blue
2     CARD16                          x
2     CARD16                          y
*/
func ParseCreateCursorRequest(order binary.ByteOrder, body []byte, seq uint16) (*CreateCursorRequest, error) {
	if len(body) != 28 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: CreateCursor, Minor: 0})
	}
	req := &CreateCursorRequest{}
	req.Cid = Cursor(order.Uint32(body[0:4]))
	req.Source = Pixmap(order.Uint32(body[4:8]))
	req.Mask = Pixmap(order.Uint32(body[8:12]))
	req.ForeRed = order.Uint16(body[12:14])
	req.ForeGreen = order.Uint16(body[14:16])
	req.ForeBlue = order.Uint16(body[16:18])
	req.BackRed = order.Uint16(body[18:20])
	req.BackGreen = order.Uint16(body[20:22])
	req.BackBlue = order.Uint16(body[22:24])
	req.X = order.Uint16(body[24:26])
	req.Y = order.Uint16(body[26:28])
	return req, nil
}

// ReqCodeCopyPlane:
type CopyPlaneRequest struct {
	SrcDrawable Drawable
	DstDrawable Drawable
	Gc          GContext
	SrcX        int16
	SrcY        int16
	DstX        int16
	DstY        int16
	Width       uint16
	Height      uint16
	PlaneMask   uint32
}

func (r *CopyPlaneRequest) OpCode() ReqCode { return CopyPlane }

/*
CopyPlane

1     63                              opcode
1                                     unused
2     8                               request length
4     DRAWABLE                        src-drawable
4     DRAWABLE                        dst-drawable
4     GCONTEXT                        gc
2     INT16                           src-x
2     INT16                           src-y
2     INT16                           dst-x
2     INT16                           dst-y
2     CARD16                          width
2     CARD16                          height
4     BITMASK                         bit-plane
*/
func ParseCopyPlaneRequest(order binary.ByteOrder, body []byte, seq uint16) (*CopyPlaneRequest, error) {
	if len(body) != 28 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: CopyPlane, Minor: 0})
	}
	req := &CopyPlaneRequest{}
	req.SrcDrawable = Drawable(order.Uint32(body[0:4]))
	req.DstDrawable = Drawable(order.Uint32(body[4:8]))
	req.Gc = GContext(order.Uint32(body[8:12]))
	req.SrcX = int16(order.Uint16(body[12:14]))
	req.SrcY = int16(order.Uint16(body[14:16]))
	req.DstX = int16(order.Uint16(body[16:18]))
	req.DstY = int16(order.Uint16(body[18:20]))
	req.Width = order.Uint16(body[20:22])
	req.Height = order.Uint16(body[22:24])
	req.PlaneMask = order.Uint32(body[24:28])
	return req, nil
}

// ReqCodeListExtensions:
type ListExtensionsRequest struct{}

func (r *ListExtensionsRequest) OpCode() ReqCode { return ListExtensions }

/*
ListExtensions

1     99                              opcode
1                                     unused
2     1                               request length
*/
func ParseListExtensionsRequest(order binary.ByteOrder, raw []byte, seq uint16) (*ListExtensionsRequest, error) {
	return &ListExtensionsRequest{}, nil
}

// ReqCodeChangePointerControl:
type ChangePointerControlRequest struct {
	AccelerationNumerator   int16
	AccelerationDenominator int16
	Threshold               int16
	DoAcceleration          bool
	DoThreshold             bool
}

func (r *ChangePointerControlRequest) OpCode() ReqCode { return ChangePointerControl }

/*
ChangePointerControl

1     105                             opcode
1                                     unused
2     3                               request length
2     INT16                           acceleration-numerator
2     INT16                           acceleration-denominator
2     INT16                           threshold
1     BOOL                            do-acceleration
1     BOOL                            do-threshold
*/
func ParseChangePointerControlRequest(order binary.ByteOrder, body []byte, seq uint16) (*ChangePointerControlRequest, error) {
	if len(body) != 8 {
		return nil, NewError(LengthErrorCode, seq, 0, Opcodes{Major: ChangePointerControl, Minor: 0})
	}
	req := &ChangePointerControlRequest{}
	req.AccelerationNumerator = int16(order.Uint16(body[0:2]))
	req.AccelerationDenominator = int16(order.Uint16(body[2:4]))
	req.Threshold = int16(order.Uint16(body[4:6]))
	req.DoAcceleration = body[6] != 0
	req.DoThreshold = body[7] != 0
	return req, nil
}

func (gc *GC) encode(order binary.ByteOrder, mask uint32) []byte {
	buf := new(bytes.Buffer)
	if mask&GCFunction != 0 {
		binary.Write(buf, order, gc.Function)
	}
	if mask&GCPlaneMask != 0 {
		binary.Write(buf, order, gc.PlaneMask)
	}
	if mask&GCForeground != 0 {
		binary.Write(buf, order, gc.Foreground)
	}
	if mask&GCBackground != 0 {
		binary.Write(buf, order, gc.Background)
	}
	if mask&GCLineWidth != 0 {
		binary.Write(buf, order, gc.LineWidth)
	}
	if mask&GCLineStyle != 0 {
		binary.Write(buf, order, gc.LineStyle)
	}
	if mask&GCCapStyle != 0 {
		binary.Write(buf, order, gc.CapStyle)
	}
	if mask&GCJoinStyle != 0 {
		binary.Write(buf, order, gc.JoinStyle)
	}
	if mask&GCFillStyle != 0 {
		binary.Write(buf, order, gc.FillStyle)
	}
	if mask&GCFillRule != 0 {
		binary.Write(buf, order, gc.FillRule)
	}
	if mask&GCTile != 0 {
		binary.Write(buf, order, gc.Tile)
	}
	if mask&GCStipple != 0 {
		binary.Write(buf, order, gc.Stipple)
	}
	if mask&GCTileStipXOrigin != 0 {
		binary.Write(buf, order, gc.TileStipXOrigin)
	}
	if mask&GCTileStipYOrigin != 0 {
		binary.Write(buf, order, gc.TileStipYOrigin)
	}
	if mask&GCFont != 0 {
		binary.Write(buf, order, gc.Font)
	}
	if mask&GCSubwindowMode != 0 {
		binary.Write(buf, order, gc.SubwindowMode)
	}
	if mask&GCGraphicsExposures != 0 {
		binary.Write(buf, order, gc.GraphicsExposures)
	}
	if mask&GCClipXOrigin != 0 {
		binary.Write(buf, order, int32(gc.ClipXOrigin))
	}
	if mask&GCClipYOrigin != 0 {
		binary.Write(buf, order, int32(gc.ClipYOrigin))
	}
	if mask&GCClipMask != 0 {
		binary.Write(buf, order, gc.ClipMask)
	}
	if mask&GCDashOffset != 0 {
		binary.Write(buf, order, gc.DashOffset)
	}
	if mask&GCDashes != 0 {
		binary.Write(buf, order, gc.Dashes)
	}
	if mask&GCArcMode != 0 {
		binary.Write(buf, order, gc.ArcMode)
	}
	return buf.Bytes()
}

func (r *CreateColormapRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(r.Alloc)
	binary.Write(buf, order, uint16(4))
	binary.Write(buf, order, r.Mid)
	binary.Write(buf, order, r.Window)
	binary.Write(buf, order, r.Visual)
	return buf.Bytes()
}

func (r *CreateGCRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(0)

	valuesBytes := r.Values.encode(order, r.ValueMask)
	length := uint16(4 + len(valuesBytes)/4)
	binary.Write(buf, order, length)
	binary.Write(buf, order, r.Cid)
	binary.Write(buf, order, r.Drawable)
	binary.Write(buf, order, r.ValueMask)
	buf.Write(valuesBytes)
	return buf.Bytes()
}

func (r *FreeColormapRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(0)
	binary.Write(buf, order, uint16(2))
	binary.Write(buf, order, r.Cmap)
	return buf.Bytes()
}

func (r *AllocNamedColorRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(0)
	n := len(r.Name)
	pad := PadLen(n)
	length := uint16(3 + (n+pad)/4)
	binary.Write(buf, order, length)
	binary.Write(buf, order, r.Cmap)
	binary.Write(buf, order, uint16(n))
	buf.Write([]byte{0, 0})
	buf.Write(r.Name)
	buf.Write(make([]byte, pad))
	return buf.Bytes()
}

func (r *AllocColorRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(0)
	binary.Write(buf, order, uint16(4))
	binary.Write(buf, order, r.Cmap)
	binary.Write(buf, order, r.Red)
	binary.Write(buf, order, r.Green)
	binary.Write(buf, order, r.Blue)
	buf.Write([]byte{0, 0})
	return buf.Bytes()
}

func (r *QueryColorsRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(0)
	n := len(r.Pixels)
	length := uint16(2 + n)
	binary.Write(buf, order, length)
	binary.Write(buf, order, r.Cmap)
	for _, p := range r.Pixels {
		binary.Write(buf, order, p)
	}
	return buf.Bytes()
}

func (r *InstallColormapRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(0)
	binary.Write(buf, order, uint16(2))
	binary.Write(buf, order, r.Cmap)
	return buf.Bytes()
}

func (r *ListInstalledColormapsRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(0)
	binary.Write(buf, order, uint16(2))
	binary.Write(buf, order, r.Window)
	return buf.Bytes()
}

func (r *FreeColorsRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(0)
	n := len(r.Pixels)
	length := uint16(3 + n)
	binary.Write(buf, order, length)
	binary.Write(buf, order, r.Cmap)
	binary.Write(buf, order, r.PlaneMask)
	for _, p := range r.Pixels {
		binary.Write(buf, order, p)
	}
	return buf.Bytes()
}

func (r *SetDashesRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(0)
	n := len(r.Dashes)
	pad := PadLen(n)
	length := uint16(3 + (n+pad)/4)
	binary.Write(buf, order, length)
	binary.Write(buf, order, r.GC)
	binary.Write(buf, order, r.DashOffset)
	binary.Write(buf, order, uint16(n))
	buf.Write(r.Dashes)
	buf.Write(make([]byte, pad))
	return buf.Bytes()
}

func (r *CreatePixmapRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(r.Depth)
	binary.Write(buf, order, uint16(4))
	binary.Write(buf, order, r.Pid)
	binary.Write(buf, order, r.Drawable)
	binary.Write(buf, order, r.Width)
	binary.Write(buf, order, r.Height)
	return buf.Bytes()
}

func (r *PutImageRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(r.Format)
	n := len(r.Data)
	pad := PadLen(n)
	length := uint16(6 + (n+pad)/4)
	binary.Write(buf, order, length)
	binary.Write(buf, order, r.Drawable)
	binary.Write(buf, order, r.Gc)
	binary.Write(buf, order, r.Width)
	binary.Write(buf, order, r.Height)
	binary.Write(buf, order, r.DstX)
	binary.Write(buf, order, r.DstY)
	buf.WriteByte(r.LeftPad)
	buf.WriteByte(r.Depth)
	buf.Write([]byte{0, 0})
	buf.Write(r.Data)
	buf.Write(make([]byte, pad))
	return buf.Bytes()
}

func (r *PolySegmentRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(0)
	n := len(r.Segments)
	length := uint16(3 + n/2)
	binary.Write(buf, order, length)
	binary.Write(buf, order, r.Drawable)
	binary.Write(buf, order, r.Gc)
	for _, c := range r.Segments {
		binary.Write(buf, order, uint16(c))
	}
	return buf.Bytes()
}

func (r *PolyRectangleRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(0)
	n := len(r.Rectangles)
	length := uint16(3 + n/2)
	binary.Write(buf, order, length)
	binary.Write(buf, order, r.Drawable)
	binary.Write(buf, order, r.Gc)
	for _, c := range r.Rectangles {
		binary.Write(buf, order, uint16(c))
	}
	return buf.Bytes()
}

func (r *PolyArcRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(0)
	n := len(r.Arcs)
	length := uint16(3 + n/2)
	binary.Write(buf, order, length)
	binary.Write(buf, order, r.Drawable)
	binary.Write(buf, order, r.Gc)
	for _, c := range r.Arcs {
		binary.Write(buf, order, uint16(c))
	}
	return buf.Bytes()
}

func (r *PolyFillRectangleRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(0)
	n := len(r.Rectangles)
	length := uint16(3 + n/2)
	binary.Write(buf, order, length)
	binary.Write(buf, order, r.Drawable)
	binary.Write(buf, order, r.Gc)
	for _, c := range r.Rectangles {
		binary.Write(buf, order, uint16(c))
	}
	return buf.Bytes()
}

func (r *PolyFillArcRequest) EncodeMessage(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, r.OpCode())
	buf.WriteByte(0)
	n := len(r.Arcs)
	length := uint16(3 + n/2)
	binary.Write(buf, order, length)
	binary.Write(buf, order, r.Drawable)
	binary.Write(buf, order, r.Gc)
	for _, c := range r.Arcs {
		binary.Write(buf, order, uint16(c))
	}
	return buf.Bytes()
}
