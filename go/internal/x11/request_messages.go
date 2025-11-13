//go:build x11

package x11

import (
	"encoding/binary"
	"errors"
	"fmt"
)

var (
	errParseError = errors.New("x11: request parsing error")
)

type request interface {
	OpCode() reqCode
}

func padLen(n int) int {
	return (4 - n%4) % 4
}

func parseRequest(order binary.ByteOrder, raw []byte, seq uint16) (request, error) {
	var reqHeader [4]byte
	if n := copy(reqHeader[:], raw); n != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, 0)
	}
	length := order.Uint16(reqHeader[2:4])
	opcode := reqCode(reqHeader[0])
	if int(4*length) != len(raw) {
		debugf("X11: parseRequest(%x...) length=%d, %d != %d", reqHeader, length, 4*length, len(raw))
		return nil, NewError(LengthErrorCode, seq, 0, 0, opcode)
	}

	data := reqHeader[1]
	body := raw[4:]

	switch opcode {
	case CreateWindow:
		return parseCreateWindowRequest(order, data, body, seq)

	case ChangeWindowAttributes:
		return parseChangeWindowAttributesRequest(order, body, seq)

	case GetWindowAttributes:
		return parseGetWindowAttributesRequest(order, body, seq)

	case DestroyWindow:
		return parseDestroyWindowRequest(order, body, seq)

	case DestroySubwindows:
		return parseDestroySubwindowsRequest(order, body, seq)

	case ChangeSaveSet:
		return parseChangeSaveSetRequest(order, data, body, seq)

	case ReparentWindow:
		return parseReparentWindowRequest(order, body, seq)

	case MapWindow:
		return parseMapWindowRequest(order, body, seq)

	case MapSubwindows:
		return parseMapSubwindowsRequest(order, body, seq)

	case UnmapWindow:
		return parseUnmapWindowRequest(order, body, seq)

	case UnmapSubwindows:
		return parseUnmapSubwindowsRequest(order, body, seq)

	case ConfigureWindow:
		return parseConfigureWindowRequest(order, body, seq)

	case CirculateWindow:
		return parseCirculateWindowRequest(order, data, body, seq)

	case GetGeometry:
		return parseGetGeometryRequest(order, body, seq)

	case QueryTree:
		return parseQueryTreeRequest(order, body, seq)

	case InternAtom:
		return parseInternAtomRequest(order, data, body, seq)

	case GetAtomName:
		return parseGetAtomNameRequest(order, body, seq)

	case ChangeProperty:
		return parseChangePropertyRequest(order, body, seq)

	case DeleteProperty:
		return parseDeletePropertyRequest(order, body, seq)

	case GetProperty:
		return parseGetPropertyRequest(order, body, seq)

	case ListProperties:
		return parseListPropertiesRequest(order, body, seq)

	case SetSelectionOwner:
		return parseSetSelectionOwnerRequest(order, body, seq)

	case GetSelectionOwner:
		return parseGetSelectionOwnerRequest(order, body, seq)

	case ConvertSelection:
		return parseConvertSelectionRequest(order, body, seq)

	case SendEvent:
		return parseSendEventRequest(order, body, seq)

	case GrabPointer:
		return parseGrabPointerRequest(order, body, seq)

	case UngrabPointer:
		return parseUngrabPointerRequest(order, body, seq)

	case GrabButton:
		return parseGrabButtonRequest(order, data, body, seq)

	case UngrabButton:
		return parseUngrabButtonRequest(order, data, body, seq)

	case ChangeActivePointerGrab:
		return parseChangeActivePointerGrabRequest(order, body, seq)

	case GrabKeyboard:
		return parseGrabKeyboardRequest(order, body, seq)

	case UngrabKeyboard:
		return parseUngrabKeyboardRequest(order, body, seq)

	case GrabKey:
		return parseGrabKeyRequest(order, data, body, seq)

	case UngrabKey:
		return parseUngrabKeyRequest(order, body, seq)

	case AllowEvents:
		return parseAllowEventsRequest(order, data, body, seq)

	case GrabServer:
		return parseGrabServerRequest(order, body, seq)

	case UngrabServer:
		return parseUngrabServerRequest(order, body, seq)

	case QueryPointer:
		return parseQueryPointerRequest(order, body, seq)

	case GetMotionEvents:
		return parseGetMotionEventsRequest(order, body, seq)

	case TranslateCoords:
		return parseTranslateCoordsRequest(order, body, seq)

	case WarpPointer:
		return parseWarpPointerRequest(order, body, seq)

	case SetInputFocus:
		return parseSetInputFocusRequest(order, body, seq)

	case GetInputFocus:
		return parseGetInputFocusRequest(order, body, seq)

	case QueryKeymap:
		return parseQueryKeymapRequest(order, body, seq)

	case OpenFont:
		return parseOpenFontRequest(order, body, seq)

	case CloseFont:
		return parseCloseFontRequest(order, body, seq)

	case QueryFont:
		return parseQueryFontRequest(order, body, seq)

	case QueryTextExtents:
		return parseQueryTextExtentsRequest(order, data, body, seq)

	case ListFonts:
		return parseListFontsRequest(order, body, seq)

	case ListFontsWithInfo:
		return parseListFontsWithInfoRequest(order, body, seq)

	case SetFontPath:
		return parseSetFontPathRequest(order, body, seq)

	case GetFontPath:
		return parseGetFontPathRequest(order, body, seq)

	case CreatePixmap:
		return parseCreatePixmapRequest(order, data, body, seq)

	case FreePixmap:
		return parseFreePixmapRequest(order, body, seq)

	case CreateGC:
		return parseCreateGCRequest(order, body, seq)

	case ChangeGC:
		return parseChangeGCRequest(order, body, seq)

	case CopyGC:
		return parseCopyGCRequest(order, body, seq)

	case SetDashes:
		return parseSetDashesRequest(order, body, seq)

	case SetClipRectangles:
		return parseSetClipRectanglesRequest(order, data, body, seq)

	case FreeGC:
		return parseFreeGCRequest(order, body, seq)

	case ClearArea:
		return parseClearAreaRequest(order, body, seq)

	case CopyArea:
		return parseCopyAreaRequest(order, body, seq)

	case PolyPoint:
		return parsePolyPointRequest(order, body, seq)

	case PolyLine:
		return parsePolyLineRequest(order, body, seq)

	case PolySegment:
		return parsePolySegmentRequest(order, body, seq)

	case PolyRectangle:
		return parsePolyRectangleRequest(order, body, seq)

	case PolyArc:
		return parsePolyArcRequest(order, body, seq)

	case FillPoly:
		return parseFillPolyRequest(order, body, seq)

	case PolyFillRectangle:
		return parsePolyFillRectangleRequest(order, body, seq)

	case PolyFillArc:
		return parsePolyFillArcRequest(order, body, seq)

	case PutImage:
		return parsePutImageRequest(order, data, body, seq)

	case GetImage:
		return parseGetImageRequest(order, data, body, seq)

	case PolyText8:
		return parsePolyText8Request(order, body, seq)

	case PolyText16:
		return parsePolyText16Request(order, body, seq)

	case ImageText8:
		return parseImageText8Request(order, data, body, seq)

	case ImageText16:
		return parseImageText16Request(order, data, body, seq)

	case CreateColormap:
		return parseCreateColormapRequest(order, data, body, seq)

	case FreeColormap:
		return parseFreeColormapRequest(order, body, seq)

	case InstallColormap:
		return parseInstallColormapRequest(order, body, seq)

	case UninstallColormap:
		return parseUninstallColormapRequest(order, body, seq)

	case ListInstalledColormaps:
		return parseListInstalledColormapsRequest(order, body, seq)

	case AllocColor:
		return parseAllocColorRequest(order, body, seq)

	case AllocNamedColor:
		return parseAllocNamedColorRequest(order, body, seq)

	case FreeColors:
		return parseFreeColorsRequest(order, body, seq)

	case StoreColors:
		return parseStoreColorsRequest(order, body, seq)

	case StoreNamedColor:
		return parseStoreNamedColorRequest(order, data, body, seq)

	case QueryColors:
		return parseQueryColorsRequest(order, body, seq)

	case LookupColor:
		return parseLookupColorRequest(order, body, seq)

	case CreateGlyphCursor:
		return parseCreateGlyphCursorRequest(order, body, seq)

	case FreeCursor:
		return parseFreeCursorRequest(order, body, seq)

	case RecolorCursor:
		return parseRecolorCursorRequest(order, body, seq)

	case QueryBestSize:
		return parseQueryBestSizeRequest(order, body, seq)

	case QueryExtension:
		return parseQueryExtensionRequest(order, body, seq)

	case Bell:
		if len(body) != 0 {
			return nil, NewError(LengthErrorCode, seq, 0, 0, Bell)
		}
		return parseBellRequest(data, seq)

	case SetPointerMapping:
		return parseSetPointerMappingRequest(order, body, seq)

	case GetPointerMapping:
		return parseGetPointerMappingRequest(order, body, seq)

	case GetKeyboardMapping:
		return parseGetKeyboardMappingRequest(order, body, seq)

	case ChangeKeyboardMapping:
		return parseChangeKeyboardMappingRequest(order, data, body, seq)

	case ChangeKeyboardControl:
		return parseChangeKeyboardControlRequest(order, body, seq)

	case GetKeyboardControl:
		return parseGetKeyboardControlRequest(order, body, seq)

	case SetScreenSaver:
		return parseSetScreenSaverRequest(order, body, seq)

	case GetScreenSaver:
		return parseGetScreenSaverRequest(order, body, seq)

	case ChangeHosts:
		return parseChangeHostsRequest(order, data, body, seq)

	case ListHosts:
		return parseListHostsRequest(order, body, seq)

	case SetAccessControl:
		return parseSetAccessControlRequest(order, data, body, seq)

	case SetCloseDownMode:
		return parseSetCloseDownModeRequest(order, data, body, seq)

	case KillClient:
		return parseKillClientRequest(order, body, seq)

	case RotateProperties:
		return parseRotatePropertiesRequest(order, body, seq)

	case ForceScreenSaver:
		return parseForceScreenSaverRequest(order, data, body, seq)

	case SetModifierMapping:
		return parseSetModifierMappingRequest(order, data, body, seq)

	case GetModifierMapping:
		return parseGetModifierMappingRequest(order, body, seq)

	case NoOperation:
		return parseNoOperationRequest(order, body, seq)

	case AllocColorCells:
		return parseAllocColorCellsRequest(order, data, body, seq)

	case AllocColorPlanes:
		return parseAllocColorPlanesRequest(order, data, body, seq)

	case CreateCursor:
		return parseCreateCursorRequest(order, body, seq)

	case CopyPlane:
		return parseCopyPlaneRequest(order, body, seq)

	case ListExtensions:
		return parseListExtensionsRequest(order, raw, seq)

	case ChangePointerControl:
		return parseChangePointerControlRequest(order, body, seq)

	case GetPointerControl:
		return parseGetPointerControlRequest(order, raw, seq)

	default:
		return nil, fmt.Errorf("x11: unhandled opcode %d", opcode)
	}
}

// auxiliary data structures

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

// PolyTextItem is an interface for items in a PolyText request.
type PolyTextItem interface {
	isPolyTextItem()
}

// PolyText8String represents a string in a PolyText8 request.
type PolyText8String struct {
	Delta int8
	Str   []byte
}

func (PolyText8String) isPolyTextItem() {}

// PolyText16String represents a string in a PolyText16 request.
type PolyText16String struct {
	Delta int8
	Str   []uint16
}

func (PolyText16String) isPolyTextItem() {}

// PolyTextFont represents a font change in a PolyText request.
type PolyTextFont struct {
	Font Font
}

func (PolyTextFont) isPolyTextItem() {}

// request messages

/*
CreateWindow

1     1                               opcode
1     DEPTH                           depth
2     8+n                             request length
4     WINDOW                          wid
4     WINDOW                          parent
2     INT16                           x
2     INT16                           y
2     CARD16                          width
2     CARD16                          height
2     CARD16                          border-width
2     { InputOutput, InputOnly,       class

	CopyFromParent }

4     VISUALID                        visual
4     BITMASK                         value-mask
4n    LISTofVALUE                     value-list
*/
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

func (CreateWindowRequest) OpCode() reqCode { return CreateWindow }

func parseCreateWindowRequest(order binary.ByteOrder, data byte, requestBody []byte, seq uint16) (*CreateWindowRequest, error) {
	if len(requestBody) < 28 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, CreateWindow)
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
	values, bytesRead, err := parseWindowAttributes(order, req.ValueMask, requestBody[28:], seq)
	if err != nil {
		return nil, err
	}
	if len(requestBody) != 28+bytesRead {
		return nil, NewError(LengthErrorCode, seq, 0, 0, CreateWindow)
	}
	req.Values = values
	return req, nil
}

/*
ChangeWindowAttributes

1     2                               opcode
1                                     unused
2     3+n                             request length
4     WINDOW                          window
4     BITMASK                         value-mask
4n    LISTofVALUE                     value-list
*/
type ChangeWindowAttributesRequest struct {
	Window    Window
	ValueMask uint32
	Values    WindowAttributes
}

func (ChangeWindowAttributesRequest) OpCode() reqCode { return ChangeWindowAttributes }

func parseChangeWindowAttributesRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*ChangeWindowAttributesRequest, error) {
	if len(requestBody) < 8 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, ChangeWindowAttributes)
	}
	req := &ChangeWindowAttributesRequest{}
	req.Window = Window(order.Uint32(requestBody[0:4]))
	req.ValueMask = order.Uint32(requestBody[4:8])
	values, bytesRead, err := parseWindowAttributes(order, req.ValueMask, requestBody[8:], seq)
	if err != nil {
		return nil, err
	}
	if len(requestBody) != 8+bytesRead {
		return nil, NewError(LengthErrorCode, seq, 0, 0, ChangeWindowAttributes)
	}
	req.Values = values
	return req, nil
}

type GetWindowAttributesRequest struct {
	Window Window
}

func (GetWindowAttributesRequest) OpCode() reqCode { return GetWindowAttributes }

/*
GetWindowAttributes

1     3                               opcode
1                                     unused
2     2                               request length
4     WINDOW                          window
*/
func parseGetWindowAttributesRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*GetWindowAttributesRequest, error) {
	if len(requestBody) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, GetWindowAttributes)
	}
	req := &GetWindowAttributesRequest{}
	req.Window = Window(order.Uint32(requestBody[0:4]))
	return req, nil
}

type DestroyWindowRequest struct {
	Window Window
}

func (DestroyWindowRequest) OpCode() reqCode { return DestroyWindow }

/*
DestroyWindow

1     4                               opcode
1                                     unused
2     2                               request length
4     WINDOW                          window
*/
func parseDestroyWindowRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*DestroyWindowRequest, error) {
	if len(requestBody) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, DestroyWindow)
	}
	req := &DestroyWindowRequest{}
	req.Window = Window(order.Uint32(requestBody[0:4]))
	return req, nil
}

type DestroySubwindowsRequest struct {
	Window Window
}

func (DestroySubwindowsRequest) OpCode() reqCode { return DestroySubwindows }

/*
DestroySubwindows

1     5                               opcode
1                                     unused
2     2                               request length
4     WINDOW                          window
*/
func parseDestroySubwindowsRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*DestroySubwindowsRequest, error) {
	if len(requestBody) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, DestroySubwindows)
	}
	req := &DestroySubwindowsRequest{}
	req.Window = Window(order.Uint32(requestBody[0:4]))
	return req, nil
}

type ChangeSaveSetRequest struct {
	Window Window
	Mode   byte
}

func (ChangeSaveSetRequest) OpCode() reqCode { return ChangeSaveSet }

/*
ChangeSaveSet

1     6                               opcode
1     { Insert, Delete }              mode
2     2                               request length
4     WINDOW                          window
*/
func parseChangeSaveSetRequest(order binary.ByteOrder, data byte, requestBody []byte, seq uint16) (*ChangeSaveSetRequest, error) {
	if len(requestBody) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, ChangeSaveSet)
	}
	req := &ChangeSaveSetRequest{}
	req.Window = Window(order.Uint32(requestBody[0:4]))
	req.Mode = data
	return req, nil
}

type ReparentWindowRequest struct {
	Window Window
	Parent Window
	X      int16
	Y      int16
}

func (ReparentWindowRequest) OpCode() reqCode { return ReparentWindow }

/*
ReparentWindow

1     7                               opcode
1                                     unused
2     4                               request length
4     WINDOW                          window
4     WINDOW                          parent
2     INT16                           x
2     INT16                           y
*/
func parseReparentWindowRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*ReparentWindowRequest, error) {
	if len(requestBody) != 12 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, ReparentWindow)
	}
	req := &ReparentWindowRequest{}
	req.Window = Window(order.Uint32(requestBody[0:4]))
	req.Parent = Window(order.Uint32(requestBody[4:8]))
	req.X = int16(order.Uint16(requestBody[8:10]))
	req.Y = int16(order.Uint16(requestBody[10:12]))
	return req, nil
}

type MapWindowRequest struct {
	Window Window
}

func (MapWindowRequest) OpCode() reqCode { return MapWindow }

/*
MapWindow

1     8                               opcode
1                                     unused
2     2                               request length
4     WINDOW                          window
*/
func parseMapWindowRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*MapWindowRequest, error) {
	if len(requestBody) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, MapWindow)
	}
	req := &MapWindowRequest{}
	req.Window = Window(order.Uint32(requestBody[0:4]))
	return req, nil
}

type MapSubwindowsRequest struct {
	Window Window
}

func (MapSubwindowsRequest) OpCode() reqCode { return MapSubwindows }

/*
MapSubwindows

1     9                               opcode
1                                     unused
2     2                               request length
4     WINDOW                          window
*/
func parseMapSubwindowsRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*MapSubwindowsRequest, error) {
	if len(requestBody) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, MapSubwindows)
	}
	req := &MapSubwindowsRequest{}
	req.Window = Window(order.Uint32(requestBody[0:4]))
	return req, nil
}

type UnmapWindowRequest struct {
	Window Window
}

func (UnmapWindowRequest) OpCode() reqCode { return UnmapWindow }

/*
UnmapWindow

1     10                              opcode
1                                     unused
2     2                               request length
4     WINDOW                          window
*/
func parseUnmapWindowRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*UnmapWindowRequest, error) {
	if len(requestBody) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, UnmapWindow)
	}
	req := &UnmapWindowRequest{}
	req.Window = Window(order.Uint32(requestBody[0:4]))
	return req, nil
}

type UnmapSubwindowsRequest struct {
	Window Window
}

func (UnmapSubwindowsRequest) OpCode() reqCode { return UnmapSubwindows }

/*
UnmapSubwindows

1     11                              opcode
1                                     unused
2     2                               request length
4     WINDOW                          window
*/
func parseUnmapSubwindowsRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*UnmapSubwindowsRequest, error) {
	if len(requestBody) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, UnmapSubwindows)
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

func (ConfigureWindowRequest) OpCode() reqCode { return ConfigureWindow }

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
func parseConfigureWindowRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*ConfigureWindowRequest, error) {
	if len(requestBody) < 8 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, ConfigureWindow)
	}
	req := &ConfigureWindowRequest{}
	req.Window = Window(order.Uint32(requestBody[0:4]))
	req.ValueMask = order.Uint16(requestBody[4:6])
	// TODO: This doesn't use the value-mask to determine how many values to read.
	// It just reads to the end of the packet.
	numValues := 0
	for i := 0; i < 16; i++ {
		if (req.ValueMask & (1 << i)) != 0 {
			numValues++
		}
	}
	if len(requestBody) != 8+numValues*4 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, ConfigureWindow)
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

func (CirculateWindowRequest) OpCode() reqCode { return CirculateWindow }

func parseCirculateWindowRequest(order binary.ByteOrder, data byte, requestBody []byte, seq uint16) (*CirculateWindowRequest, error) {
	if len(requestBody) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, CirculateWindow)
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

func (GetGeometryRequest) OpCode() reqCode { return GetGeometry }

func parseGetGeometryRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*GetGeometryRequest, error) {
	if len(requestBody) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, GetGeometry)
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

func (QueryTreeRequest) OpCode() reqCode { return QueryTree }

func parseQueryTreeRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*QueryTreeRequest, error) {
	if len(requestBody) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, QueryTree)
	}
	req := &QueryTreeRequest{}
	req.Window = Window(order.Uint32(requestBody[0:4]))
	return req, nil
}

type InternAtomRequest struct {
	Name         string
	OnlyIfExists bool
}

func (InternAtomRequest) OpCode() reqCode { return InternAtom }

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
func parseInternAtomRequest(order binary.ByteOrder, data byte, requestBody []byte, seq uint16) (*InternAtomRequest, error) {
	if len(requestBody) < 4 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, InternAtom)
	}
	req := &InternAtomRequest{}
	req.OnlyIfExists = data != 0
	nameLen := order.Uint16(requestBody[0:2])
	paddedLen := 4 + int(nameLen) + padLen(int(nameLen))
	if len(requestBody) != paddedLen {
		return nil, NewError(LengthErrorCode, seq, 0, 0, InternAtom)
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

func (GetAtomNameRequest) OpCode() reqCode { return GetAtomName }

func parseGetAtomNameRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*GetAtomNameRequest, error) {
	if len(requestBody) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, GetAtomName)
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

func (ChangePropertyRequest) OpCode() reqCode { return ChangeProperty }

func parseChangePropertyRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*ChangePropertyRequest, error) {
	if len(requestBody) < 20 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, ChangeProperty)
	}
	req := &ChangePropertyRequest{}
	req.Window = Window(order.Uint32(requestBody[0:4]))
	req.Property = Atom(order.Uint32(requestBody[4:8]))
	req.Type = Atom(order.Uint32(requestBody[8:12]))
	req.Format = requestBody[12]
	dataLen := order.Uint32(requestBody[16:20])
	if len(requestBody) < 20+int(dataLen) {
		return nil, NewError(LengthErrorCode, seq, 0, 0, ChangeProperty)
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

func (DeletePropertyRequest) OpCode() reqCode { return DeleteProperty }

func parseDeletePropertyRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*DeletePropertyRequest, error) {
	if len(requestBody) != 8 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, DeleteProperty)
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

func (GetPropertyRequest) OpCode() reqCode { return GetProperty }

func parseGetPropertyRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*GetPropertyRequest, error) {
	if len(requestBody) != 20 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, GetProperty)
	}
	req := &GetPropertyRequest{}
	req.Window = Window(order.Uint32(requestBody[0:4]))
	req.Property = Atom(order.Uint32(requestBody[4:8]))
	req.Delete = requestBody[8] != 0
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

func (ListPropertiesRequest) OpCode() reqCode { return ListProperties }

func parseListPropertiesRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*ListPropertiesRequest, error) {
	if len(requestBody) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, ListProperties)
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

func (SetSelectionOwnerRequest) OpCode() reqCode { return SetSelectionOwner }

func parseSetSelectionOwnerRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*SetSelectionOwnerRequest, error) {
	if len(requestBody) != 12 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, SetSelectionOwner)
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

func (GetSelectionOwnerRequest) OpCode() reqCode { return GetSelectionOwner }

func parseGetSelectionOwnerRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*GetSelectionOwnerRequest, error) {
	if len(requestBody) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, GetSelectionOwner)
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

func (ConvertSelectionRequest) OpCode() reqCode { return ConvertSelection }

func parseConvertSelectionRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*ConvertSelectionRequest, error) {
	if len(requestBody) != 20 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, ConvertSelection)
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

func (SendEventRequest) OpCode() reqCode { return SendEvent }

func parseSendEventRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*SendEventRequest, error) {
	if len(requestBody) != 44 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, SendEvent)
	}
	req := &SendEventRequest{}
	req.Destination = Window(order.Uint32(requestBody[4:8]))
	req.EventMask = order.Uint32(requestBody[8:12])
	req.EventData = requestBody[12:44]
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

func (GrabPointerRequest) OpCode() reqCode { return GrabPointer }

func parseGrabPointerRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*GrabPointerRequest, error) {
	if len(requestBody) != 20 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, GrabPointer)
	}
	req := &GrabPointerRequest{}
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

func (UngrabPointerRequest) OpCode() reqCode { return UngrabPointer }

func parseUngrabPointerRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*UngrabPointerRequest, error) {
	if len(requestBody) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, UngrabPointer)
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

func (GrabButtonRequest) OpCode() reqCode { return GrabButton }

func parseGrabButtonRequest(order binary.ByteOrder, data byte, requestBody []byte, seq uint16) (*GrabButtonRequest, error) {
	if len(requestBody) != 20 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, GrabButton)
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

func (UngrabButtonRequest) OpCode() reqCode { return UngrabButton }

func parseUngrabButtonRequest(order binary.ByteOrder, data byte, requestBody []byte, seq uint16) (*UngrabButtonRequest, error) {
	if len(requestBody) != 8 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, UngrabButton)
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

func (ChangeActivePointerGrabRequest) OpCode() reqCode { return ChangeActivePointerGrab }

func parseChangeActivePointerGrabRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*ChangeActivePointerGrabRequest, error) {
	if len(requestBody) != 12 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, ChangeActivePointerGrab)
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

func (GrabKeyboardRequest) OpCode() reqCode { return GrabKeyboard }

func parseGrabKeyboardRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*GrabKeyboardRequest, error) {
	if len(requestBody) != 12 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, GrabKeyboard)
	}
	req := &GrabKeyboardRequest{}
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

func (UngrabKeyboardRequest) OpCode() reqCode { return UngrabKeyboard }

func parseUngrabKeyboardRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*UngrabKeyboardRequest, error) {
	if len(requestBody) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, UngrabKeyboard)
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

func (GrabKeyRequest) OpCode() reqCode { return GrabKey }

func parseGrabKeyRequest(order binary.ByteOrder, data byte, requestBody []byte, seq uint16) (*GrabKeyRequest, error) {
	if len(requestBody) != 12 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, GrabKey)
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

func (UngrabKeyRequest) OpCode() reqCode { return UngrabKey }

func parseUngrabKeyRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*UngrabKeyRequest, error) {
	if len(requestBody) != 8 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, UngrabKey)
	}
	req := &UngrabKeyRequest{}
	req.GrabWindow = Window(order.Uint32(requestBody[0:4]))
	req.Modifiers = order.Uint16(requestBody[4:6])
	req.Key = KeyCode(requestBody[6])
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

func (AllowEventsRequest) OpCode() reqCode { return AllowEvents }

func parseAllowEventsRequest(order binary.ByteOrder, data byte, requestBody []byte, seq uint16) (*AllowEventsRequest, error) {
	if len(requestBody) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, AllowEvents)
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

func (GrabServerRequest) OpCode() reqCode { return GrabServer }

func parseGrabServerRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*GrabServerRequest, error) {
	return &GrabServerRequest{}, nil
}

/*
UngrabServer

1     37                              opcode
1                                     unused
2     1                               request length
*/
type UngrabServerRequest struct{}

func (UngrabServerRequest) OpCode() reqCode { return UngrabServer }

func parseUngrabServerRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*UngrabServerRequest, error) {
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

func (QueryPointerRequest) OpCode() reqCode { return QueryPointer }

func parseQueryPointerRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*QueryPointerRequest, error) {
	if len(requestBody) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, QueryPointer)
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

func (GetMotionEventsRequest) OpCode() reqCode { return GetMotionEvents }

func parseGetMotionEventsRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*GetMotionEventsRequest, error) {
	if len(requestBody) != 12 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, GetMotionEvents)
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

func (TranslateCoordsRequest) OpCode() reqCode { return TranslateCoords }

func parseTranslateCoordsRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*TranslateCoordsRequest, error) {
	if len(requestBody) != 12 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, TranslateCoords)
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

func (WarpPointerRequest) OpCode() reqCode { return WarpPointer }

func parseWarpPointerRequest(order binary.ByteOrder, payload []byte, seq uint16) (*WarpPointerRequest, error) {
	if len(payload) != 20 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, WarpPointer)
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

func (SetInputFocusRequest) OpCode() reqCode { return SetInputFocus }

func parseSetInputFocusRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*SetInputFocusRequest, error) {
	if len(requestBody) != 12 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, SetInputFocus)
	}
	req := &SetInputFocusRequest{}
	req.Focus = Window(order.Uint32(requestBody[0:4]))
	req.RevertTo = requestBody[4]
	req.Time = Timestamp(order.Uint32(requestBody[8:12]))
	return req, nil
}

/*
GetInputFocus

1     43                              opcode
1                                     unused
2     1                               request length
*/
type GetInputFocusRequest struct{}

func (GetInputFocusRequest) OpCode() reqCode { return GetInputFocus }

func parseGetInputFocusRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*GetInputFocusRequest, error) {
	return &GetInputFocusRequest{}, nil
}

/*
QueryKeymap

1     44                              opcode
1                                     unused
2     1                               request length
*/
type QueryKeymapRequest struct{}

func (QueryKeymapRequest) OpCode() reqCode { return QueryKeymap }

func parseQueryKeymapRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*QueryKeymapRequest, error) {
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

func (OpenFontRequest) OpCode() reqCode { return OpenFont }

func parseOpenFontRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*OpenFontRequest, error) {
	if len(requestBody) < 8 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, OpenFont)
	}
	req := &OpenFontRequest{}
	req.Fid = Font(order.Uint32(requestBody[0:4]))
	nameLen := int(order.Uint16(requestBody[4:6]))
	paddedLen := 8 + nameLen + padLen(8+nameLen)
	if len(requestBody) != paddedLen {
		return nil, NewError(LengthErrorCode, seq, 0, 0, OpenFont)
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

func (CloseFontRequest) OpCode() reqCode { return CloseFont }

func parseCloseFontRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*CloseFontRequest, error) {
	if len(requestBody) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, CloseFont)
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

func (QueryFontRequest) OpCode() reqCode { return QueryFont }

func parseQueryFontRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*QueryFontRequest, error) {
	if len(requestBody) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, QueryFont)
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

func (QueryTextExtentsRequest) OpCode() reqCode { return QueryTextExtents }

func parseQueryTextExtentsRequest(order binary.ByteOrder, data byte, requestBody []byte, seq uint16) (*QueryTextExtentsRequest, error) {
	if len(requestBody) < 4 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, QueryTextExtents)
	}
	oddLength := data != 0
	var n int
	if oddLength {
		if (len(requestBody)-4)%4 != 2 {
			return nil, NewError(LengthErrorCode, seq, 0, 0, QueryTextExtents)
		}
		n = (len(requestBody) - 4 - 2) / 2
	} else {
		if (len(requestBody)-4)%4 != 0 {
			return nil, NewError(LengthErrorCode, seq, 0, 0, QueryTextExtents)
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

func (ListFontsRequest) OpCode() reqCode { return ListFonts }

func parseListFontsRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*ListFontsRequest, error) {
	if len(requestBody) < 4 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, ListFonts)
	}
	req := &ListFontsRequest{}
	req.MaxNames = order.Uint16(requestBody[0:2])
	nameLen := int(order.Uint16(requestBody[2:4]))
	paddedLen := 4 + nameLen + padLen(nameLen)
	if len(requestBody) != paddedLen {
		return nil, NewError(LengthErrorCode, seq, 0, 0, ListFonts)
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

func (ListFontsWithInfoRequest) OpCode() reqCode { return ListFontsWithInfo }

func parseListFontsWithInfoRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*ListFontsWithInfoRequest, error) {
	if len(requestBody) < 4 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, ListFontsWithInfo)
	}
	req := &ListFontsWithInfoRequest{}
	req.MaxNames = order.Uint16(requestBody[0:2])
	nameLen := int(order.Uint16(requestBody[2:4]))
	paddedLen := 4 + nameLen + padLen(nameLen)
	if len(requestBody) != paddedLen {
		return nil, NewError(LengthErrorCode, seq, 0, 0, ListFontsWithInfo)
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

func (SetFontPathRequest) OpCode() reqCode { return SetFontPath }

func parseSetFontPathRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*SetFontPathRequest, error) {
	if len(requestBody) < 4 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, SetFontPath)
	}
	req := &SetFontPathRequest{}
	req.NumPaths = order.Uint16(requestBody[0:2])
	pathsData := requestBody[4:]
	pathsLen := 0
	tempPathsData := pathsData
	for i := 0; i < int(req.NumPaths); i++ {
		if len(tempPathsData) == 0 {
			return nil, NewError(LengthErrorCode, seq, 0, 0, SetFontPath)
		}
		pathLen := int(tempPathsData[0])
		tempPathsData = tempPathsData[1:]
		pathsLen++
		if len(tempPathsData) < pathLen {
			return nil, NewError(LengthErrorCode, seq, 0, 0, SetFontPath)
		}
		req.Paths = append(req.Paths, string(tempPathsData[:pathLen]))
		tempPathsData = tempPathsData[pathLen:]
		pathsLen += pathLen
	}
	paddedLen := pathsLen + padLen(pathsLen)
	if len(pathsData) != paddedLen {
		return nil, NewError(LengthErrorCode, seq, 0, 0, SetFontPath)
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

func (GetFontPathRequest) OpCode() reqCode { return GetFontPath }

func parseGetFontPathRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*GetFontPathRequest, error) {
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

func (CreatePixmapRequest) OpCode() reqCode { return CreatePixmap }

func parseCreatePixmapRequest(order binary.ByteOrder, data byte, payload []byte, seq uint16) (*CreatePixmapRequest, error) {
	if len(payload) != 12 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, CreatePixmap)
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

func (FreePixmapRequest) OpCode() reqCode { return FreePixmap }

func parseFreePixmapRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*FreePixmapRequest, error) {
	if len(requestBody) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, FreePixmap)
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

func (CreateGCRequest) OpCode() reqCode { return CreateGC }

func parseCreateGCRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*CreateGCRequest, error) {
	if len(requestBody) < 12 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, CreateGC)
	}
	req := &CreateGCRequest{}
	req.Cid = GContext(order.Uint32(requestBody[0:4]))
	req.Drawable = Drawable(order.Uint32(requestBody[4:8]))
	req.ValueMask = order.Uint32(requestBody[8:12])
	values, _, err := parseGCValues(order, req.ValueMask, requestBody[12:], seq)
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

func (ChangeGCRequest) OpCode() reqCode { return ChangeGC }

func parseChangeGCRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*ChangeGCRequest, error) {
	if len(requestBody) < 8 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, ChangeGC)
	}
	req := &ChangeGCRequest{}
	req.Gc = GContext(order.Uint32(requestBody[0:4]))
	req.ValueMask = order.Uint32(requestBody[4:8])
	values, _, err := parseGCValues(order, req.ValueMask, requestBody[8:], seq)
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

func (CopyGCRequest) OpCode() reqCode { return CopyGC }

func parseCopyGCRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*CopyGCRequest, error) {
	if len(requestBody) != 12 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, CopyGC)
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

func (SetDashesRequest) OpCode() reqCode { return SetDashes }

func parseSetDashesRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*SetDashesRequest, error) {
	if len(requestBody) < 8 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, SetDashes)
	}
	req := &SetDashesRequest{}
	req.GC = GContext(order.Uint32(requestBody[0:4]))
	req.DashOffset = order.Uint16(requestBody[4:6])
	nDashes := int(order.Uint16(requestBody[6:8]))
	paddedLen := 8 + nDashes + padLen(8+nDashes)
	if len(requestBody) != paddedLen {
		return nil, NewError(LengthErrorCode, seq, 0, 0, SetDashes)
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

func (SetClipRectanglesRequest) OpCode() reqCode { return SetClipRectangles }

func parseSetClipRectanglesRequest(order binary.ByteOrder, data byte, requestBody []byte, seq uint16) (*SetClipRectanglesRequest, error) {
	if len(requestBody) < 8 || len(requestBody)%8 != 0 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, SetClipRectangles)
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

func (FreeGCRequest) OpCode() reqCode { return FreeGC }

func parseFreeGCRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*FreeGCRequest, error) {
	if len(requestBody) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, FreeGC)
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

func (ClearAreaRequest) OpCode() reqCode { return ClearArea }

func parseClearAreaRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*ClearAreaRequest, error) {
	if len(requestBody) != 12 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, ClearArea)
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

func (CopyAreaRequest) OpCode() reqCode { return CopyArea }

func parseCopyAreaRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*CopyAreaRequest, error) {
	if len(requestBody) != 28 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, CopyArea)
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
	Drawable    Drawable
	Gc          GContext
	Coordinates []uint32
}

func (PolyPointRequest) OpCode() reqCode { return PolyPoint }

func parsePolyPointRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*PolyPointRequest, error) {
	if len(requestBody) < 8 || (len(requestBody)-8)%4 != 0 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, PolyPoint)
	}
	req := &PolyPointRequest{}
	req.Drawable = Drawable(order.Uint32(requestBody[0:4]))
	req.Gc = GContext(order.Uint32(requestBody[4:8]))
	numPoints := (len(requestBody) - 8) / 4
	for i := 0; i < numPoints; i++ {
		offset := 8 + i*4
		x := int32(order.Uint16(requestBody[offset : offset+2]))
		y := int32(order.Uint16(requestBody[offset+2 : offset+4]))
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
	Drawable    Drawable
	Gc          GContext
	Coordinates []uint32
}

func (PolyLineRequest) OpCode() reqCode { return PolyLine }

func parsePolyLineRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*PolyLineRequest, error) {
	if len(requestBody) < 8 || (len(requestBody)-8)%4 != 0 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, PolyLine)
	}
	req := &PolyLineRequest{}
	req.Drawable = Drawable(order.Uint32(requestBody[0:4]))
	req.Gc = GContext(order.Uint32(requestBody[4:8]))
	numPoints := (len(requestBody) - 8) / 4
	for i := 0; i < numPoints; i++ {
		offset := 8 + i*4
		x := int32(order.Uint16(requestBody[offset : offset+2]))
		y := int32(order.Uint16(requestBody[offset+2 : offset+4]))
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

func (PolySegmentRequest) OpCode() reqCode { return PolySegment }

func parsePolySegmentRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*PolySegmentRequest, error) {
	if len(requestBody) < 8 || (len(requestBody)-8)%8 != 0 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, PolySegment)
	}
	req := &PolySegmentRequest{}
	req.Drawable = Drawable(order.Uint32(requestBody[0:4]))
	req.Gc = GContext(order.Uint32(requestBody[4:8]))
	numSegments := (len(requestBody) - 8) / 8
	for i := 0; i < numSegments; i++ {
		offset := 8 + i*8
		x1 := int32(order.Uint16(requestBody[offset : offset+2]))
		y1 := int32(order.Uint16(requestBody[offset+2 : offset+4]))
		x2 := int32(order.Uint16(requestBody[offset+4 : offset+6]))
		y2 := int32(order.Uint16(requestBody[offset+6 : offset+8]))
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

func (PolyRectangleRequest) OpCode() reqCode { return PolyRectangle }

func parsePolyRectangleRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*PolyRectangleRequest, error) {
	if len(requestBody) < 8 || (len(requestBody)-8)%8 != 0 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, PolyRectangle)
	}
	req := &PolyRectangleRequest{}
	req.Drawable = Drawable(order.Uint32(requestBody[0:4]))
	req.Gc = GContext(order.Uint32(requestBody[4:8]))
	numRects := (len(requestBody) - 8) / 8
	for i := 0; i < numRects; i++ {
		offset := 8 + i*8
		x := uint32(order.Uint16(requestBody[offset : offset+2]))
		y := uint32(order.Uint16(requestBody[offset+2 : offset+4]))
		width := uint32(order.Uint16(requestBody[offset+4 : offset+6]))
		height := uint32(order.Uint16(requestBody[offset+6 : offset+8]))
		req.Rectangles = append(req.Rectangles, x, y, width, height)
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

func (PolyArcRequest) OpCode() reqCode { return PolyArc }

func parsePolyArcRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*PolyArcRequest, error) {
	if len(requestBody) < 8 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, PolyArc)
	}
	req := &PolyArcRequest{}
	req.Drawable = Drawable(order.Uint32(requestBody[0:4]))
	req.Gc = GContext(order.Uint32(requestBody[4:8]))
	numArcs := (len(requestBody) - 8) / 12
	for i := 0; i < numArcs; i++ {
		offset := 8 + i*12
		x := int32(order.Uint16(requestBody[offset : offset+2]))
		y := int32(order.Uint16(requestBody[offset+2 : offset+4]))
		width := uint32(order.Uint16(requestBody[offset+4 : offset+6]))
		height := uint32(order.Uint16(requestBody[offset+6 : offset+8]))
		angle1 := int32(order.Uint16(requestBody[offset+8 : offset+10]))
		angle2 := int32(order.Uint16(requestBody[offset+10 : offset+12]))
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
	Drawable    Drawable
	Gc          GContext
	Shape       byte
	Coordinates []uint32
}

func (FillPolyRequest) OpCode() reqCode { return FillPoly }

func parseFillPolyRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*FillPolyRequest, error) {
	if len(requestBody) < 12 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, FillPoly)
	}
	req := &FillPolyRequest{}
	req.Drawable = Drawable(order.Uint32(requestBody[0:4]))
	req.Gc = GContext(order.Uint32(requestBody[4:8]))
	numPoints := (len(requestBody) - 12) / 4
	for i := 0; i < numPoints; i++ {
		offset := 12 + i*4
		x := int32(order.Uint16(requestBody[offset : offset+2]))
		y := int32(order.Uint16(requestBody[offset+2 : offset+4]))
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

func (PolyFillRectangleRequest) OpCode() reqCode { return PolyFillRectangle }

func parsePolyFillRectangleRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*PolyFillRectangleRequest, error) {
	if len(requestBody) < 8 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, PolyFillRectangle)
	}
	req := &PolyFillRectangleRequest{}
	req.Drawable = Drawable(order.Uint32(requestBody[0:4]))
	req.Gc = GContext(order.Uint32(requestBody[4:8]))
	numRects := (len(requestBody) - 8) / 8
	for i := 0; i < numRects; i++ {
		offset := 8 + i*8
		x := uint32(order.Uint16(requestBody[offset : offset+2]))
		y := uint32(order.Uint16(requestBody[offset+2 : offset+4]))
		width := uint32(order.Uint16(requestBody[offset+4 : offset+6]))
		height := uint32(order.Uint16(requestBody[offset+6 : offset+8]))
		req.Rectangles = append(req.Rectangles, x, y, width, height)
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

func (PolyFillArcRequest) OpCode() reqCode { return PolyFillArc }

func parsePolyFillArcRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*PolyFillArcRequest, error) {
	if len(requestBody) < 8 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, PolyFillArc)
	}
	req := &PolyFillArcRequest{}
	req.Drawable = Drawable(order.Uint32(requestBody[0:4]))
	req.Gc = GContext(order.Uint32(requestBody[4:8]))
	numArcs := (len(requestBody) - 8) / 12
	for i := 0; i < numArcs; i++ {
		offset := 8 + i*12
		x := int32(order.Uint16(requestBody[offset : offset+2]))
		y := int32(order.Uint16(requestBody[offset+2 : offset+4]))
		width := uint32(order.Uint16(requestBody[offset+4 : offset+6]))
		height := uint32(order.Uint16(requestBody[offset+6 : offset+8]))
		angle1 := int32(order.Uint16(requestBody[offset+8 : offset+10]))
		angle2 := int32(order.Uint16(requestBody[offset+10 : offset+12]))
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

func (PutImageRequest) OpCode() reqCode { return PutImage }

func parsePutImageRequest(order binary.ByteOrder, data byte, requestBody []byte, seq uint16) (*PutImageRequest, error) {
	if len(requestBody) < 20 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, PutImage)
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

func (GetImageRequest) OpCode() reqCode { return GetImage }

func parseGetImageRequest(order binary.ByteOrder, data byte, requestBody []byte, seq uint16) (*GetImageRequest, error) {
	if len(requestBody) != 16 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, GetImage)
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

func (PolyText8Request) OpCode() reqCode { return PolyText8 }

func parsePolyText8Request(order binary.ByteOrder, data []byte, seq uint16) (*PolyText8Request, error) {
	var req PolyText8Request
	if len(data) < 12 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, PolyText8)
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

func (PolyText16Request) OpCode() reqCode { return PolyText16 }

func parsePolyText16Request(order binary.ByteOrder, data []byte, seq uint16) (*PolyText16Request, error) {
	var req PolyText16Request
	if len(data) < 12 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, PolyText16)
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

func (ImageText8Request) OpCode() reqCode { return ImageText8 }

func parseImageText8Request(order binary.ByteOrder, data byte, requestBody []byte, seq uint16) (*ImageText8Request, error) {
	n := int(data)
	paddedLen := 12 + n + padLen(n)
	if len(requestBody) != paddedLen {
		return nil, NewError(LengthErrorCode, seq, 0, 0, ImageText8)
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

func (ImageText16Request) OpCode() reqCode { return ImageText16 }

func parseImageText16Request(order binary.ByteOrder, data byte, requestBody []byte, seq uint16) (*ImageText16Request, error) {
	n := int(data)
	paddedLen := 12 + 2*n + padLen(12+2*n)
	if len(requestBody) != paddedLen {
		return nil, NewError(LengthErrorCode, seq, 0, 0, ImageText16)
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

func (CreateColormapRequest) OpCode() reqCode { return CreateColormap }

func parseCreateColormapRequest(order binary.ByteOrder, data byte, payload []byte, seq uint16) (*CreateColormapRequest, error) {
	if len(payload) != 12 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, CreateColormap)
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

func (FreeColormapRequest) OpCode() reqCode { return FreeColormap }

func parseFreeColormapRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*FreeColormapRequest, error) {
	if len(requestBody) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, FreeColormap)
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
// CopyColormapAndFree is not implemented.

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

func (InstallColormapRequest) OpCode() reqCode { return InstallColormap }

func parseInstallColormapRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*InstallColormapRequest, error) {
	if len(requestBody) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, InstallColormap)
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

func (UninstallColormapRequest) OpCode() reqCode { return UninstallColormap }

func parseUninstallColormapRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*UninstallColormapRequest, error) {
	if len(requestBody) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, UninstallColormap)
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

func (ListInstalledColormapsRequest) OpCode() reqCode { return ListInstalledColormaps }

func parseListInstalledColormapsRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*ListInstalledColormapsRequest, error) {
	if len(requestBody) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, ListInstalledColormaps)
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

func (AllocColorRequest) OpCode() reqCode { return AllocColor }

func parseAllocColorRequest(order binary.ByteOrder, payload []byte, seq uint16) (*AllocColorRequest, error) {
	if len(payload) != 12 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, AllocColor)
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

func (AllocNamedColorRequest) OpCode() reqCode { return AllocNamedColor }

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
func parseAllocNamedColorRequest(order binary.ByteOrder, payload []byte, seq uint16) (*AllocNamedColorRequest, error) {
	if len(payload) < 8 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, AllocNamedColor)
	}
	req := &AllocNamedColorRequest{}
	req.Cmap = Colormap(order.Uint32(payload[0:4]))
	nameLen := order.Uint16(payload[4:6])
	paddedLen := 8 + int(nameLen) + padLen(8+int(nameLen))
	if len(payload) != paddedLen {
		return nil, NewError(LengthErrorCode, seq, 0, 0, AllocNamedColor)
	}
	req.Name = payload[8 : 8+nameLen]
	return req, nil
}

type FreeColorsRequest struct {
	Cmap      Colormap
	PlaneMask uint32
	Pixels    []uint32
}

func (FreeColorsRequest) OpCode() reqCode { return FreeColors }

/*
FreeColors

	1     88                              opcode
	1                                     unused
	2     3+n                             request length
	4     COLORMAP                        cmap
	4     CARD32                          plane-mask
	4n     LISTofCARD32                   pixels
*/
func parseFreeColorsRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*FreeColorsRequest, error) {
	if len(requestBody) < 8 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, FreeColors)
	}
	req := &FreeColorsRequest{}
	req.Cmap = Colormap(order.Uint32(requestBody[0:4]))
	req.PlaneMask = order.Uint32(requestBody[4:8])
	numPixels := (len(requestBody) - 8) / 4
	if len(requestBody) < 8+numPixels*4 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, FreeColors)
	}
	for i := 0; i < numPixels; i++ {
		offset := 8 + i*4
		req.Pixels = append(req.Pixels, order.Uint32(requestBody[offset:offset+4]))
	}
	return req, nil
}

type StoreColorsRequest struct {
	Cmap  Colormap
	Items []struct {
		Pixel uint32
		Red   uint16
		Green uint16
		Blue  uint16
		Flags byte
	}
}

func (StoreColorsRequest) OpCode() reqCode { return StoreColors }

/*
StoreColors

1     89                              opcode
1                                     unused
2     2+3n                            request length
4     COLORMAP                        cmap
12n   LISTofCOLORITEM                 items
*/
func parseStoreColorsRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*StoreColorsRequest, error) {
	if len(requestBody) < 4 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, StoreColors)
	}
	req := &StoreColorsRequest{}
	req.Cmap = Colormap(order.Uint32(requestBody[0:4]))
	numItems := (len(requestBody) - 4) / 12
	for i := 0; i < numItems; i++ {
		offset := 4 + i*12
		item := struct {
			Pixel uint32
			Red   uint16
			Green uint16
			Blue  uint16
			Flags byte
		}{
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

func (StoreNamedColorRequest) OpCode() reqCode { return StoreNamedColor }

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
func parseStoreNamedColorRequest(order binary.ByteOrder, data byte, requestBody []byte, seq uint16) (*StoreNamedColorRequest, error) {
	if len(requestBody) < 12 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, StoreNamedColor)
	}
	req := &StoreNamedColorRequest{}
	req.Cmap = Colormap(order.Uint32(requestBody[0:4]))
	req.Pixel = order.Uint32(requestBody[4:8])
	nameLen := order.Uint16(requestBody[8:10])
	if len(requestBody) < 12+int(nameLen) {
		return nil, NewError(LengthErrorCode, seq, 0, 0, StoreNamedColor)
	}
	req.Name = string(requestBody[12 : 12+nameLen])
	req.Flags = data
	return req, nil
}

type QueryColorsRequest struct {
	Cmap   xID
	Pixels []uint32
}

func (QueryColorsRequest) OpCode() reqCode { return QueryColors }

/*
QueryColors

1     91                              opcode
1                                     unused
2     2+n                             request length
4     COLORMAP                        cmap
4n    LISTofCARD32                    pixels
*/
func parseQueryColorsRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*QueryColorsRequest, error) {
	if len(requestBody) < 4 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, QueryColors)
	}
	req := &QueryColorsRequest{}
	req.Cmap = xID{local: order.Uint32(requestBody[0:4])}
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

func (LookupColorRequest) OpCode() reqCode { return LookupColor }

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
func parseLookupColorRequest(order binary.ByteOrder, payload []byte, seq uint16) (*LookupColorRequest, error) {
	if len(payload) < 8 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, LookupColor)
	}
	req := &LookupColorRequest{}
	req.Cmap = Colormap(order.Uint32(payload[0:4]))
	nameLen := order.Uint16(payload[4:6])
	paddedLen := 8 + int(nameLen) + padLen(int(nameLen))
	if len(payload) != paddedLen {
		return nil, NewError(LengthErrorCode, seq, 0, 0, LookupColor)
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

func (CreateGlyphCursorRequest) OpCode() reqCode { return CreateGlyphCursor }

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
func parseCreateGlyphCursorRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*CreateGlyphCursorRequest, error) {
	if len(requestBody) != 28 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, CreateGlyphCursor)
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

func (FreeCursorRequest) OpCode() reqCode { return FreeCursor }

/*
FreeCursor

1     95                              opcode
1                                     unused
2     2                               request length
4     CURSOR                          cursor
*/
func parseFreeCursorRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*FreeCursorRequest, error) {
	if len(requestBody) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, FreeCursor)
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

func (RecolorCursorRequest) OpCode() reqCode { return RecolorCursor }

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
func parseRecolorCursorRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*RecolorCursorRequest, error) {
	if len(requestBody) != 16 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, RecolorCursor)
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

func (QueryBestSizeRequest) OpCode() reqCode { return QueryBestSize }

/*
QueryBestSize

1     97                              opcode
1     { Cursor, Tile, Stipple }       class
2     3                               request length
4     DRAWABLE                        drawable
2     CARD16                          width
2     CARD16                          height
*/
func parseQueryBestSizeRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*QueryBestSizeRequest, error) {
	if len(requestBody) != 8 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, QueryBestSize)
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

func (QueryExtensionRequest) OpCode() reqCode { return QueryExtension }

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
func parseQueryExtensionRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*QueryExtensionRequest, error) {
	if len(requestBody) < 4 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, QueryExtension)
	}
	req := &QueryExtensionRequest{}
	nameLen := order.Uint16(requestBody[0:2])
	paddedLen := 4 + int(nameLen) + padLen(int(nameLen))
	if len(requestBody) != paddedLen {
		return nil, NewError(LengthErrorCode, seq, 0, 0, QueryExtension)
	}
	req.Name = string(requestBody[4 : 4+nameLen])
	return req, nil
}

type BellRequest struct {
	Percent int8
}

func (BellRequest) OpCode() reqCode { return Bell }

/*
Bell
  1     102                             opcode
  1     INT8                            percent
  2     1                               request length
*/
func parseBellRequest(requestBody byte, seq uint16) (*BellRequest, error) {
	req := &BellRequest{}
	req.Percent = int8(requestBody)
	return req, nil
}

type SetPointerMappingRequest struct {
	Map []byte
}

func (SetPointerMappingRequest) OpCode() reqCode { return SetPointerMapping }

/*
SetPointerMapping

1     116                             opcode
1     n                               length of map
2     1+n/4                           request length
n     LISTofBYTE                      map
*/
func parseSetPointerMappingRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*SetPointerMappingRequest, error) {
	req := &SetPointerMappingRequest{}
	req.Map = requestBody
	return req, nil
}

type GetPointerMappingRequest struct{}

func (GetPointerMappingRequest) OpCode() reqCode { return GetPointerMapping }

/*
GetPointerMapping

1     117                             opcode
1                                     unused
2     1                               request length
*/
func parseGetPointerMappingRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*GetPointerMappingRequest, error) {
	return &GetPointerMappingRequest{}, nil
}

type GetKeyboardMappingRequest struct {
	FirstKeyCode KeyCode
	Count        byte
}

func (GetKeyboardMappingRequest) OpCode() reqCode { return GetKeyboardMapping }

/*
GetKeyboardMapping

1     101                             opcode
1                                     unused
2     2                               request length
1     KEYCODE                         first-keycode
1     CARD8                           count
2                                     unused
*/
func parseGetKeyboardMappingRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*GetKeyboardMappingRequest, error) {
	if len(requestBody) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, GetKeyboardMapping)
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

func (ChangeKeyboardMappingRequest) OpCode() reqCode { return ChangeKeyboardMapping }

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
func parseChangeKeyboardMappingRequest(order binary.ByteOrder, data byte, requestBody []byte, seq uint16) (*ChangeKeyboardMappingRequest, error) {
	if len(requestBody) < 4 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, ChangeKeyboardMapping)
	}
	req := &ChangeKeyboardMappingRequest{}
	req.KeyCodeCount = data
	req.FirstKeyCode = KeyCode(requestBody[0])
	req.KeySymsPerKeyCode = requestBody[1]
	numKeySyms := int(req.KeyCodeCount) * int(req.KeySymsPerKeyCode)
	if len(requestBody) < 4+numKeySyms*4 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, ChangeKeyboardMapping)
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

func (ChangeKeyboardControlRequest) OpCode() reqCode { return ChangeKeyboardControl }

/*
ChangeKeyboardControl

1     103                             opcode
1                                     unused
2     2+n                             request length
4     BITMASK                         value-mask
4n    LISTofVALUE                     value-list
*/
func parseChangeKeyboardControlRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*ChangeKeyboardControlRequest, error) {
	if len(requestBody) < 4 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, ChangeKeyboardControl)
	}
	req := &ChangeKeyboardControlRequest{}
	req.ValueMask = order.Uint32(requestBody[0:4])
	values, _, err := parseKeyboardControl(order, req.ValueMask, requestBody[4:], seq)
	if err != nil {
		return nil, err
	}
	req.Values = values
	return req, nil
}

type GetKeyboardControlRequest struct{}

func (GetKeyboardControlRequest) OpCode() reqCode { return GetKeyboardControl }

/*
GetKeyboardControl

1     104                             opcode
1                                     unused
2     1                               request length
*/
func parseGetKeyboardControlRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*GetKeyboardControlRequest, error) {
	return &GetKeyboardControlRequest{}, nil
}

type SetScreenSaverRequest struct {
	Timeout     int16
	Interval    int16
	PreferBlank byte
	AllowExpose byte
}

func (SetScreenSaverRequest) OpCode() reqCode { return SetScreenSaver }

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
func parseSetScreenSaverRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*SetScreenSaverRequest, error) {
	if len(requestBody) != 8 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, SetScreenSaver)
	}
	req := &SetScreenSaverRequest{}
	req.Timeout = int16(order.Uint16(requestBody[0:2]))
	req.Interval = int16(order.Uint16(requestBody[2:4]))
	req.PreferBlank = requestBody[4]
	req.AllowExpose = requestBody[5]
	return req, nil
}

type GetScreenSaverRequest struct{}

func (GetScreenSaverRequest) OpCode() reqCode { return GetScreenSaver }

/*
GetScreenSaver

1     108                             opcode
1                                     unused
2     1                               request length
*/
func parseGetScreenSaverRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*GetScreenSaverRequest, error) {
	return &GetScreenSaverRequest{}, nil
}

type ChangeHostsRequest struct {
	Mode byte
	Host Host
}

func (ChangeHostsRequest) OpCode() reqCode { return ChangeHosts }

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
func parseChangeHostsRequest(order binary.ByteOrder, data byte, requestBody []byte, seq uint16) (*ChangeHostsRequest, error) {
	if len(requestBody) < 4 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, ChangeHosts)
	}
	req := &ChangeHostsRequest{}
	req.Mode = data
	family := requestBody[0]
	addressLen := order.Uint16(requestBody[2:4])
	if len(requestBody) < 4+int(addressLen) {
		return nil, NewError(LengthErrorCode, seq, 0, 0, ChangeHosts)
	}
	req.Host = Host{
		Family: family,
		Data:   requestBody[4 : 4+addressLen],
	}
	return req, nil
}

type ListHostsRequest struct{}

func (ListHostsRequest) OpCode() reqCode { return ListHosts }

/*
ListHosts

1     110                             opcode
1                                     unused
2     1                               request length
*/
func parseListHostsRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*ListHostsRequest, error) {
	return &ListHostsRequest{}, nil
}

type SetAccessControlRequest struct {
	Mode byte
}

func (SetAccessControlRequest) OpCode() reqCode { return SetAccessControl }

/*
SetAccessControl

1     111                             opcode
1     { Enable, Disable }             mode
2     1                               request length
*/
func parseSetAccessControlRequest(order binary.ByteOrder, data byte, requestBody []byte, seq uint16) (*SetAccessControlRequest, error) {
	req := &SetAccessControlRequest{}
	req.Mode = data
	return req, nil
}

type SetCloseDownModeRequest struct {
	Mode byte
}

func (SetCloseDownModeRequest) OpCode() reqCode { return SetCloseDownMode }

/*
SetCloseDownMode

1     112                             opcode
1     { Destroy, RetainPermanent,     mode

	RetainTemporary }

2     1                               request length
*/
func parseSetCloseDownModeRequest(order binary.ByteOrder, data byte, requestBody []byte, seq uint16) (*SetCloseDownModeRequest, error) {
	req := &SetCloseDownModeRequest{}
	req.Mode = data
	return req, nil
}

type KillClientRequest struct {
	Resource uint32
}

func (KillClientRequest) OpCode() reqCode { return KillClient }

/*
KillClient

1     113                             opcode
1                                     unused
2     2                               request length
4     CARD32                          resource
*/
func parseKillClientRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*KillClientRequest, error) {
	if len(requestBody) != 4 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, KillClient)
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

func (RotatePropertiesRequest) OpCode() reqCode { return RotateProperties }

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
func parseRotatePropertiesRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*RotatePropertiesRequest, error) {
	if len(requestBody) < 8 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, RotateProperties)
	}
	req := &RotatePropertiesRequest{}
	req.Window = Window(order.Uint32(requestBody[0:4]))
	numAtoms := order.Uint16(requestBody[4:6])
	req.Delta = int16(order.Uint16(requestBody[6:8]))
	if len(requestBody) < 8+int(numAtoms)*4 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, RotateProperties)
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

func (ForceScreenSaverRequest) OpCode() reqCode { return ForceScreenSaver }

/*
ForceScreenSaver

1     115                             opcode
1     { Activate, Reset }             mode
2     1                               request length
*/
func parseForceScreenSaverRequest(order binary.ByteOrder, data byte, requestBody []byte, seq uint16) (*ForceScreenSaverRequest, error) {
	req := &ForceScreenSaverRequest{}
	req.Mode = data
	return req, nil
}

type SetModifierMappingRequest struct {
	KeyCodesPerModifier byte
	KeyCodes            []KeyCode
}

func (SetModifierMappingRequest) OpCode() reqCode { return SetModifierMapping }

/*
SetModifierMapping

1     118                             opcode
1     CARD8                           keycodes-per-modifier
2     1+2n                            request length
8n    LISTofKEYCODE                   keycodes
*/
func parseSetModifierMappingRequest(order binary.ByteOrder, data byte, requestBody []byte, seq uint16) (*SetModifierMappingRequest, error) {
	req := &SetModifierMappingRequest{}
	req.KeyCodesPerModifier = data
	req.KeyCodes = make([]KeyCode, 0, 8*int(req.KeyCodesPerModifier))
	if len(requestBody) != cap(req.KeyCodes) {
		return nil, NewError(LengthErrorCode, seq, 0, 0, SetModifierMapping)
	}
	for i := 0; i < len(requestBody); i++ {
		req.KeyCodes = append(req.KeyCodes, KeyCode(requestBody[i]))
	}
	return req, nil
}

type GetModifierMappingRequest struct{}

func (GetModifierMappingRequest) OpCode() reqCode { return GetModifierMapping }

/*
GetModifierMapping

1     119                             opcode
1                                     unused
2     1                               request length
*/
func parseGetModifierMappingRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*GetModifierMappingRequest, error) {
	return &GetModifierMappingRequest{}, nil
}

func parseKeyboardControl(order binary.ByteOrder, valueMask uint32, valuesData []byte, seq uint16) (KeyboardControl, int, error) {
	kc := KeyboardControl{}
	offset := 0
	if valueMask&KBKeyClickPercent != 0 {
		if len(valuesData) < offset+4 {
			return kc, 0, NewError(LengthErrorCode, seq, 0, 0, ChangeKeyboardControl)
		}
		kc.KeyClickPercent = int32(order.Uint32(valuesData[offset : offset+4]))
		offset += 4
	}
	if valueMask&KBBellPercent != 0 {
		if len(valuesData) < offset+4 {
			return kc, 0, NewError(LengthErrorCode, seq, 0, 0, ChangeKeyboardControl)
		}
		kc.BellPercent = int32(order.Uint32(valuesData[offset : offset+4]))
		offset += 4
	}
	if valueMask&KBBellPitch != 0 {
		if len(valuesData) < offset+4 {
			return kc, 0, NewError(LengthErrorCode, seq, 0, 0, ChangeKeyboardControl)
		}
		kc.BellPitch = int32(order.Uint32(valuesData[offset : offset+4]))
		offset += 4
	}
	if valueMask&KBBellDuration != 0 {
		if len(valuesData) < offset+4 {
			return kc, 0, NewError(LengthErrorCode, seq, 0, 0, ChangeKeyboardControl)
		}
		kc.BellDuration = int32(order.Uint32(valuesData[offset : offset+4]))
		offset += 4
	}
	if valueMask&KBLed != 0 {
		if len(valuesData) < offset+4 {
			return kc, 0, NewError(LengthErrorCode, seq, 0, 0, ChangeKeyboardControl)
		}
		kc.Led = order.Uint32(valuesData[offset : offset+4])
		offset += 4
	}
	if valueMask&KBLedMode != 0 {
		if len(valuesData) < offset+4 {
			return kc, 0, NewError(LengthErrorCode, seq, 0, 0, ChangeKeyboardControl)
		}
		kc.LedMode = order.Uint32(valuesData[offset : offset+4])
		offset += 4
	}
	if valueMask&KBKey != 0 {
		if len(valuesData) < offset+4 {
			return kc, 0, NewError(LengthErrorCode, seq, 0, 0, ChangeKeyboardControl)
		}
		kc.Key = KeyCode(valuesData[offset])
		offset += 4
	}
	if valueMask&KBAutoRepeatMode != 0 {
		if len(valuesData) < offset+4 {
			return kc, 0, NewError(LengthErrorCode, seq, 0, 0, ChangeKeyboardControl)
		}
		kc.AutoRepeatMode = order.Uint32(valuesData[offset : offset+4])
		offset += 4
	}
	return kc, offset, nil
}

type NoOperationRequest struct{}

func (NoOperationRequest) OpCode() reqCode { return NoOperation }

/*
NoOperation

1     127                             opcode
1                                     unused
2     1                               request length
*/
func parseNoOperationRequest(order binary.ByteOrder, requestBody []byte, seq uint16) (*NoOperationRequest, error) {
	return &NoOperationRequest{}, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func parseGCValues(order binary.ByteOrder, valueMask uint32, valuesData []byte, seq uint16) (GC, int, error) {
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
			return gc, 0, NewError(LengthErrorCode, seq, 0, 0, CreateGC)
		}
		gc.Function = order.Uint32(valuesData[offset : offset+4])
		offset += 4
	}
	if valueMask&GCPlaneMask != 0 {
		if len(valuesData) < offset+4 {
			return gc, 0, NewError(LengthErrorCode, seq, 0, 0, CreateGC)
		}
		gc.PlaneMask = order.Uint32(valuesData[offset : offset+4])
		offset += 4
	}
	if valueMask&GCForeground != 0 {
		if len(valuesData) < offset+4 {
			return gc, 0, NewError(LengthErrorCode, seq, 0, 0, CreateGC)
		}
		gc.Foreground = order.Uint32(valuesData[offset : offset+4])
		offset += 4
	}
	if valueMask&GCBackground != 0 {
		if len(valuesData) < offset+4 {
			return gc, 0, NewError(LengthErrorCode, seq, 0, 0, CreateGC)
		}
		gc.Background = order.Uint32(valuesData[offset : offset+4])
		offset += 4
	}
	if valueMask&GCLineWidth != 0 {
		if len(valuesData) < offset+4 {
			return gc, 0, NewError(LengthErrorCode, seq, 0, 0, CreateGC)
		}
		gc.LineWidth = order.Uint32(valuesData[offset : offset+4])
		offset += 4
	}
	if valueMask&GCLineStyle != 0 {
		if len(valuesData) < offset+4 {
			return gc, 0, NewError(LengthErrorCode, seq, 0, 0, CreateGC)
		}
		gc.LineStyle = order.Uint32(valuesData[offset : offset+4])
		offset += 4
	}
	if valueMask&GCCapStyle != 0 {
		if len(valuesData) < offset+4 {
			return gc, 0, NewError(LengthErrorCode, seq, 0, 0, CreateGC)
		}
		gc.CapStyle = order.Uint32(valuesData[offset : offset+4])
		offset += 4
	}
	if valueMask&GCJoinStyle != 0 {
		if len(valuesData) < offset+4 {
			return gc, 0, NewError(LengthErrorCode, seq, 0, 0, CreateGC)
		}
		gc.JoinStyle = order.Uint32(valuesData[offset : offset+4])
		offset += 4
	}
	if valueMask&GCFillStyle != 0 {
		if len(valuesData) < offset+4 {
			return gc, 0, NewError(LengthErrorCode, seq, 0, 0, CreateGC)
		}
		gc.FillStyle = order.Uint32(valuesData[offset : offset+4])
		offset += 4
	}
	if valueMask&GCFillRule != 0 {
		if len(valuesData) < offset+4 {
			return gc, 0, NewError(LengthErrorCode, seq, 0, 0, CreateGC)
		}
		gc.FillRule = order.Uint32(valuesData[offset : offset+4])
		offset += 4
	}
	if valueMask&GCTile != 0 {
		if len(valuesData) < offset+4 {
			return gc, 0, NewError(LengthErrorCode, seq, 0, 0, CreateGC)
		}
		gc.Tile = order.Uint32(valuesData[offset : offset+4])
		offset += 4
	}
	if valueMask&GCStipple != 0 {
		if len(valuesData) < offset+4 {
			return gc, 0, NewError(LengthErrorCode, seq, 0, 0, CreateGC)
		}
		gc.Stipple = order.Uint32(valuesData[offset : offset+4])
		offset += 4
	}
	if valueMask&GCTileStipXOrigin != 0 {
		if len(valuesData) < offset+4 {
			return gc, 0, NewError(LengthErrorCode, seq, 0, 0, CreateGC)
		}
		gc.TileStipXOrigin = order.Uint32(valuesData[offset : offset+4])
		offset += 4
	}
	if valueMask&GCTileStipYOrigin != 0 {
		if len(valuesData) < offset+4 {
			return gc, 0, NewError(LengthErrorCode, seq, 0, 0, CreateGC)
		}
		gc.TileStipYOrigin = order.Uint32(valuesData[offset : offset+4])
		offset += 4
	}
	if valueMask&GCFont != 0 {
		if len(valuesData) < offset+4 {
			return gc, 0, NewError(LengthErrorCode, seq, 0, 0, CreateGC)
		}
		gc.Font = order.Uint32(valuesData[offset : offset+4])
		offset += 4
	}
	if valueMask&GCSubwindowMode != 0 {
		if len(valuesData) < offset+4 {
			return gc, 0, NewError(LengthErrorCode, seq, 0, 0, CreateGC)
		}
		gc.SubwindowMode = order.Uint32(valuesData[offset : offset+4])
		offset += 4
	}
	if valueMask&GCGraphicsExposures != 0 {
		if len(valuesData) < offset+4 {
			return gc, 0, NewError(LengthErrorCode, seq, 0, 0, CreateGC)
		}
		gc.GraphicsExposures = order.Uint32(valuesData[offset : offset+4])
		offset += 4
	}
	if valueMask&GCClipXOrigin != 0 {
		if len(valuesData) < offset+4 {
			return gc, 0, NewError(LengthErrorCode, seq, 0, 0, CreateGC)
		}
		gc.ClipXOrigin = int32(order.Uint32(valuesData[offset : offset+4]))
		offset += 4
	}
	if valueMask&GCClipYOrigin != 0 {
		if len(valuesData) < offset+4 {
			return gc, 0, NewError(LengthErrorCode, seq, 0, 0, CreateGC)
		}
		gc.ClipYOrigin = int32(order.Uint32(valuesData[offset : offset+4]))
		offset += 4
	}
	if valueMask&GCClipMask != 0 {
		if len(valuesData) < offset+4 {
			return gc, 0, NewError(LengthErrorCode, seq, 0, 0, CreateGC)
		}
		gc.ClipMask = order.Uint32(valuesData[offset : offset+4])
		offset += 4
	}
	if valueMask&GCDashOffset != 0 {
		if len(valuesData) < offset+4 {
			return gc, 0, NewError(LengthErrorCode, seq, 0, 0, CreateGC)
		}
		gc.DashOffset = order.Uint32(valuesData[offset : offset+4])
		offset += 4
	}
	if valueMask&GCDashes != 0 {
		if len(valuesData) < offset+4 {
			return gc, 0, NewError(LengthErrorCode, seq, 0, 0, CreateGC)
		}
		gc.Dashes = order.Uint32(valuesData[offset : offset+4])
		offset += 4
	}
	if valueMask&GCArcMode != 0 {
		if len(valuesData) < offset+4 {
			return gc, 0, NewError(LengthErrorCode, seq, 0, 0, CreateGC)
		}
		gc.ArcMode = order.Uint32(valuesData[offset : offset+4])
		offset += 4
	}
	return gc, offset, nil
}

func parseWindowAttributes(order binary.ByteOrder, valueMask uint32, valuesData []byte, seq uint16) (WindowAttributes, int, error) {
	wa := WindowAttributes{}
	offset := 0
	if valueMask&CWBackPixmap != 0 {
		if len(valuesData) < offset+4 {
			return wa, 0, NewError(LengthErrorCode, seq, 0, 0, CreateWindow)
		}
		wa.BackgroundPixmap = Pixmap(order.Uint32(valuesData[offset : offset+4]))
		offset += 4
	}
	if valueMask&CWBackPixel != 0 {
		if len(valuesData) < offset+4 {
			return wa, 0, NewError(LengthErrorCode, seq, 0, 0, CreateWindow)
		}
		wa.BackgroundPixel = order.Uint32(valuesData[offset : offset+4])
		wa.BackgroundPixelSet = true
		offset += 4
	}
	if valueMask&CWBorderPixmap != 0 {
		if len(valuesData) < offset+4 {
			return wa, 0, NewError(LengthErrorCode, seq, 0, 0, CreateWindow)
		}
		wa.BorderPixmap = Pixmap(order.Uint32(valuesData[offset : offset+4]))
		offset += 4
	}
	if valueMask&CWBorderPixel != 0 {
		if len(valuesData) < offset+4 {
			return wa, 0, NewError(LengthErrorCode, seq, 0, 0, CreateWindow)
		}
		wa.BorderPixel = order.Uint32(valuesData[offset : offset+4])
		offset += 4
	}
	if valueMask&CWBitGravity != 0 {
		if len(valuesData) < offset+4 {
			return wa, 0, NewError(LengthErrorCode, seq, 0, 0, CreateWindow)
		}
		wa.BitGravity = order.Uint32(valuesData[offset : offset+4])
		offset += 4
	}
	if valueMask&CWWinGravity != 0 {
		if len(valuesData) < offset+4 {
			return wa, 0, NewError(LengthErrorCode, seq, 0, 0, CreateWindow)
		}
		wa.WinGravity = order.Uint32(valuesData[offset : offset+4])
		offset += 4
	}
	if valueMask&CWBackingStore != 0 {
		if len(valuesData) < offset+4 {
			return wa, 0, NewError(LengthErrorCode, seq, 0, 0, CreateWindow)
		}
		wa.BackingStore = order.Uint32(valuesData[offset : offset+4])
		offset += 4
	}
	if valueMask&CWBackingPlanes != 0 {
		if len(valuesData) < offset+4 {
			return wa, 0, NewError(LengthErrorCode, seq, 0, 0, CreateWindow)
		}
		wa.BackingPlanes = order.Uint32(valuesData[offset : offset+4])
		offset += 4
	}
	if valueMask&CWBackingPixel != 0 {
		if len(valuesData) < offset+4 {
			return wa, 0, NewError(LengthErrorCode, seq, 0, 0, CreateWindow)
		}
		wa.BackingPixel = order.Uint32(valuesData[offset : offset+4])
		offset += 4
	}
	if valueMask&CWOverrideRedirect != 0 {
		if len(valuesData) < offset+4 {
			return wa, 0, NewError(LengthErrorCode, seq, 0, 0, CreateWindow)
		}
		wa.OverrideRedirect = order.Uint32(valuesData[offset:offset+4]) != 0
		offset += 4
	}
	if valueMask&CWSaveUnder != 0 {
		if len(valuesData) < offset+4 {
			return wa, 0, NewError(LengthErrorCode, seq, 0, 0, CreateWindow)
		}
		wa.SaveUnder = order.Uint32(valuesData[offset:offset+4]) != 0
		offset += 4
	}
	if valueMask&CWEventMask != 0 {
		if len(valuesData) < offset+4 {
			return wa, 0, NewError(LengthErrorCode, seq, 0, 0, CreateWindow)
		}
		wa.EventMask = order.Uint32(valuesData[offset : offset+4])
		offset += 4
	}
	if valueMask&CWDontPropagate != 0 {
		if len(valuesData) < offset+4 {
			return wa, 0, NewError(LengthErrorCode, seq, 0, 0, CreateWindow)
		}
		wa.DontPropagateMask = order.Uint32(valuesData[offset : offset+4])
		offset += 4
	}
	if valueMask&CWColormap != 0 {
		if len(valuesData) < offset+4 {
			return wa, 0, NewError(LengthErrorCode, seq, 0, 0, CreateWindow)
		}
		wa.Colormap = Colormap(order.Uint32(valuesData[offset : offset+4]))
		offset += 4
	}
	if valueMask&CWCursor != 0 {
		if len(valuesData) < offset+4 {
			return wa, 0, NewError(LengthErrorCode, seq, 0, 0, CreateWindow)
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

func (r *AllocColorCellsRequest) OpCode() reqCode { return AllocColorCells }

/*
AllocColorCells

	1     86                              opcode
	1     BOOL                            contiguous
	2     3                               request length
	4     COLORMAP                        cmap
	2     CARD16                          colors
	2     CARD16                          planes
*/
func parseAllocColorCellsRequest(order binary.ByteOrder, data byte, body []byte, seq uint16) (*AllocColorCellsRequest, error) {
	if len(body) != 8 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, AllocColorCells)
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

func (r *AllocColorPlanesRequest) OpCode() reqCode { return AllocColorPlanes }

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
func parseAllocColorPlanesRequest(order binary.ByteOrder, data byte, body []byte, seq uint16) (*AllocColorPlanesRequest, error) {
	if len(body) != 12 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, AllocColorPlanes)
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

// reqCodeCreateCursor:
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

func (r *CreateCursorRequest) OpCode() reqCode { return CreateCursor }

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
func parseCreateCursorRequest(order binary.ByteOrder, body []byte, seq uint16) (*CreateCursorRequest, error) {
	if len(body) != 28 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, CreateCursor)
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

// reqCodeCopyPlane:
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

func (r *CopyPlaneRequest) OpCode() reqCode { return CopyPlane }

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
func parseCopyPlaneRequest(order binary.ByteOrder, body []byte, seq uint16) (*CopyPlaneRequest, error) {
	if len(body) != 28 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, CopyPlane)
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

// reqCodeListExtensions:
type ListExtensionsRequest struct{}

func (r *ListExtensionsRequest) OpCode() reqCode { return ListExtensions }

/*
ListExtensions

1     99                              opcode
1                                     unused
2     1                               request length
*/
func parseListExtensionsRequest(order binary.ByteOrder, raw []byte, seq uint16) (*ListExtensionsRequest, error) {
	return &ListExtensionsRequest{}, nil
}

// reqCodeChangePointerControl:
type ChangePointerControlRequest struct {
	AccelerationNumerator   int16
	AccelerationDenominator int16
	Threshold               int16
	DoAcceleration          bool
	DoThreshold             bool
}

func (r *ChangePointerControlRequest) OpCode() reqCode { return ChangePointerControl }

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
func parseChangePointerControlRequest(order binary.ByteOrder, body []byte, seq uint16) (*ChangePointerControlRequest, error) {
	if len(body) != 8 {
		return nil, NewError(LengthErrorCode, seq, 0, 0, ChangePointerControl)
	}
	req := &ChangePointerControlRequest{}
	req.AccelerationNumerator = int16(order.Uint16(body[0:2]))
	req.AccelerationDenominator = int16(order.Uint16(body[2:4]))
	req.Threshold = int16(order.Uint16(body[4:6]))
	req.DoAcceleration = body[6] != 0
	req.DoThreshold = body[7] != 0
	return req, nil
}

// reqCodeGetPointerControl:
type GetPointerControlRequest struct{}

func (r *GetPointerControlRequest) OpCode() reqCode { return GetPointerControl }

/*
GetPointerControl

1     106                             opcode
1                                     unused
2     1                               request length
*/
func parseGetPointerControlRequest(order binary.ByteOrder, raw []byte, seq uint16) (*GetPointerControlRequest, error) {
	return &GetPointerControlRequest{}, nil
}
