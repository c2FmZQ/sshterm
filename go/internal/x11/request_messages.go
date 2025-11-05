//go:build x11

package x11

import (
	"encoding/binary"
	"log"
)

// auxiliary data structures

type WindowAttributes struct {
	BackgroundPixmap   uint32
	BackgroundPixel    uint32
	BackgroundPixelSet bool
	BorderPixmap       uint32
	BorderPixel        uint32
	BitGravity         uint32
	WinGravity         uint32
	BackingStore       uint32
	BackingPlanes      uint32
	BackingPixel       uint32
	OverrideRedirect   uint32
	SaveUnder          uint32
	EventMask          uint32
	DontPropagateMask  uint32
	Colormap           uint32
	Cursor             uint32
}

type PolyText8Item struct {
	Delta int8
	Str   []byte
}

type PolyText16Item struct {
	Delta int8
	Str   []uint16
}

// request messages

type CreateWindowRequest struct {
	Drawable    uint32
	Parent      uint32
	X           int16
	Y           int16
	Width       uint16
	Height      uint16
	BorderWidth uint16
	Class       uint16
	Visual      uint32
	ValueMask   uint32
	Values      *WindowAttributes
}

type ChangeWindowAttributesRequest struct {
	Window    uint32
	ValueMask uint32
	Values    *WindowAttributes
}

type GetWindowAttributesRequest struct {
	Drawable uint32
}

type MapWindowRequest struct {
	Window uint32
}

type UnmapWindowRequest struct {
	Window uint32
}

type ConfigureWindowRequest struct {
	Window    uint32
	ValueMask uint16
	Values    []uint32
}

type GetGeometryRequest struct {
	Drawable uint32
}

type InternAtomRequest struct {
	Name      string
	OnlyIfExists bool
}

type GetAtomNameRequest struct {
	Atom uint32
}

type ChangePropertyRequest struct {
	Window   uint32
	Property uint32
	Type     uint32
	Format   byte
	Data     []byte
}

type DeletePropertyRequest struct {
	Window   uint32
	Property uint32
}

type GetPropertyRequest struct {
	Window   uint32
	Property uint32
	Type     uint32
	Delete   bool
	Offset   uint32
	Length   uint32
}

type ListPropertiesRequest struct {
	Window uint32
}

type SetSelectionOwnerRequest struct {
	Owner     uint32
	Selection uint32
	Time      uint32
}

type GetSelectionOwnerRequest struct {
	Selection uint32
}

type ConvertSelectionRequest struct {
	Requestor uint32
	Selection uint32
	Target    uint32
	Property  uint32
	Time      uint32
}

type SendEventRequest struct {
	Propagate   bool
	Destination uint32
	EventMask   uint32
	EventData   []byte
}

type GrabPointerRequest struct {
	OwnerEvents  bool
	GrabWindow   uint32
	EventMask    uint16
	PointerMode  byte
	KeyboardMode byte
	ConfineTo    uint32
	Cursor       uint32
	Time         uint32
}

type UngrabPointerRequest struct {
	Time uint32
}

type GrabKeyboardRequest struct {
	OwnerEvents  bool
	GrabWindow   uint32
	Time         uint32
	PointerMode  byte
	KeyboardMode byte
}

type UngrabKeyboardRequest struct {
	Time uint32
}

type AllowEventsRequest struct {
	Mode byte
	Time uint32
}

type QueryPointerRequest struct {
	Drawable uint32
}

type TranslateCoordsRequest struct {
	SrcWindow uint32
	DstWindow uint32
	SrcX      int16
	SrcY      int16
}

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

type SetInputFocusRequest struct {
	Focus    uint32
	RevertTo byte
	Time     uint32
}

type GetInputFocusRequest struct{}

type OpenFontRequest struct {
	Fid  uint32
	Name string
}

type CloseFontRequest struct {
	Fid uint32
}

type QueryFontRequest struct {
	Fid uint32
}

type ListFontsRequest struct {
	MaxNames uint16
	Pattern  string
}

type CreatePixmapRequest struct {
	Pid      uint32
	Drawable uint32
	Width    uint16
	Height   uint16
	Depth    byte
}

type FreePixmapRequest struct {
	Pid uint32
}

type CreateGCRequest struct {
	Cid       uint32
	Drawable  uint32
	ValueMask uint32
	Values    *GC
}

type ChangeGCRequest struct {
	Gc        uint32
	ValueMask uint32
	Values    *GC
}

type ClearAreaRequest struct {
	Exposures bool
	Window    uint32
	X         int16
	Y         int16
	Width     uint16
	Height    uint16
}

type CopyAreaRequest struct {
	SrcDrawable uint32
	DstDrawable uint32
	Gc          uint32
	SrcX        int16
	SrcY        int16
	DstX        int16
	DstY        int16
	Width       uint16
	Height      uint16
}

type PolyPointRequest struct {
	Drawable    uint32
	Gc          uint32
	Coordinates []uint32
}

type PolyLineRequest struct {
	Drawable    uint32
	Gc          uint32
	Coordinates []uint32
}

type PolySegmentRequest struct {
	Drawable uint32
	Gc       uint32
	Segments []uint32
}

type PolyRectangleRequest struct {
	Drawable   uint32
	Gc         uint32
	Rectangles []uint32
}

type PolyArcRequest struct {
	Drawable uint32
	Gc       uint32
	Arcs     []uint32
}

type FillPolyRequest struct {
	Drawable    uint32
	Gc          uint32
	Shape       byte
	Coordinates []uint32
}

type PolyFillRectangleRequest struct {
	Drawable   uint32
	Gc         uint32
	Rectangles []uint32
}

type PolyFillArcRequest struct {
	Drawable uint32
	Gc       uint32
	Arcs     []uint32
}

type PutImageRequest struct {
	Drawable uint32
	Gc       uint32
	Width    uint16
	Height   uint16
	DstX     int16
	DstY     int16
	LeftPad  byte
	Depth    byte
	Format   byte
	Data     []byte
}

type GetImageRequest struct {
	Drawable  uint32
	X         int16
	Y         int16
	Width     uint16
	Height    uint16
	PlaneMask uint32
	Format    byte
}

type PolyText8Request struct {
	Drawable uint32
	Gc       uint32
	X        int16
	Y        int16
	Items    []PolyText8Item
}

type PolyText16Request struct {
	Drawable uint32
	Gc       uint32
	X        int16
	Y        int16
	Items    []PolyText16Item
}

type ImageText8Request struct {
	Drawable uint32
	Gc       uint32
	X        int16
	Y        int16
	Text     []byte
}

type ImageText16Request struct {
	Drawable uint32
	Gc       uint32
	X        int16
	Y        int16
	Text     []uint16
}

type CreateColormapRequest struct {
	Alloc  byte
	Mid    uint32
	Window uint32
	Visual uint32
}

type FreeColormapRequest struct {
	Cmap uint32
}

type InstallColormapRequest struct {
	Cmap uint32
}

type UninstallColormapRequest struct {
	Cmap uint32
}

type ListInstalledColormapsRequest struct {
	Window uint32
}

type AllocColorRequest struct {
	Cmap  uint32
	Red   uint16
	Green uint16
	Blue  uint16
}

type AllocNamedColorRequest struct {
	Cmap     xID
	Name     []byte
	Sequence uint16
	MinorOp  byte
	MajorOp  reqCode
}

type FreeColorsRequest struct {
	Cmap      uint32
	PlaneMask uint32
	Pixels    []uint32
}

type StoreColorsRequest struct {
	Cmap  uint32
	Items []struct {
		Pixel uint32
		Red   uint16
		Green uint16
		Blue  uint16
		Flags byte
	}
}

type StoreNamedColorRequest struct {
	Cmap  uint32
	Pixel uint32
	Name  string
	Flags byte
}

type QueryColorsRequest struct {
	Cmap   xID
	Pixels []uint32
}

type LookupColorRequest struct {
	Cmap uint32
	Name string
}

type CreateGlyphCursorRequest struct {
	Cid         uint32
	SourceFont  uint32
	MaskFont    uint32
	SourceChar  uint16
	MaskChar    uint16
	ForeColor   [3]uint16
	BackColor   [3]uint16
}

type FreeCursorRequest struct {
	Cursor uint32
}

type QueryBestSizeRequest struct {
	Class    byte
	Drawable uint32
	Width    uint16
	Height   uint16
}

type QueryExtensionRequest struct {
	Name string
}

type BellRequest struct {
	Percent int8
}

func parseWindowAttributes(order binary.ByteOrder, valueMask uint32, body []byte) (*WindowAttributes, int) {
	attributes := &WindowAttributes{
		BackgroundPixel: 1,
	}
	read := 0
	if valueMask&CWBackPixmap != 0 {
		attributes.BackgroundPixmap = order.Uint32(body[read : read+4])
		read += 4
	}
	if valueMask&CWBackPixel != 0 {
		attributes.BackgroundPixel = order.Uint32(body[read : read+4])
		attributes.BackgroundPixelSet = true
		read += 4
	}
	if valueMask&CWBorderPixmap != 0 {
		attributes.BorderPixmap = order.Uint32(body[read : read+4])
		read += 4
	}
	if valueMask&CWBorderPixel != 0 {
		attributes.BorderPixel = order.Uint32(body[read : read+4])
		read += 4
	}
	if valueMask&CWBitGravity != 0 {
		attributes.BitGravity = order.Uint32(body[read : read+4])
		read += 4
	}
	if valueMask&CWWinGravity != 0 {
		attributes.WinGravity = order.Uint32(body[read : read+4])
		read += 4
	}
	if valueMask&CWBackingStore != 0 {
		attributes.BackingStore = order.Uint32(body[read : read+4])
		read += 4
	}
	if valueMask&CWBackingPlanes != 0 {
		attributes.BackingPlanes = order.Uint32(body[read : read+4])
		read += 4
	}
	if valueMask&CWBackingPixel != 0 {
		attributes.BackingPixel = order.Uint32(body[read : read+4])
		read += 4
	}
	if valueMask&CWOverrideRedirect != 0 {
		attributes.OverrideRedirect = order.Uint32(body[read : read+4])
		read += 4
	}
	if valueMask&CWSaveUnder != 0 {
		attributes.SaveUnder = order.Uint32(body[read : read+4])
		read += 4
	}
	if valueMask&CWEventMask != 0 {
		attributes.EventMask = order.Uint32(body[read : read+4])
		read += 4
	}
	if valueMask&CWDontPropagate != 0 {
		attributes.DontPropagateMask = order.Uint32(body[read : read+4])
		read += 4
	}
	if valueMask&CWColormap != 0 {
		attributes.Colormap = order.Uint32(body[read : read+4])
		read += 4
	}
	if valueMask&CWCursor != 0 {
		attributes.Cursor = order.Uint32(body[read : read+4])
		read += 4
	}
	return attributes, read
}

func parseCreateWindowRequest(order binary.ByteOrder, requestBody []byte) *CreateWindowRequest {
	req := &CreateWindowRequest{}
	req.Drawable = order.Uint32(requestBody[0:4])
	req.Parent = order.Uint32(requestBody[4:8])
	req.X = int16(order.Uint16(requestBody[8:10]))
	req.Y = int16(order.Uint16(requestBody[10:12]))
	req.Width = order.Uint16(requestBody[12:14])
	req.Height = order.Uint16(requestBody[14:16])
	req.BorderWidth = order.Uint16(requestBody[16:18])
	req.Class = order.Uint16(requestBody[18:20])
	req.Visual = order.Uint32(requestBody[20:24])
	req.ValueMask = order.Uint32(requestBody[24:28])
	req.Values, _ = parseWindowAttributes(order, req.ValueMask, requestBody[28:])
	return req
}

func parsePutImageRequest(order binary.ByteOrder, requestBody []byte) *PutImageRequest {
	log.Printf("parsePutImageRequest: requestBody length=%d, bytes[0:20]=%x", len(requestBody), requestBody[:min(len(requestBody), 20)])
	req := &PutImageRequest{}
	req.Drawable = order.Uint32(requestBody[0:4])
	req.Gc = order.Uint32(requestBody[4:8])
	req.Width = order.Uint16(requestBody[8:10])
	req.Height = order.Uint16(requestBody[10:12])
	req.DstX = int16(order.Uint16(requestBody[12:14]))
	req.DstY = int16(order.Uint16(requestBody[14:16]))
	req.LeftPad = requestBody[16]
	req.Depth = requestBody[17]
	req.Data = requestBody[20:]
	return req
}

func parsePolyLineRequest(order binary.ByteOrder, requestBody []byte) *PolyLineRequest {
	req := &PolyLineRequest{}
	req.Drawable = order.Uint32(requestBody[0:4])
	req.Gc = order.Uint32(requestBody[4:8])
	numPoints := (len(requestBody) - 8) / 4
	for i := 0; i < numPoints; i++ {
		offset := 8 + i*4
		x := int32(order.Uint16(requestBody[offset : offset+2]))
		y := int32(order.Uint16(requestBody[offset+2 : offset+4]))
		req.Coordinates = append(req.Coordinates, uint32(x), uint32(y))
	}
	return req
}

func parseImageText8Request(order binary.ByteOrder, requestBody []byte) *ImageText8Request {
	req := &ImageText8Request{}
	req.Drawable = order.Uint32(requestBody[0:4])
	req.Gc = order.Uint32(requestBody[4:8])
	req.X = int16(order.Uint16(requestBody[8:10]))
	req.Y = int16(order.Uint16(requestBody[10:12]))
	req.Text = requestBody[12:]
	return req
}

func parseImageText16Request(order binary.ByteOrder, requestBody []byte) *ImageText16Request {
	req := &ImageText16Request{}
	req.Drawable = order.Uint32(requestBody[0:4])
	req.Gc = order.Uint32(requestBody[4:8])
	req.X = int16(order.Uint16(requestBody[8:10]))
	req.Y = int16(order.Uint16(requestBody[10:12]))
	for i := 12; i < len(requestBody); i += 2 {
		req.Text = append(req.Text, order.Uint16(requestBody[i:i+2]))
	}
	return req
}

func parsePolyText8Request(order binary.ByteOrder, requestBody []byte) *PolyText8Request {
	req := &PolyText8Request{}
	req.Drawable = order.Uint32(requestBody[0:4])
	req.Gc = order.Uint32(requestBody[4:8])
	req.X = int16(order.Uint16(requestBody[8:10]))
	req.Y = int16(order.Uint16(requestBody[10:12]))

	currentPos := 12
	for currentPos < len(requestBody) {
		n := int(requestBody[currentPos])
		currentPos++

		if n == 255 {
			currentPos += 4
		} else if n > 0 {
			delta := int8(requestBody[currentPos])
			currentPos++
			str := requestBody[currentPos : currentPos+n]
			currentPos += n
			req.Items = append(req.Items, PolyText8Item{Delta: delta, Str: str})
		}
		padding := (4 - (n+2)%4) % 4
		currentPos += padding
	}
	return req
}

func parsePolyText16Request(order binary.ByteOrder, requestBody []byte) *PolyText16Request {
	req := &PolyText16Request{}
	req.Drawable = order.Uint32(requestBody[0:4])
	req.Gc = order.Uint32(requestBody[4:8])
	req.X = int16(order.Uint16(requestBody[8:10]))
	req.Y = int16(order.Uint16(requestBody[10:12]))

	currentPos := 12
	for currentPos < len(requestBody) {
		n := int(requestBody[currentPos])
		currentPos++

		if n == 255 {
			currentPos += 4
		} else if n > 0 {
			delta := int8(requestBody[currentPos])
			currentPos++
			var str []uint16
			for i := 0; i < n; i++ {
				str = append(str, order.Uint16(requestBody[currentPos:currentPos+2]))
				currentPos += 2
			}
			req.Items = append(req.Items, PolyText16Item{Delta: delta, Str: str})
		}
		padding := (4 - (n*2+2)%4) % 4
		currentPos += padding
	}
	return req
}

func parsePolyFillRectangleRequest(order binary.ByteOrder, requestBody []byte) *PolyFillRectangleRequest {
	req := &PolyFillRectangleRequest{}
	req.Drawable = order.Uint32(requestBody[0:4])
	req.Gc = order.Uint32(requestBody[4:8])
	numRects := (len(requestBody) - 8) / 8
	for i := 0; i < numRects; i++ {
		offset := 8 + i*8
		x := uint32(order.Uint16(requestBody[offset : offset+2]))
		y := uint32(order.Uint16(requestBody[offset+2 : offset+4]))
		width := uint32(order.Uint16(requestBody[offset+4 : offset+6]))
		height := uint32(order.Uint16(requestBody[offset+6 : offset+8]))
		req.Rectangles = append(req.Rectangles, x, y, width, height)
	}
	return req
}

func parseFillPolyRequest(order binary.ByteOrder, requestBody []byte) *FillPolyRequest {
	req := &FillPolyRequest{}
	req.Drawable = order.Uint32(requestBody[0:4])
	req.Gc = order.Uint32(requestBody[4:8])
	numPoints := (len(requestBody) - 12) / 4
	for i := 0; i < numPoints; i++ {
		offset := 12 + i*4
		x := int32(order.Uint16(requestBody[offset : offset+2]))
		y := int32(order.Uint16(requestBody[offset+2 : offset+4]))
		req.Coordinates = append(req.Coordinates, uint32(x), uint32(y))
	}
	return req
}

func parsePolySegmentRequest(order binary.ByteOrder, requestBody []byte) *PolySegmentRequest {
	req := &PolySegmentRequest{}
	req.Drawable = order.Uint32(requestBody[0:4])
	req.Gc = order.Uint32(requestBody[4:8])
	numSegments := (len(requestBody) - 8) / 8
	for i := 0; i < numSegments; i++ {
		offset := 8 + i*8
		x1 := int32(order.Uint16(requestBody[offset : offset+2]))
		y1 := int32(order.Uint16(requestBody[offset+2 : offset+4]))
		x2 := int32(order.Uint16(requestBody[offset+4 : offset+6]))
		y2 := int32(order.Uint16(requestBody[offset+6 : offset+8]))
		req.Segments = append(req.Segments, uint32(x1), uint32(y1), uint32(x2), uint32(y2))
	}
	return req
}

func parsePolyPointRequest(order binary.ByteOrder, requestBody []byte) *PolyPointRequest {
	req := &PolyPointRequest{}
	req.Drawable = order.Uint32(requestBody[0:4])
	req.Gc = order.Uint32(requestBody[4:8])
	numPoints := (len(requestBody) - 8) / 4
	for i := 0; i < numPoints; i++ {
		offset := 8 + i*4
		x := int32(order.Uint16(requestBody[offset : offset+2]))
		y := int32(order.Uint16(requestBody[offset+2 : offset+4]))
		req.Coordinates = append(req.Coordinates, uint32(x), uint32(y))
	}
	return req
}

func parsePolyRectangleRequest(order binary.ByteOrder, requestBody []byte) *PolyRectangleRequest {
	req := &PolyRectangleRequest{}
	req.Drawable = order.Uint32(requestBody[0:4])
	req.Gc = order.Uint32(requestBody[4:8])
	numRects := (len(requestBody) - 8) / 8
	for i := 0; i < numRects; i++ {
		offset := 8 + i*8
		x := uint32(order.Uint16(requestBody[offset : offset+2]))
		y := uint32(order.Uint16(requestBody[offset+2 : offset+4]))
		width := uint32(order.Uint16(requestBody[offset+4 : offset+6]))
		height := uint32(order.Uint16(requestBody[offset+6 : offset+8]))
		req.Rectangles = append(req.Rectangles, x, y, width, height)
	}
	return req
}

func parsePolyArcRequest(order binary.ByteOrder, requestBody []byte) *PolyArcRequest {
	req := &PolyArcRequest{}
	req.Drawable = order.Uint32(requestBody[0:4])
	req.Gc = order.Uint32(requestBody[4:8])
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
	return req
}

func parsePolyFillArcRequest(order binary.ByteOrder, requestBody []byte) *PolyFillArcRequest {
	req := &PolyFillArcRequest{}
	req.Drawable = order.Uint32(requestBody[0:4])
	req.Gc = order.Uint32(requestBody[4:8])
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
	return req
}

func parseGetWindowAttributesRequest(order binary.ByteOrder, requestBody []byte) *GetWindowAttributesRequest {
	req := &GetWindowAttributesRequest{}
	req.Drawable = order.Uint32(requestBody[0:4])
	return req
}

func parseConfigureWindowRequest(order binary.ByteOrder, requestBody []byte) *ConfigureWindowRequest {
	req := &ConfigureWindowRequest{}
	req.Window = order.Uint32(requestBody[0:4])
	req.ValueMask = order.Uint16(requestBody[4:6])
	for i := 8; i < len(requestBody); i += 4 {
		req.Values = append(req.Values, order.Uint32(requestBody[i:i+4]))
	}
	return req
}

func parseGetGeometryRequest(order binary.ByteOrder, requestBody []byte) *GetGeometryRequest {
	req := &GetGeometryRequest{}
	req.Drawable = order.Uint32(requestBody[0:4])
	return req
}

func parseSendEventRequest(order binary.ByteOrder, requestBody []byte) *SendEventRequest {
	req := &SendEventRequest{}
	req.Destination = order.Uint32(requestBody[4:8])
	req.EventMask = order.Uint32(requestBody[8:12])
	req.EventData = requestBody[12:44]
	return req
}

func parseClearAreaRequest(order binary.ByteOrder, requestBody []byte) *ClearAreaRequest {
	req := &ClearAreaRequest{}
	req.Window = order.Uint32(requestBody[0:4])
	req.X = int16(order.Uint16(requestBody[4:6]))
	req.Y = int16(order.Uint16(requestBody[6:8]))
	req.Width = order.Uint16(requestBody[8:10])
	req.Height = order.Uint16(requestBody[10:12])
	return req
}

func parseQueryPointerRequest(order binary.ByteOrder, requestBody []byte) *QueryPointerRequest {
	req := &QueryPointerRequest{}
	req.Drawable = order.Uint32(requestBody[0:4])
	return req
}

func parseCopyAreaRequest(order binary.ByteOrder, requestBody []byte) *CopyAreaRequest {
	req := &CopyAreaRequest{}
	req.SrcDrawable = order.Uint32(requestBody[0:4])
	req.DstDrawable = order.Uint32(requestBody[4:8])
	req.Gc = order.Uint32(requestBody[8:12])
	req.SrcX = int16(order.Uint16(requestBody[12:14]))
	req.SrcY = int16(order.Uint16(requestBody[14:16]))
	req.DstX = int16(order.Uint16(requestBody[16:18]))
	req.DstY = int16(order.Uint16(requestBody[18:20]))
	req.Width = order.Uint16(requestBody[20:22])
	req.Height = order.Uint16(requestBody[22:24])
	return req
}

func parseGetImageRequest(order binary.ByteOrder, requestBody []byte) *GetImageRequest {
	req := &GetImageRequest{}
	req.Drawable = order.Uint32(requestBody[0:4])
	req.X = int16(order.Uint16(requestBody[4:6]))
	req.Y = int16(order.Uint16(requestBody[6:8]))
	req.Width = order.Uint16(requestBody[8:10])
	req.Height = order.Uint16(requestBody[10:12])
	req.PlaneMask = order.Uint32(requestBody[12:16])
	return req
}

func parseGetAtomNameRequest(order binary.ByteOrder, requestBody []byte) *GetAtomNameRequest {
	req := &GetAtomNameRequest{}
	req.Atom = order.Uint32(requestBody[0:4])
	return req
}

func parseListPropertiesRequest(order binary.ByteOrder, requestBody []byte) *ListPropertiesRequest {
	req := &ListPropertiesRequest{}
	req.Window = order.Uint32(requestBody[0:4])
	return req
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func parseCreateGlyphCursorRequest(order binary.ByteOrder, requestBody []byte) *CreateGlyphCursorRequest {
	req := &CreateGlyphCursorRequest{}
	req.Cid = order.Uint32(requestBody[0:4])
	req.SourceFont = order.Uint32(requestBody[4:8])
	req.MaskFont = order.Uint32(requestBody[8:12])
	req.SourceChar = order.Uint16(requestBody[12:14])
	req.MaskChar = order.Uint16(requestBody[14:16])
	req.ForeColor[0] = order.Uint16(requestBody[16:18])
	req.ForeColor[1] = order.Uint16(requestBody[18:20])
	req.ForeColor[2] = order.Uint16(requestBody[20:22])
	req.BackColor[0] = order.Uint16(requestBody[22:24])
	req.BackColor[1] = order.Uint16(requestBody[24:26])
	req.BackColor[2] = order.Uint16(requestBody[26:28])
	return req
}

func parseChangeWindowAttributesRequest(order binary.ByteOrder, requestBody []byte) *ChangeWindowAttributesRequest {
	req := &ChangeWindowAttributesRequest{}
	req.Window = order.Uint32(requestBody[0:4])
	req.ValueMask = order.Uint32(requestBody[4:8])
	req.Values, _ = parseWindowAttributes(order, req.ValueMask, requestBody[8:])
	return req
}

func parseFreeCursorRequest(order binary.ByteOrder, requestBody []byte) *FreeCursorRequest {
	req := &FreeCursorRequest{}
	req.Cursor = order.Uint32(requestBody[0:4])
	return req
}

func parseTranslateCoordsRequest(order binary.ByteOrder, requestBody []byte) *TranslateCoordsRequest {
	req := &TranslateCoordsRequest{}
	req.SrcWindow = order.Uint32(requestBody[0:4])
	req.DstWindow = order.Uint32(requestBody[4:8])
	req.SrcX = int16(order.Uint16(requestBody[8:10]))
	req.SrcY = int16(order.Uint16(requestBody[10:12]))
	return req
}

func parseSetSelectionOwnerRequest(order binary.ByteOrder, requestBody []byte) *SetSelectionOwnerRequest {
	req := &SetSelectionOwnerRequest{}
	req.Owner = order.Uint32(requestBody[0:4])
	req.Selection = order.Uint32(requestBody[4:8])
	req.Time = order.Uint32(requestBody[8:12])
	return req
}

func parseGetSelectionOwnerRequest(order binary.ByteOrder, requestBody []byte) *GetSelectionOwnerRequest {
	req := &GetSelectionOwnerRequest{}
	req.Selection = order.Uint32(requestBody[0:4])
	return req
}

func parseConvertSelectionRequest(order binary.ByteOrder, requestBody []byte) *ConvertSelectionRequest {
	req := &ConvertSelectionRequest{}
	req.Requestor = order.Uint32(requestBody[0:4])
	req.Selection = order.Uint32(requestBody[4:8])
	req.Target = order.Uint32(requestBody[8:12])
	req.Property = order.Uint32(requestBody[12:16])
	req.Time = order.Uint32(requestBody[16:20])
	return req
}

func parseGrabPointerRequest(order binary.ByteOrder, requestBody []byte) *GrabPointerRequest {
	req := &GrabPointerRequest{}
	req.GrabWindow = order.Uint32(requestBody[0:4])
	req.EventMask = order.Uint16(requestBody[4:6])
	req.PointerMode = requestBody[6]
	req.KeyboardMode = requestBody[7]
	req.ConfineTo = order.Uint32(requestBody[8:12])
	req.Cursor = order.Uint32(requestBody[12:16])
	req.Time = order.Uint32(requestBody[16:20])
	return req
}

func parseUngrabPointerRequest(order binary.ByteOrder, requestBody []byte) *UngrabPointerRequest {
	req := &UngrabPointerRequest{}
	req.Time = order.Uint32(requestBody[0:4])
	return req
}

func parseGrabKeyboardRequest(order binary.ByteOrder, requestBody []byte) *GrabKeyboardRequest {
	req := &GrabKeyboardRequest{}
	req.GrabWindow = order.Uint32(requestBody[0:4])
	req.Time = order.Uint32(requestBody[4:8])
	req.PointerMode = requestBody[8]
	req.KeyboardMode = requestBody[9]
	return req
}

func parseUngrabKeyboardRequest(order binary.ByteOrder, requestBody []byte) *UngrabKeyboardRequest {
	req := &UngrabKeyboardRequest{}
	req.Time = order.Uint32(requestBody[0:4])
	return req
}

func parseQueryBestSizeRequest(order binary.ByteOrder, requestBody []byte) *QueryBestSizeRequest {
	req := &QueryBestSizeRequest{}
	req.Drawable = order.Uint32(requestBody[0:4])
	req.Width = order.Uint16(requestBody[4:6])
	req.Height = order.Uint16(requestBody[6:8])
	return req
}

func parseFreeColormapRequest(order binary.ByteOrder, requestBody []byte) *FreeColormapRequest {
	req := &FreeColormapRequest{}
	req.Cmap = order.Uint32(requestBody[0:4])
	return req
}

func parseQueryExtensionRequest(order binary.ByteOrder, requestBody []byte) *QueryExtensionRequest {
	req := &QueryExtensionRequest{}
	nameLen := order.Uint16(requestBody[0:2])
	req.Name = string(requestBody[4 : 4+nameLen])
	return req
}

func parseStoreColorsRequest(order binary.ByteOrder, requestBody []byte) *StoreColorsRequest {
	req := &StoreColorsRequest{}
	req.Cmap = order.Uint32(requestBody[0:4])
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
	return req
}

func parseQueryColorsRequest(order binary.ByteOrder, requestBody []byte) *QueryColorsRequest {
	req := &QueryColorsRequest{}
	req.Cmap = xID{local: order.Uint32(requestBody[0:4])}
	numPixels := (len(requestBody) - 4) / 4
	for i := 0; i < numPixels; i++ {
		offset := 4 + i*4
		req.Pixels = append(req.Pixels, order.Uint32(requestBody[offset:offset+4]))
	}
	return req
}

func parseListFontsRequest(order binary.ByteOrder, requestBody []byte) *ListFontsRequest {
	req := &ListFontsRequest{}
	req.MaxNames = order.Uint16(requestBody[0:2])
	nameLen := order.Uint16(requestBody[2:4])
	req.Pattern = string(requestBody[4 : 4+nameLen])
	return req
}

func parseCloseFontRequest(order binary.ByteOrder, requestBody []byte) *CloseFontRequest {
	req := &CloseFontRequest{}
	req.Fid = order.Uint32(requestBody[0:4])
	return req
}

func parseQueryFontRequest(order binary.ByteOrder, requestBody []byte) *QueryFontRequest {
	req := &QueryFontRequest{}
	req.Fid = order.Uint32(requestBody[0:4])
	return req
}

func parseFreeColorsRequest(order binary.ByteOrder, requestBody []byte) *FreeColorsRequest {
	req := &FreeColorsRequest{}
	req.Cmap = order.Uint32(requestBody[0:4])
	req.PlaneMask = order.Uint32(requestBody[4:8])
	numPixels := (len(requestBody) - 8) / 4
	for i := 0; i < numPixels; i++ {
		offset := 8 + i*4
		req.Pixels = append(req.Pixels, order.Uint32(requestBody[offset:offset+4]))
	}
	return req
}

func parseInstallColormapRequest(order binary.ByteOrder, requestBody []byte) *InstallColormapRequest {
	req := &InstallColormapRequest{}
	req.Cmap = order.Uint32(requestBody[0:4])
	return req
}

func parseUninstallColormapRequest(order binary.ByteOrder, requestBody []byte) *UninstallColormapRequest {
	req := &UninstallColormapRequest{}
	req.Cmap = order.Uint32(requestBody[0:4])
	return req
}

func parseListInstalledColormapsRequest(order binary.ByteOrder, requestBody []byte) *ListInstalledColormapsRequest {
	req := &ListInstalledColormapsRequest{}
	req.Window = order.Uint32(requestBody[0:4])
	return req
}

func parseInternAtomRequest(order binary.ByteOrder, requestBody []byte) *InternAtomRequest {
	req := &InternAtomRequest{}
	nameLen := order.Uint16(requestBody[0:2])
	req.Name = string(requestBody[4 : 4+nameLen])
	return req
}

func parseChangePropertyRequest(order binary.ByteOrder, requestBody []byte) *ChangePropertyRequest {
	req := &ChangePropertyRequest{}
	req.Window = order.Uint32(requestBody[0:4])
	req.Property = order.Uint32(requestBody[4:8])
	req.Type = order.Uint32(requestBody[8:12])
	req.Format = requestBody[12]
	dataLen := order.Uint32(requestBody[16:20])
	req.Data = requestBody[20 : 20+dataLen]
	return req
}

func parseCreateGCRequest(order binary.ByteOrder, requestBody []byte) *CreateGCRequest {
	req := &CreateGCRequest{}
	req.Cid = order.Uint32(requestBody[0:4])
	req.Drawable = order.Uint32(requestBody[4:8])
	req.ValueMask = order.Uint32(requestBody[8:12])
	req.Values, _ = parseGCValues(order, req.ValueMask, requestBody[12:])
	return req
}

func parseChangeGCRequest(order binary.ByteOrder, requestBody []byte) *ChangeGCRequest {
	req := &ChangeGCRequest{}
	req.Gc = order.Uint32(requestBody[0:4])
	req.ValueMask = order.Uint32(requestBody[4:8])
	req.Values, _ = parseGCValues(order, req.ValueMask, requestBody[8:])
	return req
}

func parseGCValues(order binary.ByteOrder, valueMask uint32, body []byte) (*GC, int) {
	gc := &GC{
		Function:   GXcopy,
		Foreground: 0,
		Background: 1,
	}
	read := 0
	if valueMask&GCFunction != 0 {
		gc.Function = order.Uint32(body[read : read+4])
		read += 4
	}
	if valueMask&GCPlaneMask != 0 {
		gc.PlaneMask = order.Uint32(body[read : read+4])
		read += 4
	}
	if valueMask&GCForeground != 0 {
		gc.Foreground = order.Uint32(body[read : read+4])
		read += 4
	}
	if valueMask&GCBackground != 0 {
		gc.Background = order.Uint32(body[read : read+4])
		read += 4
	}
	if valueMask&GCLineWidth != 0 {
		gc.LineWidth = order.Uint32(body[read : read+4])
		read += 4
	}
	if valueMask&GCLineStyle != 0 {
		gc.LineStyle = order.Uint32(body[read : read+4])
		read += 4
	}
	if valueMask&GCCapStyle != 0 {
		gc.CapStyle = order.Uint32(body[read : read+4])
		read += 4
	}
	if valueMask&GCJoinStyle != 0 {
		gc.JoinStyle = order.Uint32(body[read : read+4])
		read += 4
	}
	if valueMask&GCFillStyle != 0 {
		gc.FillStyle = order.Uint32(body[read : read+4])
		read += 4
	}
	if valueMask&GCFillRule != 0 {
		gc.FillRule = order.Uint32(body[read : read+4])
		read += 4
	}
	if valueMask&GCTile != 0 {
		gc.Tile = order.Uint32(body[read : read+4])
		read += 4
	}
	if valueMask&GCStipple != 0 {
		gc.Stipple = order.Uint32(body[read : read+4])
		read += 4
	}
	if valueMask&GCTileStipXOrigin != 0 {
		gc.TileStipXOrigin = order.Uint32(body[read : read+4])
		read += 4
	}
	if valueMask&GCTileStipYOrigin != 0 {
		gc.TileStipYOrigin = order.Uint32(body[read : read+4])
		read += 4
	}
	if valueMask&GCFont != 0 {
		gc.Font = order.Uint32(body[read : read+4])
		read += 4
	}
	if valueMask&GCSubwindowMode != 0 {
		gc.SubwindowMode = order.Uint32(body[read : read+4])
		read += 4
	}
	if valueMask&GCGraphicsExposures != 0 {
		gc.GraphicsExposures = order.Uint32(body[read : read+4])
		read += 4
	}
	if valueMask&GCClipXOrigin != 0 {
		gc.ClipXOrigin = int32(order.Uint32(body[read : read+4]))
		read += 4
	}
	if valueMask&GCClipYOrigin != 0 {
		gc.ClipYOrigin = int32(order.Uint32(body[read : read+4]))
		read += 4
	}
	if valueMask&GCClipMask != 0 {
		gc.ClipMask = order.Uint32(body[read : read+4])
		read += 4
	}
	if valueMask&GCDashOffset != 0 {
		gc.DashOffset = order.Uint32(body[read : read+4])
		read += 4
	}
	if valueMask&GCDashList != 0 {
		gc.Dashes = order.Uint32(body[read : read+4])
		read += 4
	}
	if valueMask&GCArcMode != 0 {
		gc.ArcMode = order.Uint32(body[read : read+4])
		read += 4
	}
	return gc, read
}

func parseCreatePixmapRequest(order binary.ByteOrder, payload []byte) *CreatePixmapRequest {
	req := &CreatePixmapRequest{}
	req.Pid = order.Uint32(payload[0:4])
	req.Drawable = order.Uint32(payload[4:8])
	req.Width = order.Uint16(payload[8:10])
	req.Height = order.Uint16(payload[10:12])
	return req
}

func parseWarpPointerRequest(order binary.ByteOrder, payload []byte) *WarpPointerRequest {
	req := &WarpPointerRequest{}
	req.DstX = int16(order.Uint16(payload[12:14]))
	req.DstY = int16(order.Uint16(payload[14:16]))
	return req
}

func parseAllowEventsRequest(order binary.ByteOrder, requestBody []byte) *AllowEventsRequest {
	req := &AllowEventsRequest{}
	req.Mode = requestBody[0]
	req.Time = order.Uint32(requestBody[4:8])
	return req
}

func parseOpenFontRequest(order binary.ByteOrder, requestBody []byte) *OpenFontRequest {
	req := &OpenFontRequest{}
	req.Fid = order.Uint32(requestBody[0:4])
	nameLen := order.Uint16(requestBody[4:6])
	req.Name = string(requestBody[8 : 8+nameLen])
	return req
}

func parseCreateColormapRequest(order binary.ByteOrder, payload []byte) *CreateColormapRequest {
	req := &CreateColormapRequest{}
	req.Alloc = payload[0]
	req.Mid = order.Uint32(payload[4:8])
	req.Window = order.Uint32(payload[8:12])
	req.Visual = order.Uint32(payload[12:16])
	return req
}

func parseAllocColorRequest(order binary.ByteOrder, payload []byte) *AllocColorRequest {
	req := &AllocColorRequest{}
	req.Cmap = order.Uint32(payload[0:4])
	req.Red = order.Uint16(payload[4:6])
	req.Green = order.Uint16(payload[6:8])
	req.Blue = order.Uint16(payload[8:10])
	return req
}

func parseLookupColorRequest(order binary.ByteOrder, payload []byte) *LookupColorRequest {
	req := &LookupColorRequest{}
	req.Cmap = order.Uint32(payload[0:4])
	nameLen := order.Uint16(payload[4:6])
	req.Name = string(payload[8 : 8+nameLen])
	return req
}

func parseAllocNamedColorRequest(order binary.ByteOrder, payload []byte) *AllocNamedColorRequest {
	req := &AllocNamedColorRequest{}
	req.Cmap = xID{local: order.Uint32(payload[0:4])}
	nameLen := order.Uint16(payload[4:6])
	req.Name = payload[8 : 8+nameLen]
	return req
}

func parseGetPropertyRequest(order binary.ByteOrder, requestBody []byte) *GetPropertyRequest {
	req := &GetPropertyRequest{}
	req.Window = order.Uint32(requestBody[0:4])
	req.Property = order.Uint32(requestBody[4:8])
	req.Delete = requestBody[8] != 0
	req.Offset = order.Uint32(requestBody[12:16])
	req.Length = order.Uint32(requestBody[16:20])
	return req
}

func parseBellRequest(requestBody byte) *BellRequest {
	req := &BellRequest{}
	req.Percent = int8(requestBody)
	return req
}

func parseFreePixmapRequest(order binary.ByteOrder, requestBody []byte) *FreePixmapRequest {
	req := &FreePixmapRequest{}
	req.Pid = order.Uint32(requestBody[0:4])
	return req
}

func parseMapWindowRequest(order binary.ByteOrder, requestBody []byte) *MapWindowRequest {
	req := &MapWindowRequest{}
	req.Window = order.Uint32(requestBody[0:4])
	return req
}

func parseUnmapWindowRequest(order binary.ByteOrder, requestBody []byte) *UnmapWindowRequest {
	req := &UnmapWindowRequest{}
	req.Window = order.Uint32(requestBody[0:4])
	return req
}
