//go:build x11

package x11

import (
	"bytes"
	"encoding/binary"
)


type xCharInfo struct {
	LeftSideBearing  int16
	RightSideBearing int16
	CharacterWidth   uint16
	Ascent           int16
	Descent          int16
	Attributes       uint16
}

type color struct {
	Red   uint16
	Green uint16
	Blue  uint16
}

func boolToByte(b bool) byte {
	if b {
		return 1
	}
	return 0
}

// getWindowAttributesReply implements messageEncoder for GetWindowAttributes reply.
type getWindowAttributesReply struct {
	sequence           uint16
	backingStore       byte
	visualID           uint32
	class              uint16
	bitGravity         byte
	winGravity         byte
	backingPlanes      uint32
	backingPixel       uint32
	saveUnder          bool
	mapped             bool
	mapState           byte
	overrideRedirect   bool
	colormap           uint32
	allEventMasks      uint32
	yourEventMask      uint32
	doNotPropagateMask uint16
}

func (r *getWindowAttributesReply) encodeMessage(order binary.ByteOrder) []byte {
	reply := make([]byte, 44)
	reply[0] = 1 // Reply type
	reply[1] = r.backingStore
	order.PutUint16(reply[2:4], r.sequence)
	order.PutUint32(reply[4:8], 3) // Reply length (3 * 4 bytes = 12 bytes, plus 32 bytes header = 44 bytes total)
	order.PutUint32(reply[8:12], r.visualID)
	order.PutUint16(reply[12:14], r.class)
	reply[14] = r.bitGravity
	reply[15] = r.winGravity
	order.PutUint32(reply[16:20], r.backingPlanes)
	order.PutUint32(reply[20:24], r.backingPixel)
	reply[24] = boolToByte(r.saveUnder)
	reply[25] = boolToByte(r.mapped)
	reply[26] = r.mapState
	reply[27] = boolToByte(r.overrideRedirect)
	order.PutUint32(reply[28:32], r.colormap)
	order.PutUint32(reply[32:36], r.allEventMasks)
	order.PutUint32(reply[36:40], r.yourEventMask)
	order.PutUint16(reply[40:42], r.doNotPropagateMask)
	// reply[42:44] is padding
	return reply
}

// getGeometryReply implements messageEncoder for GetGeometry reply.
type getGeometryReply struct {
	sequence      uint16
	depth         byte
	root          uint32
	x, y          int16
	width, height uint16
	borderWidth   uint16
}

func (r *getGeometryReply) encodeMessage(order binary.ByteOrder) []byte {
	reply := make([]byte, 32)
	reply[0] = 1 // Reply type
	reply[1] = r.depth
	order.PutUint16(reply[2:4], r.sequence)
	order.PutUint32(reply[4:8], 0) // Reply length (0 * 4 bytes = 0 bytes, plus 32 bytes header = 32 bytes total)
	order.PutUint32(reply[8:12], r.root)
	order.PutUint16(reply[12:14], uint16(r.x))
	order.PutUint16(reply[14:16], uint16(r.y))
	order.PutUint16(reply[16:18], r.width)
	order.PutUint16(reply[18:20], r.height)
	order.PutUint16(reply[20:22], r.borderWidth)
	// reply[22:32] is padding
	return reply
}

// internAtomReply implements messageEncoder for InternAtom reply.
type internAtomReply struct {
	sequence uint16
	atom     uint32
}

func (r *internAtomReply) encodeMessage(order binary.ByteOrder) []byte {
	reply := make([]byte, 32)
	reply[0] = 1 // Reply type
	// byte 1 is unused
	order.PutUint16(reply[2:4], r.sequence)
	order.PutUint32(reply[4:8], 0) // Reply length (0 * 4 bytes = 0 bytes, plus 32 bytes header = 32 bytes total)
	order.PutUint32(reply[8:12], r.atom)
	// reply[12:32] is padding
	return reply
}

// getAtomNameReply implements messageEncoder for GetAtomName reply.
type getAtomNameReply struct {
	sequence   uint16
	nameLength uint16
	name       string
}

func (r *getAtomNameReply) encodeMessage(order binary.ByteOrder) []byte {
	nameLen := len(r.name)
	p := (4 - (nameLen % 4)) % 4
	reply := make([]byte, 32+nameLen+p)
	reply[0] = 1 // Reply type
	// byte 1 is unused
	order.PutUint16(reply[2:4], r.sequence)
	order.PutUint32(reply[4:8], uint32((nameLen+p)/4)) // Reply length
	order.PutUint16(reply[8:10], uint16(nameLen))
	// reply[10:32] is padding
	copy(reply[32:], r.name)
	return reply
}

// getPropertyReply implements messageEncoder for GetProperty reply.
type getPropertyReply struct {
	sequence              uint16
	format                byte
	propertyType          uint32
	bytesAfter            uint32
	valueLenInFormatUnits uint32
	value                 []byte
}

func (r *getPropertyReply) encodeMessage(order binary.ByteOrder) []byte {
	n := len(r.value)
	p := (4 - (n % 4)) % 4
	replyLen := (n + p) / 4

	reply := make([]byte, 32+n+p)
	reply[0] = 1 // Reply type
	reply[1] = r.format
	order.PutUint16(reply[2:4], r.sequence)
	order.PutUint32(reply[4:8], uint32(replyLen)) // Reply length
	order.PutUint32(reply[8:12], r.propertyType)
	order.PutUint32(reply[12:16], r.bytesAfter)
	order.PutUint32(reply[16:20], r.valueLenInFormatUnits)
	// reply[20:32] is padding
	copy(reply[32:], r.value)
	return reply
}

// listPropertiesReply implements messageEncoder for ListProperties reply.
type listPropertiesReply struct {
	sequence      uint16
	numProperties uint16
	atoms         []uint32
}

func (r *listPropertiesReply) encodeMessage(order binary.ByteOrder) []byte {
	numAtoms := len(r.atoms)
	reply := make([]byte, 32+numAtoms*4)
	reply[0] = 1 // Reply type
	// byte 1 is unused
	order.PutUint16(reply[2:4], r.sequence)
	order.PutUint32(reply[4:8], uint32(numAtoms)) // Reply length
	order.PutUint16(reply[8:10], uint16(numAtoms))
	// reply[10:32] is padding
	for i, atom := range r.atoms {
		order.PutUint32(reply[32+i*4:], atom)
	}
	return reply
}

// getSelectionOwnerReply implements messageEncoder for GetSelectionOwner reply.
type getSelectionOwnerReply struct {
	sequence uint16
	owner    uint32
}

func (r *getSelectionOwnerReply) encodeMessage(order binary.ByteOrder) []byte {
	reply := make([]byte, 32)
	reply[0] = 1 // Reply type
	// byte 1 is unused
	order.PutUint16(reply[2:4], r.sequence)
	order.PutUint32(reply[4:8], 0) // Reply length (0 * 4 bytes = 0 bytes, plus 32 bytes header = 32 bytes total)
	order.PutUint32(reply[8:12], r.owner)
	// reply[12:32] is padding
	return reply
}

// grabPointerReply implements messageEncoder for GrabPointer reply.
type grabPointerReply struct {
	sequence uint16
	status   byte
}

func (r *grabPointerReply) encodeMessage(order binary.ByteOrder) []byte {
	reply := make([]byte, 32)
	reply[0] = 1 // Reply type
	reply[1] = r.status
	order.PutUint16(reply[2:4], r.sequence)
	order.PutUint32(reply[4:8], 0) // Reply length (0 * 4 bytes = 0 bytes, plus 32 bytes header = 32 bytes total)
	// reply[8:32] is padding
	return reply
}

// grabKeyboardReply implements messageEncoder for GrabKeyboard reply.
type grabKeyboardReply struct {
	sequence uint16
	status   byte
}

func (r *grabKeyboardReply) encodeMessage(order binary.ByteOrder) []byte {
	reply := make([]byte, 32)
	reply[0] = 1 // Reply type
	reply[1] = r.status
	order.PutUint16(reply[2:4], r.sequence)
	order.PutUint32(reply[4:8], 0) // Reply length (0 * 4 bytes = 0 bytes, plus 32 bytes header = 32 bytes total)
	// reply[8:32] is padding
	return reply
}

// queryPointerReply implements messageEncoder for QueryPointer reply.
type queryPointerReply struct {
	sequence     uint16
	sameScreen   bool
	root         uint32
	child        uint32
	rootX, rootY int16
	winX, winY   int16
	mask         uint16
}

func (r *queryPointerReply) encodeMessage(order binary.ByteOrder) []byte {
	reply := make([]byte, 32)
	reply[0] = 1 // Reply type
	reply[1] = boolToByte(r.sameScreen)
	order.PutUint16(reply[2:4], r.sequence)
	order.PutUint32(reply[4:8], 0) // Reply length (0 * 4 bytes = 0 bytes, plus 32 bytes header = 32 bytes total)
	order.PutUint32(reply[8:12], r.root)
	order.PutUint32(reply[12:16], r.child)
	order.PutUint16(reply[16:18], uint16(r.rootX))
	order.PutUint16(reply[18:20], uint16(r.rootY))
	order.PutUint16(reply[20:22], uint16(r.winX))
	order.PutUint16(reply[22:24], uint16(r.winY))
	order.PutUint16(reply[24:26], r.mask)
	// reply[26:32] is padding
	return reply
}

// translateCoordsReply implements messageEncoder for TranslateCoords reply.
type translateCoordsReply struct {
	sequence   uint16
	sameScreen bool
	child      uint32
	dstX, dstY int16
}

func (r *translateCoordsReply) encodeMessage(order binary.ByteOrder) []byte {
	reply := make([]byte, 32)
	reply[0] = 1 // Reply type
	reply[1] = boolToByte(r.sameScreen)
	order.PutUint16(reply[2:4], r.sequence)
	order.PutUint32(reply[4:8], 0) // Reply length (0 * 4 bytes = 0 bytes, plus 32 bytes header = 32 bytes total)
	order.PutUint32(reply[8:12], r.child)
	order.PutUint16(reply[12:14], uint16(r.dstX))
	order.PutUint16(reply[14:16], uint16(r.dstY))
	// reply[16:32] is padding
	return reply
}

// getInputFocusReply implements messageEncoder for GetInputFocus reply.
type getInputFocusReply struct {
	sequence uint16
	revertTo byte
	focus    uint32
}

func (r *getInputFocusReply) encodeMessage(order binary.ByteOrder) []byte {
	reply := make([]byte, 32)
	reply[0] = 1 // Reply type
	reply[1] = r.revertTo
	order.PutUint16(reply[2:4], r.sequence)
	order.PutUint32(reply[4:8], 0) // Reply length (0 * 4 bytes = 0 bytes, plus 32 bytes header = 32 bytes total)
	order.PutUint32(reply[8:12], r.focus)
	// reply[12:32] is padding
	return reply
}

// queryFontReply implements messageEncoder for QueryFont reply.
type queryFontReply struct {
	sequence       uint16
	minBounds      xCharInfo
	maxBounds      xCharInfo
	minCharOrByte2 uint16
	maxCharOrByte2 uint16
	defaultChar    uint16
	numFontProps   uint16
	drawDirection  uint8
	minByte1       uint8
	maxByte1       uint8
	allCharsExist  bool
	fontAscent     int16
	fontDescent    int16
	numCharInfos   uint32
	charInfos      []xCharInfo
}

func (r *queryFontReply) encodeMessage(order binary.ByteOrder) []byte {
	numFontProps := 0 // Not implemented yet
	numCharInfos := len(r.charInfos)

	reply := make([]byte, 60+8*numFontProps+12*numCharInfos)
	reply[0] = 1 // Reply
	reply[1] = 1 // font-info-present (True)
	order.PutUint16(reply[2:4], r.sequence)
	order.PutUint32(reply[4:8], uint32(7+2*numFontProps+3*numCharInfos)) // Reply length

	// min-bounds
	order.PutUint16(reply[8:10], uint16(r.minBounds.LeftSideBearing))
	order.PutUint16(reply[10:12], uint16(r.minBounds.RightSideBearing))
	order.PutUint16(reply[12:14], uint16(r.minBounds.CharacterWidth))
	order.PutUint16(reply[14:16], uint16(r.minBounds.Ascent))
	order.PutUint16(reply[16:18], uint16(r.minBounds.Descent))
	order.PutUint16(reply[18:20], r.minBounds.Attributes)

	// max-bounds
	order.PutUint16(reply[24:26], uint16(r.maxBounds.LeftSideBearing))
	order.PutUint16(reply[26:28], uint16(r.maxBounds.RightSideBearing))
	order.PutUint16(reply[28:30], uint16(r.maxBounds.CharacterWidth))
	order.PutUint16(reply[30:32], uint16(r.maxBounds.Ascent))
	order.PutUint16(reply[32:34], uint16(r.maxBounds.Descent))
	order.PutUint16(reply[34:36], r.maxBounds.Attributes)

	order.PutUint16(reply[40:42], r.minCharOrByte2)
	order.PutUint16(reply[42:44], r.maxCharOrByte2)
	order.PutUint16(reply[44:46], r.defaultChar)
	order.PutUint16(reply[46:48], uint16(numFontProps))

	reply[48] = r.drawDirection & 0x1
	reply[49] = r.minByte1
	reply[50] = r.maxByte1
	reply[51] = boolToByte(r.allCharsExist)

	order.PutUint16(reply[52:54], uint16(r.fontAscent))
	order.PutUint16(reply[54:56], uint16(r.fontDescent))

	order.PutUint32(reply[56:60], uint32(numCharInfos))

	offset := 60 + 8*numFontProps
	for _, ci := range r.charInfos {
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

// listFontsReply implements messageEncoder for ListFonts reply.
type listFontsReply struct {
	sequence  uint16
	numFonts  uint16
	fontNames []string
}

func (r *listFontsReply) encodeMessage(order binary.ByteOrder) []byte {
	var namesData []byte
	for _, name := range r.fontNames {
		namesData = append(namesData, byte(len(name)))
		namesData = append(namesData, []byte(name)...)
	}

	namesSize := len(namesData)
	padSize := (4 - (namesSize % 4)) % 4

	reply := make([]byte, 32+namesSize+padSize)
	reply[0] = 1 // Reply
	// byte 1 is unused
	order.PutUint16(reply[2:4], r.sequence)
	order.PutUint32(reply[4:8], uint32((namesSize+padSize)/4)) // Reply length
	order.PutUint16(reply[8:10], uint16(len(r.fontNames)))
	// reply[10:32] is padding
	copy(reply[32:], namesData)
	return reply
}

// getImageReply implements messageEncoder for GetImage reply.
type getImageReply struct {
	sequence  uint16
	depth     byte
	visualID  uint32
	imageData []byte
}

func (r *getImageReply) encodeMessage(order binary.ByteOrder) []byte {
	reply := make([]byte, 32+len(r.imageData))
	reply[0] = 1 // Reply type
	reply[1] = r.depth
	order.PutUint16(reply[2:4], r.sequence)
	order.PutUint32(reply[4:8], uint32(len(r.imageData)/4)) // Reply length
	order.PutUint32(reply[8:12], r.visualID)
	// reply[12:32] is padding
	copy(reply[32:], r.imageData)
	return reply
}

// listInstalledColormapsReply implements messageEncoder for ListInstalledColormaps reply.
type listInstalledColormapsReply struct {
	sequence     uint16
	numColormaps uint16
	colormaps    []uint32
}

func (r *listInstalledColormapsReply) encodeMessage(order binary.ByteOrder) []byte {
	nColormaps := len(r.colormaps)
	reply := make([]byte, 32+nColormaps*4)
	reply[0] = 1 // Reply
	// byte 1 is unused
	order.PutUint16(reply[2:4], r.sequence)
	order.PutUint32(reply[4:8], uint32(nColormaps)) // length
	order.PutUint16(reply[8:10], uint16(nColormaps))
	// reply[10:32] is padding
	for i, cmap := range r.colormaps {
		order.PutUint32(reply[32+i*4:], cmap)
	}
	return reply
}

// allocColorReply implements messageEncoder for AllocColor reply.
type allocColorReply struct {
	sequence uint16
	red      uint16
	green    uint16
	blue     uint16
	pixel    uint32
}

func (r *allocColorReply) encodeMessage(order binary.ByteOrder) []byte {
	reply := make([]byte, 32)
	reply[0] = 1 // Reply type
	// byte 1 is unused
	order.PutUint16(reply[2:4], r.sequence)
	order.PutUint32(reply[4:8], 0) // Reply length (0 * 4 bytes = 0 bytes, plus 32 bytes header = 32 bytes total)
	order.PutUint16(reply[8:10], r.red)
	order.PutUint16(reply[10:12], r.green)
	order.PutUint16(reply[12:14], r.blue)
	// reply[14:16] is padding
	order.PutUint32(reply[8:12], r.pixel)
	// reply[20:32] is padding
	return reply
}

// queryColorsReply implements messageEncoder for QueryColors reply.
type queryColorsReply struct {
	sequence uint16
	colors   []color
}

func (r *queryColorsReply) encodeMessage(order binary.ByteOrder) []byte {
	numColors := len(r.colors)
	replies := make([]byte, numColors*8)
	for i, color := range r.colors {
		order.PutUint16(replies[i*8:], color.Red)
		order.PutUint16(replies[i*8+2:], color.Green)
		order.PutUint16(replies[i*8+4:], color.Blue)
		// replies[i*8+6:i*8+8] unused
	}

	reply := make([]byte, 32+len(replies))
	reply[0] = 1 // Reply
	// byte 1 is unused
	order.PutUint16(reply[2:4], r.sequence)
	order.PutUint32(reply[4:8], uint32(len(replies)/4)) // Reply length
	order.PutUint16(reply[8:10], uint16(numColors))
	// reply[10:32] is padding
	copy(reply[32:], replies)
	return reply
}

// lookupColorReply implements messageEncoder for LookupColor reply.
type lookupColorReply struct {
	sequence   uint16
	red        uint16
	green      uint16
	blue       uint16
	exactRed   uint16
	exactGreen uint16
	exactBlue  uint16
}

func (r *lookupColorReply) encodeMessage(order binary.ByteOrder) []byte {
	reply := make([]byte, 32)
	reply[0] = 1 // Reply type
	// byte 1 is unused
	order.PutUint16(reply[2:4], r.sequence)
	order.PutUint32(reply[4:8], 0) // Reply length (0 * 4 bytes = 0 bytes, plus 32 bytes header = 32 bytes total)
	order.PutUint16(reply[8:10], r.red)
	order.PutUint16(reply[10:12], r.green)
	order.PutUint16(reply[12:14], r.blue)
	order.PutUint16(reply[14:16], r.exactRed)
	order.PutUint16(reply[16:18], r.exactGreen)
	order.PutUint16(reply[18:20], r.exactBlue)
	// reply[20:32] is padding
	return reply
}

// queryBestSizeReply implements messageEncoder for QueryBestSize reply.
type queryBestSizeReply struct {
	sequence uint16
	width    uint16
	height   uint16
}

func (r *queryBestSizeReply) encodeMessage(order binary.ByteOrder) []byte {
	reply := make([]byte, 32)
	reply[0] = 1 // Reply type
	// byte 1 is unused
	order.PutUint16(reply[2:4], r.sequence)
	order.PutUint32(reply[4:8], 0) // Reply length (0 * 4 bytes = 0 bytes, plus 32 bytes header = 32 bytes total)
	order.PutUint16(reply[8:10], r.width)
	order.PutUint16(reply[10:12], r.height)
	// reply[12:32] is padding
	return reply
}

// queryExtensionReply implements messageEncoder for QueryExtension reply.
type queryExtensionReply struct {
	sequence    uint16
	present     bool
	majorOpcode byte
	firstEvent  byte
	firstError  byte
}

func (r *queryExtensionReply) encodeMessage(order binary.ByteOrder) []byte {
	reply := make([]byte, 32)
	reply[0] = 1 // Reply type
	reply[1] = boolToByte(r.present)
	order.PutUint16(reply[2:4], r.sequence)
	order.PutUint32(reply[4:8], 0) // Reply length (0 * 4 bytes = 0 bytes, plus 32 bytes header = 32 bytes total)
	reply[8] = r.majorOpcode
	reply[9] = r.firstEvent
	reply[10] = r.firstError
	// reply[11:32] is padding
	return reply
}

// setupResponse implements messageEncoder for the X11 setup response.
type setupResponse struct {
	success                  byte
	protocolVersion          uint16
	releaseNumber            uint32
	resourceIDBase           uint32
	resourceIDMask           uint32
	motionBufferSize         uint32
	vendorLength             uint16
	maxRequestLength         uint16
	numScreens               uint8
	numPixmapFormats         uint8
	imageByteOrder           uint8
	bitmapFormatBitOrder     byte
	bitmapFormatScanlineUnit byte
	bitmapFormatScanlinePad  byte
	minKeycode               uint8
	maxKeycode               uint8
	vendorString             string
	pixmapFormats            []format
	screens                  []screen
}

func (r *setupResponse) encodeMessage(order binary.ByteOrder) []byte {
	setup := newDefaultSetup() // This should probably be passed in or generated once
	setupData := setup.marshal(order)

	response := make([]byte, 8+len(setupData))
	response[0] = r.success
	// byte 1 is unused
	order.PutUint16(response[2:4], r.protocolVersion)
	order.PutUint16(response[4:6], 0) // length of additional data in 4-byte units
	order.PutUint16(response[6:8], uint16(len(setupData)/4))
	copy(response[8:], setupData)
	return response
}

// Start of setup struct
type setup struct {
	releaseNumber            uint32
	resourceIDBase           uint32
	resourceIDMask           uint32
	motionBufferSize         uint32
	vendorLength             uint16
	maxRequestLength         uint16
	numScreens               uint8
	numPixmapFormats         uint8
	imageByteOrder           uint8
	bitmapFormatBitOrder     uint8
	bitmapFormatScanlineUnit uint8
	bitmapFormatScanlinePad  uint8
	minKeycode               uint8
	maxKeycode               uint8
	vendorString             string
	pixmapFormats            []format
	screens                  []screen
}

type format struct {
	depth        uint8
	bitsPerPixel uint8
	scanlinePad  uint8
}

type screen struct {
	root                uint32
	defaultColormap     uint32
	whitePixel          uint32
	blackPixel          uint32
	currentInputMasks   uint32
	widthInPixels       uint16
	heightInPixels      uint16
	widthInMillimeters  uint16
	heightInMillimeters uint16
	minInstalledMaps    uint16
	maxInstalledMaps    uint16
	rootVisual          uint32
	backingStores       uint8
	saveUnders          bool
	rootDepth           uint8
	numDepths           uint8
	depths              []depth
}

type depth struct {
	depth      uint8
	numVisuals uint16
	visuals    []visualType
}

type visualType struct {
	visualID        uint32 // visual-id
	class           uint8
	bitsPerRGBValue uint8
	colormapEntries uint16
	redMask         uint32
	greenMask       uint32
	blueMask        uint32
}

func newDefaultSetup() *setup {
	vendorString := "sshterm"
	s := &setup{
		releaseNumber:            1,
		resourceIDBase:           0,
		resourceIDMask:           0x1FFFFF,
		motionBufferSize:         256,
		vendorLength:             uint16(len(vendorString)),
		maxRequestLength:         0xFFFF,
		numScreens:               1,
		numPixmapFormats:         1,
		imageByteOrder:           0, // LSBFirst
		bitmapFormatBitOrder:     0, // LeastSignificant
		bitmapFormatScanlineUnit: 8,
		bitmapFormatScanlinePad:  8,
		minKeycode:               8,
		maxKeycode:               255,
		vendorString:             vendorString,
		pixmapFormats: []format{
			{
				depth:        24,
				bitsPerPixel: 32,
				scanlinePad:  32,
			},
		},
		screens: []screen{
			{
				root:                0,
				defaultColormap:     1,
				whitePixel:          0xffffff,
				blackPixel:          0x000000,
				currentInputMasks:   0,
				widthInPixels:       1024,
				heightInPixels:      768,
				widthInMillimeters:  270,
				heightInMillimeters: 203,
				minInstalledMaps:    1,
				maxInstalledMaps:    1,
				rootVisual:          0x1,
				backingStores:       2, // Always
				saveUnders:          false,
				rootDepth:           24,
				numDepths:           1,
				depths: []depth{
					{
						depth:      24,
						numVisuals: 1,
						visuals: []visualType{
							{
								visualID:        0x1,
								class:           4, // TrueColor
								bitsPerRGBValue: 8,
								colormapEntries: 256,
								redMask:         0xff0000,
								greenMask:       0x00ff00,
								blueMask:        0x0000ff,
							},
						},
					},
				},
			},
		},
	}
	return s
}

func (s *setup) marshal(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, order, s.releaseNumber)
	binary.Write(buf, order, s.resourceIDBase)
	binary.Write(buf, order, s.resourceIDMask)
	binary.Write(buf, order, s.motionBufferSize)
	binary.Write(buf, order, s.vendorLength)
	binary.Write(buf, order, s.maxRequestLength)
	buf.WriteByte(s.numScreens)
	buf.WriteByte(s.numPixmapFormats)
	buf.WriteByte(s.imageByteOrder)
	buf.WriteByte(s.bitmapFormatBitOrder)
	buf.WriteByte(s.bitmapFormatScanlineUnit)
	buf.WriteByte(s.bitmapFormatScanlinePad)
	buf.WriteByte(s.minKeycode)
	buf.WriteByte(s.maxKeycode)
	buf.Write([]byte{0, 0, 0, 0}) // 4 bytes of padding
	buf.WriteString(s.vendorString)
	if pad := (4 - (len(s.vendorString) % 4)) % 4; pad > 0 {
		buf.Write(make([]byte, pad))
	}
	for _, f := range s.pixmapFormats {
		f.marshal(buf, order)
	}
	for _, scr := range s.screens {
		scr.marshal(buf, order)
	}
	return buf.Bytes()
}

func (f *format) marshal(buf *bytes.Buffer, order binary.ByteOrder) {
	buf.WriteByte(f.depth)
	buf.WriteByte(f.bitsPerPixel)
	buf.WriteByte(f.scanlinePad)
	buf.Write([]byte{0, 0, 0, 0, 0}) // 5 bytes of padding
}

func (s *screen) marshal(buf *bytes.Buffer, order binary.ByteOrder) {
	binary.Write(buf, order, s.root)
	binary.Write(buf, order, s.defaultColormap)
	binary.Write(buf, order, s.whitePixel)
	binary.Write(buf, order, s.blackPixel)
	binary.Write(buf, order, s.currentInputMasks)
	binary.Write(buf, order, s.widthInPixels)
	binary.Write(buf, order, s.heightInPixels)
	binary.Write(buf, order, s.widthInMillimeters)
	binary.Write(buf, order, s.heightInMillimeters)
	binary.Write(buf, order, s.minInstalledMaps)
	binary.Write(buf, order, s.maxInstalledMaps)
	binary.Write(buf, order, s.rootVisual)
	buf.WriteByte(s.backingStores)
	if s.saveUnders {
		buf.WriteByte(1)
	} else {
		buf.WriteByte(0)
	}
	buf.WriteByte(s.rootDepth)
	buf.WriteByte(s.numDepths)
	for _, d := range s.depths {
		d.marshal(buf, order)
	}
}

func (d *depth) marshal(buf *bytes.Buffer, order binary.ByteOrder) {
	buf.WriteByte(d.depth)
	buf.WriteByte(0) // padding
	binary.Write(buf, order, d.numVisuals)
	buf.Write([]byte{0, 0, 0, 0}) // 4 bytes of padding
	for _, v := range d.visuals {
		v.marshal(buf, order)
	}
}

func (v *visualType) marshal(buf *bytes.Buffer, order binary.ByteOrder) {
	binary.Write(buf, order, v.visualID)
	buf.WriteByte(v.class)
	buf.WriteByte(v.bitsPerRGBValue)
	binary.Write(buf, order, v.colormapEntries)
	binary.Write(buf, order, v.redMask)
	binary.Write(buf, order, v.greenMask)
	binary.Write(buf, order, v.blueMask)
	buf.Write([]byte{0, 0, 0, 0}) // 4 bytes of padding
}
