//go:build x11

package x11

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"runtime/debug"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/c2FmZQ/sshterm/internal/x11/wire"
)

var errParseError = errors.New("x11: request parsing error")

const (
	clientIDBits    = 12
	localIDBits     = 20
	clientIDMask    = (1 << clientIDBits) - 1
	localIDMask     = (1 << localIDBits) - 1
	maxClients      = 1 << clientIDBits
	maxLocalIDs     = 1 << localIDBits
	resourceIDShift = localIDBits
)

var (
	x11ServerInstance *x11Server
	once              sync.Once
)

func Enabled() bool {
	return true
}

// xID is a resource identifier.
type xID uint32

func (xid xID) String() string {
	return fmt.Sprintf("%d-%d", (xid>>localIDBits)&clientIDMask, xid&localIDMask)
}

// Logger is the interface for logging.
type Logger interface {
	Errorf(format string, args ...interface{})
	Infof(format string, args ...interface{})
	Printf(format string, args ...interface{})
}

// X11FrontendAPI is the interface for the X11 frontend.
type X11FrontendAPI interface {
	CreateWindow(xid xID, parent xID, x, y int32, width, height, depth, valueMask uint32, values wire.WindowAttributes)
	ChangeWindowAttributes(xid xID, valueMask uint32, values wire.WindowAttributes)
	GetWindowAttributes(xid xID) wire.WindowAttributes
	CreateGC(xid xID, valueMask uint32, values wire.GC)
	ChangeGC(xid xID, valueMask uint32, gc wire.GC)
	DestroyWindow(xid xID)
	ReparentWindow(window xID, parent xID, x, y int16)
	DestroySubwindows(xid xID)
	DestroyAllWindowsForClient(clientID uint32)
	MapWindow(xid xID)
	UnmapWindow(xid xID)
	ConfigureWindow(xid xID, valueMask uint16, values []uint32)
	CirculateWindow(xid xID, direction byte)
	PutImage(drawable xID, gcID xID, format uint8, width, height uint16, dstX, dstY int16, leftPad, depth uint8, data []byte)
	PolyLine(drawable xID, gcID xID, points []uint32)
	PolyFillRectangle(drawable xID, gcID xID, rects []uint32)
	FillPoly(drawable xID, gcID xID, points []uint32)
	PolySegment(drawable xID, gcID xID, segments []uint32)
	PolyPoint(drawable xID, gcID xID, points []uint32)
	PolyRectangle(drawable xID, gcID xID, rects []uint32)
	PolyArc(drawable xID, gcID xID, arcs []uint32)
	PolyFillArc(drawable xID, gcID xID, arcs []uint32)
	ClearArea(drawable xID, x, y, width, height int32)
	CopyArea(srcDrawable, dstDrawable xID, gcID xID, srcX, srcY, dstX, dstY, width, height int32)
	CopyPlane(srcDrawable, dstDrawable xID, gcID xID, srcX, srcY, dstX, dstY, width, height, bitPlane int32)
	GetImage(drawable xID, x, y, width, height int32, format uint32) ([]byte, error)
	ReadClipboard() (string, error)
	WriteClipboard(string) error
	UpdatePointerPosition(x, y int16)
	Bell(percent int8)
	SetInputFocus(focus xID, revertTo byte)
	ImageText8(drawable xID, gcID xID, x, y int32, text []byte)
	ImageText16(drawable xID, gcID xID, x, y int32, text []uint16)
	PolyText8(drawable xID, gcID xID, x, y int32, items []wire.PolyTextItem)
	PolyText16(drawable xID, gcID xID, x, y int32, items []wire.PolyTextItem)
	CreatePixmap(xid, drawable xID, width, height, depth uint32)
	FreePixmap(xid xID)
	CopyPixmap(srcID, dstID, gcID xID, srcX, srcY, width, height, dstX, dstY uint32)
	CreateCursor(cursorID xID, source, mask xID, foreColor, backColor [3]uint16, x, y uint16)
	CreateCursorFromGlyph(cursorID xID, sourceFont xID, sourceChar uint16, maskFont xID, maskChar uint16, foreColor, backColor [3]uint16)
	SetWindowCursor(windowID xID, cursorID xID)
	CopyGC(srcGC, dstGC xID)
	FreeGC(gc xID)
	FreeCursor(cursorID xID)
	SendEvent(eventData messageEncoder)
	GetFocusWindow(clientID uint32) xID
	SetWindowTitle(xid xID, title string)
	GrabPointer(grabWindow xID, ownerEvents bool, eventMask uint16, pointerMode, keyboardMode byte, confineTo uint32, cursor uint32, time uint32) byte
	UngrabPointer(time uint32)
	GrabKeyboard(grabWindow xID, ownerEvents bool, time uint32, pointerMode, keyboardMode byte) byte
	UngrabKeyboard(time uint32)
	WarpPointer(x, y int16)
	GetCanvasOperations() []CanvasOperation
	GetRGBColor(colormap xID, pixel uint32) (r, g, b uint8)
	OpenFont(fid xID, name string)
	QueryFont(fid xID) (minBounds, maxBounds wire.XCharInfo, minCharOrByte2, maxCharOrByte2, defaultChar uint16, drawDirection uint8, minByte1, maxByte1 uint8, allCharsExist bool, fontAscent, fontDescent int16, charInfos []wire.XCharInfo, fontProps []wire.FontProp)
	QueryTextExtents(font xID, text []uint16) (drawDirection uint8, fontAscent, fontDescent, overallAscent, overallDescent, overallWidth, overallLeft, overallRight int16)
	CloseFont(fid xID)
	ListFonts(maxNames uint16, pattern string) []string
	AllowEvents(clientID uint32, mode byte, time uint32)
	SetDashes(gc xID, dashOffset uint16, dashes []byte)
	SetClipRectangles(gc xID, clippingX, clippingY int16, rectangles []wire.Rectangle, ordering byte)
	RecolorCursor(cursor xID, foreColor, backColor [3]uint16)
	QueryBestSize(class byte, drawable xID, width, height uint16) (rwidth, rheight uint16)
	SetPointerMapping(pMap []byte) (byte, error)
	GetPointerMapping() ([]byte, error)
	GetPointerControl() (accelNumerator, accelDenominator, threshold uint16, err error)
	ChangePointerControl(accelNum, accelDenom, threshold int16, doAccel, doThresh bool)
	ChangeKeyboardControl(valueMask uint32, values wire.KeyboardControl)
	GetKeyboardControl() (wire.KeyboardControl, error)
	SetScreenSaver(timeout, interval int16, preferBlank, allowExpose byte)
	GetScreenSaver() (timeout, interval int16, preferBlank, allowExpose byte, err error)
	ChangeHosts(mode byte, host wire.Host)
	ListHosts() ([]wire.Host, error)
	SetAccessControl(mode byte)
	SetCloseDownMode(mode byte)
	KillClient(resource uint32)
	ForceScreenSaver(mode byte)
	SetModifierMapping(keyCodesPerModifier byte, keyCodes []wire.KeyCode) (byte, error)
	GetModifierMapping() ([]wire.KeyCode, error)
	DeviceBell(deviceID byte, feedbackID byte, feedbackClass byte, percent int8)
	XIChangeHierarchy(changes []wire.XIChangeHierarchyChange)
	ChangeFeedbackControl(deviceID byte, feedbackID byte, mask uint32, control []byte)
	ChangeDeviceKeyMapping(deviceID byte, firstKey byte, keysymsPerKeycode byte, keycodeCount byte, keysyms []uint32)
	SetDeviceModifierMapping(deviceID byte, keycodes []byte) byte
	SetDeviceButtonMapping(deviceID byte, buttonMap []byte) byte
	GetFeedbackControl(deviceID byte) []wire.FeedbackState
	GetDeviceKeyMapping(deviceID byte, firstKey byte, count byte) (byte, []uint32)
	GetDeviceModifierMapping(deviceID byte) (byte, []byte)
	GetDeviceButtonMapping(deviceID byte) []byte
	QueryDeviceState(deviceID byte) []wire.InputClassInfo
	ComposeWindow(xid xID)
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

type window struct {
	xid                       xID
	parent                    xID
	x, y                      int16
	width, height             uint16
	borderWidth               uint16
	mapped                    bool
	depth                     byte
	children                  []xID
	attributes                wire.WindowAttributes
	colormap                  xID
	dontPropagateDeviceEvents map[uint32]bool
	visual                    uint32
}

func (w *window) mapState() byte {
	if !w.mapped {
		return 0 // Unmapped
	}
	return 2 // Viewable
}

type colormap struct {
	visual    wire.VisualType
	pixels    map[uint32]wire.XColorItem
	allocated []bool   // Track if a cell is allocated
	clientID  []uint32 // Track which client allocated the cell
	writable  []bool   // Track if a cell is writable (allocated via AllocColorCells/Planes)
}

type property struct {
	data     []byte
	typeAtom uint32
	format   byte
}

type selectionOwner struct {
	window xID
	time   uint32
}

type DeviceButtonPressEventData struct {
	Event  uint32
	RootX  uint16
	RootY  uint16
	EventX uint16
	EventY uint16
}

type pixmap struct {
	width  uint16
	height uint16
	depth  byte
}

type motionEvent struct {
	time   uint32
	x, y   int16
	window xID
}

type x11Server struct {
	logger                Logger
	byteOrder             binary.ByteOrder
	frontend              X11FrontendAPI
	config                wire.ServerConfig
	windows               map[xID]*window
	windowStack           []xID
	gcs                   map[xID]wire.GC
	pixmaps               map[xID]*pixmap
	cursors               map[xID]bool
	selections            map[uint32]*selectionOwner
	atoms                 map[string]uint32
	atomNames             map[uint32]string
	nextAtomID            uint32
	properties            map[xID]map[uint32]*property
	colormaps             map[xID]*colormap
	defaultColormap       uint32
	installedColormap     xID
	visualID              uint32
	visuals               map[uint32]wire.VisualType
	rootVisual            wire.VisualType
	blackPixel            uint32
	whitePixel            uint32
	pointerX, pointerY    int16
	clients               map[uint32]*x11Client
	nextClientID          uint32
	pointerGrabWindow     xID
	keyboardGrabWindow    xID
	pointerGrabClientID   uint32
	keyboardGrabClientID  uint32
	pointerGrabTime       uint32
	keyboardGrabTime      uint32
	pointerGrabOwner      bool
	keyboardGrabOwner     bool
	pointerGrabEventMask  uint16
	keyboardGrabEventMask uint32
	inputFocus            xID
	passiveGrabs          map[xID][]*passiveGrab
	passiveDeviceGrabs    map[xID][]*passiveDeviceGrab
	deviceGrabs           map[byte]*deviceGrab // device id -> grab info
	authProtocol          string
	authCookie            []byte
	serverGrabbed         bool
	grabbingClientID      uint32
	fontPath              []string
	keymap                map[byte][]uint32
	pointerState          uint16
	startTime             time.Time
	pointerGrabMode       byte
	keyboardGrabMode      byte
	pointerGrabConfineTo  xID
	pointerGrabCursor     xID
	fonts                 map[xID]bool
	requestHandlers       map[wire.ReqCode]requestHandler
	motionEvents          []motionEvent
	pressedKeys           map[byte]bool
	dirtyDrawables        map[xID]bool

	pointerFrozen      bool
	keyboardFrozen     bool
	pointerEventQueue  []queuedEvent
	keyboardEventQueue []queuedEvent
}

type queuedEvent struct {
	client *x11Client
	event  messageEncoder
}

type requestHandler func(client *x11Client, req wire.Request, seq uint16) messageEncoder

func (s *x11Server) initRequestHandlers() {
	s.requestHandlers = map[wire.ReqCode]requestHandler{
		wire.CreateWindow:            s.handleCreateWindow,
		wire.ChangeWindowAttributes:  s.handleChangeWindowAttributes,
		wire.GetWindowAttributes:     s.handleGetWindowAttributes,
		wire.DestroyWindow:           s.handleDestroyWindow,
		wire.DestroySubwindows:       s.handleDestroySubwindows,
		wire.ChangeSaveSet:           s.handleChangeSaveSet,
		wire.ReparentWindow:          s.handleReparentWindow,
		wire.MapWindow:               s.handleMapWindow,
		wire.MapSubwindows:           s.handleMapSubwindows,
		wire.UnmapWindow:             s.handleUnmapWindow,
		wire.UnmapSubwindows:         s.handleUnmapSubwindows,
		wire.ConfigureWindow:         s.handleConfigureWindow,
		wire.CirculateWindow:         s.handleCirculateWindow,
		wire.GetGeometry:             s.handleGetGeometry,
		wire.QueryTree:               s.handleQueryTree,
		wire.InternAtom:              s.handleInternAtom,
		wire.GetAtomName:             s.handleGetAtomName,
		wire.ChangeProperty:          s.handleChangeProperty,
		wire.DeleteProperty:          s.handleDeleteProperty,
		wire.GetProperty:             s.handleGetProperty,
		wire.ListProperties:          s.handleListProperties,
		wire.SetSelectionOwner:       s.handleSetSelectionOwner,
		wire.GetSelectionOwner:       s.handleGetSelectionOwner,
		wire.ConvertSelection:        s.handleConvertSelection,
		wire.SendEvent:               s.handleSendEvent,
		wire.GrabPointer:             s.handleGrabPointer,
		wire.UngrabPointer:           s.handleUngrabPointer,
		wire.GrabButton:              s.handleGrabButton,
		wire.UngrabButton:            s.handleUngrabButton,
		wire.ChangeActivePointerGrab: s.handleChangeActivePointerGrab,
		wire.GrabKeyboard:            s.handleGrabKeyboard,
		wire.UngrabKeyboard:          s.handleUngrabKeyboard,
		wire.GrabKey:                 s.handleGrabKey,
		wire.UngrabKey:               s.handleUngrabKey,
		wire.AllowEvents:             s.handleAllowEvents,
		wire.GrabServer:              s.handleGrabServer,
		wire.UngrabServer:            s.handleUngrabServer,
		wire.QueryPointer:            s.handleQueryPointer,
		wire.GetMotionEvents:         s.handleGetMotionEvents,
		wire.TranslateCoords:         s.handleTranslateCoords,
		wire.WarpPointer:             s.handleWarpPointer,
		wire.SetInputFocus:           s.handleSetInputFocus,
		wire.GetInputFocus:           s.handleGetInputFocus,
		wire.QueryKeymap:             s.handleQueryKeymap,
		wire.OpenFont:                s.handleOpenFont,
		wire.CloseFont:               s.handleCloseFont,
		wire.QueryFont:               s.handleQueryFont,
		wire.QueryTextExtents:        s.handleQueryTextExtents,
		wire.ListFonts:               s.handleListFonts,
		wire.ListFontsWithInfo:       s.handleListFontsWithInfo,
		wire.SetFontPath:             s.handleSetFontPath,
		wire.GetFontPath:             s.handleGetFontPath,
		wire.CreatePixmap:            s.handleCreatePixmap,
		wire.FreePixmap:              s.handleFreePixmap,
		wire.CreateGC:                s.handleCreateGC,
		wire.ChangeGC:                s.handleChangeGC,
		wire.CopyGC:                  s.handleCopyGC,
		wire.SetDashes:               s.handleSetDashes,
		wire.SetClipRectangles:       s.handleSetClipRectangles,
		wire.FreeGC:                  s.handleFreeGC,
		wire.ClearArea:               s.handleClearArea,
		wire.CopyArea:                s.handleCopyArea,
		wire.CopyPlane:               s.handleCopyPlane,
		wire.PolyPoint:               s.handlePolyPoint,
		wire.PolyLine:                s.handlePolyLine,
		wire.PolySegment:             s.handlePolySegment,
		wire.PolyRectangle:           s.handlePolyRectangle,
		wire.PolyArc:                 s.handlePolyArc,
		wire.FillPoly:                s.handleFillPoly,
		wire.PolyFillRectangle:       s.handlePolyFillRectangle,
		wire.PolyFillArc:             s.handlePolyFillArc,
		wire.PutImage:                s.handlePutImage,
		wire.GetImage:                s.handleGetImage,
		wire.PolyText8:               s.handlePolyText8,
		wire.PolyText16:              s.handlePolyText16,
		wire.ImageText8:              s.handleImageText8,
		wire.ImageText16:             s.handleImageText16,
		wire.CreateColormap:          s.handleCreateColormap,
		wire.FreeColormap:            s.handleFreeColormap,
		wire.CopyColormapAndFree:     s.handleCopyColormapAndFree,
		wire.InstallColormap:         s.handleInstallColormap,
		wire.UninstallColormap:       s.handleUninstallColormap,
		wire.ListInstalledColormaps:  s.handleListInstalledColormaps,
		wire.AllocColor:              s.handleAllocColor,
		wire.AllocNamedColor:         s.handleAllocNamedColor,
		wire.AllocColorCells:         s.handleAllocColorCells,
		wire.AllocColorPlanes:        s.handleAllocColorPlanes,
		wire.FreeColors:              s.handleFreeColors,
		wire.StoreColors:             s.handleStoreColors,
		wire.StoreNamedColor:         s.handleStoreNamedColor,
		wire.QueryColors:             s.handleQueryColors,
		wire.LookupColor:             s.handleLookupColor,
		wire.CreateCursor:            s.handleCreateCursor,
		wire.CreateGlyphCursor:       s.handleCreateGlyphCursor,
		wire.FreeCursor:              s.handleFreeCursor,
		wire.RecolorCursor:           s.handleRecolorCursor,
		wire.QueryBestSize:           s.handleQueryBestSize,
		wire.QueryExtension:          s.handleQueryExtension,
		wire.ListExtensions:          s.handleListExtensions,
		wire.ChangeKeyboardMapping:   s.handleChangeKeyboardMapping,
		wire.GetKeyboardMapping:      s.handleGetKeyboardMapping,
		wire.ChangeKeyboardControl:   s.handleChangeKeyboardControl,
		wire.GetKeyboardControl:      s.handleGetKeyboardControl,
		wire.Bell:                    s.handleBell,
		wire.ChangePointerControl:    s.handleChangePointerControl,
		wire.GetPointerControl:       s.handleGetPointerControl,
		wire.SetScreenSaver:          s.handleSetScreenSaver,
		wire.GetScreenSaver:          s.handleGetScreenSaver,
		wire.ChangeHosts:             s.handleChangeHosts,
		wire.ListHosts:               s.handleListHosts,
		wire.SetAccessControl:        s.handleSetAccessControl,
		wire.SetCloseDownMode:        s.handleSetCloseDownMode,
		wire.KillClient:              s.handleKillClient,
		wire.RotateProperties:        s.handleRotateProperties,
		wire.ForceScreenSaver:        s.handleForceScreenSaver,
		wire.SetPointerMapping:       s.handleSetPointerMapping,
		wire.GetPointerMapping:       s.handleGetPointerMapping,
		wire.SetModifierMapping:      s.handleSetModifierMapping,
		wire.GetModifierMapping:      s.handleGetModifierMapping,
		wire.NoOperation:             s.handleNoOperation,
		wire.BigRequestsOpcode:       s.handleEnableBigRequests,
	}
}

type passiveGrab struct {
	clientID     uint32
	button       byte
	key          wire.KeyCode
	modifiers    uint16
	owner        bool
	eventMask    uint16
	cursor       xID
	pointerMode  byte
	keyboardMode byte
	confineTo    xID
}

type passiveDeviceGrab struct {
	clientID     uint32
	deviceID     byte
	key          wire.KeyCode
	button       byte
	detail       uint32
	modifiers    uint16
	xi2Modifiers []uint32
	owner        bool
	eventMask    []uint32
	xi2EventMask []uint32
	xi2GrabType  int
}

type deviceGrab struct {
	clientID     uint32
	window       xID
	ownerEvents  bool
	eventMask    []uint32
	xi2EventMask []uint32
	time         uint32
}

var virtualPointer = &wire.DeviceInfo{
	Header: wire.DeviceHeader{
		DeviceID:   2,
		DeviceType: 0,
		NumClasses: 2,
		Use:        0, // IsXPointer
		Name:       "Virtual Pointer",
	},
	Classes: []wire.InputClassInfo{
		&wire.ButtonClassInfo{NumButtons: 5},
		&wire.ValuatorClassInfo{
			NumAxes:    2,
			Mode:       0, // Relative
			MotionSize: 0,
			Axes: []wire.ValuatorAxisInfo{
				{Min: 0, Max: 65535, Resolution: 1},
				{Min: 0, Max: 65535, Resolution: 1},
			},
		},
	},
}

var virtualKeyboard = &wire.DeviceInfo{
	Header: wire.DeviceHeader{
		DeviceID:   3,
		DeviceType: 0,
		NumClasses: 1,
		Use:        1, // IsXKeyboard
		Name:       "Virtual Keyboard",
	},
	Classes: []wire.InputClassInfo{
		&wire.KeyClassInfo{
			NumKeys:    248,
			MinKeycode: 8,
			MaxKeycode: 255,
		},
	},
}

func (s *x11Server) serverTime() uint32 {
	return uint32(time.Since(s.startTime).Milliseconds())
}

func (s *x11Server) UpdatePointerPosition(x, y int16) {
	s.pointerX = x
	s.pointerY = y
}

func (s *x11Server) getAbsoluteWindowCoords(xid xID) (int16, int16, bool) {
	w, ok := s.windows[xid]
	if !ok {
		return 0, 0, false
	}
	absX, absY := w.x, w.y
	for uint32(w.parent) != s.rootWindowID() {
		parentW, ok := s.windows[w.parent]
		if !ok {
			s.logger.Errorf("Could not find parent window object for %d", w.parent)
			break
		}
		absX += parentW.x
		absY += parentW.y
		w = parentW
	}
	return absX, absY, true
}

func (s *x11Server) findChildWindowAt(parentXID xID, x, y int16) xID {
	parent, ok := s.windows[parentXID]
	if !ok || !parent.mapped {
		return 0 // None
	}

	// Iterate backwards through the global window stack to find the topmost child.
	for i := len(s.windowStack) - 1; i >= 0; i-- {
		childXID := s.windowStack[i]
		child, ok := s.windows[childXID]

		// Ensure the window is valid, mapped, and actually a child of the target parent.
		if !ok || !child.mapped || child.parent != parentXID {
			continue
		}

		// Check if the pointer is within the child's bounds (relative to its parent).
		if x >= child.x && x < (child.x+int16(child.width)) &&
			y >= child.y && y < (child.y+int16(child.height)) {
			// The pointer is over this child. Recursively check its children.
			// The coordinates need to be made relative to the child for the recursive call.
			grandchildID := s.findChildWindowAt(childXID, x-child.x, y-child.y)
			if grandchildID != 0 {
				return grandchildID
			}
			// If no grandchild is found, this child is the target.
			return child.xid
		}
	}

	return 0 // No child found at these coordinates
}

func (s *x11Server) findDirectChildWindowAt(parentXID xID, x, y int16) xID {
	parent, ok := s.windows[parentXID]
	if !ok || !parent.mapped {
		return 0 // None
	}

	// Iterate backwards through the global window stack to find the topmost child.
	for i := len(s.windowStack) - 1; i >= 0; i-- {
		childXID := s.windowStack[i]
		child, ok := s.windows[childXID]

		// Ensure the window is valid, mapped, and actually a direct child of the target parent.
		if !ok || !child.mapped || child.parent != parentXID {
			continue
		}

		// Check if the pointer is within the child's bounds (relative to its parent).
		if x >= child.x && x < (child.x+int16(child.width)) &&
			y >= child.y && y < (child.y+int16(child.height)) {
			// This is the top-most direct child. Return it.
			return child.xid
		}
	}

	return 0 // No child found at these coordinates
}

func (s *x11Server) findTopLevelWindowAt(x, y int16) xID {
	// Iterate backwards through the window stack to check the top-most windows first.
	for i := len(s.windowStack) - 1; i >= 0; i-- {
		xid := s.windowStack[i]
		child, ok := s.windows[xid]
		if !ok || !child.mapped || uint32(child.parent) != s.rootWindowID() {
			continue
		}

		if x >= child.x && x < (child.x+int16(child.width)) &&
			y >= child.y && y < (child.y+int16(child.height)) {
			// This window contains the point. Check its children recursively.
			grandchildID := s.findChildWindowAt(child.xid, x-child.x, y-child.y)
			if grandchildID != 0 {
				return grandchildID
			}
			return child.xid
		}
	}
	return 0 // No child found
}

func (s *x11Server) GetWindowAttributes(xid xID) (wire.WindowAttributes, bool) {
	w, ok := s.windows[xid]
	if !ok {
		return wire.WindowAttributes{}, false
	}
	return w.attributes, true
}

func (s *x11Server) destroyWindow(xid xID, removeFromParent bool) {
	w, ok := s.windows[xid]
	if !ok {
		return
	}

	// Recursively destroy children
	for _, childID := range w.children {
		s.destroyWindow(childID, false)
	}

	if removeFromParent {
		if parent, ok := s.windows[w.parent]; ok {
			for i, childID := range parent.children {
				if childID == xid {
					parent.children = append(parent.children[:i], parent.children[i+1:]...)
					break
				}
			}
		}
	}

	delete(s.windows, xid)
	s.removeWindowFromStack(xid)
	s.frontend.DestroyWindow(xid)
}

func (s *x11Server) removeWindowFromStack(xid xID) {
	idx := -1
	for i, id := range s.windowStack {
		if id == xid {
			idx = i
			break
		}
	}
	if idx != -1 {
		s.windowStack = append(s.windowStack[:idx], s.windowStack[idx+1:]...)
	}
}

func (s *x11Server) checkWindow(xid xID, seq uint16, majorReq wire.ReqCode, minorReq byte) wire.Error {
	if uint32(xid) == s.rootWindowID() {
		return nil
	}
	if _, ok := s.windows[xid]; !ok {
		return wire.NewGenericError(seq, uint32(xid), minorReq, majorReq, wire.WindowErrorCode)
	}
	return nil
}

func (s *x11Server) checkClientID(xid xID, client *x11Client, seq uint16, majorReq wire.ReqCode, minorReq byte) wire.Error {
	if (uint32(xid)>>resourceIDShift)&clientIDMask != client.id {
		return wire.NewGenericError(seq, uint32(xid), minorReq, majorReq, wire.AccessErrorCode)
	}
	return nil
}

func (s *x11Server) checkPixmap(xid xID, seq uint16, majorReq wire.ReqCode, minorReq byte) wire.Error {
	if _, ok := s.pixmaps[xid]; !ok {
		return wire.NewGenericError(seq, uint32(xid), minorReq, majorReq, wire.PixmapErrorCode)
	}
	return nil
}

func (s *x11Server) checkDrawable(xid xID, seq uint16, majorReq wire.ReqCode, minorReq byte) wire.Error {
	if _, ok := s.windows[xid]; ok {
		return nil
	}
	if _, ok := s.pixmaps[xid]; ok {
		return nil
	}
	if uint32(xid) == s.rootWindowID() {
		return nil
	}
	return wire.NewGenericError(seq, uint32(xid), minorReq, majorReq, wire.DrawableErrorCode)
}

func (s *x11Server) checkGC(xid xID, seq uint16, majorReq wire.ReqCode, minorReq byte) wire.Error {
	if _, ok := s.gcs[xid]; !ok {
		return wire.NewGenericError(seq, uint32(xid), minorReq, majorReq, wire.GContextErrorCode)
	}
	return nil
}

func (s *x11Server) checkCursor(xid xID, seq uint16, majorReq wire.ReqCode, minorReq byte) wire.Error {
	if _, ok := s.cursors[xid]; !ok {
		return wire.NewGenericError(seq, uint32(xid), minorReq, majorReq, wire.CursorErrorCode)
	}
	return nil
}

func (s *x11Server) checkColormap(xid xID, seq uint16, majorReq wire.ReqCode, minorReq byte) wire.Error {
	if uint32(xid) == s.defaultColormap {
		xid = xID(uint32(xid))
	}
	if _, ok := s.colormaps[xid]; !ok {
		return wire.NewGenericError(seq, uint32(xid), minorReq, majorReq, wire.ColormapErrorCode)
	}
	return nil
}

func (s *x11Server) checkFont(xid xID, seq uint16, majorReq wire.ReqCode, minorReq byte) wire.Error {
	if _, ok := s.fonts[xid]; !ok {
		return wire.NewGenericError(seq, uint32(xid), minorReq, majorReq, wire.FontErrorCode)
	}
	return nil
}

func NewWindowAttributes() wire.WindowAttributes {
	return wire.WindowAttributes{}
}

func (s *x11Server) SendMouseEvent(xid xID, eventType string, x, y, detail int32) {
	debugf("X11: SendMouseEvent xid=%d type=%s x=%d y=%d detail=%d", xid, eventType, x, y, detail)

	originalXID := xid
	if _, ok := s.windows[originalXID]; !ok {
		log.Printf("X11: Failed to write mouse event: window not found")
		return
	}

	// Add to motion event buffer
	if eventType == "mousemove" {
		s.motionEvents = append(s.motionEvents, motionEvent{
			time:   s.serverTime(),
			x:      int16(x),
			y:      int16(y),
			window: originalXID,
		})
		// Keep buffer from growing too large
		if len(s.motionEvents) > 1024 {
			s.motionEvents = s.motionEvents[len(s.motionEvents)-1024:]
		}
	}

	// Calculate delta
	dx := float64(x - int32(s.pointerX))
	dy := float64(y - int32(s.pointerY))

	state := uint16(detail >> 16)
	s.pointerState = state
	button := byte(detail & 0xFFFF)
	deviceID := virtualPointer.Header.DeviceID

	// 0. Handle Raw Events (XI 2.x)
	// "Raw events are sent to all clients that have selected for the event type on the root window."
	// We iterate all clients to check if they selected Raw events on the Root Window.
	for _, client := range s.clients {
		if client.xi2EventMasks != nil {
			if devMasks, ok := client.xi2EventMasks[s.rootWindowID()]; ok {
				var mask []uint32
				if m, ok := devMasks[uint16(deviceID)]; ok {
					mask = m
				} else if m, ok := devMasks[wire.XIAllMasterDevices]; ok {
					mask = m
				}

				if mask != nil {
					var evType uint16
					switch eventType {
					case "mousedown":
						evType = wire.XI_RawButtonPress
					case "mouseup":
						evType = wire.XI_RawButtonRelease
					case "mousemove":
						evType = wire.XI_RawMotion
					}

					if evType > 0 {
						wordIdx := int(evType / 32)
						bitIdx := int(evType % 32)
						if wordIdx < len(mask) && (mask[wordIdx]&(1<<bitIdx)) != 0 {
							s.sendXInput2RawEvent(client, evType, deviceID, button, dx, dy)
						}
					}
				}
			}
		}
	}

	// 1. Handle Device Grabs (Active and Passive)
	activeDeviceGrab, deviceGrabbed := s.deviceGrabs[deviceID]

	// Check passive device grabs if no active grab
	if !deviceGrabbed && eventType == "mousedown" {
		if grabs, ok := s.passiveDeviceGrabs[originalXID]; ok {
			for _, grab := range grabs {
				xi1Match := grab.xi2GrabType == 0 && grab.deviceID == deviceID && grab.button == button && (grab.modifiers == wire.AnyModifier || grab.modifiers == state)

				xi2Match := false
				if grab.xi2GrabType == wire.XI_ButtonPress && grab.deviceID == deviceID && byte(grab.detail) == button {
					if len(grab.xi2Modifiers) == 0 {
						xi2Match = true
					} else {
						for _, mod := range grab.xi2Modifiers {
							if (mod & 0xFFFF) == uint32(state) {
								xi2Match = true
								break
							}
						}
					}
				}

				if xi1Match || xi2Match {
					activeDeviceGrab = &deviceGrab{
						clientID:     grab.clientID,
						window:       originalXID, // Grab is on this window
						ownerEvents:  grab.owner,
						eventMask:    grab.eventMask,
						xi2EventMask: grab.xi2EventMask,
						time:         s.serverTime(),
					}
					s.deviceGrabs[deviceID] = activeDeviceGrab
					deviceGrabbed = true
					break
				}
			}
		}
	}

	var xiEventMask uint32
	switch eventType {
	case "mousedown":
		xiEventMask = wire.DeviceButtonPressMask
	case "mouseup":
		xiEventMask = wire.DeviceButtonReleaseMask
	}

	if deviceGrabbed {
		// Send XInput event to grabbing client if mask matches
		grabbingClient, clientExists := s.clients[activeDeviceGrab.clientID]
		if clientExists {
			// XI 1.x
			if xiEventMask > 0 {
				match := false
				for _, class := range activeDeviceGrab.eventMask {
					// class is (mask << 8) | deviceID
					if byte(class&0xFF) == deviceID {
						mask := class >> 8
						if mask&uint32(xiEventMask) != 0 {
							match = true
							break
						}
					}
				}
				if match {
					s.sendXInputMouseEvent(grabbingClient, eventType, deviceID, button, uint32(originalXID), x, y, state)
				}
			}

			// XI 2.x
			if activeDeviceGrab.xi2EventMask != nil {
				var evType uint16
				switch eventType {
				case "mousedown":
					evType = wire.XI_ButtonPress
				case "mouseup":
					evType = wire.XI_ButtonRelease
				case "mousemove":
					evType = wire.XI_Motion
				}

				if evType > 0 {
					wordIdx := int(evType / 32)
					bitIdx := int(evType % 32)
					if wordIdx < len(activeDeviceGrab.xi2EventMask) && (activeDeviceGrab.xi2EventMask[wordIdx]&(1<<bitIdx)) != 0 {
						s.sendXInput2MouseEvent(grabbingClient, evType, deviceID, button, uint32(originalXID), x, y, state)
					}
				}
			}
		}
		// Core events are suppressed when device is grabbed
		return
	}

	// 2. Handle Core Grabs and Events (only if device not grabbed)
	grabActive := s.pointerGrabWindow != 0
	if grabActive {
		xid = s.pointerGrabWindow
	}

	var eventMask uint32
	switch eventType {
	case "mousedown":
		eventMask = wire.ButtonPressMask
	case "mouseup":
		eventMask = wire.ButtonReleaseMask
	case "mousemove":
		eventMask = wire.PointerMotionMask
		if state&wire.Button1Mask != 0 {
			eventMask |= wire.Button1MotionMask
		}
		if state&wire.Button2Mask != 0 {
			eventMask |= wire.Button2MotionMask
		}
		if state&wire.Button3Mask != 0 {
			eventMask |= wire.Button3MotionMask
		}
		if state&wire.Button4Mask != 0 {
			eventMask |= wire.Button4MotionMask
		}
		if state&wire.Button5Mask != 0 {
			eventMask |= wire.Button5MotionMask
		}
		if state&uint16(wire.ButtonPressMask|wire.ButtonReleaseMask) != 0 {
			eventMask |= wire.ButtonMotionMask
		}
	}

	if !grabActive && eventType == "mousedown" {
		if grabs, ok := s.passiveGrabs[originalXID]; ok {
			for _, grab := range grabs {
				if grab.button == button && (grab.modifiers == wire.AnyModifier || grab.modifiers == state) {
					s.pointerGrabWindow = originalXID
					s.pointerGrabClientID = grab.clientID
					s.pointerGrabOwner = grab.owner
					s.pointerGrabEventMask = grab.eventMask
					s.pointerGrabMode = grab.pointerMode
					s.keyboardGrabMode = grab.keyboardMode
					s.pointerGrabConfineTo = grab.confineTo
					s.pointerGrabCursor = grab.cursor
					s.pointerGrabTime = s.serverTime()
					grabActive = true
					s.frontend.SetWindowCursor(originalXID, grab.cursor)
					break
				}
			}
		}
	}

	// Dispatch Core events.
	if grabActive {
		grabbingClient, grabberOk := s.clients[s.pointerGrabClientID]
		if grabberOk && (uint32(s.pointerGrabEventMask)&eventMask) != 0 {
			eventWindowID := uint32(originalXID)
			if !s.pointerGrabOwner {
				eventWindowID = uint32(s.pointerGrabWindow)
			}
			s.sendCoreMouseEvent(grabbingClient, eventType, button, eventWindowID, x, y, state)
		}

		if s.pointerGrabOwner {
			ownerClient, ownerOk := s.clients[((uint32(originalXID) >> resourceIDShift) & clientIDMask)]
			if ownerOk && (!grabberOk || ownerClient.id != grabbingClient.id) {
				if w, ok := s.windows[originalXID]; ok {
					if w.attributes.EventMask&eventMask != 0 {
						s.sendCoreMouseEvent(ownerClient, eventType, button, uint32(originalXID), x, y, state)
					}
				}
			}
		}
	} else {
		if w, ok := s.windows[originalXID]; ok {
			if client, ok := s.clients[((uint32(originalXID) >> resourceIDShift) & clientIDMask)]; ok {
				if w.attributes.EventMask&eventMask != 0 {
					s.sendCoreMouseEvent(client, eventType, button, uint32(originalXID), x, y, state)
				}
			}
		}
	}

	// 3. Send XInput events (non-grabbed)
	for _, client := range s.clients {
		// XI 1.x
		if xiEventMask > 0 {
			if deviceInfo, ok := client.openDevices[deviceID]; ok {
				if mask, ok := deviceInfo.EventMasks[uint32(originalXID)]; ok {
					if mask&xiEventMask != 0 {
						s.sendXInputMouseEvent(client, eventType, deviceID, button, uint32(originalXID), x, y, state)
					}
				}
			}
		}

		// XI 2.x
		if client.xi2EventMasks != nil {
			if devMasks, ok := client.xi2EventMasks[uint32(originalXID)]; ok {
				// Check specific device or AllDevices (0) or AllMasterDevices (1)
				// For now, check deviceID (2) and AllMasterDevices (1)
				var mask []uint32
				if m, ok := devMasks[uint16(deviceID)]; ok {
					mask = m
				} else if m, ok := devMasks[1]; ok { // XIAllMasterDevices
					mask = m
				}

				if mask != nil {
					var evType uint16
					switch eventType {
					case "mousedown":
						evType = 4 // XI_ButtonPress
					case "mouseup":
						evType = 5 // XI_ButtonRelease
					case "mousemove":
						evType = 6 // XI_Motion
					}

					if evType > 0 {
						// Check bit in mask
						// Mask is []uint32. Bit N is in word N/32 at bit N%32
						wordIdx := int(evType / 32)
						bitIdx := int(evType % 32)
						if wordIdx < len(mask) && (mask[wordIdx]&(1<<bitIdx)) != 0 {
							s.sendXInput2MouseEvent(client, evType, deviceID, button, uint32(originalXID), x, y, state)
						}
					}
				}
			}
		}
	}
}

func (s *x11Server) sendXInput2RawEvent(client *x11Client, evType uint16, deviceID byte, detail byte, dx, dy float64) {
	var mask uint32
	var values []float64

	// Raw motion events report relative movement, so always include both axes.
	// Axis 0: X
	mask |= 1 << 0
	values = append(values, dx)

	// Axis 1: Y
	mask |= 1 << 1
	values = append(values, dy)

	valuatorsMask := []uint32{mask}

	event := &wire.XIRawEvent{
		Sequence:       client.sequence - 1,
		EventType:      evType,
		DeviceID:       uint16(deviceID),
		Time:           s.serverTime(),
		Detail:         uint32(detail),
		SourceID:       uint16(deviceID),
		ValuatorsMask:  valuatorsMask,
		ValuatorValues: values,
		RawValues:      values, // Assuming raw == relative for virtual device
	}

	s.sendEvent(client, event)
}

func (s *x11Server) sendXInput2MouseEvent(client *x11Client, evType uint16, deviceID byte, button byte, eventWindowID uint32, x, y int32, state uint16) {
	// Modifiers
	mods := wire.ModifierInfo{
		Base:      uint32(state),
		Latched:   0,
		Locked:    0,
		Effective: uint32(state),
	}

	// Buttons mask
	// Convert X11 state mask to XI2 button mask
	buttonMask := uint32(0)
	if state&wire.Button1Mask != 0 {
		buttonMask |= (1 << 0)
	}
	if state&wire.Button2Mask != 0 {
		buttonMask |= (1 << 1)
	}
	if state&wire.Button3Mask != 0 {
		buttonMask |= (1 << 2)
	}
	if state&wire.Button4Mask != 0 {
		buttonMask |= (1 << 3)
	}
	if state&wire.Button5Mask != 0 {
		buttonMask |= (1 << 4)
	}

	// For ButtonPress/Release, we might need to ensure the button is set/unset correctly.
	// Assuming `state` reflects the state *after* the event (as per JS semantics).

	buttons := []uint32{buttonMask}

	// FP1616 coordinates
	rootX := x << 16
	rootY := y << 16
	eventX := x << 16
	eventY := y << 16

	event := &wire.XIDeviceEvent{
		Sequence:  client.sequence - 1,
		EventType: evType,
		DeviceID:  uint16(deviceID),
		Time:      s.serverTime(),
		Detail:    uint32(button),
		Root:      s.rootWindowID(),
		Event:     eventWindowID,
		Child:     0,
		RootX:     rootX,
		RootY:     rootY,
		EventX:    eventX,
		EventY:    eventY,
		Buttons:   buttons,
		Valuators: nil,
		SourceID:  uint16(deviceID), // For now, SourceID is same as DeviceID (Master)
		Mods:      mods,
		Group:     wire.GroupInfo{},
	}

	// Wrap in GenericEvent
	// XIDeviceEvent.EncodeMessage returns the full packet including the GenericEvent header.
	// client.send calls EncodeMessage, so we can pass the event directly.

	s.sendEvent(client, event)
}

func (s *x11Server) sendXInput2KeyboardEvent(client *x11Client, evType uint16, deviceID byte, keycode byte, eventWindowID uint32, state uint16) {
	mods := wire.ModifierInfo{
		Base:      uint32(state),
		Latched:   0,
		Locked:    0,
		Effective: uint32(state),
	}

	buttonMask := uint32(0)
	if state&wire.Button1Mask != 0 {
		buttonMask |= (1 << 0)
	}
	if state&wire.Button2Mask != 0 {
		buttonMask |= (1 << 1)
	}
	if state&wire.Button3Mask != 0 {
		buttonMask |= (1 << 2)
	}
	if state&wire.Button4Mask != 0 {
		buttonMask |= (1 << 3)
	}
	if state&wire.Button5Mask != 0 {
		buttonMask |= (1 << 4)
	}

	buttons := []uint32{buttonMask}

	event := &wire.XIDeviceEvent{
		Sequence:  client.sequence - 1,
		EventType: evType,
		DeviceID:  uint16(deviceID),
		Time:      s.serverTime(),
		Detail:    uint32(keycode),
		Root:      s.rootWindowID(),
		Event:     eventWindowID,
		Child:     0,
		RootX:     int32(s.pointerX) << 16,
		RootY:     int32(s.pointerY) << 16,
		EventX:    int32(s.pointerX) << 16,
		EventY:    int32(s.pointerY) << 16,
		Buttons:   buttons,
		Valuators: nil,
		SourceID:  uint16(deviceID),
		Mods:      mods,
		Group:     wire.GroupInfo{},
	}

	s.sendEvent(client, event)
}

func (s *x11Server) sendCoreMouseEvent(client *x11Client, eventType string, button byte, eventWindowID uint32, x, y int32, state uint16) {
	var event messageEncoder
	switch eventType {
	case "mousedown":
		event = &wire.ButtonPressEvent{
			Sequence:   client.sequence - 1,
			Detail:     button,
			Time:       s.serverTime(),
			Root:       s.rootWindowID(),
			Event:      eventWindowID,
			Child:      0, // 0 for now
			RootX:      int16(x),
			RootY:      int16(y),
			EventX:     int16(x),
			EventY:     int16(y),
			State:      state,
			SameScreen: true,
		}
	case "mouseup":
		event = &wire.ButtonReleaseEvent{
			Sequence:   client.sequence - 1,
			Detail:     button,
			Time:       s.serverTime(),
			Root:       s.rootWindowID(),
			Event:      eventWindowID,
			Child:      0, // 0 for now
			RootX:      int16(x),
			RootY:      int16(y),
			EventX:     int16(x),
			EventY:     int16(y),
			State:      state,
			SameScreen: true,
		}
	case "mousemove":
		event = &wire.MotionNotifyEvent{
			Sequence:   client.sequence - 1,
			Detail:     0, // 0 for Normal
			Time:       s.serverTime(),
			Root:       s.rootWindowID(),
			Event:      eventWindowID,
			Child:      0, // 0 for now
			RootX:      int16(x),
			RootY:      int16(y),
			EventX:     int16(x),
			EventY:     int16(y),
			State:      state,
			SameScreen: true,
		}
	default:
		debugf("X11: Unknown mouse event type: %s", eventType)
		return
	}
	s.sendEvent(client, event)
}

func (s *x11Server) sendXInputMouseEvent(client *x11Client, eventType string, deviceID, button byte, eventWindowID uint32, x, y int32, state uint16) {
	var xiEvent messageEncoder
	switch eventType {
	case "mousedown":
		xiEvent = &wire.DeviceButtonPressEvent{
			Sequence:   client.sequence - 1,
			DeviceID:   deviceID,
			Time:       s.serverTime(),
			Detail:     button,
			Root:       s.rootWindowID(),
			Event:      eventWindowID,
			Child:      0, // Or a child window ID if applicable
			RootX:      int16(x),
			RootY:      int16(y),
			EventX:     int16(x),
			EventY:     int16(y),
			State:      state,
			SameScreen: true,
		}
	case "mouseup":
		xiEvent = &wire.DeviceButtonReleaseEvent{
			Sequence:   client.sequence - 1,
			DeviceID:   deviceID,
			Time:       s.serverTime(),
			Button:     button,
			Root:       s.rootWindowID(),
			Event:      eventWindowID,
			Child:      0, // Or a child window ID if applicable
			RootX:      int16(x),
			RootY:      int16(y),
			EventX:     int16(x),
			EventY:     int16(y),
			State:      state,
			SameScreen: true,
		}
	}

	if xiEvent != nil {
		s.sendEvent(client, xiEvent)
	}
}
func (s *x11Server) SendKeyboardEvent(xid xID, eventType string, code string, altKey, ctrlKey, shiftKey, metaKey bool) {
	debugf("X11: SendKeyboardEvent xid=%d type=%s code=%s alt=%t ctrl=%t shift=%t meta=%t", xid, eventType, code, altKey, ctrlKey, shiftKey, metaKey)

	state := uint16(0)
	if shiftKey {
		state |= 1
	}
	if ctrlKey {
		state |= 4
	}
	if altKey {
		state |= 8
	}
	if metaKey {
		state |= 64
	}

	// Preserve button state
	state |= (s.pointerState & 0xFF00)
	s.pointerState = state

	keycode, ok := jsCodeToX11Keycode[code]
	if !ok {
		keycode = jsCodeToX11Keycode["Unidentified"]
	}

	// Update pressed keys state
	if eventType == "keydown" {
		s.pressedKeys[keycode] = true
	} else if eventType == "keyup" {
		delete(s.pressedKeys, keycode)
	}

	deviceID := virtualKeyboard.Header.DeviceID

	// 1. Handle Device Grabs (Active and Passive)
	activeDeviceGrab, deviceGrabbed := s.deviceGrabs[deviceID]

	if !deviceGrabbed && eventType == "keydown" {
		if grabs, ok := s.passiveDeviceGrabs[xid]; ok {
			for _, grab := range grabs {
				xi1Match := grab.xi2GrabType == 0 && grab.deviceID == deviceID && grab.key == wire.KeyCode(keycode) && (grab.modifiers == wire.AnyModifier || grab.modifiers == state)

				xi2Match := false
				if grab.xi2GrabType == wire.XI_KeyPress && grab.deviceID == deviceID && byte(grab.detail) == byte(keycode) {
					if len(grab.xi2Modifiers) == 0 {
						xi2Match = true
					} else {
						for _, mod := range grab.xi2Modifiers {
							if (mod & 0xFFFF) == uint32(state) {
								xi2Match = true
								break
							}
						}
					}
				}

				if xi1Match || xi2Match {
					activeDeviceGrab = &deviceGrab{
						clientID:     grab.clientID,
						window:       xid,
						ownerEvents:  grab.owner,
						eventMask:    grab.eventMask,
						xi2EventMask: grab.xi2EventMask,
						time:         s.serverTime(),
					}
					s.deviceGrabs[deviceID] = activeDeviceGrab
					deviceGrabbed = true
					break
				}
			}
		}
	}

	var xiEventMask uint32
	switch eventType {
	case "keydown":
		xiEventMask = wire.DeviceKeyPressMask
	case "keyup":
		xiEventMask = wire.DeviceKeyReleaseMask
	}

	if deviceGrabbed {
		grabbingClient, clientExists := s.clients[activeDeviceGrab.clientID]
		if clientExists {
			if xiEventMask > 0 {
				match := false
				for _, class := range activeDeviceGrab.eventMask {
					if byte(class&0xFF) == deviceID {
						mask := class >> 8
						if mask&uint32(xiEventMask) != 0 {
							match = true
							break
						}
					}
				}
				if match {
					s.sendXInputKeyboardEvent(grabbingClient, eventType, keycode, uint32(s.inputFocus), state)
				}
			}

			if activeDeviceGrab.xi2EventMask != nil {
				var evType uint16
				switch eventType {
				case "keydown":
					evType = wire.XI_KeyPress
				case "keyup":
					evType = wire.XI_KeyRelease
				}

				if evType > 0 {
					wordIdx := int(evType / 32)
					bitIdx := int(evType % 32)
					if wordIdx < len(activeDeviceGrab.xi2EventMask) && (activeDeviceGrab.xi2EventMask[wordIdx]&(1<<bitIdx)) != 0 {
						s.sendXInput2KeyboardEvent(grabbingClient, evType, deviceID, keycode, uint32(s.inputFocus), state)
					}
				}
			}
		}
		return
	}

	// 2. Handle Core Grabs and Events
	grabActive := s.keyboardGrabWindow != 0

	var eventMask uint32
	switch eventType {
	case "keydown":
		eventMask = wire.KeyPressMask
	case "keyup":
		eventMask = wire.KeyReleaseMask
	}

	if !grabActive && eventType == "keydown" {
		if grabs, ok := s.passiveGrabs[xid]; ok {
			for _, grab := range grabs {
				if grab.key == wire.KeyCode(keycode) && (grab.modifiers == wire.AnyModifier || grab.modifiers == state) {
					s.keyboardGrabWindow = xid
					s.keyboardGrabClientID = grab.clientID
					s.keyboardGrabOwner = grab.owner
					s.pointerGrabMode = grab.pointerMode
					s.keyboardGrabMode = grab.keyboardMode
					s.keyboardGrabTime = s.serverTime()
					grabActive = true
					if client, ok := s.clients[s.keyboardGrabClientID]; ok {
						s.sendCoreKeyboardEvent(client, eventType, keycode, uint32(xid), state)
					}
					return
				}
			}
		}
	}

	if grabActive {
		grabbingClient, grabberOk := s.clients[s.keyboardGrabClientID]
		if grabberOk {
			eventWindow := uint32(s.keyboardGrabWindow)
			if s.keyboardGrabOwner {
				eventWindow = uint32(xid)
			}
			s.sendCoreKeyboardEvent(grabbingClient, eventType, keycode, eventWindow, state)
		}

		if s.keyboardGrabOwner {
			ownerClient, ownerOk := s.clients[((uint32(xid) >> resourceIDShift) & clientIDMask)]
			if ownerOk && (!grabberOk || ownerClient.id != grabbingClient.id) {
				if w, ok := s.windows[xid]; ok {
					if w.attributes.EventMask&eventMask != 0 {
						s.sendCoreKeyboardEvent(ownerClient, eventType, keycode, uint32(xid), state)
					}
				}
			}
		}
		return
	}

	// No active grab, send to interested clients
	focusID := s.inputFocus
	if focusID == 1 { // PointerRoot
		focusID = xid
	}

	if w, ok := s.windows[focusID]; ok {
		if client, ok := s.clients[((uint32(focusID) >> resourceIDShift) & clientIDMask)]; ok {
			if w.attributes.EventMask&eventMask != 0 {
				s.sendCoreKeyboardEvent(client, eventType, keycode, uint32(focusID), state)
			}
		}
	}

	// 3. Send XInput events (non-grabbed)
	if xiEventMask > 0 {
		for _, client := range s.clients {
			if deviceInfo, ok := client.openDevices[virtualKeyboard.Header.DeviceID]; ok {
				if mask, ok := deviceInfo.EventMasks[uint32(s.inputFocus)]; ok {
					if mask&xiEventMask != 0 {
						s.sendXInputKeyboardEvent(client, eventType, keycode, uint32(s.inputFocus), state)
					}
				}
			}
		}
	}
}

func (s *x11Server) sendCoreKeyboardEvent(client *x11Client, eventType string, keycode byte, eventWindowID uint32, state uint16) {
	event := &wire.KeyEvent{
		Sequence:   client.sequence - 1,
		Detail:     keycode,
		Time:       s.serverTime(),
		Root:       s.rootWindowID(),
		Event:      eventWindowID,
		Child:      0, // No child for now
		RootX:      s.pointerX,
		RootY:      s.pointerY,
		EventX:     s.pointerX,
		EventY:     s.pointerY,
		State:      state,
		SameScreen: true,
	}

	if eventType == "keydown" {
		event.Opcode = 2 // KeyPress
	} else if eventType == "keyup" {
		event.Opcode = 3 // KeyRelease
	} else {
		debugf("X11: Unknown keyboard event type: %s", eventType)
		return
	}

	s.sendEvent(client, event)
}

func (s *x11Server) sendXInputKeyboardEvent(client *x11Client, eventType string, keycode byte, eventWindowID uint32, state uint16) {
	var xiEvent messageEncoder
	switch eventType {
	case "keydown":
		xiEvent = &wire.DeviceKeyPressEvent{
			Sequence:   client.sequence - 1,
			DeviceID:   virtualKeyboard.Header.DeviceID,
			Time:       s.serverTime(),
			KeyCode:    keycode,
			Root:       s.rootWindowID(),
			Event:      eventWindowID,
			Child:      0, // Or a child window ID if applicable
			RootX:      s.pointerX,
			RootY:      s.pointerY,
			EventX:     s.pointerX,
			EventY:     s.pointerY,
			State:      state,
			SameScreen: true,
		}
	case "keyup":
		xiEvent = &wire.DeviceKeyReleaseEvent{
			Sequence:   client.sequence - 1,
			DeviceID:   virtualKeyboard.Header.DeviceID,
			Time:       s.serverTime(),
			KeyCode:    keycode,
			Root:       s.rootWindowID(),
			Event:      eventWindowID,
			Child:      0, // Or a child window ID if applicable
			RootX:      s.pointerX,
			RootY:      s.pointerY,
			EventX:     s.pointerX,
			EventY:     s.pointerY,
			State:      state,
			SameScreen: true,
		}
	}

	if xiEvent != nil {
		s.sendEvent(client, xiEvent)
	}
}
func (s *x11Server) SendPointerCrossingEvent(isEnter bool, xid xID, rootX, rootY, eventX, eventY int16, state uint16, mode, detail byte) {
	client, ok := s.clients[((uint32(xid) >> resourceIDShift) & clientIDMask)]
	if !ok {
		log.Printf("X11: Failed to write pointer crossing event: client %d not found", ((uint32(xid) >> resourceIDShift) & clientIDMask))
		return
	}

	var event messageEncoder
	if isEnter {
		event = &wire.EnterNotifyEvent{
			Sequence:   client.sequence - 1,
			Detail:     detail,
			Time:       s.serverTime(),
			Root:       s.rootWindowID(),
			Event:      uint32(xid),
			Child:      0, // Or a child window ID if applicable
			RootX:      rootX,
			RootY:      rootY,
			EventX:     eventX,
			EventY:     eventY,
			State:      state,
			Mode:       mode,
			SameScreen: true,
			Focus:      s.frontend.GetFocusWindow(client.id) == xid,
		}
	} else {
		event = &wire.LeaveNotifyEvent{
			Sequence:   client.sequence - 1,
			Detail:     detail,
			Time:       s.serverTime(),
			Root:       s.rootWindowID(),
			Event:      uint32(xid),
			Child:      0, // Or a child window ID if applicable
			RootX:      rootX,
			RootY:      rootY,
			EventX:     eventX,
			EventY:     eventY,
			State:      state,
			Mode:       mode,
			SameScreen: true,
			Focus:      s.frontend.GetFocusWindow(client.id) == xid,
		}
	}

	if err := client.send(event); err != nil {
		debugf("X11: Failed to write pointer crossing event: %v", err)
	}
}

func (s *x11Server) sendConfigureNotifyEvent(windowID xID, x, y int16, width, height uint16) {
	debugf("X11: Sending ConfigureNotify event for window %d", windowID)
	client, ok := s.clients[((uint32(windowID) >> resourceIDShift) & clientIDMask)]
	if !ok {
		log.Printf("X11: Failed to write ConfigureNotify event: client %d not found", ((uint32(windowID) >> resourceIDShift) & clientIDMask))
		return
	}

	event := &wire.ConfigureNotifyEvent{
		Sequence:         client.sequence - 1,
		Event:            uint32(windowID),
		Window:           uint32(windowID),
		AboveSibling:     0, // None
		X:                x,
		Y:                y,
		Width:            width,
		Height:           height,
		BorderWidth:      0,
		OverrideRedirect: false,
	}

	if err := client.send(event); err != nil {
		debugf("X11: Failed to write ConfigureNotify event: %v", err)
	}
}

func (s *x11Server) sendExposeEvent(windowID xID, x, y, width, height uint16) {
	debugf("X11: Sending Expose event for window %d", windowID)
	client, ok := s.clients[((uint32(windowID) >> resourceIDShift) & clientIDMask)]
	if !ok {
		debugf("X11: sendExposeEvent unknown client %d", ((uint32(windowID) >> resourceIDShift) & clientIDMask))
		return
	}

	event := &wire.ExposeEvent{
		Sequence: client.sequence - 1,
		Window:   uint32(windowID),
		X:        x,
		Y:        y,
		Width:    width,
		Height:   height,
		Count:    0, // count = 0, no more expose events to follow
	}

	s.sendEvent(client, event)
}

func (s *x11Server) SendClientMessageEvent(windowID xID, messageTypeAtom uint32, data [20]byte) {
	debugf("X11: Sending ClientMessage event for window %d", windowID)
	client, ok := s.clients[((uint32(windowID) >> resourceIDShift) & clientIDMask)]
	if !ok {
		debugf("X11: SendClientMessageEvent unknown client %d", ((uint32(windowID) >> resourceIDShift) & clientIDMask))
		return
	}

	event := &wire.ClientMessageEvent{
		Sequence:    client.sequence - 1,
		Format:      32, // Format is always 32 for ClientMessage
		Window:      uint32(windowID),
		MessageType: messageTypeAtom,
		Data:        data,
	}

	if err := client.send(event); err != nil {
		debugf("X11: Failed to write ClientMessage event: %v", err)
	}
}

func (s *x11Server) SendSelectionNotify(requestor xID, selection, target, property uint32, data []byte) {
	client, ok := s.clients[((uint32(requestor) >> resourceIDShift) & clientIDMask)]
	if !ok {
		debugf("X11: SendSelectionNotify unknown client %d", ((uint32(requestor) >> resourceIDShift) & clientIDMask))
		return
	}

	event := &wire.SelectionNotifyEvent{
		Sequence:  client.sequence - 1,
		Requestor: uint32(requestor),
		Selection: selection,
		Target:    target,
		Property:  property,
		Time:      s.serverTime(),
	}
	s.sendEvent(client, event)
}

func (s *x11Server) isPointerEvent(event messageEncoder) bool {
	switch e := event.(type) {
	case *wire.ButtonPressEvent, *wire.ButtonReleaseEvent, *wire.MotionNotifyEvent,
		*wire.EnterNotifyEvent, *wire.LeaveNotifyEvent,
		*wire.DeviceButtonPressEvent, *wire.DeviceButtonReleaseEvent, *wire.DeviceMotionNotifyEvent:
		return true
	case *wire.X11RawEvent:
		if len(e.Data) > 0 {
			switch e.Data[0] {
			case 4, 5, 6, 7, 8: // ButtonPress, ButtonRelease, MotionNotify, EnterNotify, LeaveNotify
				return true
			}
		}
	}
	return false
}

func (s *x11Server) isKeyboardEvent(event messageEncoder) bool {
	switch e := event.(type) {
	case *wire.KeyEvent, *wire.DeviceKeyPressEvent, *wire.DeviceKeyReleaseEvent:
		return true
	case *wire.X11RawEvent:
		if len(e.Data) > 0 {
			switch e.Data[0] {
			case 2, 3: // KeyPress, KeyRelease
				return true
			}
		}
	}
	return false
}

func (s *x11Server) sendEvent(client *x11Client, event messageEncoder) {
	if s.pointerFrozen && s.isPointerEvent(event) {
		s.pointerEventQueue = append(s.pointerEventQueue, queuedEvent{client: client, event: event})
		return
	}
	if s.keyboardFrozen && s.isKeyboardEvent(event) {
		s.keyboardEventQueue = append(s.keyboardEventQueue, queuedEvent{client: client, event: event})
		return
	}
	if err := client.send(event); err != nil {
		s.logger.Errorf("Failed to write event: %v", err)
	}
}

func (s *x11Server) flushPointerEvents() {
	s.pointerFrozen = false
	queue := s.pointerEventQueue
	s.pointerEventQueue = nil
	for _, qe := range queue {
		s.sendEvent(qe.client, qe.event)
	}
}

func (s *x11Server) flushKeyboardEvents() {
	s.keyboardFrozen = false
	queue := s.keyboardEventQueue
	s.keyboardEventQueue = nil
	for _, qe := range queue {
		s.sendEvent(qe.client, qe.event)
	}
}

func (s *x11Server) GetRGBColor(colormap xID, pixel uint32) (r, g, b uint8) {
	if uint32(colormap) == s.defaultColormap {
		colormap = xID(uint32(colormap))
	}
	visual, ok := s.getVisualByID(s.visualID)
	if !ok {
		visual = s.rootVisual
	}

	// For TrueColor visuals, the pixel value directly encodes RGB components.
	switch visual.Class {
	case 0, 1: // StaticGray, GrayScale
		// For grayscale, the pixel value is an index into a ramp of gray colors.
		// We can simulate this by scaling the pixel value to the 0-255 range.
		maxVal := visual.ColormapEntries - 1
		if maxVal == 0 {
			maxVal = 255
		}
		gray := uint8(float64(pixel) / float64(maxVal) * 255.0)
		return gray, gray, gray
	case 2, 3: // StaticColor, PseudoColor
		// These visuals use a colormap to look up RGB values.
		if cm, ok := s.colormaps[colormap]; ok {
			if color, ok := cm.pixels[pixel]; ok {
				return uint8(color.Red >> 8), uint8(color.Green >> 8), uint8(color.Blue >> 8)
			}
		}
	case 4, 5: // TrueColor, DirectColor
		r = uint8((pixel & visual.RedMask) >> calculateShift(visual.RedMask))
		g = uint8((pixel & visual.GreenMask) >> calculateShift(visual.GreenMask))
		b = uint8((pixel & visual.BlueMask) >> calculateShift(visual.BlueMask))
		debugf("GetRGBColor: cmap:%d pixel:%x return RGB for pixel", colormap, pixel)
		return r, g, b
	}
	// Default to black if not found
	debugf("GetRGBColor: cmap:%d pixel:%x return black", colormap, pixel)
	return 0, 0, 0
}

// calculateShift determines the right shift needed to extract the color component.
func (s *x11Server) getVisualByID(visualID uint32) (wire.VisualType, bool) {
	visual, ok := s.visuals[visualID]
	return visual, ok
}

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

func (s *x11Server) initAtoms() {
	s.atoms = map[string]uint32{
		"PRIMARY":             1,
		"SECONDARY":           2,
		"ARC":                 3,
		"ATOM":                4,
		"BITMAP":              5,
		"CARDINAL":            6,
		"COLORMAP":            7,
		"CURSOR":              8,
		"CUT_BUFFER0":         9,
		"CUT_BUFFER1":         10,
		"CUT_BUFFER2":         11,
		"CUT_BUFFER3":         12,
		"CUT_BUFFER4":         13,
		"CUT_BUFFER5":         14,
		"CUT_BUFFER6":         15,
		"CUT_BUFFER7":         16,
		"DRAWABLE":            17,
		"FONT":                18,
		"INTEGER":             19,
		"PIXMAP":              20,
		"POINT":               21,
		"RECTANGLE":           22,
		"RESOURCE_MANAGER":    23,
		"RGB_COLOR_MAP":       24,
		"RGB_BEST_MAP":        25,
		"RGB_BLUE_MAP":        26,
		"RGB_DEFAULT_MAP":     27,
		"RGB_GRAY_MAP":        28,
		"RGB_GREEN_MAP":       29,
		"RGB_RED_MAP":         30,
		"STRING":              31,
		"VISUALID":            32,
		"WINDOW":              33,
		"WM_COMMAND":          34,
		"WM_HINTS":            35,
		"WM_CLIENT_MACHINE":   36,
		"WM_ICON_NAME":        37,
		"WM_ICON_SIZE":        38,
		"WM_NAME":             39,
		"WM_NORMAL_HINTS":     40,
		"WM_SIZE_HINTS":       41,
		"WM_ZOOM_HINTS":       42,
		"MIN_SPACE":           43,
		"NORM_SPACE":          44,
		"MAX_SPACE":           45,
		"END_SPACE":           46,
		"SUPERSCRIPT_X":       47,
		"SUPERSCRIPT_Y":       48,
		"SUBSCRIPT_X":         49,
		"SUBSCRIPT_Y":         50,
		"UNDERLINE_POSITION":  51,
		"UNDERLINE_THICKNESS": 52,
		"STRIKEOUT_ASCENT":    53,
		"STRIKEOUT_DESCENT":   54,
		"ITALIC_ANGLE":        55,
		"X_HEIGHT":            56,
		"QUAD_WIDTH":          57,
		"WEIGHT":              58,
		"POINT_SIZE":          59,
		"RESOLUTION":          60,
		"COPYRIGHT":           61,
		"NOTICE":              62,
		"FONT_NAME":           63,
		"FAMILY_NAME":         64,
		"FULL_NAME":           65,
		"CAP_HEIGHT":          66,
		"WM_CLASS":            67,
		"WM_TRANSIENT_FOR":    68,
	}
	s.atomNames = make(map[uint32]string)
	for name, id := range s.atoms {
		s.atomNames[id] = name
	}
	s.nextAtomID = 69
}

func (s *x11Server) GetAtom(name string) uint32 {
	if id, ok := s.atoms[name]; ok {
		return id
	}
	id := s.nextAtomID
	s.nextAtomID++
	s.atoms[name] = id
	s.atomNames[id] = name
	return id
}

func (s *x11Server) GetAtomName(atom uint32) string {
	return s.atomNames[atom]
}

func (s *x11Server) ChangeProperty(xid xID, propertyID, typeAtom uint32, format byte, data []byte) {
	props, ok := s.properties[xid]
	if !ok {
		props = make(map[uint32]*property)
		s.properties[xid] = props
	}
	props[propertyID] = &property{
		data:     data,
		typeAtom: typeAtom,
		format:   format,
	}

	s.sendPropertyNotify(xid, propertyID, 0) // PropertyNewValue

	// Check for WM_NAME etc.
	name := s.GetAtomName(propertyID)
	if name == "WM_NAME" || name == "_NET_WM_NAME" || name == "WM_ICON_NAME" {
		s.frontend.SetWindowTitle(xid, string(data))
	}
}

func (s *x11Server) DeleteProperty(xid xID, propertyID uint32) {
	if props, ok := s.properties[xid]; ok {
		delete(props, propertyID)
		s.sendPropertyNotify(xid, propertyID, 1) // PropertyDelete
	}
}

func (s *x11Server) sendPropertyNotify(windowID xID, atom uint32, state byte) {
	if client, ok := s.clients[((uint32(windowID) >> resourceIDShift) & clientIDMask)]; ok {
		if w, ok := s.windows[windowID]; ok {
			if w.attributes.EventMask&wire.PropertyChangeMask != 0 {
				event := &wire.PropertyNotifyEvent{
					Sequence: client.sequence - 1,
					Window:   uint32(windowID),
					Atom:     atom,
					Time:     s.serverTime(),
					State:    state,
				}
				s.sendEvent(client, event)
			}
		}
	}
}

func (s *x11Server) GetProperty(xid xID, propertyID uint32) *property {
	if props, ok := s.properties[xid]; ok {
		return props[propertyID]
	}
	return nil
}

func (s *x11Server) ListProperties(xid xID) []uint32 {
	var list []uint32
	if props, ok := s.properties[xid]; ok {
		for id := range props {
			list = append(list, id)
		}
	}
	return list
}

func (s *x11Server) RotateProperties(xid xID, delta int16, atoms []wire.Atom) error {
	props, ok := s.properties[xid]
	if !ok {
		return nil
	}

	// Check existence
	for _, atom := range atoms {
		if _, ok := props[uint32(atom)]; !ok {
			return errors.New("property not found")
		}
	}

	n := len(atoms)
	if n == 0 {
		return nil
	}

	newValues := make(map[uint32]*property)
	for i, atom := range atoms {
		prop := props[uint32(atom)]
		newIdx := (i + int(delta)) % n
		if newIdx < 0 {
			newIdx += n
		}
		newValues[uint32(atoms[newIdx])] = prop
	}

	for atom, prop := range newValues {
		props[atom] = prop
	}
	return nil
}

func (s *x11Server) rootWindowID() uint32 {
	return 0
}

func (s *x11Server) readRequest(client *x11Client) (wire.Request, uint16, error) {
	client.sequence++
	var header [4]byte
	if _, err := io.ReadFull(client.conn, header[:]); err != nil {
		return nil, 0, err
	}

	length := uint32(client.byteOrder.Uint16(header[2:4]))
	var extendedHeader []byte
	if client.bigRequestsEnabled && length == 0 {
		var extendedLengthBytes [4]byte
		if _, err := io.ReadFull(client.conn, extendedLengthBytes[:]); err != nil {
			return nil, 0, err
		}
		length = client.byteOrder.Uint32(extendedLengthBytes[:])
		extendedHeader = extendedLengthBytes[:]
	}

	if length == 0 {
		client.send(wire.NewError(wire.LengthErrorCode, client.sequence, 0, wire.Opcodes{Major: wire.ReqCode(header[0]), Minor: 0}))
		return nil, 0, errParseError
	}

	totalSize := 4 * length
	raw := make([]byte, totalSize)
	copy(raw[0:4], header[:])
	if extendedHeader != nil {
		copy(raw[4:8], extendedHeader)
	}

	readOffset := 4 + len(extendedHeader)
	if totalSize > uint32(readOffset) {
		if _, err := io.ReadFull(client.conn, raw[readOffset:]); err != nil {
			return nil, 0, err
		}
	}

	debugf("X11DEBUG: RAW Request: %x", raw)
	req, err := wire.ParseRequest(client.byteOrder, raw, client.sequence, client.bigRequestsEnabled)
	if err != nil {
		if x11Err, ok := err.(wire.Error); ok {
			client.send(x11Err)
		} else {
			client.send(wire.NewError(wire.LengthErrorCode, client.sequence, 0, wire.Opcodes{Major: wire.ReqCode(header[0]), Minor: 0}))
		}
		return nil, 0, err
	}
	return req, client.sequence, nil
}

func (s *x11Server) cleanupClient(client *x11Client) {
	// First, tell the frontend to clean up all windows for this client.
	// The frontend implementation should not record these as individual operations.
	s.frontend.DestroyAllWindowsForClient(client.id)

	// Identify all windows owned by this client and remove them from server state.
	var windowsToDestroy []xID
	for xid := range s.windows {
		if (uint32(xid)>>resourceIDShift)&clientIDMask == client.id {
			windowsToDestroy = append(windowsToDestroy, xid)
		}
	}
	for _, xid := range windowsToDestroy {
		w := s.windows[xid]
		if w != nil {
			// Remove from parent's children list if parent is NOT owned by the same client.
			// (If parent IS owned by the same client, it will also be removed from s.windows).
			if (uint32(w.parent)>>resourceIDShift)&clientIDMask != client.id {
				if parent, ok := s.windows[w.parent]; ok {
					for i, childID := range parent.children {
						if childID == xid {
							parent.children = append(parent.children[:i], parent.children[i+1:]...)
							break
						}
					}
				}
			}
			delete(s.windows, xid)
			s.removeWindowFromStack(xid)
		}
	}

	delete(s.clients, client.id)
}

func (s *x11Server) serve(client *x11Client) {
	defer func() {
		if r := recover(); r != nil {
			debugf("X11 Request Handler Panic: %v\n%s", r, debug.Stack())
		}
	}()
	defer client.conn.Close()
	defer s.cleanupClient(client)
	for {
		req, seq, err := s.readRequest(client)
		if err != nil {
			if err != io.EOF {
				s.logger.Errorf("Failed to read X11 request: %v", err)
				debugf("readRequest failed: %v", err)
			}
			break
		}
		reply := s.handleRequest(client, req, seq)
		if reply != nil {
			if err := client.send(reply); err != nil {
				s.logger.Errorf("Failed to write reply: %v", err)
			}
		}
		s.flushDirtyWindows()
	}
}

func (s *x11Server) flushDirtyWindows() {
	for xid := range s.dirtyDrawables {
		s.frontend.ComposeWindow(xid)
	}
	s.dirtyDrawables = make(map[xID]bool)
}

func (s *x11Server) handleRequest(client *x11Client, req wire.Request, seq uint16) (reply messageEncoder) {
	if s.serverGrabbed && s.grabbingClientID != client.id {
		// Ignore requests from other clients while the server is grabbed
		return nil
	}
	debugf("X11DEBUG: handleRequest(%d) opcode: %d: %#v", seq, req.OpCode(), req)
	if req.OpCode() == wire.XInputOpcode {
		return s.handleXInputRequest(client, req, seq)
	}

	if handler, ok := s.requestHandlers[req.OpCode()]; ok {
		return handler(client, req, seq)
	}

	debugf("Unknown X11 request opcode: %d", req.OpCode())
	return nil
}

func (s *x11Server) handshake(client *x11Client) {
	var handshake [12]byte
	if _, err := io.ReadFull(client.conn, handshake[:]); err != nil {
		debugf("x11 handshake: %v", err)
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

	authProtoName := make([]byte, authProtoNameLen)
	if _, err := io.ReadFull(client.conn, authProtoName); err != nil {
		debugf("Failed to read auth protocol name: %v", err)
		return
	}
	if pad := authProtoNameLen % 4; pad != 0 {
		if _, err := io.CopyN(io.Discard, client.conn, int64(4-pad)); err != nil {
			debugf("Failed to discard auth protocol name padding: %v", err)
			return
		}
	}
	authProtoData := make([]byte, authProtoDataLen)
	if _, err := io.ReadFull(client.conn, authProtoData); err != nil {
		debugf("Failed to read auth protocol data: %v", err)
		return
	}
	if pad := authProtoDataLen % 4; pad != 0 {
		if _, err := io.CopyN(io.Discard, client.conn, int64(4-pad)); err != nil {
			debugf("Failed to discard auth protocol data padding: %v", err)
			return
		}
	}

	if s.authProtocol != "" || s.authCookie != nil {
		if s.authProtocol != string(authProtoName) || string(s.authCookie) != string(authProtoData) {
			debugf("X11 auth failed: protocol=%q cookie=%q, expected protocol=%q cookie=%q",
				authProtoName, authProtoData, s.authProtocol, s.authCookie)
			client.send(&wire.SetupResponse{
				Success: 0, // Failed
				Reason:  "Invalid authorization",
			})
			return
		}
	}

	setup := wire.NewDefaultSetup(&s.config)
	setup.ResourceIDBase = (client.id << resourceIDShift)
	setup.ResourceIDMask = localIDMask

	// Create the setup response message encoder
	responseMsg := &wire.SetupResponse{
		Success:                  1, // Success
		ProtocolVersion:          11,
		ReleaseNumber:            setup.ReleaseNumber,
		ResourceIDBase:           setup.ResourceIDBase,
		ResourceIDMask:           setup.ResourceIDMask,
		MotionBufferSize:         setup.MotionBufferSize,
		VendorLength:             setup.VendorLength,
		MaxRequestLength:         setup.MaxRequestLength,
		NumScreens:               setup.NumScreens,
		NumPixmapFormats:         setup.NumPixmapFormats,
		ImageByteOrder:           setup.ImageByteOrder,
		BitmapFormatBitOrder:     setup.BitmapFormatBitOrder,
		BitmapFormatScanlineUnit: setup.BitmapFormatScanlineUnit,
		BitmapFormatScanlinePad:  setup.BitmapFormatScanlinePad,
		MinKeycode:               setup.MinKeycode,
		MaxKeycode:               setup.MaxKeycode,
		VendorString:             setup.VendorString,
		PixmapFormats:            setup.PixmapFormats,
		Screens:                  setup.Screens,
		Data:                     setup,
	}

	if err := client.send(responseMsg); err != nil {
		s.logger.Errorf("x11 handshake write: %v", err)
		return
	}
	s.visualID = setup.Screens[0].RootVisual
	for _, screen := range setup.Screens {
		for _, depth := range screen.Depths {
			for _, visual := range depth.Visuals {
				visual.Depth = depth.Depth
				s.visuals[visual.VisualID] = visual
			}
		}
	}
	s.rootVisual, _ = s.visuals[s.visualID]
	if cm, ok := s.colormaps[xID(s.defaultColormap)]; ok {
		cm.visual = s.rootVisual
	}
	s.blackPixel = setup.Screens[0].BlackPixel
	s.whitePixel = setup.Screens[0].WhitePixel
}

func HandleX11Forwarding(logger Logger, client *ssh.Client, authProtocol string, authCookie []byte) {
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
					logger:      logger,
					windows:     make(map[xID]*window),
					windowStack: make([]xID, 0),
					gcs:         make(map[xID]wire.GC),
					pixmaps:     make(map[xID]*pixmap),
					cursors:     make(map[xID]bool),
					selections:  make(map[uint32]*selectionOwner),
					properties:  make(map[xID]map[uint32]*property),
					colormaps: map[xID]*colormap{
						xID(1): {
							pixels: map[uint32]wire.XColorItem{
								0x000000: {Pixel: 0x000000, Red: 0x0000, Green: 0x0000, Blue: 0x0000, Flags: 0},
								1:        {Pixel: 1, Red: 0xffff, Green: 0xffff, Blue: 0xffff, Flags: 0},
								0xffffff: {Pixel: 0xffffff, Red: 0xffff, Green: 0xffff, Blue: 0xffff, Flags: 0},
							},
						},
					},
					defaultColormap:    1,
					clients:            make(map[uint32]*x11Client),
					nextClientID:       1,
					passiveGrabs:       make(map[xID][]*passiveGrab),
					passiveDeviceGrabs: make(map[xID][]*passiveDeviceGrab),
					deviceGrabs:        make(map[byte]*deviceGrab),
					authProtocol:       authProtocol,
					authCookie:         authCookie,
					keymap:             make(map[byte][]uint32),
					fonts:              make(map[xID]bool),
					startTime:          time.Now(),
					motionEvents:       make([]motionEvent, 0, 1024),
					pressedKeys:        make(map[byte]bool),
					dirtyDrawables:     make(map[xID]bool),
					visuals:            make(map[uint32]wire.VisualType),
				}
				x11ServerInstance.initAtoms()
				x11ServerInstance.initRequestHandlers()
				for k, v := range KeyCodeToKeysym {
					x11ServerInstance.keymap[k] = []uint32{v}
				}
				x11ServerInstance.frontend = newX11Frontend(logger, x11ServerInstance)
			})

			client := &x11Client{
				id:            x11ServerInstance.nextClientID,
				conn:          channel,
				sequence:      0,
				byteOrder:     binary.LittleEndian, // Default, will be updated in handshake
				saveSet:       make(map[uint32]bool),
				openDevices:   make(map[byte]*wire.DeviceInfo),
				xi2EventMasks: make(map[uint32]map[uint16][]uint32),
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
