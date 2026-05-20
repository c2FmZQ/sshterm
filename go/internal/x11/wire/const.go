//go:build x11

package wire

// ReqCode represents an X11 request opcode.
type ReqCode uint8

// X11 Request Codes
const (
	CreateWindow            = ReqCode(1)   // Creates a window.
	ChangeWindowAttributes  = ReqCode(2)   // Changes window attributes.
	GetWindowAttributes     = ReqCode(3)   // Returns window attributes.
	DestroyWindow           = ReqCode(4)   // Destroys a window.
	DestroySubwindows       = ReqCode(5)   // Destroys subwindows.
	ChangeSaveSet           = ReqCode(6)   // Changes the save set.
	ReparentWindow          = ReqCode(7)   // Reparents a window.
	MapWindow               = ReqCode(8)   // Maps a window.
	MapSubwindows           = ReqCode(9)   // Maps subwindows.
	UnmapWindow             = ReqCode(10)  // Unmaps a window.
	UnmapSubwindows         = ReqCode(11)  // Unmaps subwindows.
	ConfigureWindow         = ReqCode(12)  // Configures window attributes (geometry, stack).
	CirculateWindow         = ReqCode(13)  // Circulates window stacking order.
	GetGeometry             = ReqCode(14)  // Returns drawable geometry.
	QueryTree               = ReqCode(15)  // Returns window tree structure.
	InternAtom              = ReqCode(16)  // Returns atom ID for a name.
	GetAtomName             = ReqCode(17)  // Returns name for an atom ID.
	ChangeProperty          = ReqCode(18)  // Changes a window property.
	DeleteProperty          = ReqCode(19)  // Deletes a window property.
	GetProperty             = ReqCode(20)  // Returns a window property.
	ListProperties          = ReqCode(21)  // Lists properties of a window.
	SetSelectionOwner       = ReqCode(22)  // Sets the owner of a selection.
	GetSelectionOwner       = ReqCode(23)  // Returns the owner of a selection.
	ConvertSelection        = ReqCode(24)  // Requests conversion of a selection.
	SendEvent               = ReqCode(25)  // Sends an event.
	GrabPointer             = ReqCode(26)  // Grabs the pointer.
	UngrabPointer           = ReqCode(27)  // Ungrabs the pointer.
	GrabButton              = ReqCode(28)  // Grabs a pointer button.
	UngrabButton            = ReqCode(29)  // Ungrabs a pointer button.
	ChangeActivePointerGrab = ReqCode(30)  // Changes active pointer grab parameters.
	GrabKeyboard            = ReqCode(31)  // Grabs the keyboard.
	UngrabKeyboard          = ReqCode(32)  // Ungrabs the keyboard.
	GrabKey                 = ReqCode(33)  // Grabs a keyboard key.
	UngrabKey               = ReqCode(34)  // Ungrabs a keyboard key.
	AllowEvents             = ReqCode(35)  // Releases queued events.
	GrabServer              = ReqCode(36)  // Grabs the server.
	UngrabServer            = ReqCode(37)  // Ungrabs the server.
	QueryPointer            = ReqCode(38)  // Returns pointer coordinates.
	GetMotionEvents         = ReqCode(39)  // Returns motion history.
	TranslateCoords         = ReqCode(40)  // Translates coordinates.
	WarpPointer             = ReqCode(41)  // Moves the pointer.
	SetInputFocus           = ReqCode(42)  // Sets input focus.
	GetInputFocus           = ReqCode(43)  // Returns input focus.
	QueryKeymap             = ReqCode(44)  // Returns keymap state.
	OpenFont                = ReqCode(45)  // Opens a font.
	CloseFont               = ReqCode(46)  // Closes a font.
	QueryFont               = ReqCode(47)  // Returns font information.
	QueryTextExtents        = ReqCode(48)  // Returns text extents.
	ListFonts               = ReqCode(49)  // Lists available fonts.
	ListFontsWithInfo       = ReqCode(50)  // Lists fonts with information.
	SetFontPath             = ReqCode(51)  // Sets font search path.
	GetFontPath             = ReqCode(52)  // Returns font search path.
	CreatePixmap            = ReqCode(53)  // Creates a pixmap.
	FreePixmap              = ReqCode(54)  // Frees a pixmap.
	CreateGC                = ReqCode(55)  // Creates a graphics context.
	ChangeGC                = ReqCode(56)  // Changes GC attributes.
	CopyGC                  = ReqCode(57)  // Copies GC attributes.
	SetDashes               = ReqCode(58)  // Sets dash pattern.
	SetClipRectangles       = ReqCode(59)  // Sets clipping rectangles.
	FreeGC                  = ReqCode(60)  // Frees a graphics context.
	ClearArea               = ReqCode(61)  // Clears a window area.
	CopyArea                = ReqCode(62)  // Copies a drawable area.
	CopyPlane               = ReqCode(63)  // Copies a single plane.
	PolyPoint               = ReqCode(64)  // Draws points.
	PolyLine                = ReqCode(65)  // Draws lines.
	PolySegment             = ReqCode(66)  // Draws segments.
	PolyRectangle           = ReqCode(67)  // Draws rectangles.
	PolyArc                 = ReqCode(68)  // Draws arcs.
	FillPoly                = ReqCode(69)  // Fills a polygon.
	PolyFillRectangle       = ReqCode(70)  // Fills rectangles.
	PolyFillArc             = ReqCode(71)  // Fills arcs.
	PutImage                = ReqCode(72)  // Puts image data.
	GetImage                = ReqCode(73)  // Gets image data.
	PolyText8               = ReqCode(74)  // Draws 8-bit text strings.
	PolyText16              = ReqCode(75)  // Draws 16-bit text strings.
	ImageText8              = ReqCode(76)  // Draws 8-bit image text.
	ImageText16             = ReqCode(77)  // Draws 16-bit image text.
	CreateColormap          = ReqCode(78)  // Creates a colormap.
	FreeColormap            = ReqCode(79)  // Frees a colormap.
	CopyColormapAndFree     = ReqCode(80)  // Copies colormap entries and frees old ones.
	InstallColormap         = ReqCode(81)  // Installs a colormap.
	UninstallColormap       = ReqCode(82)  // Uninstalls a colormap.
	ListInstalledColormaps  = ReqCode(83)  // Lists installed colormaps.
	AllocColor              = ReqCode(84)  // Allocates a color.
	AllocNamedColor         = ReqCode(85)  // Allocates a named color.
	AllocColorCells         = ReqCode(86)  // Allocates read/write color cells.
	AllocColorPlanes        = ReqCode(87)  // Allocates read/write color planes.
	FreeColors              = ReqCode(88)  // Frees colors.
	StoreColors             = ReqCode(89)  // Stores colors.
	StoreNamedColor         = ReqCode(90)  // Stores a named color.
	QueryColors             = ReqCode(91)  // Queries color values.
	LookupColor             = ReqCode(92)  // Looks up a named color.
	CreateCursor            = ReqCode(93)  // Creates a cursor.
	CreateGlyphCursor       = ReqCode(94)  // Creates a cursor from a font glyph.
	FreeCursor              = ReqCode(95)  // Frees a cursor.
	RecolorCursor           = ReqCode(96)  // Recolors a cursor.
	QueryBestSize           = ReqCode(97)  // Queries best size for object.
	QueryExtension          = ReqCode(98)  // Queries extension existence.
	ListExtensions          = ReqCode(99)  // Lists available extensions.
	ChangeKeyboardMapping   = ReqCode(100) // Changes keyboard mapping.
	GetKeyboardMapping      = ReqCode(101) // Returns keyboard mapping.
	ChangeKeyboardControl   = ReqCode(102) // Changes keyboard control.
	GetKeyboardControl      = ReqCode(103) // Returns keyboard control.
	Bell                    = ReqCode(104) // Rings the bell.
	ChangePointerControl    = ReqCode(105) // Changes pointer control.
	GetPointerControl       = ReqCode(106) // Returns pointer control.
	SetScreenSaver          = ReqCode(107) // Sets screen saver parameters.
	GetScreenSaver          = ReqCode(108) // Returns screen saver parameters.
	ChangeHosts             = ReqCode(109) // Changes access control hosts.
	ListHosts               = ReqCode(110) // Lists access control hosts.
	SetAccessControl        = ReqCode(111) // Sets access control mode.
	SetCloseDownMode        = ReqCode(112) // Sets close down mode.
	KillClient              = ReqCode(113) // Kills a client resource.
	RotateProperties        = ReqCode(114) // Rotates window properties.
	ForceScreenSaver        = ReqCode(115) // Forces screen saver on/off.
	SetPointerMapping       = ReqCode(116) // Sets pointer button mapping.
	GetPointerMapping       = ReqCode(117) // Returns pointer button mapping.
	SetModifierMapping      = ReqCode(118) // Sets modifier key mapping.
	GetModifierMapping      = ReqCode(119) // Returns modifier key mapping.
	NoOperation             = ReqCode(127) // No operation.
	XInputOpcode            = ReqCode(131) // XInput extension opcode.
	BigRequestsOpcode       = ReqCode(133) // Big Requests extension opcode.
)

const (
	AsyncPointer   = 0
	SyncPointer    = 1
	ReplayPointer  = 2
	AsyncKeyboard  = 3
	SyncKeyboard   = 4
	ReplayKeyboard = 5
	AsyncBoth      = 6
	SyncBoth       = 7
)

const (
	// XInputExtensionName is the name of the XInput extension.
	XInputExtensionName = "XInputExtension"
)

// X11 Error Codes
const (
	RequestErrorCode        byte = 1  // Bad Request.
	ValueErrorCode          byte = 2  // Bad Value.
	WindowErrorCode         byte = 3  // Bad Window.
	PixmapErrorCode         byte = 4  // Bad Pixmap.
	AtomErrorCode           byte = 5  // Bad Atom.
	CursorErrorCode         byte = 6  // Bad Cursor.
	FontErrorCode           byte = 7  // Bad Font.
	MatchErrorCode          byte = 8  // Bad Match.
	DrawableErrorCode       byte = 9  // Bad Drawable.
	AccessErrorCode         byte = 10 // Bad Access.
	AllocErrorCode          byte = 11 // Bad Alloc.
	ColormapErrorCode       byte = 12 // Bad Colormap.
	GContextErrorCode       byte = 13 // Bad GC.
	IDChoiceErrorCode       byte = 14 // Bad IDChoice.
	NameErrorCode           byte = 15 // Bad Name.
	LengthErrorCode         byte = 16 // Bad Length.
	ImplementationErrorCode byte = 17 // Implementation specific error.
	DeviceErrorCode         byte = 20 // Bad Device (XInput).
)

// X11 Event Codes
const (
	KeyPress           byte = 2  // Key press event.
	KeyRelease         byte = 3  // Key release event.
	ButtonPress        byte = 4  // Button press event.
	ButtonRelease      byte = 5  // Button release event.
	MotionNotify       byte = 6  // Pointer motion event.
	EnterNotify        byte = 7  // Pointer enter window event.
	LeaveNotify        byte = 8  // Pointer leave window event.
	Expose             byte = 12 // Expose event.
	ColormapNotifyCode byte = 32 // Colormap change event.
	ConfigureNotify    byte = 22 // Window configuration change event.
	ClientMessage      byte = 33 // Client message event.
	SelectionNotify    byte = 31 // Selection notify event.
)

// XInput event types
const (
	DeviceButtonPress   = 2 // XInput device button press.
	DeviceButtonRelease = 3 // XInput device button release.
	DeviceKeyPress      = 4 // XInput device key press.
	DeviceKeyRelease    = 5 // XInput device key release.
	DeviceMotionNotify  = 6 // XInput device motion.
	ProximityIn         = 8 // XInput proximity in.
	ProximityOut        = 9 // XInput proximity out.
)

// Other Event Codes
const (
	GraphicsExposure byte = 13 // Graphics exposure event.
	NoExposure       byte = 14 // No exposure event.
	VisibilityNotify byte = 15 // Visibility change event.
	CreateNotify     byte = 16 // Window creation event.
	DestroyNotify    byte = 17 // Window destruction event.
	UnmapNotify      byte = 18 // Window unmap event.
	MapNotify        byte = 19 // Window map event.
	MapRequest       byte = 20 // Window map request.
	ReparentNotify   byte = 21 // Window reparent event.
	ConfigureRequest byte = 23 // Window configure request.
	GravityNotify    byte = 24 // Window gravity event.
	ResizeRequest    byte = 25 // Window resize request.
	CirculateNotify  byte = 26 // Window circulate event.
	CirculateRequest byte = 27 // Window circulate request.
	PropertyNotify   byte = 28 // Property change event.
	SelectionClear   byte = 29 // Selection clear event.
	SelectionRequest byte = 30 // Selection request event.
	MappingNotify    byte = 34 // Keyboard/Pointer mapping change event.
	GenericEvent     byte = 35 // Generic event (XGE).
)

// XInput 2.0 Event Types
const (
	XI_DeviceChanged    = 1  // XI2 DeviceChanged
	XI_KeyPress         = 2  // XI2 KeyPress
	XI_KeyRelease       = 3  // XI2 KeyRelease
	XI_ButtonPress      = 4  // XI2 ButtonPress
	XI_ButtonRelease    = 5  // XI2 ButtonRelease
	XI_Motion           = 6  // XI2 Motion
	XI_Enter            = 7  // XI2 Enter
	XI_Leave            = 8  // XI2 Leave
	XI_FocusIn          = 9  // XI2 FocusIn
	XI_FocusOut         = 10 // XI2 FocusOut
	XI_HierarchyChanged = 11 // XI2 HierarchyChanged
	XI_PropertyEvent    = 12 // XI2 PropertyEvent
	XI_RawKeyPress      = 13 // XI2 RawKeyPress
	XI_RawKeyRelease    = 14 // XI2 RawKeyRelease
	XI_RawButtonPress   = 15 // XI2 RawButtonPress
	XI_RawButtonRelease = 16 // XI2 RawButtonRelease
	XI_RawMotion        = 17 // XI2 RawMotion
	XI_TouchBegin       = 18 // XI2 TouchBegin
	XI_TouchUpdate      = 19 // XI2 TouchUpdate
	XI_TouchEnd         = 20 // XI2 TouchEnd
	XI_TouchOwnership   = 21 // XI2 TouchOwnership
	XI_RawTouchBegin    = 22 // XI2 RawTouchBegin
	XI_RawTouchUpdate   = 23 // XI2 RawTouchUpdate
	XI_RawTouchEnd      = 24 // XI2 RawTouchEnd
	XI_BarrierHit       = 25 // XI2 BarrierHit
	XI_BarrierLeave     = 26 // XI2 BarrierLeave
)

// Window Attribute Masks
const (
	CWBackPixmap       = 1 << 0  // Background pixmap attribute.
	CWBackPixel        = 1 << 1  // Background pixel attribute.
	CWBorderPixmap     = 1 << 2  // Border pixmap attribute.
	CWBorderPixel      = 1 << 3  // Border pixel attribute.
	CWBitGravity       = 1 << 4  // Bit gravity attribute.
	CWWinGravity       = 1 << 5  // Window gravity attribute.
	CWBackingStore     = 1 << 6  // Backing store attribute.
	CWBackingPlanes    = 1 << 7  // Backing planes attribute.
	CWBackingPixel     = 1 << 8  // Backing pixel attribute.
	CWOverrideRedirect = 1 << 9  // Override redirect attribute.
	CWSaveUnder        = 1 << 10 // Save under attribute.
	CWEventMask        = 1 << 11 // Event mask attribute.
	CWDontPropagate    = 1 << 12 // Dont propagate attribute.
	CWColormap         = 1 << 13 // Colormap attribute.
	CWCursor           = 1 << 14 // Cursor attribute.
	CWSibling          = 1 << 5  // Sibling attribute (ConfigureWindow).
	CWStackMode        = 1 << 6  // Stack mode attribute (ConfigureWindow).
)

// Color Masks
const (
	DoRed   byte = 1 << 0 // Operate on red component.
	DoGreen byte = 1 << 1 // Operate on green component.
	DoBlue  byte = 1 << 2 // Operate on blue component.
)

// Keyboard Control Masks
const (
	KBKeyClickPercent = 1 << 0 // Key click volume mask.
	KBBellPercent     = 1 << 1 // Bell volume mask.
	KBBellPitch       = 1 << 2 // Bell pitch mask.
	KBBellDuration    = 1 << 3 // Bell duration mask.
	KBLed             = 1 << 4 // LED mask.
	KBLedMode         = 1 << 5 // LED mode mask.
	KBKey             = 1 << 6 // Key mask.
	KBAutoRepeatMode  = 1 << 7 // Auto repeat mode mask.
)

// Event Selection Masks
const (
	KeyPressMask             = 1 << 0  // Select KeyPress events.
	KeyReleaseMask           = 1 << 1  // Select KeyRelease events.
	ButtonPressMask          = 1 << 2  // Select ButtonPress events.
	ButtonReleaseMask        = 1 << 3  // Select ButtonRelease events.
	EnterWindowMask          = 1 << 4  // Select EnterNotify events.
	LeaveWindowMask          = 1 << 5  // Select LeaveNotify events.
	PointerMotionMask        = 1 << 6  // Select MotionNotify events.
	PointerMotionHintMask    = 1 << 7  // Select MotionNotify hints.
	Button1MotionMask        = 1 << 8  // Select MotionNotify while Button1 pressed.
	Button2MotionMask        = 1 << 9  // Select MotionNotify while Button2 pressed.
	Button3MotionMask        = 1 << 10 // Select MotionNotify while Button3 pressed.
	Button4MotionMask        = 1 << 11 // Select MotionNotify while Button4 pressed.
	Button5MotionMask        = 1 << 12 // Select MotionNotify while Button5 pressed.
	ButtonMotionMask         = 1 << 13 // Select MotionNotify while any button pressed.
	KeymapStateMask          = 1 << 14 // Select KeymapNotify events.
	ExposureMask             = 1 << 15 // Select Expose events.
	VisibilityChangeMask     = 1 << 16 // Select VisibilityNotify events.
	StructureNotifyMask      = 1 << 17 // Select StructureNotify events (Resize, Unmap, etc.).
	ResizeRedirectMask       = 1 << 18 // Select ResizeRequest events.
	SubstructureNotifyMask   = 1 << 19 // Select SubstructureNotify events.
	SubstructureRedirectMask = 1 << 20 // Select SubstructureRedirect events.
	FocusChangeMask          = 1 << 21 // Select FocusIn/FocusOut events.
	PropertyChangeMask       = 1 << 22 // Select PropertyNotify events.
	ColormapChangeMask       = 1 << 23 // Select ColormapNotify events.
	OwnerGrabButtonMask      = 1 << 24 // Select automatic grabs.
)

// XInput Event Selection Masks
const (
	DeviceKeyPressMask      = 1 << 0 // Select XInput KeyPress.
	DeviceKeyReleaseMask    = 1 << 1 // Select XInput KeyRelease.
	DeviceButtonPressMask   = 1 << 2 // Select XInput ButtonPress.
	DeviceButtonReleaseMask = 1 << 3 // Select XInput ButtonRelease.
)

// Modifier and Button Masks
const (
	ShiftMask   = 1 << 0  // Shift key mask.
	LockMask    = 1 << 1  // Lock key mask.
	ControlMask = 1 << 2  // Control key mask.
	Mod1Mask    = 1 << 3  // Mod1 key mask.
	Mod2Mask    = 1 << 4  // Mod2 key mask.
	Mod3Mask    = 1 << 5  // Mod3 key mask.
	Mod4Mask    = 1 << 6  // Mod4 key mask.
	Mod5Mask    = 1 << 7  // Mod5 key mask.
	Button1Mask = 1 << 8  // Button1 mask.
	Button2Mask = 1 << 9  // Button2 mask.
	Button3Mask = 1 << 10 // Button3 mask.
	Button4Mask = 1 << 11 // Button4 mask.
	Button5Mask = 1 << 12 // Button5 mask.
	AnyModifier = 1 << 15 // Match any modifier.
)

// Grab Modes
const (
	GrabModeSync  byte = 0 // Synchronous grab mode.
	GrabModeAsync byte = 1 // Asynchronous grab mode.
)

// Grab Status Codes
const (
	GrabSuccess     byte = 0 // Grab successful.
	AlreadyGrabbed  byte = 1 // Resource already grabbed.
	GrabInvalidTime byte = 2 // Invalid time specified.
	GrabNotViewable byte = 3 // Grab window not viewable.
	GrabFrozen      byte = 4 // Grab frozen.
)

// Window Classes
const (
	CopyFromParent = 0 // Window class CopyFromParent.
	InputOutput    = 1 // Window class InputOutput.
	InputOnly      = 2 // Window class InputOnly.
)

// Bit Gravity
const (
	NorthWestGravity = 1 // NorthWestGravity.
)

// Backing Store
const (
	NotUseful = 0 // Backing store not useful.
)

// Map State
const (
	IsUnmapped = 0 // Window is unmapped.
)

// Visual Class
const (
	StaticGray  = 0
	GrayScale   = 1
	StaticColor = 2
	PseudoColor = 3 // PseudoColor.
	TrueColor   = 4
	DirectColor = 5
)
