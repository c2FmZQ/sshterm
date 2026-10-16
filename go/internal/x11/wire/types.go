//go:build x11

package wire

// Window is a 32-bit value representing a window resource ID.
type Window uint32

// Drawable is a 32-bit value representing a drawable (window or pixmap) resource ID.
type Drawable uint32

// Font is a 32-bit value representing a font resource ID.
type Font uint32

// Pixmap is a 32-bit value representing a pixmap resource ID.
type Pixmap uint32

// Cursor is a 32-bit value representing a cursor resource ID.
type Cursor uint32

// Colormap is a 32-bit value representing a colormap resource ID.
type Colormap uint32

// GContext is a 32-bit value representing a graphics context resource ID.
type GContext uint32

// Atom is a 32-bit value representing an atom identifier.
type Atom uint32

// VisualID is a 32-bit value representing a visual ID.
type VisualID uint32

// BitCount returns the number of set bits in a mask.
func BitCount(mask uint32) uint32 {
	count := uint32(0)
	for mask > 0 {
		if mask&1 != 0 {
			count++
		}
		mask >>= 1
	}
	return count
}

// BitOffset returns the offset of the first set bit in a mask.
func BitOffset(mask uint32) uint32 {
	if mask == 0 {
		return 0
	}
	offset := uint32(0)
	for mask&1 == 0 {
		mask >>= 1
		offset++
	}
	return offset
}

// Timestamp is a 32-bit value representing a timestamp in milliseconds.
type Timestamp uint32

// KeyCode is an 8-bit value representing a physical key code.
type KeyCode uint8

// Rectangle specifies a rectangular area.
type Rectangle struct {
	X      int16  // X coordinate of the top-left corner.
	Y      int16  // Y coordinate of the top-left corner.
	Width  uint16 // Width of the rectangle.
	Height uint16 // Height of the rectangle.
}

// KeyboardControl defines the attributes for keyboard control requests.
type KeyboardControl struct {
	KeyClickPercent int32   // Volume for key clicks (0-100).
	BellPercent     int32   // Base volume for the bell (0-100).
	BellPitch       int32   // Pitch (frequency) of the bell in Hz.
	BellDuration    int32   // Duration of the bell in milliseconds.
	Led             uint32  // LED mask.
	LedMode         uint32  // LED mode (On/Off).
	Key             KeyCode // Specific key for auto-repeat control.
	AutoRepeatMode  uint32  // Auto-repeat mode (On/Off/Default).
}

// Host defines a host address for access control.
type Host struct {
	Family byte   // Address family (e.g., Internet, DECnet).
	Data   []byte // Address data.
}

// XColorItem defines a color entry in a colormap.
type XColorItem struct {
	Pixel    uint32 // Pixel value.
	Red      uint16 // Red component.
	Green    uint16 // Green component.
	Blue     uint16 // Blue component.
	Flags    byte   // Flags indicating which components are valid (DoRed, DoGreen, DoBlue).
	ClientID uint32 // ID of the client that allocated this color (internal use).
}

// XID is a generic 32-bit X resource identifier.
type XID uint32

// Opcodes holds the major and minor opcodes for identifying a request.
type Opcodes struct {
	Major ReqCode // Major opcode.
	Minor uint8   // Minor opcode (for extensions).
}

// ServerConfig holds dynamic server properties.
type ServerConfig struct {
	ScreenWidth  uint16
	ScreenHeight uint16
	Vendor       string
	Screens      []Screen
}
