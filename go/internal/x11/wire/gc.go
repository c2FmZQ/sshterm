//go:build x11

package wire

// GC attribute masks used in CreateGC and ChangeGC requests.
const (
	GCFunction          = 1 << 0  // Function attribute mask.
	GCPlaneMask         = 1 << 1  // PlaneMask attribute mask.
	GCForeground        = 1 << 2  // Foreground attribute mask.
	GCBackground        = 1 << 3  // Background attribute mask.
	GCLineWidth         = 1 << 4  // LineWidth attribute mask.
	GCLineStyle         = 1 << 5  // LineStyle attribute mask.
	GCCapStyle          = 1 << 6  // CapStyle attribute mask.
	GCJoinStyle         = 1 << 7  // JoinStyle attribute mask.
	GCFillStyle         = 1 << 8  // FillStyle attribute mask.
	GCFillRule          = 1 << 9  // FillRule attribute mask.
	GCTile              = 1 << 10 // Tile attribute mask.
	GCStipple           = 1 << 11 // Stipple attribute mask.
	GCTileStipXOrigin   = 1 << 12 // TileStipXOrigin attribute mask.
	GCTileStipYOrigin   = 1 << 13 // TileStipYOrigin attribute mask.
	GCFont              = 1 << 14 // Font attribute mask.
	GCSubwindowMode     = 1 << 15 // SubwindowMode attribute mask.
	GCGraphicsExposures = 1 << 16 // GraphicsExposures attribute mask.
	GCClipXOrigin       = 1 << 17 // ClipXOrigin attribute mask.
	GCClipYOrigin       = 1 << 18 // ClipYOrigin attribute mask.
	GCClipMask          = 1 << 19 // ClipMask attribute mask.
	GCDashOffset        = 1 << 20 // DashOffset attribute mask.
	GCDashes            = 1 << 21 // Dashes attribute mask.
	GCArcMode           = 1 << 22 // ArcMode attribute mask.
)

// Graphics functions used in GC.Function.
const (
	FunctionClear        = 0  // 0
	FunctionAnd          = 1  // src AND dst
	FunctionAndReverse   = 2  // src AND (NOT dst)
	FunctionCopy         = 3  // src
	FunctionAndInverted  = 4  // (NOT src) AND dst
	FunctionNoOp         = 5  // dst
	FunctionXor          = 6  // src XOR dst
	FunctionOr           = 7  // src OR dst
	FunctionNor          = 8  // (NOT src) AND (NOT dst)
	FunctionEquiv        = 9  // (NOT src) XOR dst
	FunctionInvert       = 10 // NOT dst
	FunctionOrReverse    = 11 // src OR (NOT dst)
	FunctionCopyInverted = 12 // NOT src
	FunctionOrInverted   = 13 // (NOT src) OR dst
	FunctionNand         = 14 // (NOT src) OR (NOT dst)
	FunctionSet          = 15 // 1
)

// Line styles used in GC.LineStyle.
const (
	LineStyleSolid      = 0 // Solid line.
	LineStyleOnOffDash  = 1 // Dashed line, only foreground is drawn.
	LineStyleDoubleDash = 2 // Dashed line, even dashes in foreground, odd in background.
)

// Cap styles used in GC.CapStyle.
const (
	CapStyleNotLast    = 0 // Endpoint is not drawn (implementation dependent).
	CapStyleButt       = 1 // Square at endpoint, perpendicular to slope.
	CapStyleRound      = 2 // Round ending with diameter equal to line width.
	CapStyleProjecting = 3 // Square ending extending by half line width.
)

// Join styles used in GC.JoinStyle.
const (
	JoinStyleMiter = 0 // Outer edges extended until they meet.
	JoinStyleRound = 1 // Circular arc with diameter equal to line width.
	JoinStyleBevel = 2 // Endpoints of lines are connected by a straight line.
)

// Fill styles used in GC.FillStyle.
const (
	FillStyleSolid          = 0 // Fill with foreground color.
	FillStyleTiled          = 1 // Fill with tile pixmap.
	FillStyleStippled       = 2 // Fill with foreground masked by stipple.
	FillStyleOpaqueStippled = 3 // Fill with foreground/background masked by stipple.
)

// Fill rules used in GC.FillRule.
const (
	FillRuleEvenOdd = 0 // Even-odd rule.
	FillRuleWinding = 1 // Winding rule.
)

// Subwindow modes used in GC.SubwindowMode.
const (
	SubwindowModeClipByChildren   = 0 // Clip output by children.
	SubwindowModeIncludeInferiors = 1 // Draw through inferiors.
)

// Arc modes used in GC.ArcMode.
const (
	ArcModeChord    = 0 // Join endpoints to center.
	ArcModePieSlice = 1 // Join endpoints to each other.
)

// GC represents a Graphics Context which contains state for graphics operations.
// See: https://www.x.org/releases/X11R7.6/doc/xproto/x11protocol.html#requests:CreateGC
type GC struct {
	Function           uint32      // Logical operation.
	PlaneMask          uint32      // Plane mask.
	Foreground         uint32      // Foreground pixel.
	Background         uint32      // Background pixel.
	LineWidth          uint32      // Line width.
	LineStyle          uint32      // Line style (Solid, Dash, etc.).
	CapStyle           uint32      // Line cap style (Butt, Round, etc.).
	JoinStyle          uint32      // Line join style (Miter, Round, etc.).
	FillStyle          uint32      // Fill style (Solid, Tiled, etc.).
	FillRule           uint32      // Fill rule (EvenOdd, Winding).
	Tile               uint32      // Tile pixmap for tiling operations.
	Stipple            uint32      // Stipple pixmap for stippling operations.
	TileStipXOrigin    uint32      // X origin for tile/stipple.
	TileStipYOrigin    uint32      // Y origin for tile/stipple.
	Font               uint32      // Font ID.
	SubwindowMode      uint32      // Subwindow mode (ClipByChildren, IncludeInferiors).
	GraphicsExposures  uint32      // Boolean: generate GraphicsExposures events.
	ClipXOrigin        int32       // X origin for clipping.
	ClipYOrigin        int32       // Y origin for clipping.
	ClipMask           uint32      // Bitmap for clipping.
	DashOffset         uint32      // Phase of the dash pattern.
	Dashes             uint32      // Dash pattern (if single value).
	ArcMode            uint32      // Arc mode (Chord, PieSlice).
	ClippingRectangles []Rectangle // Explicit clipping rectangles (not part of standard GC struct on wire, but used internally).
	DashPattern        []byte      // Explicit dash list (not part of standard GC struct on wire, but used internally).
}
