//go:build x11 && wasm

package x11

import (
	"encoding/binary"
	"fmt"
	"image"
	"math"
	"strconv"
	"strings"
	"syscall/js"

	"github.com/c2FmZQ/sshterm/internal/jsutil"
	"github.com/c2FmZQ/sshterm/internal/x11/wire"
)

type windowInfo struct {
	div             js.Value
	canvas          js.Value
	ctx             js.Value // 2D rendering context (visible)
	offscreenCanvas js.Value
	offscreenCtx    js.Value // 2D rendering context (offscreen)
	mouseEvents     map[string]js.Func
	focusEvent      js.Func
	blurEvent       js.Func
	keyDownEvent    js.Func
	keyUpEvent      js.Func
	xInputEvents    map[string]js.Func
	zIndex          int
	backgroundPixel uint32
	colormap        xID
	isTopLevel      bool

	titleBar      js.Value
	windowTitle   js.Value
	dragMouseDown js.Func
	dragMouseMove js.Func
	dragMouseUp   js.Func

	resizeHandles   map[string]js.Value
	resizeMouseDown js.Func
	resizeMouseMove js.Func
	resizeMouseUp   js.Func
}

type pixmapInfo struct {
	canvas  js.Value
	context js.Value
}

type fontInfo struct {
	x11Name string
	cssFont string // CSS font string, e.g., "12px monospace"
}

type cursorInfo struct {
	style     string
	source    xID
	mask      xID
	x, y      uint16
	foreColor [3]uint16
	backColor [3]uint16
}

type wasmX11Frontend struct {
	document           js.Value
	body               js.Value
	mainContainer      js.Value
	windows            map[xID]*windowInfo    // Map to store window elements (div)
	pixmaps            map[xID]*pixmapInfo    // Map to store pixmap elements (canvas)
	gcs                map[xID]wire.GC        // Map to store graphics contexts (Go representation)
	fonts              map[xID]*fontInfo      // Map to store opened fonts
	cursors            map[xID]*cursorInfo    // Map to store cursor info
	focusedWindowID    xID                    // Track the currently focused window
	server             *x11Server             // To call back into the server for pointer updates
	canvasOperations   []CanvasOperation      // Store canvas operations for testing
	cursorStyles       map[uint32]*cursorInfo // Map X11 cursor IDs to CSS cursor styles
	modifierMap        []wire.KeyCode
	deviceModifierMaps map[byte][]byte
	deviceButtonMaps   map[byte][]byte
	deviceKeymaps      map[byte]map[byte][]uint32
	lastPointerID      int
	grabbedWindowID    xID

	// ScreenSaver state
	screenSaverTimeout     int16
	screenSaverInterval    int16
	screenSaverPreferBlank byte
	screenSaverAllowExpose byte

	// PointerControl state
	pointerAccelNumerator   int16
	pointerAccelDenominator int16
	pointerThreshold        int16
}

func (w *wasmX11Frontend) showMessage(message string) {
	debugf("Show Message: %q", message)
	document := js.Global().Get("document")
	msg := document.Call("createElement", "div")
	msg.Set("style", "position: absolute; bottom: 0; right: 0; padding: 0.5rem; background-color: white; color: black; font-family: monospace; border: solid 1px black; z-Index: 1000;")
	msg.Set("textContent", message)

	document.Get("body").Call("appendChild", msg)
	var remove js.Func
	remove = js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		msg.Call("remove")
		remove.Release()
		return nil
	})
	js.Global().Get("setTimeout").Invoke(remove, 3000)
}

func newX11Frontend(logger Logger, s *x11Server) *wasmX11Frontend {
	document := js.Global().Get("document")
	body := document.Get("body")
	frontend := &wasmX11Frontend{
		document:           document,
		body:               body,
		mainContainer:      body,
		windows:            make(map[xID]*windowInfo),
		pixmaps:            make(map[xID]*pixmapInfo),
		gcs:                make(map[xID]wire.GC),
		fonts:              make(map[xID]*fontInfo),
		cursors:            make(map[xID]*cursorInfo),
		server:             s,
		cursorStyles:       make(map[uint32]*cursorInfo),
		deviceModifierMaps: make(map[byte][]byte),
		deviceButtonMaps:   make(map[byte][]byte),
		deviceKeymaps:      make(map[byte]map[byte][]uint32),
	}
	frontend.initDefaultCursors()
	frontend.initCanvasOperations()

	// Set initial root window size and add resize listener
	win := js.Global().Get("window")
	width := win.Get("innerWidth").Int()
	height := win.Get("innerHeight").Int()
	s.config = wire.ServerConfig{
		ScreenWidth:  uint16(width),
		ScreenHeight: uint16(height),
		Vendor:       "sshterm-wasm",
		Screens:      wire.NewDefaultSetup(&wire.ServerConfig{}).Screens,
	}
	s.config.Screens[0].WidthInPixels = uint16(width)
	s.config.Screens[0].HeightInPixels = uint16(height)

	resizeHandler := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		newWidth := win.Get("innerWidth").Int()
		newHeight := win.Get("innerHeight").Int()
		s.config.ScreenWidth = uint16(newWidth)
		s.config.ScreenHeight = uint16(newHeight)
		return nil
	})
	win.Call("addEventListener", "resize", resizeHandler)

	gotCapture := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		debugf("X11: GLOBAL gotpointercapture")
		return nil
	})
	lostCapture := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		debugf("X11: GLOBAL lostpointercapture")
		if frontend.grabbedWindowID != 0 {
			debugf("X11: Lost pointer capture globally, informing server")
			frontend.grabbedWindowID = 0
		}
		return nil
	})
	frontend.mainContainer.Call("addEventListener", "gotpointercapture", gotCapture)
	frontend.mainContainer.Call("addEventListener", "lostpointercapture", lostCapture)

	frontend.showMessage("X11 Frontend Started")
	return frontend
}

func (w *wasmX11Frontend) getForegroundColor(cmap xID, gc wire.GC) (out string) {
	defer func() {
		debugf("getForegroundColor: cmap:%d gc=%+v %s", cmap, gc, out)
	}()
	r, g, b := w.GetRGBColor(cmap, gc.Foreground)
	visual, ok := w.server.getVisualByID(w.server.visualID)
	if !ok {
		return fmt.Sprintf("rgba(%d, %d, %d, 1.0)", r, g, b)
	}
	switch visual.Class {
	case 0, 1: // StaticGray, GrayScale
		return fmt.Sprintf("rgba(%d, %d, %d, 1.0)", r, r, r)
	default:
		return fmt.Sprintf("rgba(%d, %d, %d, 1.0)", r, g, b)
	}
}

func (w *wasmX11Frontend) getBackgroundColor(cmap xID, gc wire.GC) (out string) {
	defer func() {
		debugf("getBackgroundColor: cmap:%d gc=%+v %s", cmap, gc, out)
	}()
	r, g, b := w.GetRGBColor(cmap, gc.Background)
	visual, ok := w.server.getVisualByID(w.server.visualID)
	if !ok {
		return fmt.Sprintf("rgba(%d, %d, %d, 1.0)", r, g, b)
	}
	switch visual.Class {
	case 0, 1: // StaticGray, GrayScale
		return fmt.Sprintf("rgba(%d, %d, %d, 1.0)", r, r, r)
	default:
		return fmt.Sprintf("rgba(%d, %d, %d, 1.0)", r, g, b)
	}
}

func (w *wasmX11Frontend) CreateWindow(xid xID, parent xID, x, y int32, width, height, depth, valueMask uint32, values wire.WindowAttributes) {
	debugf("X11: createWindow xid=%d parent=%d x=%d y=%d width=%d height=%d depth=%d values=%+v", xid, parent, x, y, width, height, depth, values)

	windowDiv := w.document.Call("createElement", "div")
	windowDiv.Set("id", js.ValueOf(fmt.Sprintf("x11-window-%s", xid)))
	style := windowDiv.Get("style")
	style.Set("position", "absolute")
	style.Set("width", js.ValueOf(fmt.Sprintf("%dpx", width)))
	style.Set("border", "1px solid black")
	winZIndex := w.getHighestZIndex() + 1
	if len(w.windows) == 0 {
		winZIndex = 100
	}
	style.Set("zIndex", js.ValueOf(fmt.Sprintf("%d", winZIndex)))
	style.Set("overflow", "hidden") // Hide overflow during resize

	// Create canvas first so it can be referenced in handlers, but don't append yet.
	canvas := w.document.Call("createElement", "canvas")
	canvas.Set("id", js.ValueOf(fmt.Sprintf("x11-canvas-%s", xid)))
	canvas.Set("width", width)
	canvas.Set("height", height)
	canvas.Get("style").Set("display", "block")

	// Create offscreen canvas
	offscreenCanvas := w.document.Call("createElement", "canvas")
	offscreenCanvas.Set("width", width)
	offscreenCanvas.Set("height", height)

	isTopLevel := parent == xID(w.server.rootWindowID())
	var titleBarHeight int
	var titleBar, windowTitleSpan js.Value
	var dragMouseDown, dragMouseMove, dragMouseUp js.Func
	var resizeHandlesMap map[string]js.Value
	var resizeMouseDown, resizeMouseMove, resizeMouseUp js.Func
	var titleBarStyle js.Value

	// These need to be accessible by blurEvent
	var isDragging bool
	var isResizing bool

	if isTopLevel {
		style.Set("backgroundColor", "white")

		titleBarHeight = 20

		// Title bar
		titleBar = w.document.Call("createElement", "div")
		titleBar.Set("id", js.ValueOf(fmt.Sprintf("x11-titlebar-%s", xid)))
		titleBarStyle = titleBar.Get("style")
		titleBarStyle.Set("height", "20px")
		titleBarStyle.Set("backgroundColor", "#333")
		titleBarStyle.Set("color", "white")
		titleBarStyle.Set("fontFamily", "monospace")
		titleBarStyle.Set("fontSize", "14px")
		titleBarStyle.Set("lineHeight", "20px")
		titleBarStyle.Set("paddingLeft", "5px")
		titleBarStyle.Set("cursor", "move")
		titleBarStyle.Set("userSelect", "none")
		windowDiv.Call("appendChild", titleBar)

		// Window title text
		windowTitleSpan = w.document.Call("createElement", "span")
		windowTitleSpan.Set("id", js.ValueOf(fmt.Sprintf("x11-window-title-%s", xid)))
		windowTitleSpan.Set("textContent", fmt.Sprintf("Window %d", xid)) // Default title
		titleBar.Call("appendChild", windowTitleSpan)

		// Close button
		closeButton := w.document.Call("createElement", "button")
		closeButton.Set("textContent", "X")
		closeButton.Set("ariaLabel", "Close Window")
		closeButtonStyle := closeButton.Get("style")
		closeButtonStyle.Set("float", "right")
		closeButtonStyle.Set("backgroundColor", "#f00")
		closeButtonStyle.Set("color", "white")
		closeButtonStyle.Set("border", "none")
		closeButtonStyle.Set("height", "100%")
		closeButtonStyle.Set("cursor", "pointer")
		closeButton.Call("addEventListener", "click", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
			w.CloseWindow(xid)
			return nil
		}))
		titleBar.Call("appendChild", closeButton)

		// Dragging functionality
		var dragOffsetX, dragOffsetY int

		dragMouseMove = js.FuncOf(func(this js.Value, args []js.Value) interface{} {
			event := args[0]
			if isDragging {
				newX := event.Get("clientX").Int() - dragOffsetX
				newY := event.Get("clientY").Int() - dragOffsetY
				style.Set("left", js.ValueOf(fmt.Sprintf("%dpx", newX)))
				style.Set("top", js.ValueOf(fmt.Sprintf("%dpx", newY)))
			}
			return nil
		})

		dragMouseUp = js.FuncOf(func(this js.Value, args []js.Value) interface{} {
			isDragging = false
			titleBarStyle.Set("cursor", "move")
			w.document.Call("removeEventListener", "mousemove", dragMouseMove)
			w.document.Call("removeEventListener", "mouseup", dragMouseUp)
			w.SendConfigureAndExposeEvent(xid, int16(windowDiv.Get("offsetLeft").Int()), int16(windowDiv.Get("offsetTop").Int()), uint16(canvas.Get("width").Int()), uint16(canvas.Get("height").Int()))
			return nil
		})

		dragMouseDown = js.FuncOf(func(this js.Value, args []js.Value) interface{} {
			event := args[0]
			isDragging = true
			dragOffsetX = event.Get("clientX").Int() - windowDiv.Get("offsetLeft").Int()
			dragOffsetY = event.Get("clientY").Int() - windowDiv.Get("offsetTop").Int()
			titleBarStyle.Set("cursor", "grabbing")
			w.document.Call("addEventListener", "mousemove", dragMouseMove)
			w.document.Call("addEventListener", "mouseup", dragMouseUp)
			return nil
		})

		titleBar.Call("addEventListener", "mousedown", dragMouseDown)

		// Resizing functionality
		var resizeStartX, resizeStartY, resizeStartWidth, resizeStartHeight, resizeStartLeft, resizeStartTop int
		var resizeHandle string

		resizeHandlesMap = make(map[string]js.Value)
		handleNames := []string{"n", "s", "e", "w", "nw", "ne", "sw", "se"}
		for _, name := range handleNames {
			handle := w.document.Call("createElement", "div")
			handle.Set("className", "resize-handle "+name)
			handleStyle := handle.Get("style")
			handleStyle.Set("position", "absolute")
			handleStyle.Set("backgroundColor", "rgba(0, 0, 0, 0)") // Transparent
			handleStyle.Set("zIndex", "101")
			const handleSize = 8 // pixels

			switch name {
			case "n":
				handleStyle.Set("height", fmt.Sprintf("%dpx", handleSize))
				handleStyle.Set("left", fmt.Sprintf("%dpx", handleSize))
				handleStyle.Set("right", fmt.Sprintf("%dpx", handleSize))
				handleStyle.Set("top", fmt.Sprintf("-%dpx", handleSize/2))
				handleStyle.Set("cursor", "ns-resize")
			case "s":
				handleStyle.Set("height", fmt.Sprintf("%dpx", handleSize))
				handleStyle.Set("left", fmt.Sprintf("%dpx", handleSize))
				handleStyle.Set("right", fmt.Sprintf("%dpx", handleSize))
				handleStyle.Set("bottom", fmt.Sprintf("-%dpx", handleSize/2))
				handleStyle.Set("cursor", "ns-resize")
			case "e":
				handleStyle.Set("width", fmt.Sprintf("%dpx", handleSize))
				handleStyle.Set("top", fmt.Sprintf("%dpx", handleSize))
				handleStyle.Set("bottom", fmt.Sprintf("%dpx", handleSize))
				handleStyle.Set("right", fmt.Sprintf("-%dpx", handleSize/2))
				handleStyle.Set("cursor", "ew-resize")
			case "w":
				handleStyle.Set("width", fmt.Sprintf("%dpx", handleSize))
				handleStyle.Set("top", fmt.Sprintf("%dpx", handleSize))
				handleStyle.Set("bottom", fmt.Sprintf("%dpx", handleSize))
				handleStyle.Set("left", fmt.Sprintf("-%dpx", handleSize/2))
				handleStyle.Set("cursor", "ew-resize")
			case "nw":
				handleStyle.Set("width", fmt.Sprintf("%dpx", handleSize))
				handleStyle.Set("height", fmt.Sprintf("%dpx", handleSize))
				handleStyle.Set("top", fmt.Sprintf("-%dpx", handleSize/2))
				handleStyle.Set("left", fmt.Sprintf("-%dpx", handleSize/2))
				handleStyle.Set("cursor", "nwse-resize")
			case "ne":
				handleStyle.Set("width", fmt.Sprintf("%dpx", handleSize))
				handleStyle.Set("height", fmt.Sprintf("%dpx", handleSize))
				handleStyle.Set("top", fmt.Sprintf("-%dpx", handleSize/2))
				handleStyle.Set("right", fmt.Sprintf("-%dpx", handleSize/2))
				handleStyle.Set("cursor", "nesw-resize")
			case "sw":
				handleStyle.Set("width", fmt.Sprintf("%dpx", handleSize))
				handleStyle.Set("height", fmt.Sprintf("%dpx", handleSize))
				handleStyle.Set("bottom", fmt.Sprintf("-%dpx", handleSize/2))
				handleStyle.Set("left", fmt.Sprintf("-%dpx", handleSize/2))
				handleStyle.Set("cursor", "nesw-resize")
			case "se":
				handleStyle.Set("width", fmt.Sprintf("%dpx", handleSize))
				handleStyle.Set("height", fmt.Sprintf("%dpx", handleSize))
				handleStyle.Set("bottom", fmt.Sprintf("-%dpx", handleSize/2))
				handleStyle.Set("right", fmt.Sprintf("-%dpx", handleSize/2))
				handleStyle.Set("cursor", "nwse-resize")
			}
			windowDiv.Call("appendChild", handle)
			resizeHandlesMap[name] = handle
		}

		resizeMouseMove = js.FuncOf(func(this js.Value, args []js.Value) interface{} {
			event := args[0]
			if !isResizing {
				return nil
			}

			currentX := event.Get("clientX").Int()
			currentY := event.Get("clientY").Int()

			deltaX := currentX - resizeStartX
			deltaY := currentY - resizeStartY

			newWidth := resizeStartWidth
			newHeight := resizeStartHeight
			newX := resizeStartLeft
			newY := resizeStartTop

			name := strings.TrimPrefix(resizeHandle, "resize-handle ")
			switch {
			case strings.Contains(name, "n"):
				newHeight = resizeStartHeight - deltaY
				newY = resizeStartTop + deltaY
			case strings.Contains(name, "s"):
				newHeight = resizeStartHeight + deltaY
			}
			switch {
			case strings.Contains(name, "w"):
				newWidth = resizeStartWidth - deltaX
				newX = resizeStartLeft + deltaX
			case strings.Contains(name, "e"):
				newWidth = resizeStartWidth + deltaX
			}

			// Minimum size
			if newWidth < 50 {
				newWidth = 50
			}
			if newHeight < 50 {
				newHeight = 50
			}

			style.Set("width", fmt.Sprintf("%dpx", newWidth))
			style.Set("height", fmt.Sprintf("%dpx", newHeight))
			style.Set("left", js.ValueOf(fmt.Sprintf("%dpx", newX)))
			style.Set("top", js.ValueOf(fmt.Sprintf("%dpx", newY)))

			canvas.Set("width", newWidth)
			canvas.Set("height", newHeight-20) // Adjust for title bar height
			offscreenCanvas.Set("width", newWidth)
			offscreenCanvas.Set("height", newHeight-20)

			return nil
		})

		resizeMouseUp = js.FuncOf(func(this js.Value, args []js.Value) interface{} {
			isResizing = false
			w.document.Call("removeEventListener", "mousemove", resizeMouseMove)
			w.document.Call("removeEventListener", "mouseup", resizeMouseUp)
			winInfo, ok := w.windows[xid]
			if !ok {
				return nil
			}
			w.SendConfigureAndExposeEvent(xid, int16(winInfo.div.Get("offsetLeft").Int()), int16(winInfo.div.Get("offsetTop").Int()), uint16(winInfo.canvas.Get("width").Int()), uint16(winInfo.canvas.Get("height").Int()))
			return nil
		})

		resizeMouseDown = js.FuncOf(func(this js.Value, args []js.Value) interface{} {
			event := args[0]
			isResizing = true
			resizeStartX = event.Get("clientX").Int()
			resizeStartY = event.Get("clientY").Int()
			resizeStartWidth = windowDiv.Get("offsetWidth").Int()
			resizeStartHeight = windowDiv.Get("offsetHeight").Int()
			resizeStartLeft = windowDiv.Get("offsetLeft").Int()
			resizeStartTop = windowDiv.Get("offsetTop").Int()
			resizeHandle = this.Get("className").String() // e.g., "resize-handle n"
			w.document.Call("addEventListener", "mousemove", resizeMouseMove)
			w.document.Call("addEventListener", "mouseup", resizeMouseUp)
			return nil
		})

		for _, handle := range resizeHandlesMap {
			handle.Call("addEventListener", "mousedown", resizeMouseDown)
		}
	}

	windowDiv.Call("appendChild", canvas)

	// Enable alpha channel for transparency
	ctxOptions := js.Global().Get("Object").New()
	ctxOptions.Set("alpha", true)
	ctx := canvas.Call("getContext", "2d", ctxOptions)

	// Get offscreen context
	offscreenCtx := offscreenCanvas.Call("getContext", "2d", ctxOptions)

	var finalX, finalY int32 = x, y
	var parentDiv js.Value = w.body

	if !isTopLevel {
		if parentInfo, ok := w.windows[xID(parent)]; ok {
			parentDiv = parentInfo.div
			if parentInfo.isTopLevel {
				finalY = y + 20
			}
		}
	}
	style.Set("left", js.ValueOf(fmt.Sprintf("%dpx", finalX)))
	style.Set("top", js.ValueOf(fmt.Sprintf("%dpx", finalY)))
	if isTopLevel {
		titleBarHeight = 20
	}
	style.Set("height", js.ValueOf(fmt.Sprintf("%dpx", height+uint32(titleBarHeight))))

	// Create and store event listeners
	mouseEvents := make(map[string]js.Func)
	mouseEvents["mousedown"] = w.mouseEventHandler(xid, "mousedown")
	mouseEvents["mouseup"] = w.mouseEventHandler(xid, "mouseup")
	mouseEvents["mousemove"] = w.mouseEventHandler(xid, "mousemove")
	mouseEvents["wheel"] = w.mouseEventHandler(xid, "wheel")
	mouseEvents["mouseenter"] = w.pointerCrossingEventHandler(xid, true)
	mouseEvents["mouseleave"] = w.pointerCrossingEventHandler(xid, false)

	w.mainContainer.Call("addEventListener", "gotpointercapture", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		debugf("X11: gotpointercapture")
		return nil
	}))
	w.mainContainer.Call("addEventListener", "lostpointercapture", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		debugf("X11: lostpointercapture")
		if w.grabbedWindowID != 0 {
			debugf("X11: Lost pointer capture, informing server")
			w.grabbedWindowID = 0
		}
		return nil
	}))

	keyDownEvent := w.keyboardEventHandler(xid, "keydown")
	keyUpEvent := w.keyboardEventHandler(xid, "keyup")

	focusEvent := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		debugf("X11: Window %d focused", xid)
		w.focusedWindowID = xid
		w.document.Call("addEventListener", "keydown", keyDownEvent)
		w.document.Call("addEventListener", "keyup", keyUpEvent)
		return nil
	})
	blurEvent := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		debugf("X11: Window %d blurred", xid)
		w.focusedWindowID = 0
		w.document.Call("removeEventListener", "keydown", keyDownEvent)
		w.document.Call("removeEventListener", "keyup", keyUpEvent)
		if isTopLevel {
			if isDragging {
				isDragging = false
				titleBarStyle.Set("cursor", "move")
				w.document.Call("removeEventListener", "mousemove", dragMouseMove)
				w.document.Call("removeEventListener", "mouseup", dragMouseUp)
			}
			if isResizing {
				isResizing = false
				w.document.Call("removeEventListener", "mousemove", resizeMouseMove)
				w.document.Call("removeEventListener", "mouseup", resizeMouseUp)
			}
		}
		return nil
	})

	// Attach mouse event listeners
	canvas.Call("addEventListener", "mousedown", mouseEvents["mousedown"])
	canvas.Call("addEventListener", "mouseup", mouseEvents["mouseup"])
	canvas.Call("addEventListener", "mousemove", mouseEvents["mousemove"])
	canvas.Call("addEventListener", "wheel", mouseEvents["wheel"])
	canvas.Call("addEventListener", "mouseenter", mouseEvents["mouseenter"])
	canvas.Call("addEventListener", "mouseleave", mouseEvents["mouseleave"])

	// Attach focus/blur event listeners
	windowDiv.Set("tabIndex", 0) // Make the div focusable
	windowDiv.Call("addEventListener", "focus", focusEvent)
	windowDiv.Call("addEventListener", "blur", blurEvent)

	// Store window info in the map
	w.windows[xid] = &windowInfo{
		div:             windowDiv,
		canvas:          canvas,
		ctx:             ctx,
		offscreenCanvas: offscreenCanvas,
		offscreenCtx:    offscreenCtx,
		mouseEvents:     mouseEvents,
		focusEvent:      focusEvent,
		blurEvent:       blurEvent,
		keyDownEvent:    keyDownEvent, // Store for removal
		keyUpEvent:      keyUpEvent,   // Store for removal
		xInputEvents:    make(map[string]js.Func),
		zIndex:          winZIndex,
		isTopLevel:      isTopLevel,
		titleBar:        titleBar,
		windowTitle:     windowTitleSpan,
		dragMouseDown:   dragMouseDown,
		dragMouseMove:   dragMouseMove,
		dragMouseUp:     dragMouseUp,
		resizeHandles:   resizeHandlesMap,
		resizeMouseDown: resizeMouseDown,
		resizeMouseMove: resizeMouseMove,
		resizeMouseUp:   resizeMouseUp,
	}
	if values.Colormap != 0 {
		w.windows[xid].colormap = xID(values.Colormap)
	}

	parentDiv.Call("appendChild", windowDiv)

	w.recordOperation(CanvasOperation{
		Type: "createWindow",
		Args: []any{uint32(xid), parent, x, y, width, height, depth},
	})
}

func (w *wasmX11Frontend) updateVisibleArea(xid xID, x, y, width, height int) {
	if winInfo, ok := w.windows[xid]; ok {
		// Draw the dirty rectangle from offscreen canvas to onscreen canvas
		winInfo.ctx.Call("drawImage", winInfo.offscreenCanvas, x, y, width, height, x, y, width, height)
	}
}

func (w *wasmX11Frontend) DestroyWindow(wid xID) {
	w.destroyWindow(wid, true)
}

func (w *wasmX11Frontend) DestroySubwindows(xid xID) {
	debugf("X11: destroySubwindows id=%d", xid)
	if winInfo, ok := w.windows[xid]; ok {
		// Create a slice to hold children to be removed, to avoid modifying the list while iterating
		var toRemove []js.Value
		children := winInfo.div.Get("childNodes")
		for i := 0; i < children.Length(); i++ {
			child := children.Index(i)
			// Check if the child is a window managed by us
			childXIDStr := child.Get("id").String()
			if strings.HasPrefix(childXIDStr, "x11-window-") {
				toRemove = append(toRemove, child)
			}
		}
		for _, child := range toRemove {
			childXIDStr := strings.TrimPrefix(child.Get("id").String(), "x11-window-")
			id, err := strconv.Atoi(childXIDStr)
			if err == nil {
				w.destroyWindow(xID(id), false)
			}
		}
	}
	w.recordOperation(CanvasOperation{
		Type: "destroySubwindows",
		Args: []any{uint32(xid)},
	})
}

func (w *wasmX11Frontend) ReparentWindow(windowID, parentID xID, x, y int16) {
	debugf("X11: ReparentWindow window=%d parent=%d x=%d y=%d", windowID, parentID, x, y)

	winInfo, ok := w.windows[windowID]
	if !ok {
		debugf("X11: ReparentWindow: window %d not found", windowID)
		return
	}

	var parentDiv js.Value
	if uint32(parentID) == w.server.rootWindowID() {
		parentDiv = w.body
	} else if parentInfo, ok := w.windows[parentID]; ok {
		parentDiv = parentInfo.div
	} else {
		debugf("X11: ReparentWindow: parent window %d not found", parentID)
		return
	}

	style := winInfo.div.Get("style")
	style.Set("left", fmt.Sprintf("%dpx", x))
	style.Set("top", fmt.Sprintf("%dpx", y))

	parentDiv.Call("appendChild", winInfo.div)

	w.recordOperation(CanvasOperation{
		Type: "reparentWindow",
		Args: []any{uint32(windowID), uint32(parentID), x, y},
	})
}

func (w *wasmX11Frontend) destroyWindow(wid xID, logit bool) {
	if winInfo, ok := w.windows[wid]; ok {
		// Remove event listeners from the document and window elements
		if winInfo.isTopLevel {
			winInfo.titleBar.Call("removeEventListener", "mousedown", winInfo.dragMouseDown)
			w.document.Call("removeEventListener", "mousemove", winInfo.dragMouseMove)
			w.document.Call("removeEventListener", "mouseup", winInfo.dragMouseUp)

			for _, handle := range winInfo.resizeHandles {
				handle.Call("removeEventListener", "mousedown", winInfo.resizeMouseDown)
			}
			w.document.Call("removeEventListener", "mousemove", winInfo.resizeMouseMove)
			w.document.Call("removeEventListener", "mouseup", winInfo.resizeMouseUp)
		}

		winInfo.canvas.Call("removeEventListener", "mousedown", winInfo.mouseEvents["mousedown"])
		winInfo.canvas.Call("removeEventListener", "mouseup", winInfo.mouseEvents["mouseup"])
		winInfo.canvas.Call("removeEventListener", "mousemove", winInfo.mouseEvents["mousemove"])
		winInfo.canvas.Call("removeEventListener", "wheel", winInfo.mouseEvents["wheel"])
		winInfo.canvas.Call("removeEventListener", "mouseenter", winInfo.mouseEvents["mouseenter"])
		winInfo.canvas.Call("removeEventListener", "mouseleave", winInfo.mouseEvents["mouseleave"])

		winInfo.div.Call("removeEventListener", "focus", winInfo.focusEvent)
		winInfo.div.Call("removeEventListener", "blur", winInfo.blurEvent)

		// If the window is focused, remove the keyboard listeners from the document
		if w.focusedWindowID == wid {
			w.document.Call("removeEventListener", "keydown", winInfo.keyDownEvent)
			w.document.Call("removeEventListener", "keyup", winInfo.keyUpEvent)
		}

		winInfo.div.Call("remove")
		// Release all js.Func objects to prevent memory leaks
		for _, fn := range winInfo.mouseEvents {
			fn.Release()
		}
		for _, fn := range winInfo.xInputEvents {
			fn.Release()
		}
		winInfo.focusEvent.Release()
		winInfo.blurEvent.Release()
		winInfo.keyDownEvent.Release() // Release keyboard event listeners
		winInfo.keyUpEvent.Release()   // Release keyboard event listeners

		if winInfo.isTopLevel {
			winInfo.dragMouseDown.Release()
			winInfo.dragMouseMove.Release()
			winInfo.dragMouseUp.Release()
			winInfo.resizeMouseDown.Release()
			winInfo.resizeMouseMove.Release()
			winInfo.resizeMouseUp.Release()
		}

		delete(w.windows, wid)
	}
	if logit {
		w.recordOperation(CanvasOperation{
			Type: "destroyWindow",
			Args: []any{uint32(wid)},
		})
	}
}

func (w *wasmX11Frontend) CloseWindow(xid xID) {
	_, ok := w.windows[xid]
	if !ok {
		return
	}

	wmProtocolsAtom := w.server.GetAtom("WM_PROTOCOLS")
	wmDeleteWindowAtom := w.server.GetAtom("WM_DELETE_WINDOW")

	supportsDelete := false
	protocolsProp := w.server.GetProperty(xid, wmProtocolsAtom)
	if protocolsProp != nil && protocolsProp.format == 32 {
		// The property contains a list of atoms (CARD32).
		for i := 0; i < len(protocolsProp.data); i += 4 {
			atom := w.server.byteOrder.Uint32(protocolsProp.data[i : i+4])
			if atom == wmDeleteWindowAtom {
				supportsDelete = true
				break
			}
		}
	}

	if supportsDelete {
		debugf("X11: Sending WM_DELETE_WINDOW ClientMessage to window %d", xid)
		var data [20]byte
		w.server.byteOrder.PutUint32(data[0:4], wmDeleteWindowAtom)
		// The second element is a timestamp, which we can leave as 0 for now.
		w.server.byteOrder.PutUint32(data[4:8], 0) // Timestamp
		w.server.SendClientMessageEvent(xid, wmProtocolsAtom, data)
	} else {
		debugf("X11: WM_DELETE_WINDOW not supported for window %d, destroying directly", xid)
		w.destroyWindow(xid, false)
	}
}

func (w *wasmX11Frontend) MapWindow(wid xID) {
	if winInfo, ok := w.windows[wid]; ok {
		winInfo.div.Get("style").Set("display", "block")
	}
	w.recordOperation(CanvasOperation{
		Type: "mapWindow",
		Args: []any{uint32(wid)},
	})
}
func (w *wasmX11Frontend) UnmapWindow(wid xID) {
	if winInfo, ok := w.windows[wid]; ok {
		winInfo.div.Get("style").Set("display", "none")
	}
	w.recordOperation(CanvasOperation{
		Type: "unmapWindow",
		Args: []any{uint32(wid)},
	})
}

func (w *wasmX11Frontend) CirculateWindow(xid xID, direction byte) {
	debugf("X11: circulateWindow id=%d direction=%d", xid, direction)
	if winInfo, ok := w.windows[xid]; ok {
		parent := winInfo.div.Get("parentNode")
		if direction == 0 { // RaiseLowest
			parent.Call("appendChild", winInfo.div)
		} else { // LowerHighest
			parent.Call("insertBefore", winInfo.div, parent.Get("firstChild"))
		}
	}
	w.recordOperation(CanvasOperation{
		Type: "circulateWindow",
		Args: []any{uint32(xid), direction},
	})
}

func (w *wasmX11Frontend) ConfigureWindow(xid xID, valueMask uint16, values []uint32) {
	const (
		CWX           = 1 << 0
		CWY           = 1 << 1
		CWWidth       = 1 << 2
		CWHeight      = 1 << 3
		CWBorderWidth = 1 << 4
		CWSibling     = 1 << 5
		CWStackMode   = 1 << 6
	)
	debugf("X11: configureWindow id=%d valueMask=%d values=%v", xid, valueMask, values)
	if winInfo, ok := w.windows[xid]; ok {
		style := winInfo.div.Get("style")
		var valueIndex int
		if valueMask&CWX != 0 {
			style.Set("left", fmt.Sprintf("%dpx", values[valueIndex]))
			valueIndex++
		}
		if valueMask&CWY != 0 {
			style.Set("top", fmt.Sprintf("%dpx", values[valueIndex]))
			valueIndex++
		}
		if valueMask&CWWidth != 0 {
			style.Set("width", fmt.Sprintf("%dpx", values[valueIndex]))
			winInfo.canvas.Set("width", values[valueIndex])
			winInfo.offscreenCanvas.Set("width", values[valueIndex])
			valueIndex++
		}
		if valueMask&CWHeight != 0 {
			style.Set("height", fmt.Sprintf("%dpx", values[valueIndex]))
			winInfo.canvas.Set("height", values[valueIndex])
			winInfo.offscreenCanvas.Set("height", values[valueIndex])
			valueIndex++
		}
		if valueMask&CWSibling != 0 {
			// Sibling is not implemented yet
			valueIndex++
		}
		if valueMask&CWStackMode != 0 {
			stackMode := values[valueIndex]
			switch stackMode {
			case 0: // Above
				winInfo.zIndex = w.getHighestZIndex() + 1
			case 1: // Below
				winInfo.zIndex = w.getLowestZIndex() - 1
			}
			style.Set("zIndex", fmt.Sprintf("%d", winInfo.zIndex))
			valueIndex++
		}
	}
	w.recordOperation(CanvasOperation{
		Type: "configureWindow",
		Args: []any{uint32(xid), valueMask, values},
	})
}

func (w *wasmX11Frontend) getHighestZIndex() int {
	highest := 0
	for _, winInfo := range w.windows {
		if winInfo.zIndex > highest {
			highest = winInfo.zIndex
		}
	}
	return highest
}

func (w *wasmX11Frontend) getLowestZIndex() int {
	lowest := 0
	for _, winInfo := range w.windows {
		if winInfo.zIndex < lowest {
			lowest = winInfo.zIndex
		}
	}
	return lowest
}
func (w *wasmX11Frontend) CreateGC(xid xID, valueMask uint32, values wire.GC) {
	debugf("X11: createGC id=%d gc=%+v", xid, values)
	w.gcs[xid] = values
	w.recordOperation(CanvasOperation{
		Type: "createGC",
		Args: []any{uint32(xid), valueMask, values},
	})
}

func (w *wasmX11Frontend) ChangeGC(xid xID, valueMask uint32, gc wire.GC) {
	debugf("X11: changeGC id=%d valueMask=%d gc=%+v", xid, valueMask, gc)
	existingGC, ok := w.gcs[xid]
	if !ok {
		// This shouldn't happen, but if it does, treat it as a CreateGC
		w.gcs[xid] = gc
		w.recordOperation(CanvasOperation{
			Type: "createGC",
			Args: []any{uint32(xid)},
		})
		return
	}

	if valueMask&wire.GCFunction != 0 {
		existingGC.Function = gc.Function
	}
	if valueMask&wire.GCPlaneMask != 0 {
		existingGC.PlaneMask = gc.PlaneMask
	}
	if valueMask&wire.GCForeground != 0 {
		existingGC.Foreground = gc.Foreground
	}
	if valueMask&wire.GCBackground != 0 {
		existingGC.Background = gc.Background
	}
	if valueMask&wire.GCLineWidth != 0 {
		existingGC.LineWidth = gc.LineWidth
	}
	if valueMask&wire.GCLineStyle != 0 {
		existingGC.LineStyle = gc.LineStyle
	}
	if valueMask&wire.GCCapStyle != 0 {
		existingGC.CapStyle = gc.CapStyle
	}
	if valueMask&wire.GCJoinStyle != 0 {
		existingGC.JoinStyle = gc.JoinStyle
	}
	if valueMask&wire.GCFillStyle != 0 {
		existingGC.FillStyle = gc.FillStyle
	}
	if valueMask&wire.GCFillRule != 0 {
		existingGC.FillRule = gc.FillRule
	}
	if valueMask&wire.GCTile != 0 {
		existingGC.Tile = gc.Tile
	}
	if valueMask&wire.GCStipple != 0 {
		existingGC.Stipple = gc.Stipple
	}
	if valueMask&wire.GCTileStipXOrigin != 0 {
		existingGC.TileStipXOrigin = gc.TileStipXOrigin
	}
	if valueMask&wire.GCTileStipYOrigin != 0 {
		existingGC.TileStipYOrigin = gc.TileStipYOrigin
	}
	if valueMask&wire.GCFont != 0 {
		existingGC.Font = gc.Font
	}
	if valueMask&wire.GCSubwindowMode != 0 {
		existingGC.SubwindowMode = gc.SubwindowMode
	}
	if valueMask&wire.GCGraphicsExposures != 0 {
		existingGC.GraphicsExposures = gc.GraphicsExposures
	}
	if valueMask&wire.GCClipXOrigin != 0 {
		existingGC.ClipXOrigin = gc.ClipXOrigin
	}
	if valueMask&wire.GCClipYOrigin != 0 {
		existingGC.ClipYOrigin = gc.ClipYOrigin
	}
	if valueMask&wire.GCClipMask != 0 {
		existingGC.ClipMask = gc.ClipMask
	}
	if valueMask&wire.GCDashOffset != 0 {
		existingGC.DashOffset = gc.DashOffset
	}
	if valueMask&wire.GCDashes != 0 {
		existingGC.Dashes = gc.Dashes
	}
	if valueMask&wire.GCArcMode != 0 {
		existingGC.ArcMode = gc.ArcMode
	}

	w.gcs[xid] = existingGC
	w.recordOperation(CanvasOperation{
		Type: "changeGC",
		Args: []any{uint32(xid), valueMask},
	})
}

func (w *wasmX11Frontend) SetWindowTitle(xid xID, title string) {
	if winInfo, ok := w.windows[xid]; ok {
		// Set HTML title attribute for tooltip
		winInfo.div.Set("title", title)
		// Set the text in the title bar, if it exists
		if !winInfo.windowTitle.IsUndefined() {
			winInfo.windowTitle.Set("textContent", title)
		}
		debugf("X11: Window %d title set to: %s", xid, title)
	}
	w.recordOperation(CanvasOperation{
		Type: "setWindowTitle",
		Args: []any{uint32(xid), title},
	})
}

func (w *wasmX11Frontend) SetInputFocus(focus xID, revertTo byte) {
	debugf("X11: setInputFocus focus=%d revertTo=%d", focus, revertTo)
	if winInfo, ok := w.windows[focus]; ok {
		winInfo.div.Call("focus")
		w.focusedWindowID = focus
	} else if uint32(focus) == 0 { // Revert to root
		if w.focusedWindowID != 0 {
			if focusedWin, ok := w.windows[w.focusedWindowID]; ok {
				focusedWin.div.Call("blur")
			}
		}
		w.focusedWindowID = 0
	}
	w.recordOperation(CanvasOperation{
		Type: "setInputFocus",
		Args: []any{uint32(focus), revertTo},
	})
}

func (w *wasmX11Frontend) ComposeWindow(xid xID) {
	// Find top-level window
	currentID := xid
	for {
		win, ok := w.server.windows[currentID]
		if !ok {
			return
		}
		if uint32(win.parent) == w.server.rootWindowID() {
			break
		}
		// Assuming same client for parent
		currentID = win.parent
	}
	// currentID is now the top-level window
	w.redrawWindow(currentID)
}

func (w *wasmX11Frontend) redrawWindow(xid xID) {
	winInfo, ok := w.windows[xid]
	if !ok {
		return
	}
	// Clear visible canvas
	width := winInfo.canvas.Get("width").Int()
	height := winInfo.canvas.Get("height").Int()
	winInfo.ctx.Call("clearRect", 0, 0, width, height)

	w.drawTree(winInfo.ctx, xid, 0, 0)
}

func (w *wasmX11Frontend) drawTree(ctx js.Value, xid xID, x, y int) {
	winInfo, ok := w.windows[xid]
	if !ok {
		return
	}
	// Draw this window's offscreen buffer
	ctx.Call("drawImage", winInfo.offscreenCanvas, x, y)

	// Iterate children
	// Use server's window hierarchy
	if win, ok := w.server.windows[xid]; ok {
		for _, childID := range win.children {
			childXID := xID(childID)
			if childWin, ok := w.server.windows[childXID]; ok {
				if childWin.mapped {
					w.drawTree(ctx, childXID, x+int(childWin.x), y+int(childWin.y))
				}
			}
		}
	}
}

func (w *wasmX11Frontend) PutImage(drawable xID, gcID xID, format uint8, width, height uint16, dstX, dstY int16, leftPad, depth uint8, imgData []byte) {
	gc, ok := w.gcs[gcID]
	if !ok {
		return
	}
	debugf("X11: putImage drawable=%d gc=%v format=%d width=%d height=%d dstX=%d dstY=%d leftPad=%d depth=%d data length=%d first 16 bytes of data: %x", drawable, gc, format, width, height, dstX, dstY, leftPad, depth, len(imgData), imgData[:min(len(imgData), 16)])

	var currentColormap xID
	var ctx js.Value
	winInfo, ok := w.windows[drawable]
	if ok {
		ctx = winInfo.offscreenCtx
		currentColormap = winInfo.colormap
	} else if pixmapInfo, ok := w.pixmaps[drawable]; ok {
		ctx = pixmapInfo.context
		// For pixmaps, use the default colormap of the screen
		currentColormap = xID(w.server.defaultColormap)
	} else {
		debugf("X11: PutImage on unknown drawable %d", drawable)
		return
	}

	if ctx.IsNull() || width == 0 || height == 0 {
		return
	}
	switch format {
	case 0: // Bitmap
		r, g, b := w.GetRGBColor(currentColormap, gc.Foreground)
		fgR, fgG, fgB := r, g, b

		r, g, b = w.GetRGBColor(currentColormap, gc.Background)
		bgR, bgG, bgB := r, g, b

		rgbaData := make([]byte, int(width*height*4))
		dataIndex := 0
		scanlineStride := (int(width) + int(leftPad) + 7) / 8

		for row := 0; row < int(height); row++ {
			scanlineOffset := row * scanlineStride
			for col := 0; col < int(width); col++ {
				bitPos := int(leftPad) + col
				byteIndex := scanlineOffset + (bitPos / 8)
				bitIndex := bitPos % 8

				if (imgData[byteIndex]>>(bitIndex))&1 == 1 {
					rgbaData[dataIndex] = fgR
					rgbaData[dataIndex+1] = fgG
					rgbaData[dataIndex+2] = fgB
				} else {
					rgbaData[dataIndex] = bgR
					rgbaData[dataIndex+1] = bgG
					rgbaData[dataIndex+2] = bgB
				}
				rgbaData[dataIndex+3] = 255 // Alpha
				dataIndex += 4
			}
		}
		jsImgData := jsutil.Uint8ClampedArrayFromBytes(rgbaData)
		imageData := js.Global().Get("ImageData").New(jsImgData, width, height)
		ctx.Call("putImageData", imageData, dstX, dstY)

	case 1: // XYPixmap
		rgbaData := make([]byte, int(width*height*4))
		pixelValues := make([]uint32, width*height)
		scanlineStride := (int(width) + 7) / 8

		for d := 0; d < int(depth); d++ {
			plane := imgData[d*int(height)*scanlineStride:]
			for y := 0; y < int(height); y++ {
				for x := 0; x < int(width); x++ {
					byteIndex := (y*scanlineStride + x/8)
					bitIndex := x % 8
					if (plane[byteIndex]>>bitIndex)&1 != 0 {
						pixelValues[y*int(width)+x] |= (1 << d)
					}
				}
			}
		}

		for i, pixel := range pixelValues {
			r, g, b := w.GetRGBColor(currentColormap, pixel)
			rgbaData[i*4+0] = r
			rgbaData[i*4+1] = g
			rgbaData[i*4+2] = b
			rgbaData[i*4+3] = 255
		}

		jsImgData := jsutil.Uint8ClampedArrayFromBytes(rgbaData)
		imageData := js.Global().Get("ImageData").New(jsImgData, width, height)
		ctx.Call("putImageData", imageData, dstX, dstY)

	case 2: // ZPixmap
		bpp := int(depth)
		scanlinePad := 8
		for _, f := range w.server.pixmapFormats {
			if f.Depth == depth {
				bpp = int(f.BitsPerPixel)
				scanlinePad = int(f.ScanlinePad)
				break
			}
		}
		if bpp == 0 {
			bpp = 8
		}
		scanlineStride := ((int(width)*bpp + scanlinePad - 1) / scanlinePad) * (scanlinePad / 8)

		rgbaData := make([]byte, int(width)*int(height)*4)
		for y := 0; y < int(height); y++ {
			line := imgData[y*scanlineStride:]
			for x := 0; x < int(width); x++ {
				var pixel uint32
				bitOffset := x * bpp
				byteIndex := bitOffset / 8

				switch bpp {
				case 1:
					pixel = uint32((line[byteIndex] >> (bitOffset % 8)) & 1)
				case 4:
					pixel = uint32((line[byteIndex] >> (bitOffset % 8)) & 0x0F)
				case 8:
					pixel = uint32(line[x])
				case 16:
					pixel = uint32(binary.LittleEndian.Uint16(line[x*2 : x*2+2]))
				case 24, 32:
					// We assume 32-bit for 24-bit depth on wire as per our setup
					pixel = binary.LittleEndian.Uint32(line[x*4 : x*4+4])
				}

				r, g, b := w.GetRGBColor(currentColormap, pixel)
				rgbaData[(y*int(width)+x)*4+0] = r
				rgbaData[(y*int(width)+x)*4+1] = g
				rgbaData[(y*int(width)+x)*4+2] = b
				rgbaData[(y*int(width)+x)*4+3] = 255
			}
		}
		jsImgData := jsutil.Uint8ClampedArrayFromBytes(rgbaData)
		imageData := js.Global().Get("ImageData").New(jsImgData, width, height)
		ctx.Call("putImageData", imageData, dstX, dstY)
	}

	w.updateVisibleArea(drawable, int(dstX), int(dstY), int(width), int(height))

	w.recordOperation(CanvasOperation{
		Type: "putImage",
		Args: []any{uint32(drawable), gc, dstX, dstY, width, height, leftPad, format, len(imgData)},
	})
}

func (w *wasmX11Frontend) applyGCState(ctx js.Value, colormap xID, gc wire.GC, clientID uint32) {
	ctx.Set("imageSmoothingEnabled", false)

	color := w.getForegroundColor(colormap, gc)
	ctx.Set("strokeStyle", color)
	ctx.Set("fillStyle", color)
	ctx.Set("lineWidth", gc.LineWidth)

	switch gc.LineStyle {
	case wire.LineStyleOnOffDash, wire.LineStyleDoubleDash:
	case wire.LineStyleSolid:
		ctx.Call("setLineDash", js.Global().Get("Array").New())
	}
	switch gc.CapStyle {
	case wire.CapStyleNotLast, wire.CapStyleButt:
		ctx.Set("lineCap", "butt")
	case wire.CapStyleRound:
		ctx.Set("lineCap", "round")
	case wire.CapStyleProjecting:
		ctx.Set("lineCap", "square")
	}
	switch gc.JoinStyle {
	case wire.JoinStyleMiter:
		ctx.Set("lineJoin", "miter")
	case wire.JoinStyleRound:
		ctx.Set("lineJoin", "round")
	case wire.JoinStyleBevel:
		ctx.Set("lineJoin", "bevel")
	}

	switch gc.FillStyle {
	case wire.FillStyleSolid:
		ctx.Set("fillStyle", color)
	case wire.FillStyleTiled:
		if tilePixmap, ok := w.pixmaps[xID(gc.Tile)]; ok {
			pattern := ctx.Call("createPattern", tilePixmap.canvas, "repeat")
			ctx.Set("fillStyle", pattern)
		}
	case wire.FillStyleStippled:
		if stipplePixmap, ok := w.pixmaps[xID(gc.Stipple)]; ok {
			stippleCanvas := w.document.Call("createElement", "canvas")
			stippleCanvas.Set("width", stipplePixmap.canvas.Get("width"))
			stippleCanvas.Set("height", stipplePixmap.canvas.Get("height"))
			stippleCtx := stippleCanvas.Call("getContext", "2d")

			stippleCtx.Set("fillStyle", color)
			stippleCtx.Call("fillRect", 0, 0, stippleCanvas.Get("width"), stippleCanvas.Get("height"))
			stippleCtx.Set("globalCompositeOperation", "destination-in")
			stippleCtx.Call("drawImage", stipplePixmap.canvas, 0, 0)

			pattern := ctx.Call("createPattern", stippleCanvas, "repeat")
			ctx.Set("fillStyle", pattern)
		}
	case wire.FillStyleOpaqueStippled:
		if stipplePixmap, ok := w.pixmaps[xID(gc.Stipple)]; ok {
			stippleCanvas := w.document.Call("createElement", "canvas")
			stippleCanvas.Set("width", stipplePixmap.canvas.Get("width"))
			stippleCanvas.Set("height", stipplePixmap.canvas.Get("height"))
			stippleCtx := stippleCanvas.Call("getContext", "2d")

			r, g, b := w.GetRGBColor(colormap, gc.Background)
			bgColor := fmt.Sprintf("#%02x%02x%02x", r, g, b)
			stippleCtx.Set("fillStyle", bgColor)
			stippleCtx.Call("fillRect", 0, 0, stippleCanvas.Get("width"), stippleCanvas.Get("height"))

			stippleCtx.Set("fillStyle", color)
			stippleCtx.Call("fillRect", 0, 0, stippleCanvas.Get("width"), stippleCanvas.Get("height"))
			stippleCtx.Set("globalCompositeOperation", "destination-in")
			stippleCtx.Call("drawImage", stipplePixmap.canvas, 0, 0)

			pattern := ctx.Call("createPattern", stippleCanvas, "repeat")
			ctx.Set("fillStyle", pattern)
		}
	}

	if gc.Font != 0 {
		if font, ok := w.fonts[xID(gc.Font)]; ok {
			debugf("applyGCState: setting font to %q for gc.Font=%d", font.cssFont, gc.Font)
			ctx.Set("font", font.cssFont)
		} else {
			debugf("applyGCState: font %d not found for client %d", gc.Font, clientID)
		}
	}
	if gc.ClippingRectangles != nil && len(gc.ClippingRectangles) > 0 {
		ctx.Call("beginPath")
		for _, rect := range gc.ClippingRectangles {
			ctx.Call("rect", rect.X, rect.Y, rect.Width, rect.Height)
		}
		ctx.Call("clip")
	}
	if gc.DashPattern != nil && len(gc.DashPattern) > 0 {
		jsDashes := make([]interface{}, len(gc.DashPattern))
		for i, v := range gc.DashPattern {
			jsDashes[i] = v
		}
		ctx.Call("setLineDash", jsDashes)
		ctx.Set("lineDashOffset", gc.DashOffset)
	} else if (gc.LineStyle == wire.LineStyleOnOffDash || gc.LineStyle == wire.LineStyleDoubleDash) && gc.Dashes > 0 {
		jsDashes := []interface{}{gc.Dashes, gc.Dashes}
		ctx.Call("setLineDash", jsDashes)
		ctx.Set("lineDashOffset", gc.DashOffset)
	}
}

func (w *wasmX11Frontend) applyGC(drawable xID, gcID xID, draw func(js.Value), opBounds image.Rectangle) {
	debugf("applyGC: start drawable=%d gcID=%d", drawable, gcID)
	gc, ok := w.gcs[gcID]
	if !ok {
		debugf("applyGC: gcID %d not found", gcID)
		return
	}

	var destCtx js.Value
	var colormap xID
	winInfo, ok := w.windows[drawable]
	if ok {
		destCtx = winInfo.offscreenCtx
		colormap = winInfo.colormap
	} else if pixmapInfo, ok := w.pixmaps[drawable]; ok {
		destCtx = pixmapInfo.context
		colormap = xID(w.server.defaultColormap)
	} else {
		debugf("applyGC: drawable %d not found", drawable)
		return
	}

	if destCtx.IsUndefined() || destCtx.IsNull() {
		return
	}

	var nativeOp string
	var forceColor string
	useSoftwareEmulation := false

	// PlaneMask check: Canvas operations affect all channels.
	// If PlaneMask doesn't cover all visual bits, we must fallback to software.
	visual := w.server.rootVisual
	fullMask := visual.RedMask | visual.GreenMask | visual.BlueMask
	if fullMask == 0 {
		fullMask = 0xffffff
	}
	isFullPlaneMask := (gc.PlaneMask & fullMask) == fullMask

	switch gc.Function {
	case wire.FunctionClear:
		nativeOp = "destination-out"
	case wire.FunctionCopy:
		nativeOp = "source-over"
	case wire.FunctionNoOp:
		debugf("applyGC: NoOp, returning")
		return
	case wire.FunctionXor:
		if isFullPlaneMask {
			nativeOp = "difference"
			r, g, b := w.GetRGBColor(colormap, gc.Foreground)
			if r != 255 || g != 255 || b != 255 {
				useSoftwareEmulation = true
			}
		} else {
			useSoftwareEmulation = true
		}
	case wire.FunctionInvert:
		if isFullPlaneMask {
			nativeOp = "difference"
			forceColor = "#ffffff"
		} else {
			useSoftwareEmulation = true
		}
	default:
		useSoftwareEmulation = true
	}
	debugf("applyGC: gc.Function=%d, useSoftwareEmulation=%t, nativeOp=%q", gc.Function, useSoftwareEmulation, nativeOp)

	if !useSoftwareEmulation {
		debugf("applyGC: using native path")
		destCtx.Call("save")
		w.applyGCState(destCtx, colormap, gc, (uint32(gcID)>>resourceIDShift)&clientIDMask)
		if forceColor != "" {
			destCtx.Set("strokeStyle", forceColor)
			destCtx.Set("fillStyle", forceColor)
		}
		destCtx.Set("globalCompositeOperation", nativeOp)
		draw(destCtx)
		destCtx.Call("restore")
		debugf("applyGC: native path done")

		// Update visible area if it's a window
		if _, ok := w.windows[drawable]; ok {
			w.updateVisibleArea(drawable, opBounds.Min.X, opBounds.Min.Y, opBounds.Dx(), opBounds.Dy())
		}
		return
	}

	x, y := opBounds.Min.X, opBounds.Min.Y
	width, height := opBounds.Dx(), opBounds.Dy()

	if width <= 0 || height <= 0 {
		debugf("applyGC: empty bounds, returning")
		return
	}
	debugf("applyGC: using software emulation path with bounds %+v", opBounds)

	debugf("applyGC: getting destination image data")
	destImageData := destCtx.Call("getImageData", x, y, width, height)
	destPixels := jsutil.GetImageDataBytes(destImageData)
	debugf("applyGC: got %d destination pixels", len(destPixels)/4)

	debugf("applyGC: creating temporary canvas")
	tempCanvas := w.document.Call("createElement", "canvas")
	tempCanvas.Set("width", width)
	tempCanvas.Set("height", height)
	tempCtx := tempCanvas.Call("getContext", "2d")

	tempCtx.Call("translate", -x, -y)

	debugf("applyGC: drawing to temporary canvas")
	tempCtx.Call("save")
	w.applyGCState(tempCtx, colormap, gc, (uint32(gcID)>>resourceIDShift)&clientIDMask)
	draw(tempCtx)
	tempCtx.Call("restore")
	debugf("applyGC: finished drawing to temporary canvas")

	debugf("applyGC: getting source image data")
	srcImageData := tempCtx.Call("getImageData", 0, 0, width, height)
	srcPixels := jsutil.GetImageDataBytes(srcImageData)
	debugf("applyGC: got %d source pixels", len(srcPixels)/4)

	r, g, b := w.GetRGBColor(colormap, gc.Foreground)
	srcColor := (uint32(r) << 16) | (uint32(g) << 8) | uint32(b)
	debugf("applyGC: srcColor=%#06x", srcColor)

	debugf("applyGC: starting pixel loop")
	for i := 0; i < len(destPixels); i += 4 {
		if srcPixels[i+3] == 0 {
			continue
		}

		dest := (uint32(destPixels[i]) << 16) | (uint32(destPixels[i+1]) << 8) | uint32(destPixels[i+2])
		src := srcColor & gc.PlaneMask

		var result uint32
		switch gc.Function {
		case wire.FunctionXor:
			result = src ^ dest
		case wire.FunctionAnd:
			result = src & dest
		case wire.FunctionAndReverse:
			result = src & (^dest & 0xffffff)
		case wire.FunctionAndInverted:
			result = (^src & 0xffffff) & dest
		case wire.FunctionOr:
			result = src | dest
		case wire.FunctionNor:
			result = ^(src | dest) & 0xffffff
		case wire.FunctionEquiv:
			result = ^(src ^ dest) & 0xffffff
		case wire.FunctionInvert:
			result = ^dest & 0xffffff
		case wire.FunctionOrReverse:
			result = src | (^dest & 0xffffff)
		case wire.FunctionCopyInverted:
			result = ^src & 0xffffff
		case wire.FunctionOrInverted:
			result = (^src & 0xffffff) | dest
		case wire.FunctionNand:
			result = ^(src & dest) & 0xffffff
		case wire.FunctionSet:
			result = 0xffffff & gc.PlaneMask
		}

		destPixels[i] = byte((result >> 16) & 0xff)
		destPixels[i+1] = byte((result >> 8) & 0xff)
		destPixels[i+2] = byte(result & 0xff)
		destPixels[i+3] = 255
	}
	debugf("applyGC: finished pixel loop")

	debugf("applyGC: creating new image data")
	newImageData := js.Global().Get("ImageData").New(jsutil.Uint8ClampedArrayFromBytes(destPixels), width, height)
	debugf("applyGC: putting new image data at (%d, %d)", x, y)
	destCtx.Call("putImageData", newImageData, x, y)
	debugf("applyGC: software emulation path done")

	// Update visible area if it's a window
	if _, ok := w.windows[drawable]; ok {
		w.updateVisibleArea(drawable, x, y, width, height)
	}
}

func (w *wasmX11Frontend) PolyLine(drawable xID, gcID xID, points []uint32) {
	gc, ok := w.gcs[gcID]
	if !ok {
		return
	}
	debugf("X11: polyLine drawable=%d gc=%v points=%v", drawable, gc, points)

	var opBounds image.Rectangle
	if len(points) >= 2 {
		opBounds = image.Rect(int(points[0]), int(points[1]), int(points[0])+1, int(points[1])+1)
		for i := 2; i < len(points); i += 2 {
			opBounds = opBounds.Union(image.Rect(int(points[i]), int(points[i+1]), int(points[i])+1, int(points[i+1])+1))
		}
		opBounds = opBounds.Inset(-int(gc.LineWidth))
	}

	color := w.getForegroundColor(0, gc) // Colormap ignored for logging color

	w.applyGC(drawable, gcID, func(targetCtx js.Value) {
		targetCtx.Call("beginPath")
		if len(points) >= 2 {
			targetCtx.Call("moveTo", points[0], points[1])
			for i := 2; i < len(points); i += 2 {
				targetCtx.Call("lineTo", points[i], points[i+1])
			}
		}
		targetCtx.Call("stroke")
	}, opBounds)

	w.recordOperation(CanvasOperation{
		Type:        "polyLine",
		Args:        []any{uint32(drawable), gc, points},
		StrokeStyle: color,
	})
}

func (w *wasmX11Frontend) PolyFillRectangle(drawable xID, gcID xID, rects []uint32) {
	gc, ok := w.gcs[gcID]
	if !ok {
		return
	}
	debugf("X11: polyFillRectangle drawable=%d gc=%v rects=%v GCFunction=%d", drawable, gc, rects, gc.Function)

	var opBounds image.Rectangle
	for i := 0; i < len(rects); i += 4 {
		r := image.Rect(int(rects[i]), int(rects[i+1]), int(rects[i])+int(rects[i+2]), int(rects[i+1])+int(rects[i+3]))
		if i == 0 {
			opBounds = r
		} else {
			opBounds = opBounds.Union(r)
		}
	}

	color := w.getForegroundColor(0, gc)

	w.applyGC(drawable, gcID, func(targetCtx js.Value) {
		for i := 0; i < len(rects); i += 4 {
			targetCtx.Call("fillRect", rects[i], rects[i+1], rects[i+2], rects[i+3])
		}
	}, opBounds)

	w.recordOperation(CanvasOperation{
		Type:      "polyFillRectangle",
		Args:      []any{uint32(drawable), gc, rects},
		FillStyle: color,
	})
}

func (w *wasmX11Frontend) FillPoly(drawable xID, gcID xID, points []uint32) {
	gc, ok := w.gcs[gcID]
	if !ok {
		return
	}
	debugf("X11: fillPoly drawable=%d gc=%v points=%v", drawable, gc, points)

	var opBounds image.Rectangle
	if len(points) >= 2 {
		opBounds = image.Rect(int(points[0]), int(points[1]), int(points[0])+1, int(points[1])+1)
		for i := 2; i < len(points); i += 2 {
			opBounds = opBounds.Union(image.Rect(int(points[i]), int(points[i+1]), int(points[i])+1, int(points[i+1])+1))
		}
	}

	color := w.getForegroundColor(0, gc)
	fillRule := "nonzero"
	if gc.FillRule == 0 {
		fillRule = "evenodd"
	}

	w.applyGC(drawable, gcID, func(targetCtx js.Value) {
		targetCtx.Call("beginPath")
		if len(points) >= 2 {
			targetCtx.Call("moveTo", points[0], points[1])
			for i := 2; i < len(points); i += 2 {
				targetCtx.Call("lineTo", points[i], points[i+1])
			}
		}
		targetCtx.Call("closePath")
		targetCtx.Call("fill", fillRule)
	}, opBounds)

	w.recordOperation(CanvasOperation{
		Type:      "fillPoly",
		Args:      []any{uint32(drawable), gc, points},
		FillStyle: color,
	})
}

func (w *wasmX11Frontend) PolySegment(drawable xID, gcID xID, segments []uint32) {
	gc, ok := w.gcs[gcID]
	if !ok {
		return
	}
	debugf("X11: polySegment drawable=%d gc=%v segments=%v", drawable, gc, segments)

	var opBounds image.Rectangle
	for i := 0; i < len(segments); i += 4 {
		r := image.Rect(int(segments[i]), int(segments[i+1]), int(segments[i+2])+1, int(segments[i+3])+1).Canon()
		if i == 0 {
			opBounds = r
		} else {
			opBounds = opBounds.Union(r)
		}
	}
	opBounds = opBounds.Inset(-int(gc.LineWidth))

	color := w.getForegroundColor(0, gc)

	w.applyGC(drawable, gcID, func(targetCtx js.Value) {
		for i := 0; i < len(segments); i += 4 {
			targetCtx.Call("beginPath")
			targetCtx.Call("moveTo", segments[i], segments[i+1])
			targetCtx.Call("lineTo", segments[i+2], segments[i+3])
			targetCtx.Call("stroke")
		}
	}, opBounds)

	w.recordOperation(CanvasOperation{
		Type:        "polySegment",
		Args:        []any{uint32(drawable), gc, segments},
		StrokeStyle: color,
	})
}

func (w *wasmX11Frontend) PolyPoint(drawable xID, gcID xID, points []uint32) {
	gc, ok := w.gcs[gcID]
	if !ok {
		return
	}
	debugf("X11: polyPoint drawable=%d gc=%v points=%v", drawable, gc, points)

	var opBounds image.Rectangle
	for i := 0; i < len(points); i += 2 {
		r := image.Rect(int(points[i]), int(points[i+1]), int(points[i])+1, int(points[i+1])+1)
		if i == 0 {
			opBounds = r
		} else {
			opBounds = opBounds.Union(r)
		}
	}

	color := w.getForegroundColor(0, gc)

	w.applyGC(drawable, gcID, func(targetCtx js.Value) {
		for i := 0; i < len(points); i += 2 {
			targetCtx.Call("fillRect", points[i], points[i+1], 1, 1)
		}
	}, opBounds)

	w.recordOperation(CanvasOperation{
		Type:      "polyPoint",
		Args:      []any{uint32(drawable), gc, points},
		FillStyle: color,
	})
}

func (w *wasmX11Frontend) PolyRectangle(drawable xID, gcID xID, rects []uint32) {
	gc, ok := w.gcs[gcID]
	if !ok {
		return
	}
	debugf("X11: polyRectangle drawable=%d gc=%v rects=%v", drawable, gc, rects)

	var opBounds image.Rectangle
	for i := 0; i < len(rects); i += 4 {
		r := image.Rect(int(rects[i]), int(rects[i+1]), int(rects[i])+int(rects[i+2]), int(rects[i+1])+int(rects[i+3]))
		if i == 0 {
			opBounds = r
		} else {
			opBounds = opBounds.Union(r)
		}
	}
	opBounds = opBounds.Inset(-int(gc.LineWidth))

	color := w.getForegroundColor(0, gc)

	w.applyGC(drawable, gcID, func(targetCtx js.Value) {
		for i := 0; i < len(rects); i += 4 {
			targetCtx.Call("strokeRect", rects[i], rects[i+1], rects[i+2], rects[i+3])
		}
	}, opBounds)

	w.recordOperation(CanvasOperation{
		Type:        "polyRectangle",
		Args:        []any{uint32(drawable), gc, rects},
		StrokeStyle: color,
	})
}

func (w *wasmX11Frontend) PolyArc(drawable xID, gcID xID, arcs []uint32) {
	gc, ok := w.gcs[gcID]
	if !ok {
		return
	}
	debugf("X11: polyArc drawable=%d gc=%v arcs=%v", drawable, gc, arcs)

	var opBounds image.Rectangle
	for i := 0; i < len(arcs); i += 6 {
		r := image.Rect(int(arcs[i]), int(arcs[i+1]), int(arcs[i])+int(arcs[i+2]), int(arcs[i+1])+int(arcs[i+3]))
		if i == 0 {
			opBounds = r
		} else {
			opBounds = opBounds.Union(r)
		}
	}
	opBounds = opBounds.Inset(-int(gc.LineWidth))

	color := w.getForegroundColor(0, gc)

	w.applyGC(drawable, gcID, func(targetCtx js.Value) {
		for i := 0; i < len(arcs); i += 6 {
			targetCtx.Call("beginPath")
			// X11 angles are in 1/64th degrees, clockwise. Canvas angles are in radians, clockwise.
			// Start angle: arcs[i+4] / 64 * (Math.PI / 180)
			// End angle: (arcs[i+4] + arcs[i+5]) / 64 * (Math.PI / 180)
			startAngle := float64(arcs[i+4]) / 64 * (math.Pi / 180)
			endAngle := float64(arcs[i+4]+arcs[i+5]) / 64 * (math.Pi / 180)
			rx := uint32(arcs[i+2] / 2)
			ry := uint32(arcs[i+3] / 2)
			x := uint32(arcs[i] + rx)
			y := uint32(arcs[i+1] + ry)
			targetCtx.Call("ellipse", x, y, rx, ry, 0, startAngle, endAngle)
			targetCtx.Call("stroke")
		}
	}, opBounds)

	w.recordOperation(CanvasOperation{
		Type:        "polyArc",
		Args:        []any{uint32(drawable), gc, arcs},
		StrokeStyle: color,
	})
}

func (w *wasmX11Frontend) PolyFillArc(drawable xID, gcID xID, arcs []uint32) {
	gc, ok := w.gcs[gcID]
	if !ok {
		return
	}
	debugf("X11: polyFillArc drawable=%d gc=%v arcs=%v", drawable, gc, arcs)

	var opBounds image.Rectangle
	for i := 0; i < len(arcs); i += 6 {
		r := image.Rect(int(arcs[i]), int(arcs[i+1]), int(arcs[i])+int(arcs[i+2]), int(arcs[i+1])+int(arcs[i+3]))
		if i == 0 {
			opBounds = r
		} else {
			opBounds = opBounds.Union(r)
		}
	}

	color := w.getForegroundColor(0, gc)
	fillRule := "nonzero"
	if gc.FillRule == 0 {
		fillRule = "evenodd"
	}

	w.applyGC(drawable, gcID, func(targetCtx js.Value) {
		for i := 0; i < len(arcs); i += 6 {
			targetCtx.Call("beginPath")
			startAngle := float64(arcs[i+4]) / 64 * (math.Pi / 180)
			endAngle := float64(arcs[i+4]+arcs[i+5]) / 64 * (math.Pi / 180)
			rx := uint32(arcs[i+2] / 2)
			ry := uint32(arcs[i+3] / 2)
			x := uint32(arcs[i] + rx)
			y := uint32(arcs[i+1] + ry)
			targetCtx.Call("ellipse", x, y, rx, ry, 0, startAngle, endAngle)
			if gc.ArcMode == 1 { // Pie
				targetCtx.Call("lineTo", x, y)
				targetCtx.Call("closePath")
			}
			targetCtx.Call("fill", fillRule)
		}
	}, opBounds)

	w.recordOperation(CanvasOperation{
		Type:      "polyFillArc",
		Args:      []any{uint32(drawable), gc, arcs},
		FillStyle: color,
	})
}

func (w *wasmX11Frontend) ClearArea(drawable xID, x, y, width, height int32) {
	if width == 0 {
		width = int32(w.server.windows[drawable].width) - x
	}
	if height == 0 {
		height = int32(w.server.windows[drawable].height) - y
	}
	debugf("X11: clearArea drawable=%d x=%d y=%d width=%d height=%d", drawable, x, y, width, height)
	if winInfo, ok := w.windows[drawable]; ok {
		if !winInfo.canvas.IsNull() {
			// Clear the area with the window's background color
			var r, g, b uint8 = 0xff, 0xff, 0xff
			if w.server.windows[drawable].attributes.BackgroundPixelSet {
				// Get RGB color from server's colormap or visual
				r, g, b = w.GetRGBColor(winInfo.colormap, w.server.windows[drawable].attributes.BackgroundPixel)
			}
			bgColor := fmt.Sprintf("rgb(%d, %d, %d)", r, g, b)
			debugf("X11: ClearArea filling with fillStyle: %s", bgColor)
			winInfo.offscreenCtx.Set("fillStyle", bgColor)
			winInfo.offscreenCtx.Call("fillRect", x, y, width, height)
			w.updateVisibleArea(drawable, int(x), int(y), int(width), int(height))
		}
	}
	w.recordOperation(CanvasOperation{
		Type: "clearArea",
		Args: []any{uint32(drawable), x, y, width, height},
	})
}

func (w *wasmX11Frontend) CopyArea(srcDrawable, dstDrawable xID, gcID xID, srcX, srcY, dstX, dstY, width, height int32) {
	gc, ok := w.gcs[gcID]
	if !ok {
		return
	}
	debugf("X11: copyArea src=%d dst=%d gc=%v srcX=%d srcY=%d dstX=%d dstY=%d width=%d height=%d", srcDrawable, dstDrawable, gc, srcX, srcY, dstX, dstY, width, height)
	var srcCanvas js.Value
	srcWinInfo, srcIsWindow := w.windows[srcDrawable]
	srcPixmapInfo, srcIsPixmap := w.pixmaps[srcDrawable]

	if srcIsWindow {
		srcCanvas = srcWinInfo.offscreenCanvas
	} else if srcIsPixmap {
		srcCanvas = srcPixmapInfo.canvas
	} else {
		debugf("X11: CopyArea source drawable %d not found", srcDrawable)
		return
	}

	dstWinInfo, dstIsWindow := w.windows[dstDrawable]
	if !dstIsWindow {
		debugf("X11: CopyArea destination drawable %d not found or not a window", dstDrawable)
		return
	}

	if !srcCanvas.IsNull() && !dstWinInfo.canvas.IsNull() {
		dstWinInfo.offscreenCtx.Call("drawImage", srcCanvas, srcX, srcY, width, height, dstX, dstY, width, height)
		w.updateVisibleArea(dstDrawable, int(dstX), int(dstY), int(width), int(height))
	}
	w.recordOperation(CanvasOperation{
		Type: "copyArea",
		Args: []any{uint32(srcDrawable), uint32(dstDrawable), gc, srcX, srcY, dstX, dstY, width, height},
	})
}

func (w *wasmX11Frontend) CopyPlane(srcDrawable, dstDrawable xID, gcID xID, srcX, srcY, dstX, dstY, width, height, bitPlane int32) {
	gc, ok := w.gcs[gcID]
	if !ok {
		return
	}
	debugf("X11: copyPlane src=%d dst=%d gc=%v srcX=%d srcY=%d dstX=%d dstY=%d width=%d height=%d bitPlane=%d", srcDrawable, dstDrawable, gc, srcX, srcY, dstX, dstY, width, height, bitPlane)
	var srcCanvas js.Value
	srcWinInfo, srcIsWindow := w.windows[srcDrawable]
	srcPixmapInfo, srcIsPixmap := w.pixmaps[srcDrawable]

	if srcIsWindow {
		srcCanvas = srcWinInfo.offscreenCanvas
	} else if srcIsPixmap {
		srcCanvas = srcPixmapInfo.canvas
	} else {
		debugf("X11: CopyPlane source drawable %d not found", srcDrawable)
		return
	}

	var dstCtx js.Value
	var currentColormap xID
	dstWinInfo, dstIsWindow := w.windows[dstDrawable]
	dstPixmapInfo, dstIsPixmap := w.pixmaps[dstDrawable]

	if dstIsWindow {
		dstCtx = dstWinInfo.offscreenCtx
		currentColormap = dstWinInfo.colormap
	} else if dstIsPixmap {
		dstCtx = dstPixmapInfo.context
		currentColormap = xID(w.server.defaultColormap)
	} else {
		debugf("X11: CopyPlane destination drawable %d not found", dstDrawable)
		return
	}

	if !srcCanvas.IsNull() && !dstCtx.IsUndefined() {
		// 1. Create a temporary canvas to prepare the source image.
		tempCanvas := w.document.Call("createElement", "canvas")
		tempCanvas.Set("width", width)
		tempCanvas.Set("height", height)
		tempCtx := tempCanvas.Call("getContext", "2d")

		// 2. Get the image data from the source drawable.
		srcImageData := srcCanvas.Call("getContext", "2d").Call("getImageData", srcX, srcY, width, height)
		srcData := srcImageData.Get("data")
		jsImgData := js.Global().Get("Uint8ClampedArray").New(int(width * height * 4))

		r, g, b := w.GetRGBColor(currentColormap, gc.Foreground)
		fgR, fgG, fgB := r, g, b

		r, g, b = w.GetRGBColor(currentColormap, gc.Background)
		bgR, bgG, bgB := r, g, b

		// 3. Iterate through the source image data and check the bitPlane.
		for i := 0; i < srcData.Length(); i += 4 {
			// The source is treated as a bitmap. We get the pixel value from the source,
			// and if the bit corresponding to bitPlane is set, we use the foreground color.
			// Otherwise, we use the background color.
			pixelValue := uint32(srcData.Index(i).Int()) | (uint32(srcData.Index(i+1).Int()) << 8) | (uint32(srcData.Index(i+2).Int()) << 16)

			// 4. Populate the temporary canvas with foreground or background color.
			if (pixelValue & uint32(bitPlane)) != 0 {
				jsImgData.SetIndex(i+0, int(fgR))
				jsImgData.SetIndex(i+1, int(fgG))
				jsImgData.SetIndex(i+2, int(fgB))
				jsImgData.SetIndex(i+3, 255) // Alpha for foreground
			} else {
				jsImgData.SetIndex(i+0, int(bgR))
				jsImgData.SetIndex(i+1, int(bgG))
				jsImgData.SetIndex(i+2, int(bgB))
				jsImgData.SetIndex(i+3, 255) // Alpha for background
			}
		}

		newImageData := js.Global().Get("ImageData").New(jsImgData, width, height)
		tempCtx.Call("putImageData", newImageData, 0, 0)

		// 5. Apply the GC to the destination context and draw the image.
		opBounds := image.Rect(int(dstX), int(dstY), int(dstX)+int(width), int(dstY)+int(height))
		w.applyGC(dstDrawable, gcID, func(targetCtx js.Value) {
			targetCtx.Call("drawImage", tempCanvas, dstX, dstY)
		}, opBounds)
	}
	w.recordOperation(CanvasOperation{
		Type: "copyPlane",
		Args: []any{uint32(srcDrawable), uint32(dstDrawable), gc, srcX, srcY, dstX, dstY, width, height, bitPlane},
	})
}

func (w *wasmX11Frontend) GetImage(drawable xID, x, y, width, height int32, format uint32) ([]byte, error) {
	if winInfo, ok := w.windows[drawable]; ok {
		if !winInfo.canvas.IsNull() {
			imageData := winInfo.offscreenCtx.Call("getImageData", x, y, width, height)
			data := imageData.Get("data") // Uint8ClampedArray
			byteSlice := make([]byte, data.Length())
			js.CopyBytesToGo(byteSlice, data)
			return byteSlice, nil
		}
	}
	return nil, fmt.Errorf("window or canvas not found for drawable %d", drawable)
}

func (w *wasmX11Frontend) ImageText8(drawable xID, gcID xID, x, y int32, text []byte) {
	gc, ok := w.gcs[gcID]
	if !ok {
		return
	}
	decodedTextForLog := js.Global().Get("TextDecoder").New().Call("decode", jsutil.Uint8ArrayFromBytes(text)).String()
	decodedTextForLog = strings.ReplaceAll(decodedTextForLog, "\x00", "") // Trim null terminators
	debugf("X11: imageText8 drawable=%d gc=%v x=%d y=%d text=%s", drawable, gc, x, y, decodedTextForLog)

	var ctx js.Value
	var colormap xID
	winInfo, ok := w.windows[drawable]
	if ok {
		ctx = winInfo.offscreenCtx
		colormap = winInfo.colormap
	} else {
		return
	}

	if ctx.IsUndefined() {
		return
	}

	decodedText := js.Global().Get("TextDecoder").New().Call("decode", jsutil.Uint8ArrayFromBytes(text)).String()
	decodedText = strings.ReplaceAll(decodedText, "\x00", "") // Trim null terminators

	ctx.Call("save")
	w.applyGCState(ctx, colormap, gc, (uint32(gcID)>>resourceIDShift)&clientIDMask)
	metrics := ctx.Call("measureText", decodedText)
	ctx.Call("restore")

	width := int(math.Ceil(metrics.Get("width").Float()))
	// Use font bounding box if available for more consistent background clearing
	var ascent, descent int
	if !metrics.Get("fontBoundingBoxAscent").IsUndefined() {
		ascent = int(math.Ceil(metrics.Get("fontBoundingBoxAscent").Float()))
		descent = int(math.Ceil(metrics.Get("fontBoundingBoxDescent").Float()))
	} else {
		ascent = int(math.Ceil(metrics.Get("actualBoundingBoxAscent").Float()))
		descent = int(math.Ceil(metrics.Get("actualBoundingBoxDescent").Float()))
	}
	// Ensure reasonable minimums
	if ascent == 0 {
		ascent = 10
	}
	if descent == 0 {
		descent = 2
	}

	opBounds := image.Rect(int(x), int(y)-ascent, int(x)+width, int(y)+descent)

	color := w.getForegroundColor(colormap, gc)
	bgColor := w.getBackgroundColor(colormap, gc)
	debugf("ImageText8: bounds=%v color=%s bg=%s", opBounds, color, bgColor)

	w.applyGC(drawable, gcID, func(targetCtx js.Value) {
		// Fill background rectangle
		targetCtx.Call("save")
		targetCtx.Set("fillStyle", bgColor)
		targetCtx.Call("fillRect", int(x), int(y)-ascent, width, ascent+descent)
		targetCtx.Call("restore")

		// Draw text
		targetCtx.Call("fillText", decodedText, x, y)
	}, opBounds)

	w.recordOperation(CanvasOperation{
		Type:      "imageText8",
		Args:      []any{uint32(drawable), gc, x, y, decodedTextForLog},
		FillStyle: color,
	})
}

func (w *wasmX11Frontend) ImageText16(drawable xID, gcID xID, x, y int32, text []uint16) {
	gc, ok := w.gcs[gcID]
	if !ok {
		return
	}
	// Convert []uint16 to []byte for TextDecoder
	textBytes := make([]byte, len(text)*2)
	for i, r := range text {
		binary.LittleEndian.PutUint16(textBytes[i*2:], r)
	}
	decodedTextForLog := js.Global().Get("TextDecoder").New().Call("decode", jsutil.Uint8ArrayFromBytes(textBytes)).String()
	decodedTextForLog = strings.ReplaceAll(decodedTextForLog, "\x00", "") // Trim null terminators
	debugf("X11: imageText16 drawable=%d gc=%v x=%d y=%d text=%s", drawable, gc, x, y, decodedTextForLog)

	var ctx js.Value
	var colormap xID
	winInfo, ok := w.windows[drawable]
	if ok {
		ctx = winInfo.offscreenCtx
		colormap = winInfo.colormap
	} else {
		return
	}

	if ctx.IsUndefined() {
		return
	}

	decodedText := js.Global().Get("TextDecoder").New().Call("decode", jsutil.Uint8ArrayFromBytes(textBytes)).String()
	decodedText = strings.ReplaceAll(decodedText, "\x00", "") // Trim null terminators

	ctx.Call("save")
	w.applyGCState(ctx, colormap, gc, (uint32(gcID)>>resourceIDShift)&clientIDMask)
	metrics := ctx.Call("measureText", decodedText)
	ctx.Call("restore")

	width := int(math.Ceil(metrics.Get("width").Float()))
	// Use font bounding box if available for more consistent background clearing
	var ascent, descent int
	if !metrics.Get("fontBoundingBoxAscent").IsUndefined() {
		ascent = int(math.Ceil(metrics.Get("fontBoundingBoxAscent").Float()))
		descent = int(math.Ceil(metrics.Get("fontBoundingBoxDescent").Float()))
	} else {
		ascent = int(math.Ceil(metrics.Get("actualBoundingBoxAscent").Float()))
		descent = int(math.Ceil(metrics.Get("actualBoundingBoxDescent").Float()))
	}
	if ascent == 0 {
		ascent = 10
	}
	if descent == 0 {
		descent = 2
	}

	opBounds := image.Rect(int(x), int(y)-ascent, int(x)+width, int(y)+descent)

	color := w.getForegroundColor(colormap, gc)
	bgColor := w.getBackgroundColor(colormap, gc)
	debugf("ImageText16: bounds=%v color=%s bg=%s", opBounds, color, bgColor)

	w.applyGC(drawable, gcID, func(targetCtx js.Value) {
		// Fill background rectangle
		targetCtx.Call("save")
		targetCtx.Set("fillStyle", bgColor)
		targetCtx.Call("fillRect", int(x), int(y)-ascent, width, ascent+descent)
		targetCtx.Call("restore")

		targetCtx.Call("fillText", decodedText, x, y)
	}, opBounds)

	w.recordOperation(CanvasOperation{
		Type:      "imageText16",
		Args:      []any{uint32(drawable), gc, x, y, decodedTextForLog},
		FillStyle: color,
	})
}

func (w *wasmX11Frontend) PolyText8(drawable xID, gcID xID, x, y int32, items []wire.PolyTextItem) {
	gc, ok := w.gcs[gcID]
	if !ok {
		return
	}
	debugf("X11: polyText8 drawable=%d gc=%v x=%d y=%d items=%v", drawable, gc, x, y, items)

	var ctx js.Value
	var colormap xID
	winInfo, ok := w.windows[drawable]
	if ok {
		ctx = winInfo.offscreenCtx
		colormap = winInfo.colormap
	} else {
		return
	}

	if ctx.IsUndefined() {
		return
	}

	var opBounds image.Rectangle
	currentX := x
	ctx.Call("save")
	w.applyGCState(ctx, colormap, gc, (uint32(gcID)>>resourceIDShift)&clientIDMask)

	for _, item := range items {
		switch it := item.(type) {
		case wire.PolyText8String:
			currentX += int32(it.Delta)
			decodedText := js.Global().Get("TextDecoder").New().Call("decode", jsutil.Uint8ArrayFromBytes(it.Str)).String()
			decodedText = strings.ReplaceAll(decodedText, "\x00", "") // Trim null terminators
			metrics := ctx.Call("measureText", decodedText)

			width := int(math.Ceil(metrics.Get("width").Float()))
			ascent := int(math.Ceil(metrics.Get("actualBoundingBoxAscent").Float()))
			descent := int(math.Ceil(metrics.Get("actualBoundingBoxDescent").Float()))
			itemBounds := image.Rect(int(currentX), int(y)-ascent, int(currentX)+width, int(y)+descent)
			if opBounds.Empty() {
				opBounds = itemBounds
			} else {
				opBounds = opBounds.Union(itemBounds)
			}
		case wire.PolyTextFont:
			if font, ok := w.fonts[xID(it.Font)]; ok {
				ctx.Set("font", font.cssFont)
			}
		}
	}
	ctx.Call("restore")

	color := w.getForegroundColor(colormap, gc)
	var recordedItems []any

	w.applyGC(drawable, gcID, func(targetCtx js.Value) {
		currentX := x
		recordedItems = nil // Reset for re-recording
		for _, item := range items {
			switch it := item.(type) {
			case wire.PolyText8String:
				currentX += int32(it.Delta)
				decodedText := js.Global().Get("TextDecoder").New().Call("decode", jsutil.Uint8ArrayFromBytes(it.Str)).String()
				decodedText = strings.ReplaceAll(decodedText, "\x00", "") // Trim null terminators
				targetCtx.Call("fillText", decodedText, currentX, y)
				recordedItems = append(recordedItems, map[string]any{"delta": it.Delta, "text": decodedText})
			case wire.PolyTextFont:
				if font, ok := w.fonts[xID(it.Font)]; ok {
					targetCtx.Set("font", font.cssFont)
					recordedItems = append(recordedItems, map[string]any{"font": it.Font})
				}
			}
		}
	}, opBounds)

	w.recordOperation(CanvasOperation{
		Type:      "polyText8",
		Args:      []any{uint32(drawable), gc, x, y, recordedItems},
		FillStyle: color,
	})
}

func (w *wasmX11Frontend) PolyText16(drawable xID, gcID xID, x, y int32, items []wire.PolyTextItem) {
	gc, ok := w.gcs[gcID]
	if !ok {
		return
	}
	debugf("X11: polyText16 drawable=%d gc=%v x=%d y=%d items=%v", drawable, gc, x, y, items)

	var ctx js.Value
	var colormap xID
	winInfo, ok := w.windows[drawable]
	if ok {
		ctx = winInfo.offscreenCtx
		colormap = winInfo.colormap
	} else {
		return
	}

	if ctx.IsUndefined() {
		return
	}

	var opBounds image.Rectangle
	currentX := x
	ctx.Call("save")
	w.applyGCState(ctx, colormap, gc, (uint32(gcID)>>resourceIDShift)&clientIDMask)

	for _, item := range items {
		switch it := item.(type) {
		case wire.PolyText16String:
			currentX += int32(it.Delta)
			textBytes := make([]byte, len(it.Str)*2)
			for i, r := range it.Str {
				binary.LittleEndian.PutUint16(textBytes[i*2:], r)
			}
			decodedText := js.Global().Get("TextDecoder").New().Call("decode", jsutil.Uint8ArrayFromBytes(textBytes)).String()
			decodedText = strings.ReplaceAll(decodedText, "\x00", "") // Trim null terminators
			metrics := ctx.Call("measureText", decodedText)

			width := int(math.Ceil(metrics.Get("width").Float()))
			ascent := int(math.Ceil(metrics.Get("actualBoundingBoxAscent").Float()))
			descent := int(math.Ceil(metrics.Get("actualBoundingBoxDescent").Float()))
			itemBounds := image.Rect(int(currentX), int(y)-ascent, int(currentX)+width, int(y)+descent)
			if opBounds.Empty() {
				opBounds = itemBounds
			} else {
				opBounds = opBounds.Union(itemBounds)
			}
		case wire.PolyTextFont:
			if font, ok := w.fonts[xID(it.Font)]; ok {
				ctx.Set("font", font.cssFont)
			}
		}
	}
	ctx.Call("restore")

	color := w.getForegroundColor(colormap, gc)
	var recordedItems []any

	w.applyGC(drawable, gcID, func(targetCtx js.Value) {
		currentX := x
		recordedItems = nil // Reset for re-recording
		for _, item := range items {
			switch it := item.(type) {
			case wire.PolyText16String:
				currentX += int32(it.Delta)
				textBytes := make([]byte, len(it.Str)*2)
				for i, r := range it.Str {
					binary.LittleEndian.PutUint16(textBytes[i*2:], r)
				}
				decodedText := js.Global().Get("TextDecoder").New().Call("decode", jsutil.Uint8ArrayFromBytes(textBytes)).String()
				decodedText = strings.ReplaceAll(decodedText, "\x00", "") // Trim null terminators
				targetCtx.Call("fillText", decodedText, currentX, y)
				recordedItems = append(recordedItems, map[string]any{"delta": it.Delta, "text": decodedText})
			case wire.PolyTextFont:
				if font, ok := w.fonts[xID(it.Font)]; ok {
					targetCtx.Set("font", font.cssFont)
					recordedItems = append(recordedItems, map[string]any{"font": it.Font})
				}
			}
		}
	}, opBounds)

	w.recordOperation(CanvasOperation{
		Type:      "polyText16",
		Args:      []any{uint32(drawable), gc, x, y, recordedItems},
		FillStyle: color,
	})
}

func (w *wasmX11Frontend) SetDashes(gcID xID, dashOffset uint16, dashes []byte) {
	debugf("X11: setDashes gc=%d dashOffset=%d dashes=%v", gcID, dashOffset, dashes)
	if gc, ok := w.gcs[gcID]; ok {
		gc.DashOffset = uint32(dashOffset)
		gc.DashPattern = dashes
		w.gcs[gcID] = gc
	}
	w.recordOperation(CanvasOperation{
		Type: "setDashes",
		Args: []any{uint32(gcID), dashOffset, dashes},
	})
}

func (w *wasmX11Frontend) SetClipRectangles(gcID xID, clippingX, clippingY int16, rectangles []wire.Rectangle, ordering byte) {
	debugf("X11: setClipRectangles gc=%d clippingX=%d clippingY=%d rectangles=%v ordering=%d", gcID, clippingX, clippingY, rectangles, ordering)
	if gc, ok := w.gcs[gcID]; ok {
		gc.ClipXOrigin = int32(clippingX)
		gc.ClipYOrigin = int32(clippingY)
		gc.ClippingRectangles = rectangles
		w.gcs[gcID] = gc
	}
	w.recordOperation(CanvasOperation{
		Type: "setClipRectangles",
		Args: []any{uint32(gcID), clippingX, clippingY, rectangles, ordering},
	})
}

func (w *wasmX11Frontend) RecolorCursor(cursorID xID, foreColor, backColor [3]uint16) {
	debugf("X11: RecolorCursor id=%d", cursorID)
	cursor, ok := w.cursorStyles[uint32(cursorID)]
	if !ok {
		debugf("X11: RecolorCursor cursor %d not found", cursorID)
		return
	}

	w.CreateCursor(cursorID, cursor.source, cursor.mask, foreColor, backColor, cursor.x, cursor.y)
	w.recordOperation(CanvasOperation{
		Type: "recolorCursor",
		Args: []any{uint32(cursorID)},
	})
}

func (w *wasmX11Frontend) SetPointerMapping(pMap []byte) (byte, error) {
	debugf("X11: SetPointerMapping (not implemented)")
	w.recordOperation(CanvasOperation{
		Type: "setPointerMapping",
		Args: []any{},
	})
	return 0, nil
}

func (w *wasmX11Frontend) GetPointerMapping() ([]byte, error) {
	debugf("X11: GetPointerMapping")
	w.recordOperation(CanvasOperation{
		Type: "getPointerMapping",
		Args: []any{},
	})
	// For a web environment, we can return a simple default mapping.
	// 1, 2, 3 represents the left, middle, and right mouse buttons.
	return []byte{1, 2, 3}, nil
}

func (w *wasmX11Frontend) GetPointerControl() (accelNumerator, accelDenominator, threshold uint16, err error) {
	debugf("X11: GetPointerControl")
	w.recordOperation(CanvasOperation{
		Type: "getPointerControl",
		Args: []any{},
	})
	if w.pointerAccelNumerator == 0 {
		w.pointerAccelNumerator = 1
	}
	if w.pointerAccelDenominator == 0 {
		w.pointerAccelDenominator = 1
	}
	if w.pointerThreshold == 0 {
		w.pointerThreshold = 1
	}
	return uint16(w.pointerAccelNumerator), uint16(w.pointerAccelDenominator), uint16(w.pointerThreshold), nil
}

func (w *wasmX11Frontend) ChangePointerControl(accelNum, accelDenom, threshold int16, doAccel, doThresh bool) {
	debugf("X11: ChangePointerControl num=%d den=%d thresh=%d doAccel=%t doThresh=%t", accelNum, accelDenom, threshold, doAccel, doThresh)
	if doAccel {
		if accelNum != -1 {
			w.pointerAccelNumerator = accelNum
		}
		if accelDenom != -1 {
			w.pointerAccelDenominator = accelDenom
		}
	}
	if doThresh && threshold != -1 {
		w.pointerThreshold = threshold
	}
	w.recordOperation(CanvasOperation{
		Type: "changePointerControl",
		Args: []any{accelNum, accelDenom, threshold, doAccel, doThresh},
	})
}

func (w *wasmX11Frontend) ChangeKeyboardControl(valueMask uint32, values wire.KeyboardControl) {
	debugf("X11: ChangeKeyboardControl (not implemented)")
	w.recordOperation(CanvasOperation{
		Type: "changeKeyboardControl",
		Args: []any{},
	})
}

func (w *wasmX11Frontend) GetKeyboardControl() (wire.KeyboardControl, error) {
	debugf("X11: GetKeyboardControl (not implemented)")
	w.recordOperation(CanvasOperation{
		Type: "getKeyboardControl",
		Args: []any{},
	})
	return wire.KeyboardControl{}, nil
}

func (w *wasmX11Frontend) SetScreenSaver(timeout, interval int16, preferBlank, allowExpose byte) {
	debugf("X11: SetScreenSaver timeout=%d interval=%d preferBlank=%d allowExpose=%d", timeout, interval, preferBlank, allowExpose)
	if timeout != -1 {
		w.screenSaverTimeout = timeout
	}
	if interval != -1 {
		w.screenSaverInterval = interval
	}
	w.screenSaverPreferBlank = preferBlank
	w.screenSaverAllowExpose = allowExpose

	w.recordOperation(CanvasOperation{
		Type: "setScreenSaver",
		Args: []any{timeout, interval, preferBlank, allowExpose},
	})
}

func (w *wasmX11Frontend) GetScreenSaver() (timeout, interval int16, preferBlank, allowExpose byte, err error) {
	debugf("X11: GetScreenSaver")
	w.recordOperation(CanvasOperation{
		Type: "getScreenSaver",
		Args: []any{},
	})
	return w.screenSaverTimeout, w.screenSaverInterval, w.screenSaverPreferBlank, w.screenSaverAllowExpose, nil
}

func (w *wasmX11Frontend) ChangeHosts(mode byte, host wire.Host) {
	debugf("X11: ChangeHosts (not implemented)")
	w.recordOperation(CanvasOperation{
		Type: "changeHosts",
		Args: []any{},
	})
}

func (w *wasmX11Frontend) ListHosts() ([]wire.Host, error) {
	debugf("X11: ListHosts (not implemented)")
	w.recordOperation(CanvasOperation{
		Type: "listHosts",
		Args: []any{},
	})
	return nil, nil
}

func (w *wasmX11Frontend) SetAccessControl(mode byte) {
	debugf("X11: SetAccessControl (not implemented)")
	w.recordOperation(CanvasOperation{
		Type: "setAccessControl",
		Args: []any{},
	})
}

func (w *wasmX11Frontend) SetCloseDownMode(mode byte) {
	debugf("X11: SetCloseDownMode (not implemented)")
	w.recordOperation(CanvasOperation{
		Type: "setCloseDownMode",
		Args: []any{},
	})
}

func (w *wasmX11Frontend) KillClient(resource uint32) {
	debugf("X11: KillClient (not implemented)")
	w.recordOperation(CanvasOperation{
		Type: "killClient",
		Args: []any{},
	})
}

func (w *wasmX11Frontend) ForceScreenSaver(mode byte) {
	debugf("X11: ForceScreenSaver (not implemented)")
	w.recordOperation(CanvasOperation{
		Type: "forceScreenSaver",
		Args: []any{},
	})
}

func (w *wasmX11Frontend) SetModifierMapping(keyCodesPerModifier byte, keyCodes []wire.KeyCode) (byte, error) {
	debugf("X11: SetModifierMapping keyCodesPerModifier=%d keyCodes=%v", keyCodesPerModifier, keyCodes)
	w.recordOperation(CanvasOperation{
		Type: "setModifierMapping",
		Args: []any{keyCodesPerModifier, keyCodes},
	})
	w.modifierMap = keyCodes
	return 0, nil
}

func (w *wasmX11Frontend) GetModifierMapping() ([]wire.KeyCode, error) {
	debugf("X11: GetModifierMapping")
	w.recordOperation(CanvasOperation{
		Type: "getModifierMapping",
		Args: []any{},
	})
	if w.modifierMap == nil {
		return make([]wire.KeyCode, 8), nil
	}
	return w.modifierMap, nil
}

func (f *wasmX11Frontend) DeviceBell(deviceID byte, feedbackID byte, feedbackClass byte, percent int8) {
	f.Bell(percent)
}

func (f *wasmX11Frontend) XIChangeHierarchy(changes []wire.XIChangeHierarchyChange) {
	debugf("X11: XIChangeHierarchy (not implemented)")
}

func (f *wasmX11Frontend) ChangeFeedbackControl(deviceID byte, feedbackID byte, mask uint32, control []byte) {
	debugf("X11: ChangeFeedbackControl (not implemented)")
}

func (f *wasmX11Frontend) ChangeDeviceKeyMapping(deviceID byte, firstKey byte, keysymsPerKeycode byte, keycodeCount byte, keysyms []uint32) {
	if _, ok := f.deviceKeymaps[deviceID]; !ok {
		f.deviceKeymaps[deviceID] = make(map[byte][]uint32)
	}
	keysymIndex := 0
	for i := 0; i < int(keycodeCount); i++ {
		keycode := firstKey + byte(i)
		if keysymIndex+int(keysymsPerKeycode) > len(keysyms) {
			debugf("X11: ChangeDeviceKeyMapping: not enough keysyms provided.")
			break
		}
		f.deviceKeymaps[deviceID][keycode] = keysyms[keysymIndex : keysymIndex+int(keysymsPerKeycode)]
		keysymIndex += int(keysymsPerKeycode)
	}
	debugf("X11: ChangeDeviceKeyMapping deviceID=%d, firstKey=%d, keycodeCount=%d", deviceID, firstKey, keycodeCount)
}

func (f *wasmX11Frontend) SetDeviceModifierMapping(deviceID byte, keycodes []byte) byte {
	f.deviceModifierMaps[deviceID] = keycodes
	debugf("X11: SetDeviceModifierMapping deviceID=%d, keycodes=%v", deviceID, keycodes)
	return 0
}

func (f *wasmX11Frontend) SetDeviceButtonMapping(deviceID byte, buttonMap []byte) byte {
	f.deviceButtonMaps[deviceID] = buttonMap
	debugf("X11: SetDeviceButtonMapping deviceID=%d, map=%v", deviceID, buttonMap)
	return 0
}

func (f *wasmX11Frontend) GetFeedbackControl(deviceID byte) []wire.FeedbackState {
	debugf("X11: GetFeedbackControl deviceID=%d", deviceID)

	var feedbacks []wire.FeedbackState

	switch deviceID {
	case wire.CorePointerDeviceID:
		feedbacks = append(feedbacks, &wire.PtrFeedbackState{
			ClassID:    wire.PtrFeedbackClass,
			ID:         0,
			Len:        12,
			AccelNum:   1,
			AccelDenom: 1,
			Threshold:  1,
		})
	case wire.CoreKeyboardDeviceID:
		var autoRepeats [32]byte
		for i := range autoRepeats {
			autoRepeats[i] = 0xff // All keys auto-repeat by default
		}
		feedbacks = append(feedbacks, &wire.KbdFeedbackState{
			ClassID:          wire.KbdFeedbackClass,
			ID:               0,
			Len:              44,
			Pitch:            440,
			Duration:         100,
			LedMask:          0,
			LedValues:        0,
			GlobalAutoRepeat: true,
			Click:            0,
			Percent:          50,
			AutoRepeats:      autoRepeats,
		})
	}

	return feedbacks
}

func (f *wasmX11Frontend) GetDeviceKeyMapping(deviceID byte, firstKey byte, count byte) (byte, []uint32) {
	deviceMap, ok := f.deviceKeymaps[deviceID]
	if !ok {
		// Device not found, return default mapping.
		keysyms := make([]uint32, count)
		for i := 0; i < int(count); i++ {
			// By default, keysym is same as keycode
			keysyms[i] = uint32(firstKey + byte(i))
		}
		debugf("X11: GetDeviceKeyMapping deviceID=%d (no map), returning default", deviceID)
		return 1, keysyms
	}

	var keysymsPerKeycode byte = 1
	found := false
	for i := 0; i < int(count); i++ {
		keycode := firstKey + byte(i)
		if ks, ok := deviceMap[keycode]; ok {
			keysymsPerKeycode = byte(len(ks))
			if keysymsPerKeycode == 0 {
				keysymsPerKeycode = 1
			}
			found = true
			break
		}
	}
	if !found {
		for _, ks := range deviceMap {
			keysymsPerKeycode = byte(len(ks))
			if keysymsPerKeycode == 0 {
				keysymsPerKeycode = 1
			}
			break
		}
	}

	keysyms := make([]uint32, 0, int(count)*int(keysymsPerKeycode))
	for i := 0; i < int(count); i++ {
		keycode := firstKey + byte(i)
		ks, ok := deviceMap[keycode]
		if ok {
			paddedKs := make([]uint32, keysymsPerKeycode)
			copy(paddedKs, ks)
			keysyms = append(keysyms, paddedKs...)
		} else {
			for j := 0; j < int(keysymsPerKeycode); j++ {
				keysyms = append(keysyms, 0)
			}
		}
	}

	debugf("X11: GetDeviceKeyMapping deviceID=%d, firstKey=%d, count=%d -> keysymsPerKeycode=%d, len(keysyms)=%d", deviceID, firstKey, count, keysymsPerKeycode, len(keysyms))
	return keysymsPerKeycode, keysyms
}

func (f *wasmX11Frontend) GetDeviceModifierMapping(deviceID byte) (byte, []byte) {
	keycodes, ok := f.deviceModifierMaps[deviceID]
	if !ok {
		// No specific mapping, return default. The protocol states this is a variable-length reply.
		// A common default is 8 modifiers, each with 0 keycodes assigned initially.
		debugf("X11: GetDeviceModifierMapping deviceID=%d (no map), returning default", deviceID)
		return 8, []byte{}
	}
	numKeycodesPerModifier := len(keycodes) / 8
	debugf("X11: GetDeviceModifierMapping deviceID=%d, num_keycodes=%d", deviceID, len(keycodes))
	return byte(numKeycodesPerModifier), keycodes
}

func (f *wasmX11Frontend) GetDeviceButtonMapping(deviceID byte) []byte {
	buttonMap, ok := f.deviceButtonMaps[deviceID]
	if !ok {
		// Return a default 1-to-1 mapping if none is set.
		debugf("X11: GetDeviceButtonMapping deviceID=%d (no map), returning default", deviceID)
		return []byte{1, 2, 3, 4, 5, 6, 7} // Default for 7 buttons
	}
	debugf("X11: GetDeviceButtonMapping deviceID=%d, map=%v", deviceID, buttonMap)
	return buttonMap
}

func (f *wasmX11Frontend) QueryDeviceState(deviceID byte) []wire.InputClassInfo {
	debugf("X11: QueryDeviceState deviceID=%d", deviceID)

	var infos []wire.InputClassInfo

	switch deviceID {
	case wire.CorePointerDeviceID:
		// ButtonClassInfo
		infos = append(infos, &wire.ButtonClassInfo{
			NumButtons: 7,
		})
		// ValuatorClassInfo
		infos = append(infos, &wire.ValuatorClassInfo{
			NumAxes:    2,
			Mode:       0, // Relative
			MotionSize: 0,
			Axes:       []wire.ValuatorAxisInfo{},
		})
	case wire.CoreKeyboardDeviceID:
		// KeyClassInfo
		infos = append(infos, &wire.KeyClassInfo{
			NumKeys:    248, // Standard number of keys
			MinKeycode: 8,
			MaxKeycode: 255,
		})
	}

	return infos
}

func (w *wasmX11Frontend) QueryBestSize(class byte, drawable xID, width, height uint16) (rwidth, rheight uint16) {
	debugf("X11: QueryBestSize class=%d drawable=%d width=%d height=%d", class, drawable, width, height)
	w.recordOperation(CanvasOperation{
		Type: "queryBestSize",
		Args: []any{class, uint32(drawable), width, height},
	})
	switch class {
	case 0: // Cursor
		if width >= 64 && height >= 64 {
			return 64, 64
		}
		if width >= 32 && height >= 32 {
			return 32, 32
		}
		return 16, 16
	case 1, 2: // Tile, Stipple
		// For tiles and stipples, we can handle any size, but powers of 2 are preferred.
		// For now just return the requested size.
		return width, height
	}
	return width, height
}

func (w *wasmX11Frontend) CreatePixmap(xid, drawable xID, width, height, depth uint32) {
	debugf("X11: createPixmap id=%d drawable=%d width=%d height=%d depth=%d", xid, drawable, width, height, depth)
	canvas := w.document.Call("createElement", "canvas")
	canvas.Set("width", width)
	canvas.Set("height", height)
	ctx := canvas.Call("getContext", "2d")
	w.pixmaps[xid] = &pixmapInfo{
		canvas:  canvas,
		context: ctx,
	}
	w.recordOperation(CanvasOperation{
		Type: "createPixmap",
		Args: []any{uint32(xid), uint32(drawable), width, height, depth},
	})
}

func (w *wasmX11Frontend) FreePixmap(xid xID) {
	debugf("X11: freePixmap id=%d", xid)
	delete(w.pixmaps, xid)
	w.recordOperation(CanvasOperation{
		Type: "freePixmap",
		Args: []any{uint32(xid)},
	})
}

func (w *wasmX11Frontend) CopyPixmap(srcID, dstID, gcID xID, srcX, srcY, width, height, dstX, dstY uint32) {
	debugf("X11: copyPixmap src=%d dst=%d gc=%d srcX=%d srcY=%d width=%d height=%d dstX=%d dstY=%d", srcID, dstID, gcID, srcX, srcY, width, height, dstX, dstY)
	srcPixmap, srcOk := w.pixmaps[srcID]
	dstWin, dstOk := w.windows[dstID]
	if !srcOk || !dstOk {
		return
	}
	if !srcPixmap.canvas.IsNull() && !dstWin.canvas.IsNull() {
		dstWin.offscreenCtx.Call("drawImage", srcPixmap.canvas, srcX, srcY, width, height, dstX, dstY, width, height)
		w.updateVisibleArea(dstID, int(dstX), int(dstY), int(width), int(height))
	}
	w.recordOperation(CanvasOperation{
		Type: "copyPixmap",
		Args: []any{uint32(srcID), uint32(dstID), uint32(gcID), srcX, srcY, width, height, dstX, dstY},
	})
}

func (w *wasmX11Frontend) WarpPointer(x, y int16) {
	debugf("X11: warpPointer x=%d y=%d", x, y)
	w.server.UpdatePointerPosition(x, y)
	w.recordOperation(CanvasOperation{
		Type: "warpPointer",
		Args: []any{x, y},
	})
}

func (w *wasmX11Frontend) CreateCursor(cursorID xID, source, mask xID, foreColor, backColor [3]uint16, x, y uint16) {
	debugf("X11: CreateCursor id=%d source=%d mask=%d", cursorID, source, mask)

	sourcePixmap, sourceOk := w.pixmaps[source]
	if !sourceOk {
		debugf("X11: CreateCursor source pixmap %d not found", source)
		return
	}

	maskPixmap, maskOk := w.pixmaps[mask]
	if !maskOk && uint32(mask) != 0 {
		debugf("X11: CreateCursor mask pixmap %d not found", mask)
		return
	}

	width := sourcePixmap.canvas.Get("width").Int()
	height := sourcePixmap.canvas.Get("height").Int()

	if width == 0 || height == 0 {
		return
	}

	// Optimization: Check if we already have this cursor and it's the same
	if info, ok := w.cursorStyles[uint32(cursorID)]; ok {
		if info.source == source && info.mask == mask && info.x == x && info.y == y && info.foreColor == foreColor && info.backColor == backColor {
			debugf("X11: CreateCursor: Using cached cursor for %d", cursorID)
			return
		}
	}

	// Create a temporary canvas to generate the cursor image
	tempCanvas := w.document.Call("createElement", "canvas")
	tempCanvas.Set("width", width)
	tempCanvas.Set("height", height)
	tempCtx := tempCanvas.Call("getContext", "2d")

	// Get image data from source and mask pixmaps
	sourceJSData := sourcePixmap.context.Call("getImageData", 0, 0, width, height).Get("data")
	sourceBytes := make([]byte, sourceJSData.Length())
	js.CopyBytesToGo(sourceBytes, sourceJSData)

	var maskBytes []byte
	if uint32(mask) != 0 {
		maskJSData := maskPixmap.context.Call("getImageData", 0, 0, width, height).Get("data")
		maskBytes = make([]byte, maskJSData.Length())
		js.CopyBytesToGo(maskBytes, maskJSData)
	}

	cursorBytes := make([]byte, width*height*4)

	fgR := uint8(foreColor[0] >> 8)
	fgG := uint8(foreColor[1] >> 8)
	fgB := uint8(foreColor[2] >> 8)
	bgR := uint8(backColor[0] >> 8)
	bgG := uint8(backColor[1] >> 8)
	bgB := uint8(backColor[2] >> 8)

	for i := 0; i < width*height; i++ {
		idx := i * 4

		maskBitOn := true
		if uint32(mask) != 0 {
			maskBitOn = maskBytes[idx+3] > 0
		}

		if maskBitOn {
			sourceBitOn := sourceBytes[idx+3] > 0
			if sourceBitOn {
				// Foreground
				cursorBytes[idx+0] = fgR
				cursorBytes[idx+1] = fgG
				cursorBytes[idx+2] = fgB
				cursorBytes[idx+3] = 255
			} else {
				// Background
				cursorBytes[idx+0] = bgR
				cursorBytes[idx+1] = bgG
				cursorBytes[idx+2] = bgB
				cursorBytes[idx+3] = 255
			}
		} else {
			// Transparent
			cursorBytes[idx+0] = 0
			cursorBytes[idx+1] = 0
			cursorBytes[idx+2] = 0
			cursorBytes[idx+3] = 0
		}
	}

	cursorDataArray := jsutil.Uint8ClampedArrayFromBytes(cursorBytes)

	cursorImageData := js.Global().Get("ImageData").New(cursorDataArray, width, height)
	tempCtx.Call("putImageData", cursorImageData, 0, 0)

	dataURL := tempCanvas.Call("toDataURL").String()
	cursorStyle := fmt.Sprintf("url(%s) %d %d, auto", dataURL, x, y)

	w.cursorStyles[uint32(cursorID)] = &cursorInfo{
		style:     cursorStyle,
		source:    source,
		mask:      mask,
		x:         x,
		y:         y,
		foreColor: foreColor,
		backColor: backColor,
	}

	w.recordOperation(CanvasOperation{
		Type: "createCursor",
		Args: []any{uint32(cursorID), uint32(source), uint32(mask), x, y},
	})
}

func (w *wasmX11Frontend) CreateCursorFromGlyph(cursorID xID, sourceFont xID, sourceChar uint16, maskFont xID, maskChar uint16, foreColor, backColor [3]uint16) {
	debugf("X11: createCursorFromGlyph cursorID=%d sourceFont=%d sourceChar=%d", cursorID, sourceFont, sourceChar)

	// Try to map to standard CSS cursors if it's the "cursor" font
	var style string
	if font, ok := w.fonts[sourceFont]; ok && (font.x11Name == "cursor" || strings.Contains(font.x11Name, "cursor")) {
		switch sourceChar {
		case 152: // XC_xterm
			style = "text"
		case 34: // XC_crosshair
			style = "crosshair"
		case 58, 60: // XC_hand1, XC_hand2
			style = "pointer"
		case 52: // XC_fleur
			style = "move"
		case 94: // XC_right_ptr
			style = "pointer"
		case 150, 26: // XC_watch, XC_clock
			style = "wait"
		case 108: // XC_sb_h_double_arrow
			style = "ew-resize"
		case 116: // XC_sb_v_double_arrow
			style = "ns-resize"
		case 68: // XC_left_ptr
			style = "default"
		case 12: // XC_bottom_left_corner
			style = "sw-resize"
		case 14: // XC_bottom_right_corner
			style = "se-resize"
		case 16: // XC_bottom_side
			style = "s-resize"
		case 70: // XC_left_side
			style = "w-resize"
		case 96: // XC_right_side
			style = "e-resize"
		case 134: // XC_top_left_corner
			style = "nw-resize"
		case 136: // XC_top_right_corner
			style = "ne-resize"
		case 138: // XC_top_side
			style = "n-resize"
		case 92: // XC_question_arrow
			style = "help"
		case 128: // XC_target
			style = "crosshair"
		case 30: // XC_cross
			style = "crosshair"
		case 90: // XC_plus
			style = "copy"
		case 106: // XC_sb_down_arrow
			style = "s-resize"
		case 110: // XC_sb_left_arrow
			style = "w-resize"
		case 112: // XC_sb_right_arrow
			style = "e-resize"
		case 114: // XC_sb_up_arrow
			style = "n-resize"
		default:
			style = "default"
		}
	} else {
		style = "default"
	}

	w.cursorStyles[uint32(cursorID)] = &cursorInfo{style: style}
	w.recordOperation(CanvasOperation{
		Type: "createCursorFromGlyph",
		Args: []any{uint32(cursorID), uint32(sourceFont), sourceChar, uint32(maskFont), maskChar},
	})
}

func (w *wasmX11Frontend) SetWindowCursor(windowID xID, cursorID xID) {
	debugf("X11: setWindowCursor window=%d cursor=%d", windowID, cursorID)
	if winInfo, ok := w.windows[windowID]; ok {
		if cursor, ok := w.cursorStyles[uint32(cursorID)]; ok {
			winInfo.canvas.Get("style").Set("cursor", cursor.style)
		} else {
			winInfo.canvas.Get("style").Set("cursor", "default")
		}
	}
	w.recordOperation(CanvasOperation{
		Type: "setWindowCursor",
		Args: []any{uint32(windowID), uint32(cursorID)},
	})
}

func (w *wasmX11Frontend) CopyGC(srcGCID, dstGCID xID) {
	debugf("X11: copyGC src=%d dst=%d", srcGCID, dstGCID)
	if srcGC, ok := w.gcs[srcGCID]; ok {
		newGC := srcGC
		w.gcs[dstGCID] = newGC
	}
	w.recordOperation(CanvasOperation{
		Type: "copyGC",
		Args: []any{uint32(srcGCID), uint32(dstGCID)},
	})
}

func (w *wasmX11Frontend) FreeGC(gcID xID) {
	debugf("X11: freeGC id=%d", gcID)
	delete(w.gcs, gcID)
	w.recordOperation(CanvasOperation{
		Type: "freeGC",
		Args: []any{uint32(gcID)},
	})
}

func (w *wasmX11Frontend) FreeCursor(cursorID xID) {
	debugf("X11: freeCursor id=%d", cursorID)
	// In the wasm frontend, we only store the CSS style mapping.
	// We don't need to "free" a DOM element for a cursor.
	// We just remove it from our internal map.
	delete(w.cursorStyles, uint32(cursorID)) // Note: cursorStyles map uses uint32 as key
	w.recordOperation(CanvasOperation{
		Type: "freeCursor",
		Args: []any{uint32(cursorID)},
	})
}

func (w *wasmX11Frontend) SendEvent(eventData messageEncoder) {
	encodedData := eventData.EncodeMessage(w.server.byteOrder)
	debugf("X11: SendEvent data=%v", encodedData)
	// In a real implementation, this would send the event data back to the Go server
	// which would then forward it to the X11 client.
	w.recordOperation(CanvasOperation{
		Type: "sendEvent",
		Args: []any{encodedData},
	})
}

func (w *wasmX11Frontend) GetFocusWindow(clientID uint32) xID {
	if (uint32(w.focusedWindowID)>>resourceIDShift)&clientIDMask == clientID {
		return w.focusedWindowID
	}
	return 0
}

func (w *wasmX11Frontend) GrabKeyboard(grabWindow xID, ownerEvents bool, time uint32, pointerMode, keyboardMode byte) byte {
	debugf("X11: GrabKeyboard window=%d", grabWindow)
	if win, ok := w.windows[grabWindow]; ok {
		win.canvas.Call("focus")
	}
	w.recordOperation(CanvasOperation{
		Type: "grabKeyboard",
		Args: []any{uint32(grabWindow), ownerEvents, time, pointerMode, keyboardMode},
	})
	return 0 // Success
}

func (w *wasmX11Frontend) UngrabKeyboard(time uint32) {
	debugf("X11: UngrabKeyboard")
	w.recordOperation(CanvasOperation{
		Type: "ungrabKeyboard",
		Args: []any{time},
	})
}

func (w *wasmX11Frontend) initDefaultCursors() {
	// This is a minimal mapping from X11 cursor names to CSS cursor values.
	// The cursor IDs are taken from the standard X11 cursor font.
	w.cursorStyles[68] = &cursorInfo{style: "pointer"}
	w.cursorStyles[34] = &cursorInfo{style: "crosshair"}
	w.cursorStyles[58] = &cursorInfo{style: "help"}
	w.cursorStyles[52] = &cursorInfo{style: "move"}
	w.cursorStyles[138] = &cursorInfo{style: "text"}
	w.cursorStyles[108] = &cursorInfo{style: "wait"}
	w.cursorStyles[116] = &cursorInfo{style: "wait"}
	w.cursorStyles[118] = &cursorInfo{style: "w-resize"}
	w.cursorStyles[120] = &cursorInfo{style: "e-resize"}
	w.cursorStyles[76] = &cursorInfo{style: "n-resize"}
	w.cursorStyles[14] = &cursorInfo{style: "s-resize"}
	w.cursorStyles[10] = &cursorInfo{style: "nw-resize"}
	w.cursorStyles[12] = &cursorInfo{style: "ne-resize"}
	w.cursorStyles[134] = &cursorInfo{style: "sw-resize"}
	w.cursorStyles[136] = &cursorInfo{style: "se-resize"}
}

func (w *wasmX11Frontend) SetCursor(windowID xID, cursorID uint32) {
	debugf("X11: setCursor window=%d cursor=%d", windowID, cursorID)
	if winInfo, ok := w.windows[windowID]; ok {
		if info, ok := w.cursorStyles[cursorID]; ok {
			winInfo.canvas.Get("style").Set("cursor", info.style)
		} else {
			winInfo.canvas.Get("style").Set("cursor", "default")
		}
	}
	w.recordOperation(CanvasOperation{
		Type: "setCursor",
		Args: []any{uint32(windowID), cursorID},
	})
}

func (w *wasmX11Frontend) ReadClipboard() (string, error) {
	return jsutil.ReadClipboard()
}

func (w *wasmX11Frontend) WriteClipboard(s string) error {
	return jsutil.WriteClipboard(s)
}

func (w *wasmX11Frontend) UpdatePointerPosition(x, y int16) {
	w.server.UpdatePointerPosition(x, y)
}

func (w *wasmX11Frontend) Bell(percent int8) {
	debugf("X11: bell percent=%d", percent)
	w.showMessage("*** X11 Bell ***")
	w.recordOperation(CanvasOperation{
		Type: "bell",
		Args: []any{percent},
	})
}

func (w *wasmX11Frontend) GetRGBColor(colormap xID, pixel uint32) (r, g, b uint8) {
	return w.server.GetRGBColor(colormap, pixel)
}

func (w *wasmX11Frontend) OpenFont(fid xID, name string) {
	debugf("X11: OpenFont fid=%d name=%s", fid, name)
	debugf("X11: OpenFont received font name: %s", name)

	_, _, _, _, cssFont := MapX11FontToCSS(name)

	w.fonts[fid] = &fontInfo{
		x11Name: name,
		cssFont: cssFont,
	}

	w.recordOperation(CanvasOperation{
		Type: "openFont",
		Args: []any{uint32(fid), name},
	})
}

func (w *wasmX11Frontend) CloseFont(fid xID) {
	debugf("X11: CloseFont fid=%d", fid)
	delete(w.fonts, fid)
	w.recordOperation(CanvasOperation{
		Type: "closeFont",
		Args: []any{uint32(fid)},
	})
}

func (w *wasmX11Frontend) AllowEvents(clientID uint32, mode byte, time uint32) {
	debugf("X11: AllowEvents mode=%d time=%d (not implemented)", mode, time)
	w.recordOperation(CanvasOperation{
		Type: "allowEvents",
		Args: []any{mode, time},
	})
}

func (w *wasmX11Frontend) GrabPointer(grabWindow xID, ownerEvents bool, eventMask uint16, pointerMode, keyboardMode byte, confineTo uint32, cursor uint32, time uint32) byte {
	debugf("X11: GrabPointer window=%d", grabWindow)
	if _, ok := w.windows[grabWindow]; ok {
		if w.lastPointerID != 0 {
			// use the main container for pointer capture to ensure we get events even outside the window
			w.mainContainer.Call("setPointerCapture", w.lastPointerID)
			w.grabbedWindowID = grabWindow
		}
	}
	w.recordOperation(CanvasOperation{
		Type: "grabPointer",
		Args: []any{uint32(grabWindow), ownerEvents, eventMask, pointerMode, keyboardMode, confineTo, cursor, time},
	})
	return 0 // Success
}

func (w *wasmX11Frontend) UngrabPointer(time uint32) {
	debugf("X11: UngrabPointer")
	if w.grabbedWindowID != 0 {
		if w.lastPointerID != 0 {
			w.mainContainer.Call("releasePointerCapture", w.lastPointerID)
		}
		w.grabbedWindowID = 0
	}
	w.recordOperation(CanvasOperation{
		Type: "ungrabPointer",
		Args: []any{time},
	})
}

func (w *wasmX11Frontend) SendConfigureAndExposeEvent(windowID xID, x, y int16, width, height uint16) {
	var borderWidth uint16
	if win, ok := w.server.windows[windowID]; ok {
		borderWidth = win.borderWidth
	}
	w.server.sendConfigureNotifyEvent(windowID, x, y, width, height, borderWidth, 0)
	w.server.sendExposeEvent(windowID, 0, 0, width, height) // Send expose for the entire window
	if win, ok := w.server.windows[windowID]; ok {
		for _, childID := range win.children {
			childXID := xID(childID)
			if childWin, ok := w.server.windows[childXID]; ok {
				w.server.sendExposeEvent(childXID, 0, 0, childWin.width, childWin.height)
			}
		}
	}
}

// mouseEventHandler creates a js.Func for mouse events.
func (w *wasmX11Frontend) mouseEventHandler(xid xID, eventType string) js.Func {
	var lastMoveTime float64
	return js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		if _, ok := w.windows[xid]; !ok {
			return nil
		}
		event := args[0]

		if eventType == "mousemove" {
			now := js.Global().Get("Date").Call("now").Float()
			if now-lastMoveTime < 16 { // Throttle to ~60fps
				return nil
			}
			lastMoveTime = now
		}

		// Save the pointer ID for GrabPointer
		pid := event.Get("pointerId")
		if !pid.IsUndefined() {
			w.lastPointerID = pid.Int()
		}

		offsetX := int32(event.Get("offsetX").Int())
		offsetY := int32(event.Get("offsetY").Int())

		// The state should be the mask *before* the event.
		// The  property is the state *after* the  event,
		// and *before* the  event. So for mouseup, it's correct.
		// For mousedown, we need to remove the current button from the mask.
		state := 0
		if event.Get("shiftKey").Bool() {
			state |= 1 // ShiftMask
		}
		if event.Get("ctrlKey").Bool() {
			state |= 4 // ControlMask
		}
		if event.Get("altKey").Bool() {
			state |= 8 // Mod1Mask
		}

		// Map JS  bitmask to X11 button state masks
		jsButtons := event.Get("buttons").Int()
		buttonsMask := 0
		if (jsButtons & 1) != 0 {
			buttonsMask |= 0x0100
		} // Button1Mask
		if (jsButtons & 2) != 0 {
			buttonsMask |= 0x0400
		} // Button3Mask
		if (jsButtons & 4) != 0 {
			buttonsMask |= 0x0200
		} // Button2Mask
		state |= buttonsMask

		button := 0
		if eventType == "mousedown" || eventType == "mouseup" {
			// JS button: 0=left, 1=middle, 2=right
			// X11 button: 1=left, 2=middle, 3=right
			jsButton := event.Get("button").Int()
			switch jsButton {
			case 0:
				button = 1
			case 1:
				button = 2
			case 2:
				button = 3
			}

			if eventType == "mousedown" {
				// For mousedown, remove the current button from the state mask
				switch button {
				case 1:
					state &^= 0x0100
				case 2:
					state &^= 0x0200
				case 3:
					state &^= 0x0400
				}
			}
		}

		if eventType == "wheel" {
			event.Call("preventDefault") // Prevent page scrolling
			deltaY := event.Get("deltaY").Float()
			if deltaY < 0 {
				button = 4 // Wheel up
			} else {
				button = 5 // Wheel down
			}
			// Simulate a press and release for wheel events.
			detailDown := (state << 16) | button
			w.server.SendMouseEvent(xid, "mousedown", offsetX, offsetY, int32(detailDown))

			// For the release event, the state should include the button that was pressed.
			stateUp := state
			switch button {
			case 4:
				stateUp |= 0x0800 // Button4Mask
			case 5:
				stateUp |= 0x1000 // Button5Mask
			}
			detailUp := (stateUp << 16) | button
			w.server.SendMouseEvent(xid, "mouseup", offsetX, offsetY, int32(detailUp))

			debugf("Mouse wheel event: window=%d, x=%d, y=%d, button=%d, state=%d", xid, offsetX, offsetY, button, state)
		} else {
			// Pack button and state into a single int32
			// Use top 16 bits for state, bottom 16 for button
			detail := (state << 16) | button
			w.server.SendMouseEvent(xid, eventType, offsetX, offsetY, int32(detail))
			debugf("Mouse event: window=%d, type=%s, x=%d, y=%d, button=%d, state=%d (packed_detail=%d)", xid, eventType, offsetX, offsetY, button, state, detail)
		}

		if eventType == "mousemove" {
			w.server.UpdatePointerPosition(int16(offsetX), int16(offsetY))
		}
		return nil
	})
}

func keyMask(event js.Value) uint16 {
	state := uint16(0)
	if event.Get("shiftKey").Bool() {
		state |= 1 // ShiftMask
	}
	if event.Get("ctrlKey").Bool() {
		state |= 4 // ControlMask
	}
	if event.Get("altKey").Bool() {
		state |= 8 // Mod1Mask
	}
	// Map JS  bitmask to X11 button state masks
	jsButtons := event.Get("buttons").Int()
	if (jsButtons & 1) != 0 {
		state |= 0x0100
	} // Button1Mask
	if (jsButtons & 2) != 0 {
		state |= 0x0400
	} // Button3Mask
	if (jsButtons & 4) != 0 {
		state |= 0x0200
	} // Button2Mask
	return state
}

// pointerCrossingEventHandler creates a js.Func for mouse enter/leave events.
func (w *wasmX11Frontend) pointerCrossingEventHandler(xid xID, isEnter bool) js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		if _, ok := w.windows[xid]; !ok {
			return nil
		}
		event := args[0]
		rootX := int16(event.Get("clientX").Int())
		rootY := int16(event.Get("clientY").Int())
		eventX := int16(event.Get("offsetX").Int())
		eventY := int16(event.Get("offsetY").Int())
		state := keyMask(event)
		mode := byte(0)   // Normal
		detail := byte(0) // Not used for crossing events

		w.server.SendPointerCrossingEvent(isEnter, xid, rootX, rootY, eventX, eventY, state, mode, detail)
		debugf("Pointer crossing event: window=%d, isEnter=%t, rootX=%d, rootY=%d, eventX=%d, eventY=%d, state=%d", xid, isEnter, rootX, rootY, eventX, eventY, state)
		return nil
	})
}

// keyboardEventHandler creates a js.Func for keyboard events.
func (w *wasmX11Frontend) keyboardEventHandler(xid xID, eventType string) js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		if _, ok := w.windows[xid]; !ok {
			return nil
		}
		event := args[0]
		code := event.Get("code").String()
		altKey := event.Get("altKey").Bool()
		ctrlKey := event.Get("ctrlKey").Bool()
		shiftKey := event.Get("shiftKey").Bool()
		metaKey := event.Get("metaKey").Bool()

		w.server.SendKeyboardEvent(w.focusedWindowID, eventType, code, altKey, ctrlKey, shiftKey, metaKey)
		debugf("Keyboard event: window=%d, type=%s, code=%s, alt=%t, ctrl=%t, shift=%t, meta=%t", w.focusedWindowID, eventType, code, altKey, ctrlKey, shiftKey, metaKey)
		return nil
	})
}

func (w *wasmX11Frontend) QueryFont(fid xID) (minBounds, maxBounds wire.XCharInfo, minCharOrByte2, maxCharOrByte2, defaultChar uint16, drawDirection uint8, minByte1, maxByte1 uint8, allCharsExist bool, fontAscent, fontDescent int16, charInfos []wire.XCharInfo, fontProps []wire.FontProp) {
	w.recordOperation(CanvasOperation{
		Type: "queryFont",
		Args: []any{uint32(fid)},
	})
	debugf("X11: QueryFont fid=%d", fid)

	fontDescent = 5

	// Try to get font info from the opened fonts map
	var cssFont string = "12px monospace" // Default fallback
	if font, ok := w.fonts[fid]; ok {
		cssFont = font.cssFont
		// Parse font size from cssFont string (e.g., "12px monospace" or "normal normal 13px monospace")
		parts := strings.Split(font.cssFont, " ")
		var sizeStr string
		for _, p := range parts {
			if strings.HasSuffix(p, "px") {
				sizeStr = strings.TrimSuffix(p, "px")
				break
			}
		}
		// Fallback to first part if no px suffix found (old behavior)
		if sizeStr == "" && len(parts) > 0 {
			sizeStr = strings.TrimSuffix(parts[0], "px")
		}

		if size, err := strconv.ParseFloat(sizeStr, 64); err == nil {
			// Derive ascent, descent from the font size
			fontAscent = int16(math.Round(size * 0.8))
			fontDescent = int16(math.Round(size * 0.2))
		}
	}

	// Create a temporary off-screen canvas for font measurement
	canvas := w.document.Call("createElement", "canvas")
	ctx := canvas.Call("getContext", "2d")
	ctx.Set("font", cssFont)

	// Measure overall font metrics using a dummy character (e.g., 'M')
	overallMetrics := ctx.Call("measureText", "M")
	if !overallMetrics.Get("fontBoundingBoxAscent").IsUndefined() {
		fontAscent = int16(math.Round(overallMetrics.Get("fontBoundingBoxAscent").Float()))
	}
	if !overallMetrics.Get("fontBoundingBoxDescent").IsUndefined() {
		fontDescent = int16(math.Round(overallMetrics.Get("fontBoundingBoxDescent").Float()))
	}
	if fontAscent <= 0 {
		fontAscent = 1
	}
	if fontDescent <= 0 {
		fontDescent = 1
	}

	// Measure metrics for a space character to initialize min/max bounds
	spaceMetrics := ctx.Call("measureText", " ")
	initialCharWidth := uint16(math.Round(spaceMetrics.Get("width").Float()))
	initialAscent := int16(math.Round(spaceMetrics.Get("actualBoundingBoxAscent").Float()))
	initialDescent := int16(math.Round(spaceMetrics.Get("actualBoundingBoxDescent").Float()))
	initialLSB := int16(math.Round(spaceMetrics.Get("actualBoundingBoxLeft").Float()))
	initialRSB := int16(math.Round(spaceMetrics.Get("actualBoundingBoxRight").Float()))

	minBounds = wire.XCharInfo{
		LeftSideBearing:  initialLSB,
		RightSideBearing: initialRSB,
		CharacterWidth:   initialCharWidth,
		Ascent:           initialAscent,
		Descent:          initialDescent,
	}
	maxBounds = wire.XCharInfo{
		LeftSideBearing:  initialLSB,
		RightSideBearing: initialRSB,
		CharacterWidth:   initialCharWidth,
		Ascent:           initialAscent,
		Descent:          initialDescent,
	}

	minCharOrByte2 = 0
	maxCharOrByte2 = 255 // ASCII range
	defaultChar = 0      // Will be set to ' ' (32) if not all chars exist
	drawDirection = 0    // LeftToRight
	minByte1 = 0
	maxByte1 = 0
	allCharsExist = true // Optimistic for the 0-255 range

	charInfos = make([]wire.XCharInfo, 256)
	for i := 0; i < 256; i++ {
		char := string([]byte{byte(i)})
		metrics := ctx.Call("measureText", char)
		width := uint16(math.Round(metrics.Get("width").Float()))
		ascent := int16(math.Round(metrics.Get("actualBoundingBoxAscent").Float()))
		descent := int16(math.Round(metrics.Get("actualBoundingBoxDescent").Float()))
		lsb := int16(math.Round(metrics.Get("actualBoundingBoxLeft").Float()))
		rsb := int16(math.Round(metrics.Get("actualBoundingBoxRight").Float()))

		charInfos[i] = wire.XCharInfo{
			LeftSideBearing:  -lsb, // X11 LSB is distance from origin to left edge, usually negative if to the left
			RightSideBearing: rsb,
			CharacterWidth:   width,
			Ascent:           ascent,
			Descent:          descent,
		}

		if i == 0 {
			minBounds = charInfos[i]
			maxBounds = charInfos[i]
		} else {
			if charInfos[i].LeftSideBearing < minBounds.LeftSideBearing {
				minBounds.LeftSideBearing = charInfos[i].LeftSideBearing
			}
			if charInfos[i].RightSideBearing > maxBounds.RightSideBearing {
				maxBounds.RightSideBearing = charInfos[i].RightSideBearing
			}
			if charInfos[i].CharacterWidth < minBounds.CharacterWidth {
				minBounds.CharacterWidth = charInfos[i].CharacterWidth
			}
			if charInfos[i].CharacterWidth > maxBounds.CharacterWidth {
				maxBounds.CharacterWidth = charInfos[i].CharacterWidth
			}
			if charInfos[i].Ascent > maxBounds.Ascent {
				maxBounds.Ascent = charInfos[i].Ascent
			}
			if charInfos[i].Descent > maxBounds.Descent {
				maxBounds.Descent = charInfos[i].Descent
			}
		}
	}
	minByte1 = 0
	maxByte1 = 0
	allCharsExist = true // Assume true, set to false if any char has 0 width

	charInfos = make([]wire.XCharInfo, maxCharOrByte2-minCharOrByte2+1)

	for i := minCharOrByte2; i <= maxCharOrByte2; i++ {
		char := string(rune(i))
		metrics := ctx.Call("measureText", char)

		var charLSB, charRSB int16
		var charWidth uint16
		var charAscent, charDescent int16

		// Use actualBoundingBox properties for more accurate metrics
		if !metrics.Get("actualBoundingBoxLeft").IsUndefined() {
			charLSB = int16(math.Round(metrics.Get("actualBoundingBoxLeft").Float()))
		}
		if !metrics.Get("actualBoundingBoxRight").IsUndefined() {
			charRSB = int16(math.Round(metrics.Get("actualBoundingBoxRight").Float()))
		}
		if !metrics.Get("width").IsUndefined() {
			charWidth = uint16(math.Round(metrics.Get("width").Float()))
			if charWidth == 0 { // Ensure minimum width
				charWidth = 1
				if i != 0 { // If it's not the null character, and width is 0, then it doesn't exist
					allCharsExist = false
				}
			}
		} else {
			charWidth = 1 // Default to 1 if width is undefined
			if i != 0 {
				allCharsExist = false
			}
		}

		if !metrics.Get("actualBoundingBoxAscent").IsUndefined() {
			charAscent = int16(math.Round(math.Abs(metrics.Get("actualBoundingBoxAscent").Float())))
		} else {
			charAscent = fontAscent // Fallback to overall font ascent
		}
		if !metrics.Get("actualBoundingBoxDescent").IsUndefined() {
			charDescent = int16(math.Round(math.Abs(metrics.Get("actualBoundingBoxDescent").Float())))
		} else {
			charDescent = fontDescent // Fallback to overall font descent
		}

		// Ensure ascent and descent are at least 1
		if charAscent <= 0 {
			charAscent = 1
		}
		if charDescent <= 0 {
			charDescent = 1
		}

		ci := wire.XCharInfo{
			LeftSideBearing:  charLSB,
			RightSideBearing: charRSB,
			CharacterWidth:   charWidth,
			Ascent:           charAscent,
			Descent:          charDescent,
			Attributes:       0,
		}
		charInfos[i] = ci

		// Update minBounds
		if ci.LeftSideBearing < minBounds.LeftSideBearing {
			minBounds.LeftSideBearing = ci.LeftSideBearing
		}
		if ci.RightSideBearing < minBounds.RightSideBearing {
			minBounds.RightSideBearing = ci.RightSideBearing
		}
		if ci.CharacterWidth < minBounds.CharacterWidth {
			minBounds.CharacterWidth = ci.CharacterWidth
		}
		if ci.Ascent < minBounds.Ascent {
			minBounds.Ascent = ci.Ascent
		}
		if ci.Descent < minBounds.Descent {
			minBounds.Descent = ci.Descent
		}

		// Update maxBounds
		if ci.LeftSideBearing > maxBounds.LeftSideBearing {
			maxBounds.LeftSideBearing = ci.LeftSideBearing
		}
		if ci.RightSideBearing > maxBounds.RightSideBearing {
			maxBounds.RightSideBearing = ci.RightSideBearing
		}
		if ci.CharacterWidth > maxBounds.CharacterWidth {
			maxBounds.CharacterWidth = ci.CharacterWidth
		}
		if ci.Ascent > maxBounds.Ascent {
			maxBounds.Ascent = ci.Ascent
		}
		if ci.Descent > maxBounds.Descent {
			maxBounds.Descent = ci.Descent
		}
	}

	// Ensure minBounds ascent and descent are at least 1
	if minBounds.Ascent <= 0 {
		minBounds.Ascent = 1
	}
	if minBounds.Descent <= 0 {
		minBounds.Descent = 1
	}

	if !allCharsExist {
		defaultChar = 32 // Set defaultChar to space if not all characters exist
	}

	// Release the temporary canvas element
	canvas.Call("remove")

	debugf("X11: QueryFont fid=%d reply: minBounds=%+v, maxBounds=%+v, minCharOrByte2=%d, maxCharOrByte2=%d, defaultChar=%d, drawDirection=%d, minByte1=%d, maxByte1=%d, allCharsExist=%t, fontAscent=%d, fontDescent=%d, len(charInfos)=%d", fid, minBounds, maxBounds, minCharOrByte2, maxCharOrByte2, defaultChar, drawDirection, minByte1, maxByte1, allCharsExist, fontAscent, fontDescent, len(charInfos))

	return
}

func (w *wasmX11Frontend) QueryTextExtents(font xID, text []uint16) (drawDirection uint8, fontAscent, fontDescent, overallAscent, overallDescent, overallWidth, overallLeft, overallRight int16) {
	w.recordOperation(CanvasOperation{
		Type: "queryTextExtents",
		Args: []any{uint32(font), text},
	})
	debugf("X11: QueryTextExtents font=%d", font)

	// Try to get font info from the opened fonts map
	var cssFont string = "12px monospace" // Default fallback
	if f, ok := w.fonts[font]; ok {
		cssFont = f.cssFont
	}

	// Create a temporary off-screen canvas for font measurement
	canvas := w.document.Call("createElement", "canvas")
	ctx := canvas.Call("getContext", "2d")
	ctx.Set("font", cssFont)

	// Convert text from []uint16 to a string
	var b strings.Builder
	for _, r := range text {
		b.WriteRune(rune(r))
	}
	textStr := b.String()

	metrics := ctx.Call("measureText", textStr)

	// Use actualBoundingBox properties for more accurate metrics
	if !metrics.Get("actualBoundingBoxLeft").IsUndefined() {
		overallLeft = int16(math.Round(metrics.Get("actualBoundingBoxLeft").Float()))
	}
	if !metrics.Get("actualBoundingBoxRight").IsUndefined() {
		overallRight = int16(math.Round(metrics.Get("actualBoundingBoxRight").Float()))
	}
	if !metrics.Get("width").IsUndefined() {
		overallWidth = int16(math.Round(metrics.Get("width").Float()))
	}
	if !metrics.Get("actualBoundingBoxAscent").IsUndefined() {
		overallAscent = int16(math.Round(metrics.Get("actualBoundingBoxAscent").Float()))
	}
	if !metrics.Get("actualBoundingBoxDescent").IsUndefined() {
		overallDescent = int16(math.Round(metrics.Get("actualBoundingBoxDescent").Float()))
	}

	// Get overall font ascent/descent from the font info
	if !metrics.Get("fontBoundingBoxAscent").IsUndefined() {
		fontAscent = int16(math.Round(metrics.Get("fontBoundingBoxAscent").Float()))
	}
	if !metrics.Get("fontBoundingBoxDescent").IsUndefined() {
		fontDescent = int16(math.Round(metrics.Get("fontBoundingBoxDescent").Float()))
	}

	drawDirection = 0 // LeftToRight

	// Release the temporary canvas element
	canvas.Call("remove")

	debugf("X11: QueryTextExtents font=%d reply: fontAscent=%d, fontDescent=%d, overallAscent=%d, overallDescent=%d, overallWidth=%d, overallLeft=%d, overallRight=%d", font, fontAscent, fontDescent, overallAscent, overallDescent, overallWidth, overallLeft, overallRight)

	return
}

func (w *wasmX11Frontend) ListFonts(maxNames uint16, pattern string) []string {
	debugf("X11: ListFonts maxNames=%d pattern=%s", maxNames, pattern)

	// Simplified implementation: return a hardcoded list of fonts.
	// In a real implementation, this would query available fonts.
	// The pattern matching is also simplified.

	var matchingFonts []string

	availableFonts := GetAvailableFonts()

	for _, font := range availableFonts {
		if strings.Contains(font, pattern) || pattern == "*" || pattern == "" {
			matchingFonts = append(matchingFonts, font)
			if len(matchingFonts) >= int(maxNames) && maxNames != 0 {
				break
			}
		}
	}

	w.recordOperation(CanvasOperation{
		Type: "listFonts",
		Args: []any{maxNames, pattern},
	})

	return matchingFonts
}

func (w *wasmX11Frontend) GetWindowAttributes(xid xID) wire.WindowAttributes {
	// Not implemented for wasm
	w.recordOperation(CanvasOperation{
		Type: "getWindowAttributes",
		Args: []any{uint32(xid)},
	})
	return wire.WindowAttributes{}
}

func (w *wasmX11Frontend) watchWindowEvents(xid xID, values wire.WindowAttributes) {
	winInfo, ok := w.windows[xid]
	if !ok {
		return
	}

	// XInput keyboard events
	if values.EventMask&(wire.DeviceKeyPressMask|wire.DeviceKeyReleaseMask) != 0 {
		if _, ok := winInfo.xInputEvents["keydown"]; !ok {
			fn := w.keyboardEventHandler(xid, "keydown")
			winInfo.xInputEvents["keydown"] = fn
			winInfo.canvas.Call("addEventListener", "keydown", fn)
		}
		if _, ok := winInfo.xInputEvents["keyup"]; !ok {
			fn := w.keyboardEventHandler(xid, "keyup")
			winInfo.xInputEvents["keyup"] = fn
			winInfo.canvas.Call("addEventListener", "keyup", fn)
		}
	} else {
		if fn, ok := winInfo.xInputEvents["keydown"]; ok {
			winInfo.canvas.Call("removeEventListener", "keydown", fn)
			delete(winInfo.xInputEvents, "keydown")
		}
		if fn, ok := winInfo.xInputEvents["keyup"]; ok {
			winInfo.canvas.Call("removeEventListener", "keyup", fn)
			delete(winInfo.xInputEvents, "keyup")
		}
	}

	// XInput mouse events
	if values.EventMask&wire.DeviceButtonPressMask != 0 {
		if _, ok := winInfo.xInputEvents["mousedown"]; !ok {
			fn := w.mouseEventHandler(xid, "mousedown")
			winInfo.xInputEvents["mousedown"] = fn
			winInfo.canvas.Call("addEventListener", "mousedown", fn)
		}
	} else {
		if fn, ok := winInfo.xInputEvents["mousedown"]; ok {
			winInfo.canvas.Call("removeEventListener", "mousedown", fn)
			delete(winInfo.xInputEvents, "mousedown")
		}
	}
	if values.EventMask&wire.DeviceButtonReleaseMask != 0 {
		if _, ok := winInfo.xInputEvents["mouseup"]; !ok {
			fn := w.mouseEventHandler(xid, "mouseup")
			winInfo.xInputEvents["mouseup"] = fn
			winInfo.canvas.Call("addEventListener", "mouseup", fn)
		}
	} else {
		if fn, ok := winInfo.xInputEvents["mouseup"]; ok {
			winInfo.canvas.Call("removeEventListener", "mouseup", fn)
			delete(winInfo.xInputEvents, "mouseup")
		}
	}
}

func (w *wasmX11Frontend) ChangeWindowAttributes(xid xID, valueMask uint32, values wire.WindowAttributes) {
	debugf("X11: changeWindowAttributes id=%d valueMask=%d values=%+v", xid, valueMask, values)
	if winInfo, ok := w.windows[xid]; ok {
		style := winInfo.div.Get("style")
		if valueMask&wire.CWColormap != 0 {
			winInfo.colormap = xID(values.Colormap)
		}
		if valueMask&wire.CWBackPixel != 0 {
			r, g, b := w.GetRGBColor(winInfo.colormap, values.BackgroundPixel)
			bgColor := fmt.Sprintf("rgb(%d, %d, %d)", r, g, b)
			style.Set("backgroundColor", bgColor)
		}
		if valueMask&wire.CWBorderPixel != 0 {
			r, g, b := w.GetRGBColor(winInfo.colormap, values.BorderPixel)
			borderColor := fmt.Sprintf("rgb(%d, %d, %d)", r, g, b)
			style.Set("borderColor", borderColor)
		}
		if valueMask&wire.CWCursor != 0 {
			w.SetWindowCursor(xid, xID(values.Cursor))
		}
		if valueMask&wire.CWEventMask != 0 {
			w.watchWindowEvents(xid, values)
		}
	}
	w.recordOperation(CanvasOperation{
		Type: "changeWindowAttributes",
		Args: []any{uint32(xid), valueMask},
	})
}

func uint32SliceToAnySlice(s []uint32) []any {
	anySlice := make([]any, len(s))
	for i, v := range s {
		anySlice[i] = v
	}
	return anySlice
}

func (w *wasmX11Frontend) DestroyAllWindowsForClient(client uint32) {
	for xid := range w.windows {
		if (uint32(xid)>>resourceIDShift)&clientIDMask == client {
			w.destroyWindow(xid, false)
		}
	}
}
