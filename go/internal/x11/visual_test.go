// MIT License
//
// Copyright (c) 2025 TTBT Enterprises LLC
// Copyright (c) 2025 Robin Thellend <rthellend@rthellend.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT of OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

//go:build x11 && wasm

package x11

import (
	"encoding/binary"
	"errors"
	"fmt"
	"image"
	"syscall/js"
	"testing"
	"time"

	"github.com/c2FmZQ/sshterm/internal/x11/wire"
)

func cleanupDOMElements(t *testing.T) {
	t.Helper()
	doc := js.Global().Get("document")
	if !doc.Truthy() {
		t.Fatal("document not found")
	}
	// Remove all elements with IDs starting with "x11-window-" or "x11-canvas-"
	selectors := []string{"#x11-window-", "#x11-canvas-"}
	for _, selector := range selectors {
		elements := doc.Call("querySelectorAll", fmt.Sprintf("[id^='%s']", selector))
		for i := 0; i < elements.Length(); i++ {
			elements.Index(i).Call("remove")
		}
	}
}

func getCanvasData(t *testing.T, s *x11Server, winID xID, x, y, w, h int) *image.RGBA {
	t.Helper()
	fe := s.frontend.(*wasmX11Frontend)
	winInfo, ok := fe.windows[winID]
	if !ok {
		t.Fatalf("window %d not found in frontend", winID)
	}
	ctx := winInfo.ctx
	if !ctx.Truthy() {
		t.Fatal("canvas context not found")
	}
	imgData := ctx.Call("getImageData", x, y, w, h).Get("data")
	if !imgData.Truthy() {
		t.Fatal("failed to get image data")
	}
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	js.CopyBytesToGo(img.Pix, imgData)
	return img
}

func getWindowBounds(t *testing.T, winID xID) image.Rectangle {
	t.Helper()
	doc := js.Global().Get("document")
	if !doc.Truthy() {
		t.Fatal("document not found")
	}
	div := doc.Call("querySelector", fmt.Sprintf("#x11-window-%s", winID))
	if !div.Truthy() {
		t.Fatalf("div #x11-window-%s not found", winID)
	}
	style := div.Get("style")
	if !style.Truthy() {
		t.Fatal("div style not found")
	}
	var x, y, w, h int
	fmt.Sscanf(style.Get("left").String(), "%dpx", &x)
	fmt.Sscanf(style.Get("top").String(), "%dpx", &y)
	fmt.Sscanf(style.Get("width").String(), "%dpx", &w)
	fmt.Sscanf(style.Get("height").String(), "%dpx", &h)
	return image.Rect(x, y, x+w, y+h)
}

func checkRectangle(img *image.RGBA, rect image.Rectangle, r, g, b uint8) error {
	for y := rect.Min.Y; y < rect.Max.Y; y++ {
		for x := rect.Min.X; x < rect.Max.X; x++ {
			got := img.RGBAAt(x, y)
			if got.R != r || got.G != g || got.B != b {
				return fmt.Errorf("at (%d, %d): got RGB %v,%v,%v want %v,%v,%v", x, y, got.R, got.G, got.B, r, g, b)
			}
		}
	}
	return nil
}

func checkWindow(got, want image.Rectangle) error {
	if got != want {
		return fmt.Errorf("got %v, want %v", got, want)
	}
	return nil
}

func poll(t *testing.T, f func() error) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		if err := f(); err == nil {
			return
		} else {
			lastErr = err
		}
		time.Sleep(100 * time.Millisecond)
	}
	if lastErr != nil {
		t.Fatal(lastErr)
	}
	t.Fatal("polling deadline exceeded")
}

func TestDrawRectangle(t *testing.T) {
	t.Log("Running TestDrawRectangle")
	t.Cleanup(func() { cleanupDOMElements(t) })
	setup := wire.NewDefaultSetup(&wire.ServerConfig{
		ScreenWidth:  1024,
		ScreenHeight: 768,
		Vendor:       "test",
	})
	s := &x11Server{
		logger: &testLogger{t: t},
		windows: map[xID]*window{
			0: {
				children: []xID{},
			},
		},
		gcs:             make(map[xID]wire.GC),
		pixmaps:         make(map[xID]*pixmap),
		cursors:         make(map[xID]bool),
		selections:      make(map[uint32]*selectionOwner),
		properties:      make(map[xID]map[uint32]*property),
		colormaps:       make(map[xID]*colormap),
		clients:         make(map[uint32]*x11Client),
		byteOrder:       binary.LittleEndian,
		passiveGrabs:    make(map[xID][]*passiveGrab),
		blackPixel:      setup.Screens[0].BlackPixel,
		whitePixel:      setup.Screens[0].WhitePixel,
		defaultColormap: setup.Screens[0].DefaultColormap,
	}
	for _, d := range setup.Screens[0].Depths {
		for _, v := range d.Visuals {
			if v.Class == 4 { // TrueColor
				s.rootVisual = v
				break
			}
		}
	}
	s.initAtoms()
	fe := newX11Frontend(&testLogger{t: t}, s)
	s.frontend = fe

	winID := xID(1)
	s.windows[winID] = &window{xid: winID, parent: xID(s.rootWindowID()), width: 100, height: 80, mapped: true, eventMasks: make(map[uint32]uint32)}
	fe.CreateWindow(winID, xID(s.rootWindowID()), 10, 10, 100, 80, 24, 0, wire.WindowAttributes{})
	fe.MapWindow(winID)

	gcID := xID(2)
	fe.CreateGC(gcID, wire.GCForeground|wire.GCFunction, wire.GC{Foreground: s.blackPixel, Function: wire.FunctionCopy})

	fe.PolyFillRectangle(winID, gcID, []uint32{20, 20, 50, 40})
	fe.ComposeWindow(winID)

	poll(t, func() error {
		img := getCanvasData(t, s, winID, 20, 20, 50, 40)
		return checkRectangle(img, image.Rect(0, 0, 50, 40), 0, 0, 0)
	})
}

func TestColors(t *testing.T) {
	t.Log("Running TestColors")
	t.Cleanup(func() { cleanupDOMElements(t) })
	setup := wire.NewDefaultSetup(&wire.ServerConfig{
		ScreenWidth:  1024,
		ScreenHeight: 768,
		Vendor:       "test",
	})
	s := &x11Server{
		logger: &testLogger{t: t},
		windows: map[xID]*window{
			0: {
				children: []xID{},
			},
		},
		gcs:       make(map[xID]wire.GC),
		pixmaps:   make(map[xID]*pixmap),
		cursors:   make(map[xID]bool),
		colormaps: make(map[xID]*colormap),
		clients:   make(map[uint32]*x11Client),
		byteOrder: binary.LittleEndian,
		rootVisual: wire.VisualType{
			Class:           4, // TrueColor
			RedMask:         0x00ff0000,
			GreenMask:       0x0000ff00,
			BlueMask:        0x000000ff,
			BitsPerRGBValue: 8,
		},
		blackPixel:      setup.Screens[0].BlackPixel,
		whitePixel:      setup.Screens[0].WhitePixel,
		defaultColormap: setup.Screens[0].DefaultColormap,
	}
	s.colormaps[xID(s.defaultColormap)] = &colormap{
		pixels: map[uint32]wire.XColorItem{
			s.blackPixel: {Red: 0, Green: 0, Blue: 0},
			s.whitePixel: {Red: 0xffff, Green: 0xffff, Blue: 0xffff},
		},
	}
	fe := newX11Frontend(&testLogger{t: t}, s)
	s.frontend = fe

	winID := xID(1)
	s.windows[winID] = &window{xid: winID, parent: xID(s.rootWindowID()), width: 200, height: 200, mapped: true, eventMasks: make(map[uint32]uint32)}
	fe.CreateWindow(winID, xID(s.rootWindowID()), 10, 10, 200, 200, 24, 0, wire.WindowAttributes{})
	fe.MapWindow(winID)

	t.Run("DefaultColormap", func(t *testing.T) {
		gcID := xID(10)
		fe.CreateGC(gcID, wire.GCForeground|wire.GCFunction, wire.GC{Foreground: s.blackPixel, Function: wire.FunctionCopy})
		fe.PolyFillRectangle(winID, gcID, []uint32{10, 10, 20, 20})
		fe.ComposeWindow(winID)

		gcID2 := xID(11)
		fe.CreateGC(gcID2, wire.GCForeground|wire.GCFunction, wire.GC{Foreground: s.whitePixel, Function: wire.FunctionCopy})
		fe.PolyFillRectangle(winID, gcID2, []uint32{40, 10, 20, 20})
		fe.ComposeWindow(winID)

		poll(t, func() error {
			img := getCanvasData(t, s, winID, 10, 10, 20, 20)
			return checkRectangle(img, image.Rect(0, 0, 20, 20), 0, 0, 0)
		})
		poll(t, func() error {
			img := getCanvasData(t, s, winID, 40, 10, 20, 20)
			return checkRectangle(img, image.Rect(0, 0, 20, 20), 255, 255, 255)
		})
	})

	t.Run("CustomColormap", func(t *testing.T) {
		cmapID := xID(2)
		s.colormaps[cmapID] = &colormap{pixels: make(map[uint32]wire.XColorItem)}
		fe.ChangeWindowAttributes(winID, wire.CWColormap, wire.WindowAttributes{Colormap: wire.Colormap(cmapID)})

		pixel := uint32(0xff0000)
		s.colormaps[cmapID].pixels[pixel] = wire.XColorItem{Red: 0xff00, Green: 0, Blue: 0}

		gcID := xID(12)
		fe.CreateGC(gcID, wire.GCForeground|wire.GCFunction, wire.GC{Foreground: pixel, Function: wire.FunctionCopy})
		fe.PolyFillRectangle(winID, gcID, []uint32{70, 10, 20, 20})
		fe.ComposeWindow(winID)

		poll(t, func() error {
			img := getCanvasData(t, s, winID, 70, 10, 20, 20)
			return checkRectangle(img, image.Rect(0, 0, 20, 20), 255, 0, 0)
		})
	})

	t.Run("TrueColorDirect", func(t *testing.T) {
		pixel := uint32(0x0000ff) // Blue
		gcID := xID(13)
		fe.CreateGC(gcID, wire.GCForeground|wire.GCFunction, wire.GC{Foreground: pixel, Function: wire.FunctionCopy})
		fe.PolyFillRectangle(winID, gcID, []uint32{100, 10, 20, 20})
		fe.ComposeWindow(winID)

		poll(t, func() error {
			img := getCanvasData(t, s, winID, 100, 10, 20, 20)
			return checkRectangle(img, image.Rect(0, 0, 20, 20), 0, 0, 255)
		})
	})

	t.Run("UnallocatedColor", func(t *testing.T) {
		pixel := uint32(0x123456) // Some unallocated color
		gcID := xID(14)
		fe.CreateGC(gcID, wire.GCForeground|wire.GCFunction, wire.GC{Foreground: pixel, Function: wire.FunctionCopy})
		fe.PolyFillRectangle(winID, gcID, []uint32{130, 10, 20, 20})
		fe.ComposeWindow(winID)

		poll(t, func() error {
			// For a TrueColor visual, unallocated pixels are decoded directly
			// from the pixel value itself.
			img := getCanvasData(t, s, winID, 130, 10, 20, 20)
			return checkRectangle(img, image.Rect(0, 0, 20, 20), 0x12, 0x34, 0x56)
		})
	})
}

func checkTextDrawn(img *image.RGBA) error {
	bounds := img.Bounds()
	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			if _, _, _, a := img.At(x, y).RGBA(); a != 0 {
				return nil // Found a non-transparent pixel, assuming text is drawn
			}
		}
	}
	return errors.New("text not drawn")
}

func TestDrawText(t *testing.T) {
	t.Log("Running TestDrawText")
	t.Cleanup(func() { cleanupDOMElements(t) })
	setup := wire.NewDefaultSetup(&wire.ServerConfig{
		ScreenWidth:  1024,
		ScreenHeight: 768,
		Vendor:       "test",
	})
	s := &x11Server{
		logger:          &testLogger{t: t},
		windows:         make(map[xID]*window),
		gcs:             make(map[xID]wire.GC),
		pixmaps:         make(map[xID]*pixmap),
		cursors:         make(map[xID]bool),
		selections:      make(map[uint32]*selectionOwner),
		properties:      make(map[xID]map[uint32]*property),
		colormaps:       make(map[xID]*colormap),
		clients:         make(map[uint32]*x11Client),
		byteOrder:       binary.LittleEndian,
		passiveGrabs:    make(map[xID][]*passiveGrab),
		blackPixel:      setup.Screens[0].BlackPixel,
		whitePixel:      setup.Screens[0].WhitePixel,
		defaultColormap: setup.Screens[0].DefaultColormap,
	}
	for _, d := range setup.Screens[0].Depths {
		for _, v := range d.Visuals {
			if v.Class == 4 { // TrueColor
				s.rootVisual = v
				break
			}
		}
	}
	s.initAtoms()
	fe := newX11Frontend(&testLogger{t: t}, s)
	s.frontend = fe

	winID := xID(1)
	s.windows[winID] = &window{xid: winID, parent: xID(s.rootWindowID()), width: 100, height: 80, mapped: true, eventMasks: make(map[uint32]uint32)}
	fe.CreateWindow(winID, xID(s.rootWindowID()), 10, 10, 100, 80, 24, 0, wire.WindowAttributes{})
	fe.MapWindow(winID)

	gcID := xID(2)
	fe.CreateGC(gcID, wire.GCForeground|wire.GCFunction, wire.GC{Foreground: s.blackPixel, Function: wire.FunctionCopy})

	fe.PolyText8(winID, gcID, 20, 40, []wire.PolyTextItem{
		wire.PolyText8String{Str: []byte("Hello, world!")},
	})
	fe.ComposeWindow(winID)

	poll(t, func() error {
		img := getCanvasData(t, s, winID, 20, 30, 80, 20)
		return checkTextDrawn(img)
	})
}

func TestOverlappingWindows(t *testing.T) {
	t.Log("Running TestOverlappingWindows")
	t.Cleanup(func() { cleanupDOMElements(t) })
	setup := wire.NewDefaultSetup(&wire.ServerConfig{
		ScreenWidth:  1024,
		ScreenHeight: 768,
		Vendor:       "test",
	})
	s := &x11Server{
		logger:          &testLogger{t: t},
		windows:         make(map[xID]*window),
		gcs:             make(map[xID]wire.GC),
		pixmaps:         make(map[xID]*pixmap),
		cursors:         make(map[xID]bool),
		selections:      make(map[uint32]*selectionOwner),
		properties:      make(map[xID]map[uint32]*property),
		colormaps:       make(map[xID]*colormap),
		clients:         make(map[uint32]*x11Client),
		byteOrder:       binary.LittleEndian,
		passiveGrabs:    make(map[xID][]*passiveGrab),
		rootVisual:      setup.Screens[0].Depths[0].Visuals[0],
		blackPixel:      setup.Screens[0].BlackPixel,
		whitePixel:      setup.Screens[0].WhitePixel,
		defaultColormap: setup.Screens[0].DefaultColormap,
	}
	s.initAtoms()
	fe := newX11Frontend(&testLogger{t: t}, s)
	s.frontend = fe

	winID1 := xID(1)
	s.windows[winID1] = &window{xid: winID1, parent: xID(s.rootWindowID()), width: 100, height: 80, mapped: true, eventMasks: make(map[uint32]uint32)}
	fe.CreateWindow(winID1, xID(s.rootWindowID()), 10, 10, 100, 80, 24, 0, wire.WindowAttributes{})
	fe.MapWindow(winID1)

	gcID1 := xID(2)
	fe.CreateGC(gcID1, wire.GCForeground|wire.GCFunction, wire.GC{Foreground: s.blackPixel, Function: wire.FunctionCopy})
	fe.PolyFillRectangle(winID1, gcID1, []uint32{20, 20, 50, 40})
	fe.ComposeWindow(winID1)

	winID2 := xID(3)
	s.windows[winID2] = &window{xid: winID2, parent: xID(s.rootWindowID()), width: 100, height: 80, mapped: true, eventMasks: make(map[uint32]uint32)}
	fe.CreateWindow(winID2, xID(s.rootWindowID()), 30, 30, 100, 80, 24, 0, wire.WindowAttributes{})
	fe.MapWindow(winID2)

	gcID2 := xID(4)
	fe.CreateGC(gcID2, wire.GCForeground|wire.GCFunction, wire.GC{Foreground: s.blackPixel, Function: wire.FunctionCopy})
	fe.PolyFillRectangle(winID2, gcID2, []uint32{20, 20, 50, 40})
	fe.ComposeWindow(winID2)

	poll(t, func() error {
		return checkWindow(getWindowBounds(t, winID1), image.Rect(10, 10, 110, 110))
	})
	poll(t, func() error {
		img1 := getCanvasData(t, s, winID1, 20, 20, 50, 40)
		return checkRectangle(img1, image.Rect(0, 0, 50, 40), 0, 0, 0)
	})

	poll(t, func() error {
		return checkWindow(getWindowBounds(t, winID2), image.Rect(30, 30, 130, 130))
	})
	poll(t, func() error {
		img2 := getCanvasData(t, s, winID2, 20, 20, 50, 40)
		return checkRectangle(img2, image.Rect(0, 0, 50, 40), 0, 0, 0)
	})
}

func TestGCLogicalOperations(t *testing.T) {
	t.Log("Running TestGCLogicalOperations")

	setup := wire.NewDefaultSetup(&wire.ServerConfig{
		ScreenWidth:  1024,
		ScreenHeight: 768,
		Vendor:       "test",
	})
	s := &x11Server{
		logger:    &testLogger{t: t},
		windows:   make(map[xID]*window),
		gcs:       make(map[xID]wire.GC),
		pixmaps:   make(map[xID]*pixmap),
		cursors:   make(map[xID]bool),
		colormaps: make(map[xID]*colormap),
		clients:   make(map[uint32]*x11Client),
		byteOrder: binary.LittleEndian,
		rootVisual: wire.VisualType{
			Class:           4, // TrueColor
			RedMask:         0x00ff0000,
			GreenMask:       0x0000ff00,
			BlueMask:        0x000000ff,
			BitsPerRGBValue: 8,
		},
		blackPixel:      setup.Screens[0].BlackPixel,
		whitePixel:      setup.Screens[0].WhitePixel,
		defaultColormap: setup.Screens[0].DefaultColormap,
	}
	s.colormaps[xID(s.defaultColormap)] = &colormap{
		pixels: make(map[uint32]wire.XColorItem),
	}
	fe := newX11Frontend(&testLogger{t: t}, s)
	s.frontend = fe

	winID := xID(1)
	const (
		winWidth  = 1
		winHeight = 1
	)

	// Define source and destination colors with distinct RGB components
	srcR, srcG, srcB := uint32(0xAA), uint32(0x55), uint32(0xF0)
	dstR, dstG, dstB := uint32(0xCC), uint32(0x33), uint32(0x0F)

	src := (srcR << 16) | (srcG << 8) | srcB
	dst := (dstR << 16) | (dstG << 8) | dstB

	tests := []struct {
		name     string
		function uint32
		wantR    uint8
		wantG    uint8
		wantB    uint8
	}{
		{"Clear", wire.FunctionClear, 0, 0, 0},
		{"And", wire.FunctionAnd, uint8(srcR & dstR), uint8(srcG & dstG), uint8(srcB & dstB)},
		{"AndReverse", wire.FunctionAndReverse, uint8(srcR & (^dstR)), uint8(srcG & (^dstG)), uint8(srcB & (^dstB))},
		{"Copy", wire.FunctionCopy, uint8(srcR), uint8(srcG), uint8(srcB)},
		{"AndInverted", wire.FunctionAndInverted, uint8((^srcR) & dstR), uint8((^srcG) & dstG), uint8((^srcB) & dstB)},
		{"NoOp", wire.FunctionNoOp, uint8(dstR), uint8(dstG), uint8(dstB)},
		{"Xor", wire.FunctionXor, uint8(srcR ^ dstR), uint8(srcG ^ dstG), uint8(srcB ^ dstB)},
		{"Or", wire.FunctionOr, uint8(srcR | dstR), uint8(srcG | dstG), uint8(srcB | dstB)},
		{"Nor", wire.FunctionNor, uint8(^(srcR | dstR)), uint8(^(srcG | dstG)), uint8(^(srcB | dstB))},
		{"Equiv", wire.FunctionEquiv, uint8(^(srcR ^ dstR)), uint8(^(srcG ^ dstG)), uint8(^(srcB ^ dstB))},
		{"Invert", wire.FunctionInvert, uint8(^dstR), uint8(^dstG), uint8(^dstB)},
		{"OrReverse", wire.FunctionOrReverse, uint8(srcR | (^dstR)), uint8(srcG | (^dstG)), uint8(srcB | (^dstB))},
		{"CopyInverted", wire.FunctionCopyInverted, uint8(^srcR), uint8(^srcG), uint8(^srcB)},
		{"OrInverted", wire.FunctionOrInverted, uint8((^srcR) | dstR), uint8((^srcG) | dstG), uint8((^srcB) | dstB)},
		{"Nand", wire.FunctionNand, uint8(^(srcR & dstR)), uint8(^(srcG & dstG)), uint8(^(srcB & dstB))},
		{"Set", wire.FunctionSet, 0xFF, 0xFF, 0xFF},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("Starting test case: %s", tc.name)
			t.Cleanup(func() { cleanupDOMElements(t) })
			s.windows[winID] = &window{xid: winID, parent: xID(s.rootWindowID()), width: winWidth, height: winHeight, mapped: true, eventMasks: make(map[uint32]uint32)}
			fe.CreateWindow(winID, xID(s.rootWindowID()), 10, 10, winWidth, winHeight, 24, 0, wire.WindowAttributes{})
			fe.MapWindow(winID)

			// 1. Fill window with destination color
			bgGCID := xID(100)
			fe.CreateGC(bgGCID, wire.GCForeground|wire.GCFunction, wire.GC{Foreground: dst, Function: wire.FunctionCopy, PlaneMask: 0xffffff})
			fe.PolyFillRectangle(winID, bgGCID, []uint32{0, 0, winWidth, winHeight})
			fe.ComposeWindow(winID)

			// 2. Create GC with logical operation and draw with source color
			fgGCID := xID(200)
			fe.CreateGC(fgGCID, wire.GCForeground|wire.GCFunction|wire.GCPlaneMask, wire.GC{Foreground: src, Function: tc.function, PlaneMask: 0xffffff})
			fe.PolyFillRectangle(winID, fgGCID, []uint32{0, 0, 1, 1})
			fe.ComposeWindow(winID)

			// 3. Verify the result
			poll(t, func() error {
				img := getCanvasData(t, s, winID, 0, 0, winWidth, winHeight)
				return checkRectangle(img, image.Rect(0, 0, 1, 1), tc.wantR, tc.wantG, tc.wantB)
			})
			t.Logf("Finished test case: %s", tc.name)
		})
	}
}

func TestOptimizedGXxor(t *testing.T) {
	t.Log("Running TestOptimizedGXxor")
	t.Cleanup(func() { cleanupDOMElements(t) })

	setup := wire.NewDefaultSetup(&wire.ServerConfig{
		ScreenWidth:  1024,
		ScreenHeight: 768,
		Vendor:       "test",
	})
	s := &x11Server{
		logger:    &testLogger{t: t},
		windows:   make(map[xID]*window),
		gcs:       make(map[xID]wire.GC),
		pixmaps:   make(map[xID]*pixmap),
		cursors:   make(map[xID]bool),
		colormaps: make(map[xID]*colormap),
		clients:   make(map[uint32]*x11Client),
		byteOrder: binary.LittleEndian,
		rootVisual: wire.VisualType{
			Class:           4, // TrueColor
			RedMask:         0x00ff0000,
			GreenMask:       0x0000ff00,
			BlueMask:        0x000000ff,
			BitsPerRGBValue: 8,
		},
		blackPixel:      setup.Screens[0].BlackPixel,
		whitePixel:      setup.Screens[0].WhitePixel,
		defaultColormap: setup.Screens[0].DefaultColormap,
	}
	s.colormaps[xID(s.defaultColormap)] = &colormap{
		pixels: map[uint32]wire.XColorItem{
			s.whitePixel: {Red: 0xffff, Green: 0xffff, Blue: 0xffff},
		},
	}
	fe := newX11Frontend(&testLogger{t: t}, s)
	s.frontend = fe

	winID := xID(1)
	const (
		winWidth  = 1
		winHeight = 1
	)
	s.windows[winID] = &window{xid: winID, parent: xID(s.rootWindowID()), width: winWidth, height: winHeight, mapped: true, eventMasks: make(map[uint32]uint32)}
	fe.CreateWindow(winID, xID(s.rootWindowID()), 10, 10, winWidth, winHeight, 24, 0, wire.WindowAttributes{})
	fe.MapWindow(winID)

	// Define destination color (arbitrary)
	dstR, dstG, dstB := uint32(0xCC), uint32(0x33), uint32(0x0F)
	dst := (dstR << 16) | (dstG << 8) | dstB

	// 1. Fill window with destination color
	bgGCID := xID(100)
	fe.CreateGC(bgGCID, wire.GCForeground|wire.GCFunction, wire.GC{Foreground: dst, Function: wire.FunctionCopy, PlaneMask: 0xffffff})
	fe.PolyFillRectangle(winID, bgGCID, []uint32{0, 0, winWidth, winHeight})
	fe.ComposeWindow(winID)

	// 2. Create GC with GXxor and WHITE source (triggering optimization)
	fgGCID := xID(200)
	fe.CreateGC(fgGCID, wire.GCForeground|wire.GCFunction|wire.GCPlaneMask, wire.GC{Foreground: s.whitePixel, Function: wire.FunctionXor, PlaneMask: 0xffffff})
	fe.PolyFillRectangle(winID, fgGCID, []uint32{0, 0, 1, 1})
	fe.ComposeWindow(winID)

	// 3. Verify result is inverted destination
	// ^dst & 0xFF for 8-bit components
	wantR := uint8(^dstR)
	wantG := uint8(^dstG)
	wantB := uint8(^dstB)

	poll(t, func() error {
		img := getCanvasData(t, s, winID, 0, 0, winWidth, winHeight)
		return checkRectangle(img, image.Rect(0, 0, 1, 1), wantR, wantG, wantB)
	})
}

func findVisualByClass(s *x11Server, class uint8) (uint32, bool) {
	for _, v := range s.visuals {
		if v.Class == class {
			return v.VisualID, true
		}
	}
	return 0, false
}

func TestVisualTypes(t *testing.T) {
	t.Log("Running TestVisualTypes")

	tests := []struct {
		name                string
		visualID            uint32
		class               uint8
		pixel               uint32
		wantR, wantG, wantB uint8
	}{
		{"StaticGray", 4, 0, 0x80, 0x80, 0x80, 0x80},
		{"GrayScale", 5, 1, 0x80, 0x80, 0x80, 0x80},
		{"StaticColor", 6, 2, 0xff0000, 255, 0, 0},
		{"PseudoColor", 7, 3, 0x00ff00, 0, 255, 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("Starting test case: %s", tc.name)
			t.Cleanup(func() { cleanupDOMElements(t) })

			setup := wire.NewDefaultSetup(&wire.ServerConfig{
				ScreenWidth:  1024,
				ScreenHeight: 768,
				Vendor:       "test",
			})
			s := &x11Server{
				logger:          &testLogger{t: t},
				windows:         make(map[xID]*window),
				gcs:             make(map[xID]wire.GC),
				pixmaps:         make(map[xID]*pixmap),
				cursors:         make(map[xID]bool),
				colormaps:       make(map[xID]*colormap),
				clients:         make(map[uint32]*x11Client),
				byteOrder:       binary.LittleEndian,
				blackPixel:      setup.Screens[0].BlackPixel,
				whitePixel:      setup.Screens[0].WhitePixel,
				defaultColormap: setup.Screens[0].DefaultColormap,
				visualID:        tc.visualID,
				config: wire.ServerConfig{
					Screens: setup.Screens,
				},
				visuals: make(map[uint32]wire.VisualType),
			}
			for _, screen := range setup.Screens {
				for _, depth := range screen.Depths {
					for _, visual := range depth.Visuals {
						visual.Depth = depth.Depth
						s.visuals[visual.VisualID] = visual
					}
				}
			}

			var ok bool
			s.rootVisual, ok = s.getVisualByID(tc.visualID)
			if !ok {
				for _, v := range s.visuals {
					t.Logf("Available visual: %+v", v)
				}
				t.Fatalf("visual %d not found", tc.visualID)
			}

			s.colormaps[xID(s.defaultColormap)] = &colormap{
				pixels: map[uint32]wire.XColorItem{
					0xff0000: {Red: 0xff00, Green: 0, Blue: 0},
					0x00ff00: {Red: 0, Green: 0xff00, Blue: 0},
				},
			}
			fe := newX11Frontend(&testLogger{t: t}, s)
			s.frontend = fe

			winID := xID(1)
			s.windows[winID] = &window{
				xid:        winID,
				parent:     xID(xID(s.rootWindowID())),
				width:      1,
				height:     1,
				mapped:     true,
				colormap:   xID(s.defaultColormap),
				eventMasks: make(map[uint32]uint32),
			}
			fe.CreateWindow(winID, xID(s.rootWindowID()), 10, 10, 1, 1, 24, wire.CWColormap, wire.WindowAttributes{Colormap: wire.Colormap(s.defaultColormap)})
			fe.MapWindow(winID)

			gcID := xID(2)
			fe.CreateGC(gcID, wire.GCForeground|wire.GCFunction, wire.GC{Foreground: tc.pixel, Function: wire.FunctionCopy})
			fe.PolyFillRectangle(winID, gcID, []uint32{0, 0, 1, 1})
			fe.ComposeWindow(winID)

			poll(t, func() error {
				img := getCanvasData(t, s, winID, 0, 0, 1, 1)
				return checkRectangle(img, image.Rect(0, 0, 1, 1), tc.wantR, tc.wantG, tc.wantB)
			})
			t.Logf("Finished test case: %s", tc.name)
		})
	}
}
