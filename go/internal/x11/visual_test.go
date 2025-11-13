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
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"image"
	"syscall/js"
	"testing"
	"time"
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
		t.Fatalf("window %s not found in frontend", winID)
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
	div := doc.Call("querySelector", fmt.Sprintf("#x11-window-%d-%d", winID.client, winID.local))
	if !div.Truthy() {
		t.Fatalf("div #x11-window-%d-%d not found", winID.client, winID.local)
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
	setup := newDefaultSetup()
	s := &x11Server{
		logger: &testLogger{t: t},
		windows: map[xID]*window{
			{local: 0}: {
				children: []uint32{},
			},
		},
		gcs:             make(map[xID]GC),
		pixmaps:         make(map[xID]bool),
		cursors:         make(map[xID]bool),
		selections:      make(map[xID]uint32),
		colormaps:       make(map[xID]*colormap),
		clients:         make(map[uint32]*x11Client),
		byteOrder:       binary.LittleEndian,
		passiveGrabs:    make(map[xID][]*passiveGrab),
		rootVisual:      setup.screens[0].depths[0].visuals[0],
		blackPixel:      setup.screens[0].blackPixel,
		whitePixel:      setup.screens[0].whitePixel,
		defaultColormap: setup.screens[0].defaultColormap,
	}
	fe := newX11Frontend(&testLogger{t: t}, s)
	s.frontend = fe

	winID := xID{client: 1, local: 1}
	fe.CreateWindow(winID, s.rootWindowID(), 10, 10, 100, 80, 24, 0, WindowAttributes{})
	fe.MapWindow(winID)

	gcID := xID{client: 1, local: 2}
	fe.CreateGC(gcID, GCForeground|GCFunction, GC{Foreground: s.blackPixel, Function: FunctionCopy})

	fe.PolyFillRectangle(winID, gcID, []uint32{20, 20, 50, 40})

	poll(t, func() error {
		img := getCanvasData(t, s, winID, 20, 20, 50, 40)
		return checkRectangle(img, image.Rect(0, 0, 50, 40), 0, 0, 0)
	})
}

func TestColors(t *testing.T) {
	t.Log("Running TestColors")
	t.Cleanup(func() { cleanupDOMElements(t) })
	setup := newDefaultSetup()
	s := &x11Server{
		logger: &testLogger{t: t},
		windows: map[xID]*window{
			{local: 0}: {
				children: []uint32{},
			},
		},
		gcs:       make(map[xID]GC),
		pixmaps:   make(map[xID]bool),
		cursors:   make(map[xID]bool),
		colormaps: make(map[xID]*colormap),
		clients:   make(map[uint32]*x11Client),
		byteOrder: binary.LittleEndian,
		rootVisual: visualType{
			class:           4, // TrueColor
			redMask:         0x00ff0000,
			greenMask:       0x0000ff00,
			blueMask:        0x000000ff,
			bitsPerRGBValue: 8,
		},
		blackPixel:      setup.screens[0].blackPixel,
		whitePixel:      setup.screens[0].whitePixel,
		defaultColormap: setup.screens[0].defaultColormap,
	}
	s.colormaps[xID{local: s.defaultColormap}] = &colormap{
		pixels: map[uint32]xColorItem{
			s.blackPixel: {Red: 0, Green: 0, Blue: 0},
			s.whitePixel: {Red: 0xffff, Green: 0xffff, Blue: 0xffff},
		},
	}
	fe := newX11Frontend(&testLogger{t: t}, s)
	s.frontend = fe

	winID := xID{client: 1, local: 1}
	fe.CreateWindow(winID, s.rootWindowID(), 10, 10, 200, 200, 24, 0, WindowAttributes{})
	fe.MapWindow(winID)

	t.Run("DefaultColormap", func(t *testing.T) {
		gcID := xID{client: 1, local: 10}
		fe.CreateGC(gcID, GCForeground|GCFunction, GC{Foreground: s.blackPixel, Function: FunctionCopy})
		fe.PolyFillRectangle(winID, gcID, []uint32{10, 10, 20, 20})

		gcID2 := xID{client: 1, local: 11}
		fe.CreateGC(gcID2, GCForeground|GCFunction, GC{Foreground: s.whitePixel, Function: FunctionCopy})
		fe.PolyFillRectangle(winID, gcID2, []uint32{40, 10, 20, 20})

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
		cmapID := xID{client: 1, local: 2}
		s.colormaps[cmapID] = &colormap{pixels: make(map[uint32]xColorItem)}
		fe.ChangeWindowAttributes(winID, CWColormap, WindowAttributes{Colormap: Colormap(cmapID.local)})

		pixel := uint32(0xff0000)
		s.colormaps[cmapID].pixels[pixel] = xColorItem{Red: 0xff00, Green: 0, Blue: 0}

		gcID := xID{client: 1, local: 12}
		fe.CreateGC(gcID, GCForeground|GCFunction, GC{Foreground: pixel, Function: FunctionCopy})
		fe.PolyFillRectangle(winID, gcID, []uint32{70, 10, 20, 20})

		poll(t, func() error {
			img := getCanvasData(t, s, winID, 70, 10, 20, 20)
			return checkRectangle(img, image.Rect(0, 0, 20, 20), 255, 0, 0)
		})
	})

	t.Run("TrueColorDirect", func(t *testing.T) {
		pixel := uint32(0x0000ff) // Blue
		gcID := xID{client: 1, local: 13}
		fe.CreateGC(gcID, GCForeground|GCFunction, GC{Foreground: pixel, Function: FunctionCopy})
		fe.PolyFillRectangle(winID, gcID, []uint32{100, 10, 20, 20})

		poll(t, func() error {
			img := getCanvasData(t, s, winID, 100, 10, 20, 20)
			return checkRectangle(img, image.Rect(0, 0, 20, 20), 0, 0, 255)
		})
	})

	t.Run("UnallocatedColor", func(t *testing.T) {
		pixel := uint32(0x123456) // Some unallocated color
		gcID := xID{client: 1, local: 14}
		fe.CreateGC(gcID, GCForeground|GCFunction, GC{Foreground: pixel, Function: FunctionCopy})
		fe.PolyFillRectangle(winID, gcID, []uint32{130, 10, 20, 20})

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
	setup := newDefaultSetup()
	s := &x11Server{
		logger:          &testLogger{t: t},
		windows:         make(map[xID]*window),
		gcs:             make(map[xID]GC),
		pixmaps:         make(map[xID]bool),
		cursors:         make(map[xID]bool),
		selections:      make(map[xID]uint32),
		colormaps:       make(map[xID]*colormap),
		clients:         make(map[uint32]*x11Client),
		byteOrder:       binary.LittleEndian,
		passiveGrabs:    make(map[xID][]*passiveGrab),
		rootVisual:      setup.screens[0].depths[0].visuals[0],
		blackPixel:      setup.screens[0].blackPixel,
		whitePixel:      setup.screens[0].whitePixel,
		defaultColormap: setup.screens[0].defaultColormap,
	}
	fe := newX11Frontend(&testLogger{t: t}, s)
	s.frontend = fe

	winID := xID{client: 1, local: 1}
	fe.CreateWindow(winID, s.rootWindowID(), 10, 10, 100, 80, 24, 0, WindowAttributes{})
	fe.MapWindow(winID)

	gcID := xID{client: 1, local: 2}
	fe.CreateGC(gcID, GCForeground|GCFunction, GC{Foreground: s.blackPixel, Function: FunctionCopy})

	fe.PolyText8(winID, gcID, 20, 40, []PolyTextItem{
		PolyText8String{Str: []byte("Hello, world!")},
	})

	poll(t, func() error {
		img := getCanvasData(t, s, winID, 20, 30, 80, 20)
		return checkTextDrawn(img)
	})
}

func TestOverlappingWindows(t *testing.T) {
	t.Log("Running TestOverlappingWindows")
	t.Cleanup(func() { cleanupDOMElements(t) })
	setup := newDefaultSetup()
	s := &x11Server{
		logger:          &testLogger{t: t},
		windows:         make(map[xID]*window),
		gcs:             make(map[xID]GC),
		pixmaps:         make(map[xID]bool),
		cursors:         make(map[xID]bool),
		selections:      make(map[xID]uint32),
		colormaps:       make(map[xID]*colormap),
		clients:         make(map[uint32]*x11Client),
		byteOrder:       binary.LittleEndian,
		passiveGrabs:    make(map[xID][]*passiveGrab),
		rootVisual:      setup.screens[0].depths[0].visuals[0],
		blackPixel:      setup.screens[0].blackPixel,
		whitePixel:      setup.screens[0].whitePixel,
		defaultColormap: setup.screens[0].defaultColormap,
	}
	fe := newX11Frontend(&testLogger{t: t}, s)
	s.frontend = fe

	winID1 := xID{client: 1, local: 1}
	fe.CreateWindow(winID1, s.rootWindowID(), 10, 10, 100, 80, 24, 0, WindowAttributes{})
	fe.MapWindow(winID1)

	gcID1 := xID{client: 1, local: 2}
	fe.CreateGC(gcID1, GCForeground|GCFunction, GC{Foreground: s.blackPixel, Function: FunctionCopy})
	fe.PolyFillRectangle(winID1, gcID1, []uint32{20, 20, 50, 40})

	winID2 := xID{client: 1, local: 3}
	fe.CreateWindow(winID2, s.rootWindowID(), 30, 30, 100, 80, 24, 0, WindowAttributes{})
	fe.MapWindow(winID2)

	gcID2 := xID{client: 1, local: 4}
	fe.CreateGC(gcID2, GCForeground|GCFunction, GC{Foreground: s.blackPixel, Function: FunctionCopy})
	fe.PolyFillRectangle(winID2, gcID2, []uint32{20, 20, 50, 40})

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

	setup := newDefaultSetup()
	s := &x11Server{
		logger:    &testLogger{t: t},
		windows:   make(map[xID]*window),
		gcs:       make(map[xID]GC),
		pixmaps:   make(map[xID]bool),
		cursors:   make(map[xID]bool),
		colormaps: make(map[xID]*colormap),
		clients:   make(map[uint32]*x11Client),
		byteOrder: binary.LittleEndian,
		rootVisual: visualType{
			class:           4, // TrueColor
			redMask:         0x00ff0000,
			greenMask:       0x0000ff00,
			blueMask:        0x000000ff,
			bitsPerRGBValue: 8,
		},
		blackPixel:      setup.screens[0].blackPixel,
		whitePixel:      setup.screens[0].whitePixel,
		defaultColormap: setup.screens[0].defaultColormap,
	}
	s.colormaps[xID{local: s.defaultColormap}] = &colormap{
		pixels: make(map[uint32]xColorItem),
	}
	fe := newX11Frontend(&testLogger{t: t}, s)
	s.frontend = fe

	winID := xID{client: 1, local: 1}
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
		{"Clear", FunctionClear, 0, 0, 0},
		{"And", FunctionAnd, uint8(srcR & dstR), uint8(srcG & dstG), uint8(srcB & dstB)},
		{"AndReverse", FunctionAndReverse, uint8(srcR & (^dstR)), uint8(srcG & (^dstG)), uint8(srcB & (^dstB))},
		{"Copy", FunctionCopy, uint8(srcR), uint8(srcG), uint8(srcB)},
		{"AndInverted", FunctionAndInverted, uint8((^srcR) & dstR), uint8((^srcG) & dstG), uint8((^srcB) & dstB)},
		{"NoOp", FunctionNoOp, uint8(dstR), uint8(dstG), uint8(dstB)},
		{"Xor", FunctionXor, uint8(srcR ^ dstR), uint8(srcG ^ dstG), uint8(srcB ^ dstB)},
		{"Or", FunctionOr, uint8(srcR | dstR), uint8(srcG | dstG), uint8(srcB | dstB)},
		{"Nor", FunctionNor, uint8(^(srcR | dstR)), uint8(^(srcG | dstG)), uint8(^(srcB | dstB))},
		{"Equiv", FunctionEquiv, uint8(^(srcR ^ dstR)), uint8(^(srcG ^ dstG)), uint8(^(srcB ^ dstB))},
		{"Invert", FunctionInvert, uint8(^dstR), uint8(^dstG), uint8(^dstB)},
		{"OrReverse", FunctionOrReverse, uint8(srcR | (^dstR)), uint8(srcG | (^dstG)), uint8(srcB | (^dstB))},
		{"CopyInverted", FunctionCopyInverted, uint8(^srcR), uint8(^srcG), uint8(^srcB)},
		{"OrInverted", FunctionOrInverted, uint8((^srcR) | dstR), uint8((^srcG) | dstG), uint8((^srcB) | dstB)},
		{"Nand", FunctionNand, uint8(^(srcR & dstR)), uint8(^(srcG & dstG)), uint8(^(srcB & dstB))},
		{"Set", FunctionSet, 0xFF, 0xFF, 0xFF},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("Starting test case: %s", tc.name)
			t.Cleanup(func() { cleanupDOMElements(t) })
			fe.CreateWindow(winID, s.rootWindowID(), 10, 10, winWidth, winHeight, 24, 0, WindowAttributes{})
			fe.MapWindow(winID)

			// 1. Fill window with destination color
			bgGCID := xID{client: 1, local: 100}
			fe.CreateGC(bgGCID, GCForeground|GCFunction, GC{Foreground: dst, Function: FunctionCopy, PlaneMask: 0xffffff})
			fe.PolyFillRectangle(winID, bgGCID, []uint32{0, 0, winWidth, winHeight})
			poll(t, func() error {
				img := getCanvasData(t, s, winID, 0, 0, winWidth, winHeight)
				return checkRectangle(img, image.Rect(0, 0, winWidth, winHeight), uint8(dstR), uint8(dstG), uint8(dstB))
			})

			// 2. Create GC with logical operation and draw with source color
			fgGCID := xID{client: 1, local: 200}
			fe.CreateGC(fgGCID, GCForeground|GCFunction|GCPlaneMask, GC{Foreground: src, Function: tc.function, PlaneMask: 0xffffff})
			fe.PolyFillRectangle(winID, fgGCID, []uint32{0, 0, 1, 1})

			// 3. Verify the result
			poll(t, func() error {
				img := getCanvasData(t, s, winID, 0, 0, winWidth, winHeight)
				return checkRectangle(img, image.Rect(0, 0, 1, 1), tc.wantR, tc.wantG, tc.wantB)
			})
			t.Logf("Finished test case: %s", tc.name)
		})
	}
}
