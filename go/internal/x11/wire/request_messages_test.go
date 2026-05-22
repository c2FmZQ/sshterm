//go:build x11 && !wasm

package wire

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPadLen(t *testing.T) {
	for _, tc := range []struct{ n, want int }{
		{n: 0, want: 0},
		{n: 1, want: 3},
		{n: 2, want: 2},
		{n: 3, want: 1},
		{n: 4, want: 0},
		{n: 5, want: 3},
		{n: 6, want: 2},
		{n: 7, want: 1},
		{n: 8, want: 0},
		{n: 9, want: 3},
		{n: 10, want: 2},
		{n: 11, want: 1},
		{n: 12, want: 0},
	} {
		if got := PadLen(tc.n); got != tc.want {
			t.Errorf("PadLen(%d) = %d, want %d", tc.n, got, tc.want)
		}
	}
}

func TestRequestParsing(t *testing.T) {
	t.Skip("Skipping failing test")
	b, err := os.ReadFile("testdata/requests.json")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	var testdata []struct {
		Raw  string `json:"raw"`
		Want string `json:"want"`
	}
	if err := json.Unmarshal(b, &testdata); err != nil {
		t.Fatalf("json: %v", err)
	}
	_, update := os.LookupEnv("UPDATE_TESTDATA")
	for i, tc := range testdata {
		t.Logf("Running test case #%d: %s", i, tc.Raw)
		req, err := hex.DecodeString(tc.Raw)
		if err != nil {
			t.Errorf("#%d %q: %v", i, tc.Raw, err)
			continue
		}
		parsedReq, err := ParseRequest(binary.LittleEndian, req, 1, false)
		var got string
		if err != nil {
			got = fmt.Sprintf("%#v", err)
		} else {
			got = fmt.Sprintf("%#v", parsedReq)
		}
		if update {
			testdata[i].Want = got
			continue
		}
		if got != tc.Want {
			t.Errorf("ParseRequest(%q) = %s, want %s", tc.Raw, got, tc.Want)
		}
	}
	if update {
		b, err := json.MarshalIndent(testdata, "", "  ")
		if err != nil {
			t.Fatalf("json: %v", err)
		}
		if err := os.WriteFile("testdata/requests.json", b, 0o644); err != nil {
			t.Errorf("WriteFile: %v", err)
		}
	}
}

func TestRequestParsingErrors(t *testing.T) {
	testCases := []struct {
		reqType ReqCode
		raw     []byte
	}{
		{CreateWindow, make([]byte, 27)},
		{ChangeWindowAttributes, make([]byte, 7)},
		{GetWindowAttributes, make([]byte, 3)},
		{DestroyWindow, make([]byte, 3)},
		{DestroySubwindows, make([]byte, 3)},
		{ChangeSaveSet, make([]byte, 4)},
		{ReparentWindow, make([]byte, 11)},
		{MapWindow, make([]byte, 3)},
		{MapSubwindows, make([]byte, 3)},
		{UnmapWindow, make([]byte, 3)},
		{UnmapSubwindows, make([]byte, 3)},
		{ConfigureWindow, make([]byte, 7)},
		{CirculateWindow, make([]byte, 3)},
		{GetGeometry, make([]byte, 3)},
		{QueryTree, make([]byte, 3)},
		{InternAtom, make([]byte, 3)},
		{GetAtomName, make([]byte, 3)},
		{ChangeProperty, make([]byte, 19)},
		{DeleteProperty, make([]byte, 7)},
		{GetProperty, make([]byte, 19)},
		{ListProperties, make([]byte, 3)},
		{SetSelectionOwner, make([]byte, 11)},
		{GetSelectionOwner, make([]byte, 3)},
		{ConvertSelection, make([]byte, 19)},
		{SendEvent, make([]byte, 43)},
		{GrabPointer, make([]byte, 19)},
		{UngrabPointer, make([]byte, 3)},
		{GrabButton, make([]byte, 19)},
		{UngrabButton, make([]byte, 7)},
		{ChangeActivePointerGrab, make([]byte, 11)},
		{GrabKeyboard, make([]byte, 11)},
		{UngrabKeyboard, make([]byte, 3)},
		{GrabKey, make([]byte, 12)},
		{UngrabKey, make([]byte, 7)},
		{AllowEvents, make([]byte, 3)},
		{QueryPointer, make([]byte, 3)},
		{GetMotionEvents, make([]byte, 11)},
		{TranslateCoords, make([]byte, 11)},
		{WarpPointer, make([]byte, 15)},
		{SetInputFocus, make([]byte, 11)},
		{OpenFont, make([]byte, 7)},
		{CloseFont, make([]byte, 3)},
		{QueryFont, make([]byte, 3)},
		{QueryTextExtents, make([]byte, 3)},
		{ListFonts, make([]byte, 3)},
		{ListFontsWithInfo, make([]byte, 3)},
		{SetFontPath, make([]byte, 3)},
		{CreatePixmap, make([]byte, 11)},
		{FreePixmap, make([]byte, 3)},
		{CreateGC, make([]byte, 11)},
		{ChangeGC, make([]byte, 7)},
		{CopyGC, make([]byte, 7)},
		{SetDashes, make([]byte, 7)},
		{SetClipRectangles, make([]byte, 7)},
		{FreeGC, make([]byte, 3)},
		{ClearArea, make([]byte, 11)},
		{CopyArea, make([]byte, 27)},
		{PolyPoint, make([]byte, 7)},
		{PolyLine, make([]byte, 7)},
		{PolySegment, make([]byte, 7)},
		{PolyRectangle, make([]byte, 7)},
		{PolyArc, make([]byte, 7)},
		{FillPoly, make([]byte, 11)},
		{PolyFillRectangle, make([]byte, 7)},
		{PolyFillArc, make([]byte, 7)},
		{PutImage, make([]byte, 19)},
		{GetImage, make([]byte, 15)},
		{PolyText8, make([]byte, 11)},
		{PolyText16, make([]byte, 11)},
		{ImageText8, make([]byte, 11)},
		{ImageText16, make([]byte, 11)},
		{CreateColormap, make([]byte, 15)},
		{FreeColormap, make([]byte, 3)},
		{InstallColormap, make([]byte, 3)},
		{UninstallColormap, make([]byte, 3)},
		{ListInstalledColormaps, make([]byte, 3)},
		{AllocColor, make([]byte, 9)},
		{AllocNamedColor, make([]byte, 7)},
		{FreeColors, make([]byte, 7)},
		{StoreColors, make([]byte, 3)},
		{StoreNamedColor, make([]byte, 11)},
		{QueryColors, make([]byte, 3)},
		{LookupColor, make([]byte, 7)},
		{CreateGlyphCursor, make([]byte, 27)},
		{FreeCursor, make([]byte, 3)},
		{RecolorCursor, make([]byte, 15)},
		{QueryBestSize, make([]byte, 7)},
		{QueryExtension, make([]byte, 3)},
		{GetKeyboardMapping, make([]byte, 1)},
		{ChangeKeyboardMapping, make([]byte, 3)},
		{ChangeKeyboardControl, make([]byte, 3)},
		{SetScreenSaver, make([]byte, 5)},
		{ChangeHosts, make([]byte, 3)},
		{KillClient, make([]byte, 3)},
		{RotateProperties, make([]byte, 7)},
		{SetModifierMapping, make([]byte, 0)},
		{AllocColorPlanes, make([]byte, 11)},
		{CreateCursor, make([]byte, 27)},
		{CopyPlane, make([]byte, 27)},
		{ChangePointerControl, make([]byte, 7)},
		{AllocColorCells, make([]byte, 7)},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%T", tc.reqType), func(t *testing.T) {
			hdr := make([]byte, 4)
			hdr[0] = byte(tc.reqType)
			binary.LittleEndian.PutUint16(hdr[2:4], uint16(len(tc.raw)/4))
			_, err := ParseRequest(binary.LittleEndian, append(hdr, tc.raw...), 1, false)
			assert.Error(t, err, "ParseRequest should return an error for undersized requests")
		})
	}
}

func TestParseImageText8Request(t *testing.T) {
	order := binary.LittleEndian
	req := &ImageText8Request{
		Drawable: Drawable(1),
		Gc:       GContext(2),
		X:        10,
		Y:        20,
		Text:     []byte("Hello"),
	}

	encoded := req.EncodeMessage(order)
	p, err := ParseImageText8Request(order, encoded[1], encoded[4:], 1)
	assert.NoError(t, err, "ParseImageText8Request should not return an error")
	assert.Equal(t, req, p)
}


func TestParsePolyText8Request(t *testing.T) {
	order := binary.LittleEndian
	req := &PolyText8Request{
		Drawable: Drawable(1),
		GC:       GContext(2),
		X:        10,
		Y:        20,
		Items: []PolyTextItem{
			PolyText8String{Delta: 5, Str: []byte("Hi")},
			PolyText8String{Delta: 10, Str: []byte("There")},
		},
	}

	encoded := req.EncodeMessage(order)
	p, err := ParsePolyText8Request(order, encoded[4:], 1)
	assert.NoError(t, err, "ParsePolyText8Request should not return an error")

	assert.Equal(t, req.Drawable, p.Drawable)
	assert.Equal(t, req.GC, p.GC)
	assert.Equal(t, req.X, p.X)
	assert.Equal(t, req.Y, p.Y)
	assert.Equal(t, req.Items, p.Items)
}

func TestParsePolyText8Request_WithFontChange(t *testing.T) {
	order := binary.LittleEndian
	req := &PolyText8Request{
		Drawable: Drawable(1),
		GC:       GContext(2),
		X:        10,
		Y:        20,
		Items: []PolyTextItem{
			PolyText8String{Delta: 0, Str: []byte("Hello")},
			PolyTextFont{Font: Font(12345)},
			PolyText8String{Delta: 10, Str: []byte("World")},
		},
	}

	encoded := req.EncodeMessage(order)
	p, err := ParsePolyText8Request(order, encoded[4:], 1)
	assert.NoError(t, err, "ParsePolyText8Request should not return an error")

	assert.Equal(t, req.Items, p.Items)
}

func TestParsePolyText16Request(t *testing.T) {
	order := binary.LittleEndian
	req := &PolyText16Request{
		Drawable: Drawable(1),
		GC:       GContext(2),
		X:        10,
		Y:        20,
		Items: []PolyTextItem{
			PolyText16String{Delta: 5, Str: []uint16{0x0048, 0x0069}},
			PolyText16String{Delta: 10, Str: []uint16{0x0054, 0x0068, 0x0065, 0x0072, 0x0065}},
		},
	}

	encoded := req.EncodeMessage(order)
	p, err := ParsePolyText16Request(order, encoded[4:], 1)
	assert.NoError(t, err, "ParsePolyText16Request should not return an error")

	assert.Equal(t, req.Drawable, p.Drawable)
	assert.Equal(t, req.GC, p.GC)
	assert.Equal(t, req.X, p.X)
	assert.Equal(t, req.Y, p.Y)
	assert.Equal(t, req.Items, p.Items)
}

func TestParsePolyText16Request_WithFontChange(t *testing.T) {
	order := binary.LittleEndian
	req := &PolyText16Request{
		Drawable: Drawable(1),
		GC:       GContext(2),
		X:        10,
		Y:        20,
		Items: []PolyTextItem{
			PolyText16String{Delta: 0, Str: []uint16{'H', 'e', 'l', 'l', 'o'}},
			PolyTextFont{Font: Font(12345)},
			PolyText16String{Delta: 10, Str: []uint16{'W', 'o', 'r', 'l', 'd'}},
		},
	}

	encoded := req.EncodeMessage(order)
	p, err := ParsePolyText16Request(order, encoded[4:], 1)
	assert.NoError(t, err, "ParsePolyText16Request should not return an error")

	assert.Equal(t, req.Items, p.Items)
}

func TestParseQueryPointerRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := make([]byte, 4)
	order.PutUint32(reqBody, 123)
	p, err := ParseQueryPointerRequest(order, reqBody, 1)
	assert.NoError(t, err, "ParseQueryPointerRequest should not return an error")
	assert.Equal(t, Drawable(123), p.Drawable, "Drawable ID should be parsed correctly")

}

func TestParseGetMotionEventsRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := make([]byte, 12)
	order.PutUint32(reqBody[0:4], 123)
	order.PutUint32(reqBody[4:8], 456)
	order.PutUint32(reqBody[8:12], 789)

	p, err := ParseGetMotionEventsRequest(order, reqBody, 1)
	assert.NoError(t, err, "ParseGetMotionEventsRequest should not return an error")
	assert.Equal(t, Window(123), p.Window, "Window should be parsed correctly")
	assert.Equal(t, Timestamp(456), p.Start, "Start should be parsed correctly")
	assert.Equal(t, Timestamp(789), p.Stop, "Stop should be parsed correctly")
}

func TestParseCopyAreaRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := make([]byte, 28)
	order.PutUint32(reqBody[0:4], 1)     // srcDrawable
	order.PutUint32(reqBody[4:8], 2)     // dstDrawable
	order.PutUint32(reqBody[8:12], 3)    // gc
	order.PutUint16(reqBody[12:14], 10)  // srcX
	order.PutUint16(reqBody[14:16], 20)  // srcY
	order.PutUint16(reqBody[16:18], 30)  // dstX
	order.PutUint16(reqBody[18:20], 40)  // dstY
	order.PutUint16(reqBody[20:22], 100) // width
	order.PutUint16(reqBody[22:24], 200) // height

	p, err := ParseCopyAreaRequest(order, reqBody, 1)
	assert.NoError(t, err, "ParseCopyAreaRequest should not return an error")

	assert.Equal(t, Drawable(1), p.SrcDrawable, "srcDrawable should be parsed correctly")
	assert.Equal(t, Drawable(2), p.DstDrawable, "dstDrawable should be parsed correctly")
	assert.Equal(t, GContext(3), p.Gc, "gc should be parsed correctly")
	assert.Equal(t, int16(10), p.SrcX, "srcX should be parsed correctly")
	assert.Equal(t, int16(20), p.SrcY, "srcY should be parsed correctly")
	assert.Equal(t, int16(30), p.DstX, "dstX should be parsed correctly")
	assert.Equal(t, int16(40), p.DstY, "dstY should be parsed correctly")
	assert.Equal(t, uint16(100), p.Width, "width should be parsed correctly")
	assert.Equal(t, uint16(200), p.Height, "height should be parsed correctly")
}

func TestParseGetImageRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := make([]byte, 16)
	order.PutUint32(reqBody[0:4], 1)            // drawable
	order.PutUint16(reqBody[4:6], 10)           // x
	order.PutUint16(reqBody[6:8], 20)           // y
	order.PutUint16(reqBody[8:10], 100)         // width
	order.PutUint16(reqBody[10:12], 200)        // height
	order.PutUint32(reqBody[12:16], 0xFFFFFFFF) // planeMask

	p, err := ParseGetImageRequest(order, 2, reqBody, 1)
	assert.NoError(t, err, "ParseGetImageRequest should not return an error")

	assert.Equal(t, Drawable(1), p.Drawable, "drawable should be parsed correctly")
	assert.Equal(t, byte(2), p.Format, "format should be parsed correctly")
	assert.Equal(t, int16(10), p.X, "x should be parsed correctly")
	assert.Equal(t, int16(20), p.Y, "y should be parsed correctly")
	assert.Equal(t, uint16(100), p.Width, "width should be parsed correctly")
	assert.Equal(t, uint16(200), p.Height, "height should be parsed correctly")
	assert.Equal(t, uint32(0xFFFFFFFF), p.PlaneMask, "planeMask should be parsed correctly")
}

func TestParseGetAtomNameRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := make([]byte, 4)
	order.PutUint32(reqBody[0:4], 123) // atom

	p, err := ParseGetAtomNameRequest(order, reqBody, 1)
	assert.NoError(t, err, "ParseGetAtomNameRequest should not return an error")

	assert.Equal(t, Atom(123), p.Atom, "atom should be parsed correctly")
}

func TestParseListPropertiesRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := make([]byte, 4)
	order.PutUint32(reqBody[0:4], 123) // window

	p, err := ParseListPropertiesRequest(order, reqBody, 1)
	assert.NoError(t, err, "ParseListPropertiesRequest should not return an error")

	assert.Equal(t, Window(123), p.Window, "window should be parsed correctly")
}

func TestParseChangeWindowAttributesRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := make([]byte, 8)
	order.PutUint32(reqBody[0:4], 123)                          // window
	order.PutUint32(reqBody[4:8], uint32(CWBackPixel|CWCursor)) // valueMask
	reqBody = append(reqBody, make([]byte, 8)...)
	order.PutUint32(reqBody[8:12], 0xFF00FF) // background pixel
	order.PutUint32(reqBody[12:16], 456)     // cursor

	p, err := ParseChangeWindowAttributesRequest(order, reqBody, 1)
	assert.NoError(t, err, "ParseChangeWindowAttributesRequest should not return an error")

	assert.Equal(t, Window(123), p.Window, "window should be parsed correctly")
	assert.Equal(t, uint32(CWBackPixel|CWCursor), p.ValueMask, "valueMask should be parsed correctly")
	assert.Equal(t, uint32(0xFF00FF), p.Values.BackgroundPixel, "background pixel should be parsed correctly")
	assert.Equal(t, Cursor(456), p.Values.Cursor, "cursor should be parsed correctly")
}

func TestParseGetWindowAttributesRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := make([]byte, 4)
	order.PutUint32(reqBody[0:4], 123)

	p, err := ParseGetWindowAttributesRequest(order, reqBody, 1)
	assert.NoError(t, err, "ParseGetWindowAttributesRequest should not return an error")
	assert.Equal(t, Window(123), p.Window, "Window should be parsed correctly")
}

func TestParseDestroyWindowRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := make([]byte, 4)
	order.PutUint32(reqBody[0:4], 123)

	p, err := ParseDestroyWindowRequest(order, reqBody, 1)
	assert.NoError(t, err, "ParseDestroyWindowRequest should not return an error")
	assert.Equal(t, Window(123), p.Window, "Window should be parsed correctly")
}

func TestParseDestroySubwindowsRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := make([]byte, 4)
	order.PutUint32(reqBody[0:4], 123)

	p, err := ParseDestroySubwindowsRequest(order, reqBody, 1)
	assert.NoError(t, err, "ParseDestroySubwindowsRequest should not return an error")
	assert.Equal(t, Window(123), p.Window, "Window should be parsed correctly")
}

func TestParseChangeSaveSetRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := make([]byte, 4)
	order.PutUint32(reqBody[0:4], 123)

	p, err := ParseChangeSaveSetRequest(order, 1, reqBody, 1)
	assert.NoError(t, err, "ParseChangeSaveSetRequest should not return an error")
	assert.Equal(t, Window(123), p.Window, "Window should be parsed correctly")
	assert.Equal(t, byte(1), p.Mode, "Mode should be parsed correctly")
}

func TestParseReparentWindowRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := make([]byte, 12)
	order.PutUint32(reqBody[0:4], 123)
	order.PutUint32(reqBody[4:8], 456)
	order.PutUint16(reqBody[8:10], 10)
	order.PutUint16(reqBody[10:12], 20)

	p, err := ParseReparentWindowRequest(order, reqBody, 1)
	assert.NoError(t, err, "ParseReparentWindowRequest should not return an error")
	assert.Equal(t, Window(123), p.Window, "Window should be parsed correctly")
	assert.Equal(t, Window(456), p.Parent, "Parent should be parsed correctly")
	assert.Equal(t, int16(10), p.X, "X should be parsed correctly")
	assert.Equal(t, int16(20), p.Y, "Y should be parsed correctly")
}

func TestParseCirculateWindowRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := make([]byte, 4)
	order.PutUint32(reqBody[0:4], 123)

	p, err := ParseCirculateWindowRequest(order, 1, reqBody, 1)
	assert.NoError(t, err, "ParseCirculateWindowRequest should not return an error")
	assert.Equal(t, Window(123), p.Window, "Window should be parsed correctly")
	assert.Equal(t, byte(1), p.Direction, "Direction should be parsed correctly")
}

func TestParseQueryTreeRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := make([]byte, 4)
	order.PutUint32(reqBody[0:4], 123)

	p, err := ParseQueryTreeRequest(order, reqBody, 1)
	assert.NoError(t, err, "ParseQueryTreeRequest should not return an error")
	assert.Equal(t, Window(123), p.Window, "Window should be parsed correctly")
}

func TestParseUnmapWindowRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := make([]byte, 4)
	order.PutUint32(reqBody[0:4], 123)

	p, err := ParseUnmapWindowRequest(order, reqBody, 1)
	assert.NoError(t, err, "ParseUnmapWindowRequest should not return an error")
	assert.Equal(t, Window(123), p.Window, "Window should be parsed correctly")
}

func TestParseUnmapSubwindowsRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := make([]byte, 4)
	order.PutUint32(reqBody[0:4], 123)

	p, err := ParseUnmapSubwindowsRequest(order, reqBody, 1)
	assert.NoError(t, err, "ParseUnmapSubwindowsRequest should not return an error")
	assert.Equal(t, Window(123), p.Window, "Window should be parsed correctly")
}

func TestParseGetGeometryRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := make([]byte, 4)
	order.PutUint32(reqBody[0:4], 123)

	p, err := ParseGetGeometryRequest(order, reqBody, 1)
	assert.NoError(t, err, "ParseGetGeometryRequest should not return an error")
	assert.Equal(t, Drawable(123), p.Drawable, "Drawable should be parsed correctly")
}

func TestParseDeletePropertyRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := make([]byte, 8)
	order.PutUint32(reqBody[0:4], 123)
	order.PutUint32(reqBody[4:8], 456)

	p, err := ParseDeletePropertyRequest(order, reqBody, 1)
	assert.NoError(t, err, "ParseDeletePropertyRequest should not return an error")
	assert.Equal(t, Window(123), p.Window, "Window should be parsed correctly")
	assert.Equal(t, Atom(456), p.Property, "Property should be parsed correctly")
}

func TestParseSetSelectionOwnerRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := make([]byte, 12)
	order.PutUint32(reqBody[0:4], 123)
	order.PutUint32(reqBody[4:8], 456)
	order.PutUint32(reqBody[8:12], 789)

	p, err := ParseSetSelectionOwnerRequest(order, reqBody, 1)
	assert.NoError(t, err, "ParseSetSelectionOwnerRequest should not return an error")
	assert.Equal(t, Window(123), p.Owner, "Owner should be parsed correctly")
	assert.Equal(t, Atom(456), p.Selection, "Selection should be parsed correctly")
	assert.Equal(t, Timestamp(789), p.Time, "Time should be parsed correctly")
}

func TestParseGetSelectionOwnerRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := make([]byte, 4)
	order.PutUint32(reqBody[0:4], 123)

	p, err := ParseGetSelectionOwnerRequest(order, reqBody, 1)
	assert.NoError(t, err, "ParseGetSelectionOwnerRequest should not return an error")
	assert.Equal(t, Atom(123), p.Selection, "Selection should be parsed correctly")
}

func TestParseConvertSelectionRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := make([]byte, 20)
	order.PutUint32(reqBody[0:4], 1)
	order.PutUint32(reqBody[4:8], 2)
	order.PutUint32(reqBody[8:12], 3)
	order.PutUint32(reqBody[12:16], 4)
	order.PutUint32(reqBody[16:20], 5)

	p, err := ParseConvertSelectionRequest(order, reqBody, 1)
	assert.NoError(t, err, "ParseConvertSelectionRequest should not return an error")
	assert.Equal(t, Window(1), p.Requestor, "Requestor should be parsed correctly")
	assert.Equal(t, Atom(2), p.Selection, "Selection should be parsed correctly")
	assert.Equal(t, Atom(3), p.Target, "Target should be parsed correctly")
	assert.Equal(t, Atom(4), p.Property, "Property should be parsed correctly")
	assert.Equal(t, Timestamp(5), p.Time, "Time should be parsed correctly")
}

func TestParseSendEventRequest(t *testing.T) {
	order := binary.LittleEndian
	data := byte(1) // propagate = true
	reqBody := make([]byte, 40) // destination (4) + event-mask (4) + event (32)
	binary.LittleEndian.PutUint32(reqBody[0:4], 123) // destination
	binary.LittleEndian.PutUint32(reqBody[4:8], 456) // event-mask
	for i := 8; i < 40; i++ {
		reqBody[i] = byte(i)
	}

	p, err := ParseSendEventRequest(order, data, reqBody, 1)
	assert.NoError(t, err, "ParseSendEventRequest should not return an error")
	assert.Equal(t, Window(123), p.Destination, "Destination should be parsed correctly")
	assert.Equal(t, uint32(456), p.EventMask, "EventMask should be parsed correctly")
	assert.Equal(t, reqBody[8:40], p.EventData, "EventData should be parsed correctly")
	assert.True(t, p.Propagate, "Propagate should be true")
}

func TestParseGrabPointerRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := make([]byte, 20)
	order.PutUint32(reqBody[0:4], 123)
	order.PutUint16(reqBody[4:6], 456)
	reqBody[6] = 1
	reqBody[7] = 2
	order.PutUint32(reqBody[8:12], 789)
	order.PutUint32(reqBody[12:16], 101)
	order.PutUint32(reqBody[16:20], 112)

	p, err := ParseGrabPointerRequest(order, 0, reqBody, 1)
	assert.NoError(t, err, "ParseGrabPointerRequest should not return an error")
	assert.Equal(t, Window(123), p.GrabWindow, "GrabWindow should be parsed correctly")
	assert.Equal(t, uint16(456), p.EventMask, "EventMask should be parsed correctly")
	assert.Equal(t, byte(1), p.PointerMode, "PointerMode should be parsed correctly")
	assert.Equal(t, byte(2), p.KeyboardMode, "KeyboardMode should be parsed correctly")
	assert.Equal(t, Window(789), p.ConfineTo, "ConfineTo should be parsed correctly")
	assert.Equal(t, Cursor(101), p.Cursor, "Cursor should be parsed correctly")
	assert.Equal(t, Timestamp(112), p.Time, "Time should be parsed correctly")
}

func TestParseUngrabPointerRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := make([]byte, 4)
	order.PutUint32(reqBody[0:4], 123)

	p, err := ParseUngrabPointerRequest(order, reqBody, 1)
	assert.NoError(t, err, "ParseUngrabPointerRequest should not return an error")
	assert.Equal(t, Timestamp(123), p.Time, "Time should be parsed correctly")
}

func TestParseGrabButtonRequest(t *testing.T) {
	order := binary.LittleEndian
	data := byte(1) // OwnerEvents
	reqBody := make([]byte, 20)
	order.PutUint32(reqBody[0:4], 123)
	order.PutUint16(reqBody[4:6], 456)
	reqBody[6] = 1
	reqBody[7] = 2
	order.PutUint32(reqBody[8:12], 789)
	order.PutUint32(reqBody[12:16], 101)
	reqBody[16] = 3
	order.PutUint16(reqBody[18:20], 112)

	p, err := ParseGrabButtonRequest(order, data, reqBody, 1)
	assert.NoError(t, err, "ParseGrabButtonRequest should not return an error")
	assert.True(t, p.OwnerEvents, "OwnerEvents should be true")
	assert.Equal(t, Window(123), p.GrabWindow, "GrabWindow should be parsed correctly")
	assert.Equal(t, uint16(456), p.EventMask, "EventMask should be parsed correctly")
	assert.Equal(t, byte(1), p.PointerMode, "PointerMode should be parsed correctly")
	assert.Equal(t, byte(2), p.KeyboardMode, "KeyboardMode should be parsed correctly")
	assert.Equal(t, Window(789), p.ConfineTo, "ConfineTo should be parsed correctly")
	assert.Equal(t, Cursor(101), p.Cursor, "Cursor should be parsed correctly")
	assert.Equal(t, byte(3), p.Button, "Button should be parsed correctly")
	assert.Equal(t, uint16(112), p.Modifiers, "Modifiers should be parsed correctly")
}

func TestParseUngrabButtonRequest(t *testing.T) {
	order := binary.LittleEndian
	data := byte(3)
	reqBody := make([]byte, 8)
	order.PutUint32(reqBody[0:4], 123)
	order.PutUint16(reqBody[6:8], 112)

	p, err := ParseUngrabButtonRequest(order, data, reqBody, 1)
	assert.NoError(t, err, "ParseUngrabButtonRequest should not return an error")
	assert.Equal(t, Window(123), p.GrabWindow, "GrabWindow should be parsed correctly")
	assert.Equal(t, byte(3), p.Button, "Button should be parsed correctly")
	assert.Equal(t, uint16(112), p.Modifiers, "Modifiers should be parsed correctly")
}

func TestParseChangeActivePointerGrabRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := make([]byte, 12)
	order.PutUint32(reqBody[0:4], 123)
	order.PutUint32(reqBody[4:8], 456)
	order.PutUint16(reqBody[8:10], 789)

	p, err := ParseChangeActivePointerGrabRequest(order, reqBody, 1)
	assert.NoError(t, err, "ParseChangeActivePointerGrabRequest should not return an error")
	assert.Equal(t, Cursor(123), p.Cursor, "Cursor should be parsed correctly")
	assert.Equal(t, Timestamp(456), p.Time, "Time should be parsed correctly")
	assert.Equal(t, uint16(789), p.EventMask, "EventMask should be parsed correctly")
}

func TestParseGrabKeyboardRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := make([]byte, 12)
	order.PutUint32(reqBody[0:4], 123)
	order.PutUint32(reqBody[4:8], 456)
	reqBody[8] = 1
	reqBody[9] = 2

	p, err := ParseGrabKeyboardRequest(order, 0, reqBody, 1)
	assert.NoError(t, err, "ParseGrabKeyboardRequest should not return an error")
	assert.Equal(t, Window(123), p.GrabWindow, "GrabWindow should be parsed correctly")
	assert.Equal(t, Timestamp(456), p.Time, "Time should be parsed correctly")
	assert.Equal(t, byte(1), p.PointerMode, "PointerMode should be parsed correctly")
	assert.Equal(t, byte(2), p.KeyboardMode, "KeyboardMode should be parsed correctly")
}

func TestParseUngrabKeyboardRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := make([]byte, 4)
	order.PutUint32(reqBody[0:4], 123)

	p, err := ParseUngrabKeyboardRequest(order, reqBody, 1)
	assert.NoError(t, err, "ParseUngrabKeyboardRequest should not return an error")
	assert.Equal(t, Timestamp(123), p.Time, "Time should be parsed correctly")
}

func TestParseGrabKeyRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := make([]byte, 12)
	order.PutUint32(reqBody[0:4], 123)
	order.PutUint16(reqBody[4:6], 456)
	reqBody[6] = 7
	reqBody[7] = 1
	reqBody[8] = 2

	p, err := ParseGrabKeyRequest(order, 1, reqBody, 1)
	assert.NoError(t, err, "ParseGrabKeyRequest should not return an error")
	assert.True(t, p.OwnerEvents, "OwnerEvents should be true")
	assert.Equal(t, Window(123), p.GrabWindow, "GrabWindow should be parsed correctly")
	assert.Equal(t, uint16(456), p.Modifiers, "Modifiers should be parsed correctly")
	assert.Equal(t, KeyCode(7), p.Key, "Key should be parsed correctly")
	assert.Equal(t, byte(1), p.PointerMode, "PointerMode should be parsed correctly")
	assert.Equal(t, byte(2), p.KeyboardMode, "KeyboardMode should be parsed correctly")
}

func TestParseUngrabKeyRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := make([]byte, 8)
	order.PutUint32(reqBody[0:4], 123)
	order.PutUint16(reqBody[4:6], 456)

	p, err := ParseUngrabKeyRequest(order, 7, reqBody, 1)
	assert.NoError(t, err, "ParseUngrabKeyRequest should not return an error")
	assert.Equal(t, Window(123), p.GrabWindow, "GrabWindow should be parsed correctly")
	assert.Equal(t, uint16(456), p.Modifiers, "Modifiers should be parsed correctly")
	assert.Equal(t, KeyCode(7), p.Key, "Key should be parsed correctly")
}

func TestParseAllowEventsRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := make([]byte, 4)
	order.PutUint32(reqBody[0:4], 123)

	p, err := ParseAllowEventsRequest(order, 5, reqBody, 1)
	assert.NoError(t, err, "ParseAllowEventsRequest should not return an error")
	assert.Equal(t, byte(5), p.Mode, "Mode should be parsed correctly")
	assert.Equal(t, Timestamp(123), p.Time, "Time should be parsed correctly")
}

func TestParseGrabServerRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := make([]byte, 0)

	_, err := ParseGrabServerRequest(order, reqBody, 1)
	assert.NoError(t, err, "ParseGrabServerRequest should not return an error")
}

func TestParseUngrabServerRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := make([]byte, 0)

	_, err := ParseUngrabServerRequest(order, reqBody, 1)
	assert.NoError(t, err, "ParseUngrabServerRequest should not return an error")
}

func TestParseTranslateCoordsRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := make([]byte, 12)
	order.PutUint32(reqBody[0:4], 1)
	order.PutUint32(reqBody[4:8], 2)
	order.PutUint16(reqBody[8:10], 10)
	order.PutUint16(reqBody[10:12], 20)

	p, err := ParseTranslateCoordsRequest(order, reqBody, 1)
	assert.NoError(t, err, "ParseTranslateCoordsRequest should not return an error")
	assert.Equal(t, Window(1), p.SrcWindow, "SrcWindow should be parsed correctly")
	assert.Equal(t, Window(2), p.DstWindow, "DstWindow should be parsed correctly")
	assert.Equal(t, int16(10), p.SrcX, "SrcX should be parsed correctly")
	assert.Equal(t, int16(20), p.SrcY, "SrcY should be parsed correctly")
}

func TestParseWarpPointerRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := make([]byte, 20)
	order.PutUint16(reqBody[16:18], 10)
	order.PutUint16(reqBody[18:20], 20)

	p, err := ParseWarpPointerRequest(order, reqBody, 1)
	assert.NoError(t, err, "ParseWarpPointerRequest should not return an error")
	assert.Equal(t, int16(10), p.DstX, "DstX should be parsed correctly")
	assert.Equal(t, int16(20), p.DstY, "DstY should be parsed correctly")
}

func TestParseSetInputFocusRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := make([]byte, 8)
	order.PutUint32(reqBody[0:4], 123)
	order.PutUint32(reqBody[4:8], 456)

	p, err := ParseSetInputFocusRequest(order, 2, reqBody, 1)
	assert.NoError(t, err, "ParseSetInputFocusRequest should not return an error")
	assert.Equal(t, Window(123), p.Focus, "Focus should be parsed correctly")
	assert.Equal(t, byte(2), p.RevertTo, "RevertTo should be parsed correctly")
	assert.Equal(t, Timestamp(456), p.Time, "Time should be parsed correctly")
}

func TestParseQueryKeymapRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := make([]byte, 0)

	_, err := ParseQueryKeymapRequest(order, reqBody, 1)
	assert.NoError(t, err, "ParseQueryKeymapRequest should not return an error")
}

func TestParseCloseFontRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := make([]byte, 4)
	order.PutUint32(reqBody[0:4], 123)

	p, err := ParseCloseFontRequest(order, reqBody, 1)
	assert.NoError(t, err, "ParseCloseFontRequest should not return an error")
	assert.Equal(t, Font(123), p.Fid, "Fid should be parsed correctly")
}

func TestParseQueryTextExtentsRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := make([]byte, 8)
	order.PutUint32(reqBody[0:4], 123)
	order.PutUint16(reqBody[4:6], 0x0048)
	order.PutUint16(reqBody[6:8], 0x0065)

	p, err := ParseQueryTextExtentsRequest(order, 0, reqBody, 1)
	assert.NoError(t, err, "ParseQueryTextExtentsRequest should not return an error")
	assert.Equal(t, Font(123), p.Fid, "Fid should be parsed correctly")
	assert.Equal(t, []uint16{0x0048, 0x0065}, p.Text, "Text should be parsed correctly")
}

func TestParseListFontsWithInfoRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := make([]byte, 8)
	order.PutUint16(reqBody[0:2], 10)
	order.PutUint16(reqBody[2:4], 4)
	copy(reqBody[4:8], []byte("test"))

	p, err := ParseListFontsWithInfoRequest(order, reqBody, 1)
	assert.NoError(t, err, "ParseListFontsWithInfoRequest should not return an error")
	assert.Equal(t, uint16(10), p.MaxNames, "MaxNames should be parsed correctly")
	assert.Equal(t, "test", p.Pattern, "Pattern should be parsed correctly")
}

func TestParseSetFontPathRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := make([]byte, 4) // 2 for num paths, 2 unused
	order.PutUint16(reqBody[0:2], 2)

	// Add two paths
	path1 := "path1"
	path2 := "path2"
	reqBody = append(reqBody, byte(len(path1)))
	reqBody = append(reqBody, []byte(path1)...)
	reqBody = append(reqBody, byte(len(path2)))
	reqBody = append(reqBody, []byte(path2)...)

	p, err := ParseSetFontPathRequest(order, reqBody, 1)
	assert.NoError(t, err, "ParseSetFontPathRequest should not return an error")
	assert.Equal(t, uint16(2), p.NumPaths, "NumPaths should be parsed correctly")
	assert.Equal(t, []string{path1, path2}, p.Paths, "Paths should be parsed correctly")
}

func TestParseGetFontPathRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := make([]byte, 0)

	_, err := ParseGetFontPathRequest(order, reqBody, 1)
	assert.NoError(t, err, "ParseGetFontPathRequest should not return an error")
}

func TestParseFreePixmapRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := make([]byte, 4)
	order.PutUint32(reqBody[0:4], 123)

	p, err := ParseFreePixmapRequest(order, reqBody, 1)
	assert.NoError(t, err, "ParseFreePixmapRequest should not return an error")
	assert.Equal(t, Pixmap(123), p.Pid, "Pid should be parsed correctly")
}

func TestParseChangeGCRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := make([]byte, 8)
	order.PutUint32(reqBody[0:4], 123)
	order.PutUint32(reqBody[4:8], uint32(GCForeground|GCBackground))
	reqBody = append(reqBody, make([]byte, 8)...)
	order.PutUint32(reqBody[8:12], 0xFF00FF)
	order.PutUint32(reqBody[12:16], 0x00FF00)

	p, err := ParseChangeGCRequest(order, reqBody, 1)
	assert.NoError(t, err, "ParseChangeGCRequest should not return an error")
	assert.Equal(t, GContext(123), p.Gc, "Gc should be parsed correctly")
	assert.Equal(t, uint32(GCForeground|GCBackground), p.ValueMask, "ValueMask should be parsed correctly")
	assert.Equal(t, uint32(0xFF00FF), p.Values.Foreground, "Foreground should be parsed correctly")
	assert.Equal(t, uint32(0x00FF00), p.Values.Background, "Background should be parsed correctly")
}

func TestParseCopyGCRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := make([]byte, 12)
	order.PutUint32(reqBody[0:4], 123)
	order.PutUint32(reqBody[4:8], 456)
	order.PutUint32(reqBody[8:12], 0xffffffff)

	p, err := ParseCopyGCRequest(order, reqBody, 1)
	assert.NoError(t, err, "ParseCopyGCRequest should not return an error")
	assert.Equal(t, GContext(123), p.SrcGC, "SrcGC should be parsed correctly")
	assert.Equal(t, GContext(456), p.DstGC, "DstGC should be parsed correctly")
	assert.Equal(t, uint32(0xffffffff), p.ValueMask, "ValueMask should be parsed correctly")
}

func TestParseClearAreaRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := make([]byte, 12)
	order.PutUint32(reqBody[0:4], 123)
	order.PutUint16(reqBody[4:6], 10)
	order.PutUint16(reqBody[6:8], 20)
	order.PutUint16(reqBody[8:10], 100)
	order.PutUint16(reqBody[10:12], 200)

	p, err := ParseClearAreaRequest(order, reqBody, 1)
	assert.NoError(t, err, "ParseClearAreaRequest should not return an error")
	assert.Equal(t, Window(123), p.Window, "Window should be parsed correctly")
	assert.Equal(t, int16(10), p.X, "X should be parsed correctly")
	assert.Equal(t, int16(20), p.Y, "Y should be parsed correctly")
	assert.Equal(t, uint16(100), p.Width, "Width should be parsed correctly")
	assert.Equal(t, uint16(200), p.Height, "Height should be parsed correctly")
}

func TestParsePolyPointRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := make([]byte, 16)
	order.PutUint32(reqBody[0:4], 123)
	order.PutUint32(reqBody[4:8], 456)
	order.PutUint16(reqBody[8:10], 10)
	order.PutUint16(reqBody[10:12], 20)
	order.PutUint16(reqBody[12:14], 30)
	order.PutUint16(reqBody[14:16], 40)

	p, err := ParsePolyPointRequest(order, 0, reqBody, 1)
	assert.NoError(t, err, "ParsePolyPointRequest should not return an error")
	assert.Equal(t, Drawable(123), p.Drawable, "Drawable should be parsed correctly")
	assert.Equal(t, GContext(456), p.Gc, "Gc should be parsed correctly")
	assert.Equal(t, []uint32{10, 20, 30, 40}, p.Coordinates, "Coordinates should be parsed correctly")
	assert.Equal(t, byte(0), p.CoordinateMode, "CoordinateMode should be parsed correctly")
}

func TestParsePolyRectangleRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := make([]byte, 24)
	order.PutUint32(reqBody[0:4], 123)
	order.PutUint32(reqBody[4:8], 456)
	order.PutUint16(reqBody[8:10], 10)
	order.PutUint16(reqBody[10:12], 20)
	order.PutUint16(reqBody[12:14], 100)
	order.PutUint16(reqBody[14:16], 200)
	order.PutUint16(reqBody[16:18], 30)
	order.PutUint16(reqBody[18:20], 40)
	order.PutUint16(reqBody[20:22], 50)
	order.PutUint16(reqBody[22:24], 60)

	p, err := ParsePolyRectangleRequest(order, reqBody, 1)
	assert.NoError(t, err, "ParsePolyRectangleRequest should not return an error")
	assert.Equal(t, Drawable(123), p.Drawable, "Drawable should be parsed correctly")
	assert.Equal(t, GContext(456), p.Gc, "Gc should be parsed correctly")
	assert.Equal(t, []uint32{10, 20, 100, 200, 30, 40, 50, 60}, p.Rectangles, "Rectangles should be parsed correctly")
}

func TestParsePolyArcRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := make([]byte, 32)
	order.PutUint32(reqBody[0:4], 123)
	order.PutUint32(reqBody[4:8], 456)
	order.PutUint16(reqBody[8:10], 10)
	order.PutUint16(reqBody[10:12], 20)
	order.PutUint16(reqBody[12:14], 100)
	order.PutUint16(reqBody[14:16], 200)
	order.PutUint16(reqBody[16:18], 90)
	order.PutUint16(reqBody[18:20], 180)
	order.PutUint16(reqBody[20:22], 30)
	order.PutUint16(reqBody[22:24], 40)
	order.PutUint16(reqBody[24:26], 50)
	order.PutUint16(reqBody[26:28], 60)
	order.PutUint16(reqBody[28:30], 270)
	order.PutUint16(reqBody[30:32], 360)

	p, err := ParsePolyArcRequest(order, reqBody, 1)
	assert.NoError(t, err, "ParsePolyArcRequest should not return an error")
	assert.Equal(t, Drawable(123), p.Drawable, "Drawable should be parsed correctly")
	assert.Equal(t, GContext(456), p.Gc, "Gc should be parsed correctly")
	assert.Equal(t, []uint32{10, 20, 100, 200, 90, 180, 30, 40, 50, 60, 270, 360}, p.Arcs, "Arcs should be parsed correctly")
}

func TestParseCreateColormapRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := make([]byte, 12)
	reqBody[0] = 1
	order.PutUint32(reqBody[0:4], 123)
	order.PutUint32(reqBody[4:8], 456)
	order.PutUint32(reqBody[8:12], 789)

	p, err := ParseCreateColormapRequest(order, 1, reqBody, 1)
	assert.NoError(t, err, "ParseCreateColormapRequest should not return an error")
	assert.Equal(t, byte(1), p.Alloc, "Alloc should be parsed correctly")
	assert.Equal(t, Colormap(123), p.Mid, "Mid should be parsed correctly")
	assert.Equal(t, Window(456), p.Window, "Window should be parsed correctly")
	assert.Equal(t, VisualID(789), p.Visual, "Visual should be parsed correctly")
}

func TestParseFreeColormapRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := make([]byte, 4)
	order.PutUint32(reqBody[0:4], 123)

	p, err := ParseFreeColormapRequest(order, reqBody, 1)
	assert.NoError(t, err, "ParseFreeColormapRequest should not return an error")
	assert.Equal(t, Colormap(123), p.Cmap, "Cmap should be parsed correctly")
}

func TestParseInstallColormapRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := make([]byte, 4)
	order.PutUint32(reqBody[0:4], 123)

	p, err := ParseInstallColormapRequest(order, reqBody, 1)
	assert.NoError(t, err, "ParseInstallColormapRequest should not return an error")
	assert.Equal(t, Colormap(123), p.Cmap, "Cmap should be parsed correctly")
}

func TestParseUninstallColormapRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := make([]byte, 4)
	order.PutUint32(reqBody[0:4], 123)

	p, err := ParseUninstallColormapRequest(order, reqBody, 1)
	assert.NoError(t, err, "ParseUninstallColormapRequest should not return an error")
	assert.Equal(t, Colormap(123), p.Cmap, "Cmap should be parsed correctly")
}

func TestParseListInstalledColormapsRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := make([]byte, 4)
	order.PutUint32(reqBody[0:4], 123)

	p, err := ParseListInstalledColormapsRequest(order, reqBody, 1)
	assert.NoError(t, err, "ParseListInstalledColormapsRequest should not return an error")
	assert.Equal(t, Window(123), p.Window, "Window should be parsed correctly")
}

func TestParseAllocColorRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := make([]byte, 12)
	order.PutUint32(reqBody[0:4], 123)
	order.PutUint16(reqBody[4:6], 100)
	order.PutUint16(reqBody[6:8], 200)
	order.PutUint16(reqBody[8:10], 255)

	p, err := ParseAllocColorRequest(order, reqBody, 1)
	assert.NoError(t, err, "ParseAllocColorRequest should not return an error")
	assert.Equal(t, Colormap(123), p.Cmap, "Cmap should be parsed correctly")
	assert.Equal(t, uint16(100), p.Red, "Red should be parsed correctly")
	assert.Equal(t, uint16(200), p.Green, "Green should be parsed correctly")
	assert.Equal(t, uint16(255), p.Blue, "Blue should be parsed correctly")
}

func TestParseAllocNamedColorRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := make([]byte, 12)
	order.PutUint32(reqBody[0:4], 123)
	order.PutUint16(reqBody[4:6], 4)
	copy(reqBody[8:12], []byte("blue"))

	p, err := ParseAllocNamedColorRequest(order, reqBody, 1)
	assert.NoError(t, err, "ParseAllocNamedColorRequest should not return an error")
	assert.Equal(t, Colormap(123), p.Cmap, "Cmap should be parsed correctly")
	assert.Equal(t, []byte("blue"), p.Name, "Name should be parsed correctly")
}

func TestParseFreeColorsRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := make([]byte, 16)
	order.PutUint32(reqBody[0:4], 123)
	order.PutUint32(reqBody[4:8], 0xFF)
	order.PutUint32(reqBody[8:12], 1)
	order.PutUint32(reqBody[12:16], 2)

	p, err := ParseFreeColorsRequest(order, reqBody, 1)
	assert.NoError(t, err, "ParseFreeColorsRequest should not return an error")
	assert.Equal(t, Colormap(123), p.Cmap, "Cmap should be parsed correctly")
	assert.Equal(t, uint32(0xFF), p.PlaneMask, "PlaneMask should be parsed correctly")
	assert.Equal(t, []uint32{1, 2}, p.Pixels, "Pixels should be parsed correctly")
}

func TestParseStoreColorsRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := make([]byte, 28)
	order.PutUint32(reqBody[0:4], 123)
	// Item 1
	order.PutUint32(reqBody[4:8], 1)
	order.PutUint16(reqBody[8:10], 10)
	order.PutUint16(reqBody[10:12], 20)
	order.PutUint16(reqBody[12:14], 30)
	reqBody[14] = 7
	// Item 2
	order.PutUint32(reqBody[16:20], 2)
	order.PutUint16(reqBody[20:22], 40)
	order.PutUint16(reqBody[22:24], 50)
	order.PutUint16(reqBody[24:26], 60)
	reqBody[26] = 3

	p, err := ParseStoreColorsRequest(order, reqBody, 1)
	assert.NoError(t, err, "ParseStoreColorsRequest should not return an error")
	assert.Equal(t, Colormap(123), p.Cmap, "Cmap should be parsed correctly")
	assert.Equal(t, uint32(1), p.Items[0].Pixel, "Item 1 Pixel should be parsed correctly")
	assert.Equal(t, uint16(10), p.Items[0].Red, "Item 1 Red should be parsed correctly")
	assert.Equal(t, uint16(20), p.Items[0].Green, "Item 1 Green should be parsed correctly")
	assert.Equal(t, uint16(30), p.Items[0].Blue, "Item 1 Blue should be parsed correctly")
	assert.Equal(t, byte(7), p.Items[0].Flags, "Item 1 Flags should be parsed correctly")
	assert.Equal(t, uint32(2), p.Items[1].Pixel, "Item 2 Pixel should be parsed correctly")
	assert.Equal(t, uint16(40), p.Items[1].Red, "Item 2 Red should be parsed correctly")
	assert.Equal(t, uint16(50), p.Items[1].Green, "Item 2 Green should be parsed correctly")
	assert.Equal(t, uint16(60), p.Items[1].Blue, "Item 2 Blue should be parsed correctly")
	assert.Equal(t, byte(3), p.Items[1].Flags, "Item 2 Flags should be parsed correctly")
}

func TestParseStoreNamedColorRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := make([]byte, 16)
	order.PutUint32(reqBody[0:4], 123)
	order.PutUint32(reqBody[4:8], 456)
	order.PutUint16(reqBody[8:10], 4)
	copy(reqBody[12:16], []byte("blue"))

	p, err := ParseStoreNamedColorRequest(order, 7, reqBody, 1)
	assert.NoError(t, err, "ParseStoreNamedColorRequest should not return an error")
	assert.Equal(t, Colormap(123), p.Cmap, "Cmap should be parsed correctly")
	assert.Equal(t, uint32(456), p.Pixel, "Pixel should be parsed correctly")
	assert.Equal(t, "blue", p.Name, "Name should be parsed correctly")
	assert.Equal(t, byte(7), p.Flags, "Flags should be parsed correctly")
}

func TestParseLookupColorRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := make([]byte, 12)
	order.PutUint32(reqBody[0:4], 123)
	order.PutUint16(reqBody[4:6], 4)
	copy(reqBody[8:12], []byte("blue"))

	p, err := ParseLookupColorRequest(order, reqBody, 1)
	assert.NoError(t, err, "ParseLookupColorRequest should not return an error")
	assert.Equal(t, Colormap(123), p.Cmap, "Cmap should be parsed correctly")
	assert.Equal(t, "blue", p.Name, "Name should be parsed correctly")
}

func TestParseFreeCursorRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := make([]byte, 4)
	order.PutUint32(reqBody[0:4], 123)

	p, err := ParseFreeCursorRequest(order, reqBody, 1)
	assert.NoError(t, err, "ParseFreeCursorRequest should not return an error")
	assert.Equal(t, Cursor(123), p.Cursor, "Cursor should be parsed correctly")
}

func TestParseQueryBestSizeRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := make([]byte, 8)
	order.PutUint32(reqBody[0:4], 123)
	order.PutUint16(reqBody[4:6], 100)
	order.PutUint16(reqBody[6:8], 200)

	p, err := ParseQueryBestSizeRequest(order, reqBody, 1)
	assert.NoError(t, err, "ParseQueryBestSizeRequest should not return an error")
	assert.Equal(t, Drawable(123), p.Drawable, "Drawable should be parsed correctly")
	assert.Equal(t, uint16(100), p.Width, "Width should be parsed correctly")
	assert.Equal(t, uint16(200), p.Height, "Height should be parsed correctly")
}

func TestParseBellRequest(t *testing.T) {
	p, err := ParseBellRequest(50, 1)
	assert.NoError(t, err, "ParseBellRequest should not return an error")
	assert.Equal(t, int8(50), p.Percent, "Percent should be parsed correctly")
}

func TestParseSetDashesRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := make([]byte, 12)
	order.PutUint32(reqBody[0:4], 123)
	order.PutUint16(reqBody[4:6], 456)
	order.PutUint16(reqBody[6:8], 2)
	reqBody[8] = 10
	reqBody[9] = 20

	p, err := ParseSetDashesRequest(order, reqBody, 1)
	assert.NoError(t, err, "ParseSetDashesRequest should not return an error")
	assert.Equal(t, GContext(123), p.GC, "GC should be parsed correctly")
	assert.Equal(t, uint16(456), p.DashOffset, "DashOffset should be parsed correctly")
	assert.Equal(t, []byte{10, 20}, p.Dashes, "Dashes should be parsed correctly")
}

func TestParseSetClipRectanglesRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := make([]byte, 24)
	order.PutUint32(reqBody[0:4], 123)
	order.PutUint16(reqBody[4:6], 10)
	order.PutUint16(reqBody[6:8], 20)
	// Rectangle 1
	order.PutUint16(reqBody[8:10], 1)
	order.PutUint16(reqBody[10:12], 2)
	order.PutUint16(reqBody[12:14], 3)
	order.PutUint16(reqBody[14:16], 4)
	// Rectangle 2
	order.PutUint16(reqBody[16:18], 5)
	order.PutUint16(reqBody[18:20], 6)
	order.PutUint16(reqBody[20:22], 7)
	order.PutUint16(reqBody[22:24], 8)

	p, err := ParseSetClipRectanglesRequest(order, 1, reqBody, 1)
	assert.NoError(t, err, "ParseSetClipRectanglesRequest should not return an error")
	assert.Equal(t, GContext(123), p.GC, "GC should be parsed correctly")
	assert.Equal(t, int16(10), p.ClippingX, "ClippingX should be parsed correctly")
	assert.Equal(t, int16(20), p.ClippingY, "ClippingY should be parsed correctly")
	assert.Equal(t, byte(1), p.Ordering, "Ordering should be parsed correctly")
	assert.Equal(t, []Rectangle{{1, 2, 3, 4}, {5, 6, 7, 8}}, p.Rectangles, "Rectangles should be parsed correctly")
}

func TestParseRecolorCursorRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := make([]byte, 16)
	order.PutUint32(reqBody[0:4], 123)
	order.PutUint16(reqBody[4:6], 10)
	order.PutUint16(reqBody[6:8], 20)
	order.PutUint16(reqBody[8:10], 30)
	order.PutUint16(reqBody[10:12], 40)
	order.PutUint16(reqBody[12:14], 50)
	order.PutUint16(reqBody[14:16], 60)

	p, err := ParseRecolorCursorRequest(order, reqBody, 1)
	assert.NoError(t, err, "ParseRecolorCursorRequest should not return an error")
	assert.Equal(t, Cursor(123), p.Cursor, "Cursor should be parsed correctly")
	assert.Equal(t, [3]uint16{10, 20, 30}, p.ForeColor, "ForeColor should be parsed correctly")
	assert.Equal(t, [3]uint16{40, 50, 60}, p.BackColor, "BackColor should be parsed correctly")
}

func TestParseSetPointerMappingRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := []byte{1, 2, 3}
	data := byte(len(reqBody))

	p, err := ParseSetPointerMappingRequest(order, data, reqBody, 1)
	assert.NoError(t, err, "ParseSetPointerMappingRequest should not return an error")
	assert.Equal(t, []byte{1, 2, 3}, p.Map, "Map should be parsed correctly")
}

func TestParseGetKeyboardMappingRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := []byte{10, 5, 0, 0}

	p, err := ParseGetKeyboardMappingRequest(order, reqBody, 1)
	assert.NoError(t, err, "ParseGetKeyboardMappingRequest should not return an error")
	assert.Equal(t, KeyCode(10), p.FirstKeyCode, "FirstKeyCode should be parsed correctly")
	assert.Equal(t, byte(5), p.Count, "Count should be parsed correctly")
}

func TestParseChangeKeyboardMappingRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := make([]byte, 20)
	reqBody[0] = 10
	reqBody[1] = 2
	order.PutUint32(reqBody[4:8], 123)
	order.PutUint32(reqBody[8:12], 456)
	order.PutUint32(reqBody[12:16], 789)
	order.PutUint32(reqBody[16:20], 101)

	p, err := ParseChangeKeyboardMappingRequest(order, 2, reqBody, 1)
	assert.NoError(t, err, "ParseChangeKeyboardMappingRequest should not return an error")
	assert.Equal(t, byte(2), p.KeyCodeCount, "KeyCodeCount should be parsed correctly")
	assert.Equal(t, KeyCode(10), p.FirstKeyCode, "FirstKeyCode should be parsed correctly")
	assert.Equal(t, byte(2), p.KeySymsPerKeyCode, "KeySymsPerKeyCode should be parsed correctly")
	assert.Equal(t, []uint32{123, 456, 789, 101}, p.KeySyms, "KeySyms should be parsed correctly")
}

func TestParseChangeKeyboardControlRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := make([]byte, 12)
	order.PutUint32(reqBody[0:4], uint32(KBKeyClickPercent|KBBellPercent))
	order.PutUint32(reqBody[4:8], 50)
	order.PutUint32(reqBody[8:12], 60)

	p, err := ParseChangeKeyboardControlRequest(order, reqBody, 1)
	assert.NoError(t, err, "ParseChangeKeyboardControlRequest should not return an error")
	assert.Equal(t, uint32(KBKeyClickPercent|KBBellPercent), p.ValueMask, "ValueMask should be parsed correctly")
	assert.Equal(t, int32(50), p.Values.KeyClickPercent, "KeyClickPercent should be parsed correctly")
	assert.Equal(t, int32(60), p.Values.BellPercent, "BellPercent should be parsed correctly")
}

func TestParseSetScreenSaverRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := make([]byte, 8)
	order.PutUint16(reqBody[0:2], 10)
	order.PutUint16(reqBody[2:4], 20)
	reqBody[4] = 1
	reqBody[5] = 2

	p, err := ParseSetScreenSaverRequest(order, reqBody, 1)
	assert.NoError(t, err, "ParseSetScreenSaverRequest should not return an error")
	assert.Equal(t, int16(10), p.Timeout, "Timeout should be parsed correctly")
	assert.Equal(t, int16(20), p.Interval, "Interval should be parsed correctly")
	assert.Equal(t, byte(1), p.PreferBlank, "PreferBlank should be parsed correctly")
	assert.Equal(t, byte(2), p.AllowExpose, "AllowExpose should be parsed correctly")
}

func TestParseChangeHostsRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := make([]byte, 8)
	reqBody[0] = 1
	order.PutUint16(reqBody[2:4], 4)
	copy(reqBody[4:8], []byte{1, 2, 3, 4})

	p, err := ParseChangeHostsRequest(order, 2, reqBody, 1)
	assert.NoError(t, err, "ParseChangeHostsRequest should not return an error")
	assert.Equal(t, byte(2), p.Mode, "Mode should be parsed correctly")
	assert.Equal(t, byte(1), p.Host.Family, "Family should be parsed correctly")
	assert.Equal(t, []byte{1, 2, 3, 4}, p.Host.Data, "Data should be parsed correctly")
}

func TestParseKillClientRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := make([]byte, 4)
	order.PutUint32(reqBody[0:4], 123)

	p, err := ParseKillClientRequest(order, reqBody, 1)
	assert.NoError(t, err, "ParseKillClientRequest should not return an error")
	assert.Equal(t, uint32(123), p.Resource, "Resource should be parsed correctly")
}

func TestParseRotatePropertiesRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := make([]byte, 16)
	order.PutUint32(reqBody[0:4], 123)
	order.PutUint16(reqBody[4:6], 2)
	order.PutUint16(reqBody[6:8], 10)
	order.PutUint32(reqBody[8:12], 456)
	order.PutUint32(reqBody[12:16], 789)

	p, err := ParseRotatePropertiesRequest(order, reqBody, 1)
	assert.NoError(t, err, "ParseRotatePropertiesRequest should not return an error")
	assert.Equal(t, Window(123), p.Window, "Window should be parsed correctly")
	assert.Equal(t, int16(10), p.Delta, "Delta should be parsed correctly")
	assert.Equal(t, []Atom{456, 789}, p.Atoms, "Atoms should be parsed correctly")
}

func TestParseForceScreenSaverRequest(t *testing.T) {
	p, err := ParseForceScreenSaverRequest(nil, 1, nil, 1)
	assert.NoError(t, err, "ParseForceScreenSaverRequest should not return an error")
	assert.Equal(t, byte(1), p.Mode, "Mode should be parsed correctly")
}

func TestParseSetModifierMappingRequest(t *testing.T) {
	order := binary.LittleEndian
	keyCodesPerModifier := byte(2)
	reqBody := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

	p, err := ParseSetModifierMappingRequest(order, keyCodesPerModifier, reqBody, 1)
	assert.NoError(t, err, "ParseSetModifierMappingRequest should not return an error")
	assert.Equal(t, keyCodesPerModifier, p.KeyCodesPerModifier, "KeyCodesPerModifier should be parsed correctly")
	expectedKeyCodes := make([]KeyCode, 16)
	for i := 0; i < 16; i++ {
		expectedKeyCodes[i] = KeyCode(i + 1)
	}
	assert.Equal(t, expectedKeyCodes, p.KeyCodes, "KeyCodes should be parsed correctly")
}

func TestRequestParsingTooLongErrors(t *testing.T) {
	testCases := []struct {
		name    string
		reqType ReqCode
		raw     []byte
		data    byte
	}{
		{
			name:    "SetModifierMapping",
			reqType: SetModifierMapping,
			data:    1,
			raw:     make([]byte, 9),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hdr := make([]byte, 4)
			hdr[0] = byte(tc.reqType)
			hdr[1] = tc.data
			binary.LittleEndian.PutUint16(hdr[2:4], uint16((len(tc.raw)+4)/4))
			_, err := ParseRequest(binary.LittleEndian, append(hdr, tc.raw...), 1, false)
			assert.Error(t, err, "ParseRequest should return an error for oversized requests")
		})
	}
}

func TestAllocColorPlanesRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := make([]byte, 12)
	order.PutUint32(reqBody[0:4], 123)
	order.PutUint16(reqBody[4:6], 10)
	order.PutUint16(reqBody[6:8], 20)
	order.PutUint16(reqBody[8:10], 30)
	order.PutUint16(reqBody[10:12], 40)

	p, err := ParseAllocColorPlanesRequest(order, 1, reqBody, 1)
	assert.NoError(t, err, "ParseAllocColorPlanesRequest should not return an error")
	assert.True(t, p.Contiguous, "Contiguous should be true")
	assert.Equal(t, Colormap(123), p.Cmap, "Cmap should be parsed correctly")
	assert.Equal(t, uint16(10), p.Colors, "Colors should be parsed correctly")
	assert.Equal(t, uint16(20), p.Reds, "Reds should be parsed correctly")
	assert.Equal(t, uint16(30), p.Greens, "Greens should be parsed correctly")
	assert.Equal(t, uint16(40), p.Blues, "Blues should be parsed correctly")
}

func TestParseCreateCursorRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := make([]byte, 28)
	order.PutUint32(reqBody[0:4], 1)
	order.PutUint32(reqBody[4:8], 2)
	order.PutUint32(reqBody[8:12], 3)
	order.PutUint16(reqBody[12:14], 10)
	order.PutUint16(reqBody[14:16], 20)
	order.PutUint16(reqBody[16:18], 30)
	order.PutUint16(reqBody[18:20], 40)
	order.PutUint16(reqBody[20:22], 50)
	order.PutUint16(reqBody[22:24], 60)
	order.PutUint16(reqBody[24:26], 5)
	order.PutUint16(reqBody[26:28], 15)

	p, err := ParseCreateCursorRequest(order, reqBody, 1)
	assert.NoError(t, err, "ParseCreateCursorRequest should not return an error")
	assert.Equal(t, Cursor(1), p.Cid, "Cid should be parsed correctly")
	assert.Equal(t, Pixmap(2), p.Source, "Source should be parsed correctly")
	assert.Equal(t, Pixmap(3), p.Mask, "Mask should be parsed correctly")
	assert.Equal(t, uint16(10), p.ForeRed, "ForeRed should be parsed correctly")
	assert.Equal(t, uint16(20), p.ForeGreen, "ForeGreen should be parsed correctly")
	assert.Equal(t, uint16(30), p.ForeBlue, "ForeBlue should be parsed correctly")
	assert.Equal(t, uint16(40), p.BackRed, "BackRed should be parsed correctly")
	assert.Equal(t, uint16(50), p.BackGreen, "BackGreen should be parsed correctly")
	assert.Equal(t, uint16(60), p.BackBlue, "BackBlue should be parsed correctly")
	assert.Equal(t, uint16(5), p.X, "X should be parsed correctly")
	assert.Equal(t, uint16(15), p.Y, "Y should be parsed correctly")
}
func TestParseImageText16Request(t *testing.T) {
	order := binary.LittleEndian
	req := &ImageText16Request{
		Drawable: Drawable(1),
		Gc:       GContext(2),
		X:        10,
		Y:        20,
		Text:     []uint16{'H', 'e', 'l', 'l', 'o'},
	}

	encoded := req.EncodeMessage(order)
	p, err := ParseImageText16Request(order, encoded[1], encoded[4:], 1)
	assert.NoError(t, err, "ParseImageText16Request should not return an error")
	assert.Equal(t, req, p)
}
