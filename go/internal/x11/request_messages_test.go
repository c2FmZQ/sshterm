//go:build x11

package x11

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseImageText8Request(t *testing.T) {
	// ImageText8 request: drawable, gc, x, y, text
	drawable := uint32(1)
	gc := uint32(2)
	x := int16(10)
	y := int16(20)
	text := []byte("Hello")

	payload := make([]byte, 12) // drawable (4) + gc (4) + x (2) + y (2)
	binary.LittleEndian.PutUint32(payload[0:4], drawable)
	binary.LittleEndian.PutUint32(payload[4:8], gc)
	binary.LittleEndian.PutUint16(payload[8:10], uint16(x))
	binary.LittleEndian.PutUint16(payload[10:12], uint16(y))
	payload = append(payload, text...)

	p := parseImageText8Request(binary.LittleEndian, payload)

	if p.Drawable != drawable {
		t.Errorf("Expected drawable %d, got %d", drawable, p.Drawable)
	}
	if p.Gc != gc {
		t.Errorf("Expected gc %d, got %d", gc, p.Gc)
	}
	if p.X != x {
		t.Errorf("Expected x %d, got %d", x, p.X)
	}
	if p.Y != y {
		t.Errorf("Expected y %d, got %d", y, p.Y)
	}
	if !bytes.Equal(p.Text, text) {
		t.Errorf("Expected text %s, got %s", text, p.Text)
	}
}

func TestParseImageText16Request(t *testing.T) {
	// ImageText16 request: drawable, gc, x, y, text
	drawable := uint32(1)
	gc := uint32(2)
	x := int16(10)
	y := int16(20)
	text := []uint16{0x0048, 0x0065, 0x006c, 0x006c, 0x006f} // "Hello"

	payload := make([]byte, 12) // drawable (4) + gc (4) + x (2) + y (2)
	binary.LittleEndian.PutUint32(payload[0:4], drawable)
	binary.LittleEndian.PutUint32(payload[4:8], gc)
	binary.LittleEndian.PutUint16(payload[8:10], uint16(x))
	binary.LittleEndian.PutUint16(payload[10:12], uint16(y))
	for _, r := range text {
		buf := make([]byte, 2)
		binary.LittleEndian.PutUint16(buf, r)
		payload = append(payload, buf...)
	}

	p := parseImageText16Request(binary.LittleEndian, payload)

	assert.Equal(t, drawable, p.Drawable, "drawable mismatch")
	assert.Equal(t, gc, p.Gc, "gc mismatch")
	assert.Equal(t, x, p.X, "x mismatch")
	assert.Equal(t, y, p.Y, "y mismatch")
	assert.Equal(t, text, p.Text, "text mismatch")
}

func TestParsePolyText8Request(t *testing.T) {
	// PolyText8 request: drawable, gc, x, y, items
	drawable := uint32(1)
	gc := uint32(2)
	x := int16(10)
	y := int16(20)

	// Item 1: delta=5, text="Hi"
	// Item 2: delta=10, text="There"

	payload := make([]byte, 12) // drawable (4) + gc (4) + x (2) + y (2)
	binary.LittleEndian.PutUint32(payload[0:4], drawable)
	binary.LittleEndian.PutUint32(payload[4:8], gc)
	binary.LittleEndian.PutUint16(payload[8:10], uint16(x))
	binary.LittleEndian.PutUint16(payload[10:12], uint16(y))

	// Item 1
	payload = append(payload, 2)        // n = 2 (length of "Hi")
	payload = append(payload, 5)        // delta = 5
	payload = append(payload, 'H', 'i') // text = "Hi"
	// Padding for (1 byte n + 1 byte delta + 2 bytes string) = 4 bytes. No padding needed.

	// Item 2
	payload = append(payload, 5)                       // n = 5 (length of "There")
	payload = append(payload, 10)                      // delta = 10
	payload = append(payload, 'T', 'h', 'e', 'r', 'e') // text = "There"
	payload = append(payload, 0)                       // padding for (1 byte n + 1 byte delta + 5 bytes string) = 7 bytes. Need 1 byte padding.

	p := parsePolyText8Request(binary.LittleEndian, payload)

	assert.Equal(t, drawable, p.Drawable, "drawable mismatch")
	assert.Equal(t, gc, p.Gc, "gc mismatch")
	assert.Equal(t, x, p.X, "x mismatch")
	assert.Equal(t, y, p.Y, "y mismatch")

	expectedItems := []PolyText8Item{
		{Delta: 5, Str: []byte("Hi")},
		{Delta: 10, Str: []byte("There")},
	}
	assert.Equal(t, expectedItems, p.Items, "items mismatch")
}

func TestParsePolyText16Request(t *testing.T) {
	// PolyText16 request: drawable, gc, x, y, items
	drawable := uint32(1)
	gc := uint32(2)
	x := int16(10)
	y := int16(20)

	// Item 1: delta=5, text="Hi"
	// Item 2: delta=10, text="There"

	payload := make([]byte, 12) // drawable (4) + gc (4) + x (2) + y (2)
	binary.LittleEndian.PutUint32(payload[0:4], drawable)
	binary.LittleEndian.PutUint32(payload[4:8], gc)
	binary.LittleEndian.PutUint16(payload[8:10], uint16(x))
	binary.LittleEndian.PutUint16(payload[10:12], uint16(y))

	// Item 1
	payload = append(payload, 2)                      // n = 2 (length of "Hi" in CHAR2B)
	payload = append(payload, 5)                      // delta = 5
	payload = append(payload, 0x48, 0x00, 0x69, 0x00) // text = "Hi"
	payload = append(payload, 0, 0)                   // padding for (1 byte n + 1 byte delta + 4 bytes string) = 6 bytes. Need 2 bytes padding.

	// Item 2
	payload = append(payload, 5)                                                          // n = 5 (length of "There" in CHAR2B)
	payload = append(payload, 10)                                                         // delta = 10
	payload = append(payload, 0x54, 0x00, 0x68, 0x00, 0x65, 0x00, 0x72, 0x00, 0x65, 0x00) // text = "There"
	// Padding for (1 byte n + 1 byte delta + 10 bytes string) = 12 bytes. No padding needed.

	p := parsePolyText16Request(binary.LittleEndian, payload)

	assert.Equal(t, drawable, p.Drawable, "drawable mismatch")
	assert.Equal(t, gc, p.Gc, "gc mismatch")
	assert.Equal(t, x, p.X, "x mismatch")
	assert.Equal(t, y, p.Y, "y mismatch")

	expectedItems := []PolyText16Item{
		{Delta: 5, Str: []uint16{0x0048, 0x0069}},
		{Delta: 10, Str: []uint16{0x0054, 0x0068, 0x0065, 0x0072, 0x0065}},
	}
	assert.Equal(t, expectedItems, p.Items, "items mismatch")
}

func TestParseQueryPointerRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := make([]byte, 4)
	order.PutUint32(reqBody, 123)
	p := parseQueryPointerRequest(order, reqBody)
	assert.Equal(t, uint32(123), p.Drawable, "Drawable ID should be parsed correctly")

}

func TestParseCopyAreaRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := make([]byte, 24)
	order.PutUint32(reqBody[0:4], 1)     // srcDrawable
	order.PutUint32(reqBody[4:8], 2)     // dstDrawable
	order.PutUint32(reqBody[8:12], 3)    // gc
	order.PutUint16(reqBody[12:14], 10)  // srcX
	order.PutUint16(reqBody[14:16], 20)  // srcY
	order.PutUint16(reqBody[16:18], 30)  // dstX
	order.PutUint16(reqBody[18:20], 40)  // dstY
	order.PutUint16(reqBody[20:22], 100) // width
	order.PutUint16(reqBody[22:24], 200) // height

	p := parseCopyAreaRequest(order, reqBody)

	assert.Equal(t, uint32(1), p.SrcDrawable, "srcDrawable should be parsed correctly")
	assert.Equal(t, uint32(2), p.DstDrawable, "dstDrawable should be parsed correctly")
	assert.Equal(t, uint32(3), p.Gc, "gc should be parsed correctly")
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

	p := parseGetImageRequest(order, reqBody)

	assert.Equal(t, uint32(1), p.Drawable, "drawable should be parsed correctly")
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

	p := parseGetAtomNameRequest(order, reqBody)

	assert.Equal(t, uint32(123), p.Atom, "atom should be parsed correctly")
}

func TestParseListPropertiesRequest(t *testing.T) {
	order := binary.LittleEndian
	reqBody := make([]byte, 4)
	order.PutUint32(reqBody[0:4], 123) // window

	p := parseListPropertiesRequest(order, reqBody)

	assert.Equal(t, uint32(123), p.Window, "window should be parsed correctly")
}
