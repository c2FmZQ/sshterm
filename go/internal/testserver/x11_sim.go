package main

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/c2FmZQ/sshterm/internal/x11/wire"
	"golang.org/x/crypto/ssh"
)

const (
	// From go/internal/x11/x11.go
	atomString = 31
	atomWmName = 39
)

// X11Operation represents a single X11 drawing operation for testing purposes.
type X11Operation struct {
	Type  string
	Color uint32
	Args  []any
}

var x11Operations []X11Operation

func clearX11Operations() {
	x11Operations = nil
}

func (s *sshServer) clientXID(id uint32) uint32 {
	return s.resourceIdBase | (id & s.resourceIdMask)
}

// EncodableRequest is an interface for X11 requests that can be encoded.
type EncodableRequest interface {
	wire.Request
	EncodeMessage(order binary.ByteOrder) []byte
}

func (s *sshServer) sendRequest(channel ssh.Channel, req EncodableRequest) (uint16, error) {
	encoded := req.EncodeMessage(binary.LittleEndian)
	if _, err := channel.Write(encoded); err != nil {
		return 0, fmt.Errorf("failed to write X11 request: %w", err)
	}
	s.clientSequence++
	s.t.Logf("Sent X11 request %d (%d)", s.clientSequence, req.OpCode())
	if s.x11ReplyTracker != nil {
		s.x11ReplyTracker.Expect(s.clientSequence, wire.Opcodes{Major: req.OpCode()})
	}
	return s.clientSequence, nil
}

func (s *sshServer) readReply(reply <-chan wire.ServerMessage) wire.ServerMessage {
	s.t.Helper()
	for {
		select {
		case r := <-reply:
			if _, ok := r.(wire.Event); ok {
				continue
			}
			return r
		case <-time.After(5 * time.Second):
			s.t.Fatal("timeout waiting for reply")
		}
	}
}

func (s *sshServer) simulateX11Application(serverConn *ssh.ServerConn, authProtocol string, authCookie []byte) {
	defer close(s.x11SimDone)
	s.t.Log("Simulating X11 application (client-side)")

	windowWidth, windowHeight := 600, 400

	// Open X11 channel back to the SSH client (WASM App)
	x11Channel, x11Requests, err := serverConn.OpenChannel("x11", nil)
	if err != nil {
		s.t.Logf("Failed to open X11 channel: %v", err)
		return
	}
	defer x11Channel.Close()
	go ssh.DiscardRequests(x11Requests)

	// 1. Send SetupRequest
	s.t.Log("Sending X11 SetupRequest")
	setupRequest := make([]byte, 12)
	setupRequest[0] = 'l' // LittleEndian
	binary.LittleEndian.PutUint16(setupRequest[2:4], 11)
	binary.LittleEndian.PutUint16(setupRequest[4:6], 0)
	binary.LittleEndian.PutUint16(setupRequest[6:8], uint16(len(authProtocol)))
	binary.LittleEndian.PutUint16(setupRequest[8:10], uint16(len(authCookie)))

	if _, err = x11Channel.Write(setupRequest); err != nil {
		s.t.Logf("Failed to send X11 SetupRequest: %v", err)
		return
	}
	authProtoBytes := []byte(authProtocol)
	if pad := len(authProtoBytes) % 4; pad != 0 {
		authProtoBytes = append(authProtoBytes, make([]byte, 4-pad)...)
	}
	if _, err = x11Channel.Write(authProtoBytes); err != nil {
		s.t.Logf("Failed to send X11 auth protocol: %v", err)
		return
	}
	authCookieBytes := authCookie
	if pad := len(authCookieBytes) % 4; pad != 0 {
		authCookieBytes = append(authCookieBytes, make([]byte, 4-pad)...)
	}
	if _, err = x11Channel.Write(authCookieBytes); err != nil {
		s.t.Logf("Failed to send X11 auth cookie: %v", err)
		return
	}
	s.t.Log("X11 SetupRequest sent successfully")

	// 2. Receive SetupResponse
	s.t.Log("Waiting for X11 SetupResponse")
	setupResponseHeader := make([]byte, 8)
	_, err = io.ReadFull(x11Channel, setupResponseHeader)
	if err != nil {
		s.t.Logf("Failed to read X11 SetupResponse header: %v", err)
		return
	}
	s.t.Log("X11 SetupResponse header received")

	status := setupResponseHeader[0]
	protocolMajor := binary.LittleEndian.Uint16(setupResponseHeader[2:4])
	protocolMinor := binary.LittleEndian.Uint16(setupResponseHeader[4:6])
	additionalDataLength := binary.LittleEndian.Uint16(setupResponseHeader[6:8]) * 4 // in bytes

	s.t.Logf("X11 SetupResponse: status=%d, protocolMajor=%d, protocolMinor=%d, additionalDataLength=%d", status, protocolMajor, protocolMinor, additionalDataLength)

	if status != 1 { // 1 means success
		s.t.Logf("X11 SetupResponse indicates failure (status %d)", status)
		return
	}

	if additionalDataLength > 0 {
		remainingData := make([]byte, additionalDataLength)
		_, err := io.ReadFull(x11Channel, remainingData)
		if err != nil {
			s.t.Logf("Failed to read X11 SetupResponse remaining data: %v", err)
			return
		}

		s.resourceIdBase = binary.LittleEndian.Uint32(remainingData[4:8])
		s.resourceIdMask = binary.LittleEndian.Uint32(remainingData[8:12])

		vendorLen := binary.LittleEndian.Uint16(remainingData[16:18])
		numRoots := remainingData[20]
		numFormats := remainingData[21]

		pad := (4 - int(vendorLen)%4) % 4
		rootsOffset := 32 + int(vendorLen) + pad + 8*int(numFormats)

		if len(remainingData) >= rootsOffset+36 && numRoots > 0 {
			s.rootWindowID = binary.LittleEndian.Uint32(remainingData[rootsOffset : rootsOffset+4])
			s.rootVisualID = binary.LittleEndian.Uint32(remainingData[rootsOffset+32 : rootsOffset+36])
			s.t.Logf("X11 Setup: ResourceBase=0x%x, Mask=0x%x, RootWindow=0x%x, RootVisual=0x%x", s.resourceIdBase, s.resourceIdMask, s.rootWindowID, s.rootVisualID)
		} else {
			s.t.Log("X11 Setup: Could not find RootWindow")
			return
		}
	}

	s.t.Logf("X11 client handshake successful")
	replyChan := s.readReplies(x11Channel)

	// Now send drawing commands
	s.t.Log("Sending drawing commands...")

	// Create Window
	s.t.Log("Sending CreateWindow")
	if err := s.createWindow(x11Channel, s.clientXID(1), s.rootWindowID, 10, 20, uint32(windowWidth), uint32(windowHeight)); err != nil {
		s.t.Logf("Failed to create window: %v", err)
		return
	}

	// MapWindow
	s.t.Log("Sending MapWindow")
	if err := s.mapWindow(x11Channel, s.clientXID(1)); err != nil {
		s.t.Logf("Failed to map window: %v", err)
		return
	}

	// Fill window with white background
	s.t.Log("Filling window with white background")
	if err := s.createGCWithBackground(x11Channel, s.clientXID(99), s.clientXID(1), 0xFFFFFF, 0); err != nil {
		s.t.Logf("Failed to create white GC: %v", err)
		return
	}
	background := []int16{0, 0, int16(windowWidth), int16(windowHeight)}
	if err := s.polyFillRectangle(x11Channel, s.clientXID(1), s.clientXID(99), background); err != nil {
		s.t.Logf("Failed to fill window background: %v", err)
		return
	}

	// Create GCs
	colors := map[string]uint32{
		"red":    0xFF0000,
		"green":  0x008000, // Darker Green
		"blue":   0x0000FF,
		"yellow": 0xFFFF00,
		"brown":  0x8B4513,
		"cyan":   0x00FFFF,
	}
	gcs := make(map[string]uint32)
	i := uint32(100)
	for name, color := range colors {
		gcs[name] = s.clientXID(i)
		if err := s.createGCWithBackground(x11Channel, gcs[name], s.clientXID(1), color, 0); err != nil {
			s.t.Logf("Failed to create %s GC: %v", name, err)
			return
		}
		i++
	}

	// Draw ground
	s.t.Log("Drawing ground")
	ground := []int16{0, 300, 600, 100}
	if err := s.polyFillRectangle(x11Channel, s.clientXID(1), gcs["green"], ground); err != nil {
		s.t.Logf("Failed to draw ground: %v", err)
		return
	}

	// Draw house base
	s.t.Log("Drawing house base")
	houseBase := []int16{200, 200, 200, 150}
	if err := s.polyFillRectangle(x11Channel, s.clientXID(1), gcs["brown"], houseBase); err != nil {
		s.t.Logf("Failed to draw house base: %v", err)
		return
	}

	// Draw roof
	s.t.Log("Drawing roof")
	roof := []int16{180, 200, 300, 100, 420, 200}
	if err := s.fillPoly(x11Channel, s.clientXID(1), gcs["red"], 0, roof); err != nil {
		s.t.Logf("Failed to draw roof: %v", err)
		return
	}

	// Draw sun
	s.t.Log("Drawing sun")
	sun := []int16{500, 50, 40, 40, 0, 360 * 64}
	if err := s.polyFillArc(x11Channel, s.clientXID(1), gcs["yellow"], sun); err != nil {
		s.t.Logf("Failed to draw sun: %v", err)
		return
	}

	// Draw a star
	s.t.Log("Drawing cyan star")
	starPoints := []int16{
		100, 50, 110, 75, 135, 75, 115, 95, 125, 120,
		100, 105, 75, 120, 85, 95, 65, 75, 90, 75, 100, 50,
	}
	if err := s.polyLine(x11Channel, s.clientXID(1), gcs["cyan"], 0, starPoints); err != nil {
		s.t.Logf("Failed to draw cyan star: %v", err)
		return
	}

	// ChangeProperty (set window title)
	s.t.Log("Sending ChangeProperty")
	title := "SSHTERM X11 - House and Sun"
	if err := s.changeProperty(x11Channel, s.clientXID(1), atomWmName, atomString, 0, 8, []byte(title)); err != nil {
		s.t.Logf("Failed to change property: %v", err)
		return
	}

	if err := s.imageText8(x11Channel, s.clientXID(1), gcs["blue"], 50, 50, []byte("Hello X11!")); err != nil {
		s.t.Logf("Failed to draw text: %v", err)
		return
	}

	if err := s.imageText16(x11Channel, s.clientXID(1), gcs["red"], 50, 70, []uint16{0x0048, 0x0065, 0x006c, 0x006c, 0x006f, 0x0020, 0x0057, 0x006f, 0x0072, 0x006c, 0x0064, 0x0021}); err != nil {
		s.t.Logf("Failed to draw ImageText16: %v", err)
		return
	}

	polyText8Items := []PolyText8Item{
		{Delta: 0, Str: []byte("PolyText8 ")},
		{Delta: 10, Str: []byte("Example")},
	}
	if err := s.polyText8(x11Channel, s.clientXID(1), gcs["yellow"], 50, 90, polyText8Items); err != nil {
		s.t.Logf("Failed to draw PolyText8: %v", err)
		return
	}

	polyText16Items := []PolyText16Item{
		{Delta: 0, Str: []uint16{0x0050, 0x006f, 0x006c, 0x0079, 0x0054, 0x0065, 0x0078, 0x0074, 0x0031, 0x0036, 0x0020}},
		{Delta: 10, Str: []uint16{0x0045, 0x0078, 0x0061, 0x006d, 0x0070, 0x006c, 0x0065}},
	}
	if err := s.polyText16(x11Channel, s.clientXID(1), gcs["cyan"], 50, 110, polyText16Items); err != nil {
		s.t.Logf("Failed to draw PolyText16: %v", err)
		return
	}

	// Test Font API
	s.t.Log("Testing Font API")
	fontID := s.clientXID(200)
	fontName := "-*-helvetica-medium-r-normal-*-12-*-*-*-p-*-iso8859-1"
	if err := s.openFont(x11Channel, fontID, fontName); err != nil {
		s.t.Logf("Failed to open font: %v", err)
		return
	}

	if err := s.listFonts(x11Channel, 10, "*", replyChan); err != nil {
		s.t.Logf("Failed to list fonts: %v", err)
		return
	}

	// Create a new GC with the font
	fontGC := s.clientXID(106)
	if err := s.createGCWithFont(x11Channel, fontGC, s.clientXID(1), colors["blue"], 0, fontID); err != nil {
		s.t.Logf("Failed to create GC with font: %v", err)
		return
	}

	// Draw text with the new GC
	if err := s.imageText8(x11Channel, s.clientXID(1), fontGC, 50, 130, []byte("Text with font!")); err != nil {
		s.t.Logf("Failed to draw text with font: %v", err)
		return
	}

	if err := s.closeFont(x11Channel, fontID); err != nil {
		s.t.Logf("Failed to close font: %v", err)
		return
	}

	s.simulateXEyes(x11Channel)
	s.simulateColorOperations(x11Channel, replyChan)
	s.simulateGrabOperations(x11Channel)
	s.simulateGCOperations(x11Channel)

	s.t.Log("All drawing commands sent successfully")
	time.Sleep(2 * time.Second)
	x11Channel.Close()
}

func (s *sshServer) readReplies(channel ssh.Channel) <-chan wire.ServerMessage {
	s.x11ReplyTracker = wire.NewReplyTracker()
	return wire.ReadServerMessagesWithTracker(channel, binary.LittleEndian, s.x11ReplyTracker)
}

func (s *sshServer) simulateXEyes(x11Channel ssh.Channel) {
	s.t.Log("Simulating xeyes")
	// Create Window
	wid10 := s.clientXID(10)
	if err := s.createWindow(x11Channel, wid10, s.rootWindowID, 0, 0, 150, 100); err != nil {
		s.t.Logf("Failed to create window: %v", err)
		return
	}
	wid11 := s.clientXID(11)
	if err := s.createWindow(x11Channel, wid11, wid10, 0, 0, 150, 100); err != nil {
		s.t.Logf("Failed to create window: %v", err)
		return
	}

	// Create GCs
	whiteGC := s.clientXID(13)
	if err := s.createGCWithBackground(x11Channel, whiteGC, wid11, 0xFFFFFF, 0); err != nil {
		s.t.Logf("Failed to create white GC: %v", err)
		return
	}
	blackGC := s.clientXID(14)
	if err := s.createGCWithBackground(x11Channel, blackGC, wid11, 0x000000, 0); err != nil {
		s.t.Logf("Failed to create black GC: %v", err)
		return
	}

	// MapWindow
	if err := s.mapWindow(x11Channel, wid11); err != nil {
		s.t.Logf("Failed to map window: %v", err)
		return
	}
	if err := s.mapWindow(x11Channel, wid10); err != nil {
		s.t.Logf("Failed to map window: %v", err)
		return
	}

	// Draw eyes
	leftEyeOutline := []int16{17, 25, 13, 18, 5760, 23040}
	if err := s.polyFillArc(x11Channel, wid11, blackGC, leftEyeOutline); err != nil {
		s.t.Logf("Failed to draw left eye outline: %v", err)
		return
	}
	rightEyeOutline := []int16{92, 34, 13, 18, 5760, 23040}
	if err := s.polyFillArc(x11Channel, wid11, blackGC, rightEyeOutline); err != nil {
		s.t.Logf("Failed to draw right eye outline: %v", err)
		return
	}

	leftEye := []int16{18, 26, 11, 16, 5760, 23040}
	if err := s.polyFillArc(x11Channel, wid11, whiteGC, leftEye); err != nil {
		s.t.Logf("Failed to draw left eye: %v", err)
		return
	}
	rightEye := []int16{93, 35, 11, 16, 5760, 23040}
	if err := s.polyFillArc(x11Channel, wid11, whiteGC, rightEye); err != nil {
		s.t.Logf("Failed to draw right eye: %v", err)
		return
	}

	// Draw pupils
	leftPupil := []int16{23, 31, 5, 8, 5760, 23040}
	if err := s.polyFillArc(x11Channel, wid11, blackGC, leftPupil); err != nil {
		s.t.Logf("Failed to draw left pupil: %v", err)
		return
	}
	rightPupil := []int16{98, 40, 5, 8, 5760, 23040}
	if err := s.polyFillArc(x11Channel, wid11, blackGC, rightPupil); err != nil {
		s.t.Logf("Failed to draw right pupil: %v", err)
		return
	}
}

func (s *sshServer) simulateColorOperations(channel ssh.Channel, replyChan <-chan wire.ServerMessage) {
	s.t.Log("Simulating color operations")

	// 1. Create a new colormap
	colormapID := s.clientXID(2)
	if err := s.createColormap(channel, colormapID, s.clientXID(1), s.rootVisualID); err != nil {
		s.t.Errorf("Failed to create colormap: %v", err)
		return
	}

	// 2. Allocate some colors
	pixel, r, g, b, err := s.allocNamedColor(channel, colormapID, "blue", replyChan)
	if err != nil {
		s.t.Errorf("Failed to allocate named color: %v", err)
		return
	}
	if pixel != 0x0000ff || r != 0 || g != 0 || b != 0xffff {
		s.t.Errorf("ERR allocNamedColor(_, %d, blue, _) = %06x, (%04x, %04x, %04x)", colormapID, pixel, r, g, b)
	}
	pixel, r, g, b, err = s.allocColor(channel, colormapID, 0, 0, 65535, replyChan)
	if err != nil {
		s.t.Errorf("Failed to allocate color: %v", err)
		return
	}
	if pixel != 0x0000ff || r != 0 || g != 0 || b != 0xffff {
		s.t.Errorf("ERR allocColor(_, %d, 0, 0, 65535, _) = %06x, (%04x, %04x, %04x)", colormapID, pixel, r, g, b)
	}

	// 3. Create a new window with the new colormap
	wid20 := s.clientXID(20)
	if err := s.createWindowWithColormap(channel, wid20, s.clientXID(1), 10, 20, 200, 200, colormapID); err != nil {
		s.t.Errorf("Failed to create window with colormap: %v", err)
		return
	}
	if err := s.mapWindow(channel, wid20); err != nil {
		s.t.Errorf("Failed to map window: %v", err)
		return
	}

	// 4. Draw something in the new window
	blueGC := s.clientXID(200)
	if err := s.createGCWithBackground(channel, blueGC, wid20, 0x0000FF, 0); err != nil {
		s.t.Errorf("Failed to create blue GC: %v", err)
		return
	}
	rect := []int16{10, 10, 180, 180}
	if err := s.polyFillRectangle(channel, wid20, blueGC, rect); err != nil {
		s.t.Errorf("Failed to draw rectangle: %v", err)
		return
	}

	// 5. Query colors
	if _, err := s.queryColors(channel, colormapID, []uint32{0x0000FF}, replyChan); err != nil {
		s.t.Errorf("Failed to query colors: %v", err)
		return
	}

	// 6. Install colormap
	if err := s.installColormap(channel, colormapID); err != nil {
		s.t.Errorf("Failed to install colormap: %v", err)
		return
	}

	// 7. List installed colormaps
	if _, err := s.listInstalledColormaps(channel, replyChan); err != nil {
		s.t.Errorf("Failed to list installed colormaps: %v", err)
		return
	}

	// 8. Free colors
	if err := s.freeColors(channel, colormapID, 0, []uint32{0x0000FF}); err != nil {
		s.t.Errorf("Failed to free colors: %v", err)
		return
	}

	// 9. Free colormap
	if err := s.freeColormap(channel, colormapID); err != nil {
		s.t.Errorf("Failed to free colormap: %v", err)
		return
	}
}

func GetX11Operations() []X11Operation {
	for i := range x11Operations {
		for j := range x11Operations[i].Args {
			x11Operations[i].Args[j] = fmt.Sprint(x11Operations[i].Args[j])
		}
	}
	return x11Operations
}

func (s *sshServer) changeProperty(channel ssh.Channel, wid, property, typeAtom uint32, mode, format byte, data []byte) error {
	opType := "changeProperty"
	var args []any
	if property == atomWmName {
		opType = "setWindowTitle"
		args = []any{wid, string(data)}
	} else {
		args = []any{wid, property, typeAtom, uint32(format), string(data)}
	}
	newOp := X11Operation{
		Type: opType,
		Args: args,
	}
	x11Operations = append(x11Operations, newOp)

	req := &wire.ChangePropertyRequest{
		Window:   wire.Window(wid),
		Property: wire.Atom(property),
		Type:     wire.Atom(typeAtom),
		Format:   format,
		Data:     data,
	}
	_, err := s.sendRequest(channel, req)
	return err
}

func (s *sshServer) putImage(channel ssh.Channel, drawable, gc, x, y, width, height, leftPad, format uint32, imageData []byte) error {
	newOp := X11Operation{
		Type:  "putImage",
		Color: gcColors[gc],
		Args:  []any{drawable, gcToMap(gc), x, y, width, height, leftPad, format, len(imageData)},
	}
	x11Operations = append(x11Operations, newOp)

	req := &wire.PutImageRequest{
		Format:   byte(format),
		Drawable: wire.Drawable(drawable),
		Gc:       wire.GContext(gc),
		Width:    uint16(width),
		Height:   uint16(height),
		DstX:     int16(x),
		DstY:     int16(y),
		LeftPad:  byte(leftPad),
		Depth:    0,
		Data:     imageData,
	}

	_, err := s.sendRequest(channel, req)
	return err
}

func (s *sshServer) polyFillArc(channel ssh.Channel, drawable, gc uint32, arcs []int16) error {
	newOp := X11Operation{
		Type:  "polyFillArc",
		Color: gcColors[gc],
		Args:  []any{drawable, gcToMap(gc), uint32Slice(arcs)},
	}
	x11Operations = append(x11Operations, newOp)

	wireArcs := make([]uint32, 0, len(arcs))
	for _, v := range arcs {
		wireArcs = append(wireArcs, uint32(v))
	}

	req := &wire.PolyFillArcRequest{
		Drawable: wire.Drawable(drawable),
		Gc:       wire.GContext(gc),
		Arcs:     wireArcs,
	}

	_, err := s.sendRequest(channel, req)
	return err
}

func gcToMap(gcID uint32) map[string]interface{} {
	return map[string]interface{}{
		"Foreground": gcColors[gcID],
	}
}

func (s *sshServer) polyArc(channel ssh.Channel, drawable, gc uint32, arcs []int16) error {
	newOp := X11Operation{
		Type:  "polyArc",
		Color: gcColors[gc],
		Args:  []any{drawable, gcToMap(gc), uint32Slice(arcs)},
	}
	x11Operations = append(x11Operations, newOp)

	wireArcs := make([]uint32, 0, len(arcs))
	for _, v := range arcs {
		wireArcs = append(wireArcs, uint32(v))
	}

	req := &wire.PolyArcRequest{
		Drawable: wire.Drawable(drawable),
		Gc:       wire.GContext(gc),
		Arcs:     wireArcs,
	}

	_, err := s.sendRequest(channel, req)
	return err
}

func (s *sshServer) polyRectangle(channel ssh.Channel, drawable, gc uint32, rects []int16) error {
	newOp := X11Operation{
		Type:  "polyRectangle",
		Color: gcColors[gc],
		Args:  []any{drawable, gcToMap(gc), uint32Slice(rects)},
	}
	x11Operations = append(x11Operations, newOp)

	wireRects := make([]uint32, 0, len(rects))
	for _, v := range rects {
		wireRects = append(wireRects, uint32(v))
	}

	req := &wire.PolyRectangleRequest{
		Drawable:   wire.Drawable(drawable),
		Gc:         wire.GContext(gc),
		Rectangles: wireRects,
	}

	_, err := s.sendRequest(channel, req)
	return err
}

func (s *sshServer) polyPoint(channel ssh.Channel, drawable, gc uint32, coordinateMode byte, points []int16) error {
	newOp := X11Operation{
		Type:  "polyPoint",
		Color: gcColors[gc],
		Args:  []any{drawable, gcToMap(gc), uint32Slice(points)},
	}
	x11Operations = append(x11Operations, newOp)

	wirePoints := make([]uint32, 0, len(points))
	for _, v := range points {
		wirePoints = append(wirePoints, uint32(v))
	}

	req := &wire.PolyPointRequest{
		Drawable:    wire.Drawable(drawable),
		Gc:          wire.GContext(gc),
		Coordinates: wirePoints,
	}

	_, err := s.sendRequest(channel, req)
	return err
}

func (s *sshServer) polySegment(channel ssh.Channel, drawable, gc uint32, segments []int16) error {
	newOp := X11Operation{
		Type:  "polySegment",
		Color: gcColors[gc],
		Args:  []any{drawable, gcToMap(gc), uint32Slice(segments)},
	}
	x11Operations = append(x11Operations, newOp)

	wireSegments := make([]uint32, 0, len(segments))
	for _, v := range segments {
		wireSegments = append(wireSegments, uint32(v))
	}

	req := &wire.PolySegmentRequest{
		Drawable: wire.Drawable(drawable),
		Gc:       wire.GContext(gc),
		Segments: wireSegments,
	}

	_, err := s.sendRequest(channel, req)
	return err
}

func (s *sshServer) fillPoly(channel ssh.Channel, drawable, gc uint32, shape byte, points []int16) error {
	newOp := X11Operation{
		Type:  "fillPoly",
		Color: gcColors[gc],
		Args:  []any{drawable, gcToMap(gc), uint32Slice(points)},
	}
	x11Operations = append(x11Operations, newOp)

	wirePoints := make([]uint32, 0, len(points))
	for _, v := range points {
		wirePoints = append(wirePoints, uint32(v))
	}

	req := &wire.FillPolyRequest{
		Drawable:    wire.Drawable(drawable),
		Gc:          wire.GContext(gc),
		Shape:       shape,
		Coordinates: wirePoints,
	}

	_, err := s.sendRequest(channel, req)
	return err
}

func uint32Slice(in []int16) []any {
	out := make([]any, len(in))
	for i, v := range in {
		out[i] = uint32(v)
	}
	return out
}

func (s *sshServer) polyFillRectangle(channel ssh.Channel, drawable, gc uint32, rects []int16) error {
	newOp := X11Operation{
		Type:  "polyFillRectangle",
		Color: gcColors[gc],
		Args:  []any{drawable, gcToMap(gc), uint32Slice(rects)},
	}
	x11Operations = append(x11Operations, newOp)

	wireRects := make([]uint32, 0, len(rects))
	for _, v := range rects {
		wireRects = append(wireRects, uint32(v))
	}

	req := &wire.PolyFillRectangleRequest{
		Drawable:   wire.Drawable(drawable),
		Gc:         wire.GContext(gc),
		Rectangles: wireRects,
	}

	_, err := s.sendRequest(channel, req)
	return err
}

var gcColors = make(map[uint32]uint32)

func (s *sshServer) createGC(channel ssh.Channel, gcID, drawable, foregroundColor uint32) error {
	return s.createGCWithBackground(channel, gcID, drawable, foregroundColor, 0)
}

func (s *sshServer) createGCWithBackground(channel ssh.Channel, gcID, drawable, foregroundColor, backgroundColor uint32) error {
	return s.createGCWithAttributes(channel, gcID, drawable, map[uint32]uint32{
		wire.GCForeground: foregroundColor,
		wire.GCBackground: backgroundColor,
	})
}

func (s *sshServer) polyLine(channel ssh.Channel, drawable, gc uint32, coordinateMode byte, points []int16) error {
	x11Operations = append(x11Operations, X11Operation{
		Type:  "polyLine",
		Color: gcColors[gc],
		Args:  []any{drawable, gcToMap(gc), uint32Slice(points)},
	})

	wirePoints := make([]uint32, 0, len(points))
	for _, v := range points {
		wirePoints = append(wirePoints, uint32(v))
	}

	req := &wire.PolyLineRequest{
		Drawable:    wire.Drawable(drawable),
		Gc:          wire.GContext(gc),
		Coordinates: wirePoints,
	}

	_, err := s.sendRequest(channel, req)
	return err
}

func (s *sshServer) mapWindow(channel ssh.Channel, wid uint32) error {
	x11Operations = append(x11Operations, X11Operation{
		Type: "mapWindow",
		Args: []any{wid},
	})
	req := &wire.MapWindowRequest{
		Window: wire.Window(wid),
	}
	_, err := s.sendRequest(channel, req)
	return err
}

func (s *sshServer) imageText8(channel ssh.Channel, drawable, gc uint32, x, y int16, text []byte) error {
	x11Operations = append(x11Operations, X11Operation{
		Type:  "imageText8",
		Color: gcColors[gc],
		Args:  []any{uint32(drawable), gcToMap(gc), uint32(x), uint32(y), string(text)},
	})

	req := &wire.ImageText8Request{
		Drawable: wire.Drawable(drawable),
		Gc:       wire.GContext(gc),
		X:        x,
		Y:        y,
		Text:     text,
	}

	_, err := s.sendRequest(channel, req)
	return err
}

func (s *sshServer) imageText16(channel ssh.Channel, drawable, gc uint32, x, y int16, text []uint16) error {
	x11Operations = append(x11Operations, X11Operation{
		Type:  "imageText16",
		Color: gcColors[gc],
		Args:  []any{uint32(drawable), gcToMap(gc), uint32(x), uint32(y), uint16SliceToString(text)},
	})

	req := &wire.ImageText16Request{
		Drawable: wire.Drawable(drawable),
		Gc:       wire.GContext(gc),
		X:        x,
		Y:        y,
		Text:     text,
	}

	_, err := s.sendRequest(channel, req)
	return err
}

type PolyText8Item struct {
	Delta int8
	Str   []byte
}

func (s *sshServer) polyText8(channel ssh.Channel, drawable, gc uint32, x, y int16, items []PolyText8Item) error {
	recordedItems := make([]any, len(items))
	for i, item := range items {
		recordedItems[i] = map[string]any{"delta": item.Delta, "text": string(item.Str)}
	}
	x11Operations = append(x11Operations, X11Operation{
		Type:  "polyText8",
		Color: gcColors[gc],
		Args:  []any{uint32(drawable), gcToMap(gc), uint32(x), uint32(y), recordedItems},
	})

	wireItems := make([]wire.PolyTextItem, len(items))
	for i, item := range items {
		wireItems[i] = wire.PolyText8String{Delta: item.Delta, Str: item.Str}
	}

	req := &wire.PolyText8Request{
		Drawable: wire.Drawable(drawable),
		GC:       wire.GContext(gc),
		X:        x,
		Y:        y,
		Items:    wireItems,
	}

	_, err := s.sendRequest(channel, req)
	return err
}

type PolyText16Item struct {
	Delta int8
	Str   []uint16
}

func (s *sshServer) polyText16(channel ssh.Channel, drawable, gc uint32, x, y int16, items []PolyText16Item) error {
	recordedItems := make([]any, len(items))
	for i, item := range items {
		recordedItems[i] = map[string]any{"delta": item.Delta, "text": uint16SliceToString(item.Str)}
	}
	x11Operations = append(x11Operations, X11Operation{
		Type:  "polyText16",
		Color: gcColors[gc],
		Args:  []any{uint32(drawable), gcToMap(gc), uint32(x), uint32(y), recordedItems},
	})

	wireItems := make([]wire.PolyTextItem, len(items))
	for i, item := range items {
		wireItems[i] = wire.PolyText16String{Delta: item.Delta, Str: item.Str}
	}

	req := &wire.PolyText16Request{
		Drawable: wire.Drawable(drawable),
		GC:       wire.GContext(gc),
		X:        x,
		Y:        y,
		Items:    wireItems,
	}

	_, err := s.sendRequest(channel, req)
	return err
}

func (s *sshServer) openFont(channel ssh.Channel, fid uint32, name string) error {
	x11Operations = append(x11Operations, X11Operation{
		Type: "openFont",
		Args: []any{fid, name},
	})
	req := &wire.OpenFontRequest{
		Fid:  wire.Font(fid),
		Name: name,
	}
	_, err := s.sendRequest(channel, req)
	return err
}

func (s *sshServer) closeFont(channel ssh.Channel, fid uint32) error {
	x11Operations = append(x11Operations, X11Operation{
		Type: "closeFont",
		Args: []any{fid},
	})
	req := &wire.CloseFontRequest{
		Fid: wire.Font(fid),
	}
	_, err := s.sendRequest(channel, req)
	return err
}

func (s *sshServer) queryFont(channel ssh.Channel, fid uint32, replyChan <-chan wire.ServerMessage) error {
	x11Operations = append(x11Operations, X11Operation{
		Type: "queryFont",
		Args: []any{fid},
	})

	req := &wire.QueryFontRequest{
		Fid: wire.Font(fid),
	}

	expectedSequence, err := s.sendRequest(channel, req)
	if err != nil {
		return fmt.Errorf("failed to write QueryFont request: %w", err)
	}

	msg := s.readReply(replyChan)
	reply, ok := msg.(*wire.QueryFontReply)
	if !ok {
		if errReply, ok := msg.(wire.Error); ok {
			return fmt.Errorf("X11 error: %v", errReply)
		}
		return fmt.Errorf("unexpected reply type: %T", msg)
	}

	if reply.Sequence != expectedSequence {
		return fmt.Errorf("unexpected reply sequence number %d != %d", reply.Sequence, expectedSequence)
	}

	s.t.Logf("QueryFont Reply: fid=%d, length=%d, minCharOrByte2=%d, maxCharOrByte2=%d, defaultChar=%d, nFontProps=%d, minByte1=%d, maxByte1=%d, allCharsExist=%t, fontAscent=%d, fontDescent=%d, nCharInfos=%d",
		fid, 0, reply.MinCharOrByte2, reply.MaxCharOrByte2, reply.DefaultChar, reply.NumFontProps, reply.MinByte1, reply.MaxByte1, reply.AllCharsExist, reply.FontAscent, reply.FontDescent, reply.NumCharInfos)
	s.t.Logf("  minBounds: %+v", reply.MinBounds)
	s.t.Logf("  maxBounds: %+v", reply.MaxBounds)

	// Validate values
	if reply.FontAscent <= 0 || reply.FontDescent <= 0 {
		s.t.Errorf("ERR fontAscent (%d) or fontDescent (%d) is not positive", reply.FontAscent, reply.FontDescent)
	}
	if reply.MinBounds.Ascent <= 0 || reply.MinBounds.Descent <= 0 {
		s.t.Errorf("ERR minBounds.Ascent (%d) or minBounds.Descent (%d) is not positive", reply.MinBounds.Ascent, reply.MinBounds.Descent)
	}
	if reply.MaxBounds.Ascent <= 0 || reply.MaxBounds.Descent <= 0 {
		s.t.Errorf("ERR maxBounds.Ascent (%d) or maxBounds.Descent (%d) is not positive", reply.MaxBounds.Ascent, reply.MaxBounds.Descent)
	}
	if reply.NumCharInfos != uint32(reply.MaxCharOrByte2-reply.MinCharOrByte2+1) {
		s.t.Errorf("ERR nCharInfos (%d) does not match expected count (%d)", reply.NumCharInfos, reply.MaxCharOrByte2-reply.MinCharOrByte2+1)
	}

	for i, prop := range reply.FontProps {
		s.t.Logf("  Font Property %d: Name=%d, Value=%d", i, prop.Name, prop.Value)
	}

	for i, ci := range reply.CharInfos {
		if ci.Ascent <= 0 || ci.Descent <= 0 {
			s.t.Errorf("ERR char info %d: Ascent (%d) or Descent (%d) is not positive", i, ci.Ascent, ci.Descent)
		}
	}
	s.t.Log("QueryFont reply validated successfully")

	return nil
}

func (s *sshServer) listFonts(channel ssh.Channel, maxNames uint16, pattern string, replyChan <-chan wire.ServerMessage) error {
	x11Operations = append(x11Operations, X11Operation{
		Type: "listFonts",
		Args: []any{maxNames, pattern},
	})

	req := &wire.ListFontsRequest{
		MaxNames: maxNames,
		Pattern:  pattern,
	}

	if _, err := s.sendRequest(channel, req); err != nil {
		return err
	}
	// We consume the reply but don't do much validation in original code other than receiving it
	s.readReply(replyChan)
	return nil
}

func (s *sshServer) createGCWithFont(channel ssh.Channel, gcID, drawable, foregroundColor, backgroundColor, fontID uint32) error {
	return s.createGCWithAttributes(channel, gcID, drawable, map[uint32]uint32{
		wire.GCForeground: foregroundColor,
		wire.GCBackground: backgroundColor,
		wire.GCFont:       fontID,
	})
}

func uint16SliceToString(s []uint16) string {
	runes := make([]rune, len(s))
	for i, v := range s {
		runes[i] = rune(v)
	}
	return string(runes)
}

func (s *sshServer) createWindow(channel ssh.Channel, wid, parent, x, y, width, height uint32) error {
	return s.createWindowWithColormap(channel, wid, parent, x, y, width, height, 0)
}

func (s *sshServer) createWindowWithColormap(channel ssh.Channel, wid, parent, x, y, width, height, colormap uint32) error {
	x11Operations = append(x11Operations, X11Operation{
		Type: "createWindow",
		Args: []any{wid, parent, x, y, width, height, uint32(24)},
	})

	req := &wire.CreateWindowRequest{
		Depth:       24,
		Drawable:    wire.Window(wid),
		Parent:      wire.Window(parent),
		X:           int16(x),
		Y:           int16(y),
		Width:       uint16(width),
		Height:      uint16(height),
		BorderWidth: 0,
		Class:       wire.InputOutput,
		Visual:      0, // CopyFromParent
		ValueMask:   wire.CWBackPixel | wire.CWEventMask | wire.CWColormap,
		Values: wire.WindowAttributes{
			BackgroundPixel: 0xFFFFFF,
			EventMask:       0,
			Colormap:        wire.Colormap(colormap),
		},
	}

	_, err := s.sendRequest(channel, req)
	return err
}

func (s *sshServer) createColormap(channel ssh.Channel, mid, window, visual uint32) error {
	req := &wire.CreateColormapRequest{
		Alloc:  0, // None
		Mid:    wire.Colormap(mid),
		Window: wire.Window(window),
		Visual: wire.VisualID(visual),
	}
	_, err := s.sendRequest(channel, req)
	return err
}

func (s *sshServer) freeColormap(channel ssh.Channel, cmap uint32) error {
	req := &wire.FreeColormapRequest{
		Cmap: wire.Colormap(cmap),
	}
	_, err := s.sendRequest(channel, req)
	return err
}

func (s *sshServer) allocNamedColor(channel ssh.Channel, cmap uint32, name string, replyChan <-chan wire.ServerMessage) (uint32, uint16, uint16, uint16, error) {
	req := &wire.AllocNamedColorRequest{
		Cmap: wire.Colormap(cmap),
		Name: []byte(name),
	}

	expectedSequence, err := s.sendRequest(channel, req)
	if err != nil {
		return 0, 0, 0, 0, err
	}

	msg := s.readReply(replyChan)
	reply, ok := msg.(*wire.AllocNamedColorReply)
	if !ok {
		if errReply, ok := msg.(wire.Error); ok {
			return 0, 0, 0, 0, fmt.Errorf("X11 error: %v", errReply)
		}
		return 0, 0, 0, 0, fmt.Errorf("unexpected reply type: %T", msg)
	}

	if reply.Sequence != expectedSequence {
		return 0, 0, 0, 0, fmt.Errorf("unexpected reply sequence number %d != %d", reply.Sequence, expectedSequence)
	}

	return reply.Pixel, reply.Red, reply.Green, reply.Blue, nil
}

func (s *sshServer) allocColor(channel ssh.Channel, cmap uint32, red, green, blue uint16, replyChan <-chan wire.ServerMessage) (uint32, uint16, uint16, uint16, error) {
	req := &wire.AllocColorRequest{
		Cmap:  wire.Colormap(cmap),
		Red:   red,
		Green: green,
		Blue:  blue,
	}

	expectedSequence, err := s.sendRequest(channel, req)
	if err != nil {
		return 0, 0, 0, 0, err
	}

	msg := s.readReply(replyChan)
	reply, ok := msg.(*wire.AllocColorReply)
	if !ok {
		if errReply, ok := msg.(wire.Error); ok {
			return 0, 0, 0, 0, fmt.Errorf("X11 error: %v", errReply)
		}
		return 0, 0, 0, 0, fmt.Errorf("unexpected reply type: %T", msg)
	}

	if reply.Sequence != expectedSequence {
		return 0, 0, 0, 0, fmt.Errorf("unexpected reply sequence number %d != %d", reply.Sequence, expectedSequence)
	}

	return reply.Pixel, reply.Red, reply.Green, reply.Blue, nil
}

func (s *sshServer) queryColors(channel ssh.Channel, cmap uint32, pixels []uint32, replyChan <-chan wire.ServerMessage) ([]uint16, error) {
	req := &wire.QueryColorsRequest{
		Cmap:   cmap,
		Pixels: pixels,
	}

	expectedSequence, err := s.sendRequest(channel, req)
	if err != nil {
		return nil, err
	}

	msg := s.readReply(replyChan)
	reply, ok := msg.(*wire.QueryColorsReply)
	if !ok {
		if errReply, ok := msg.(wire.Error); ok {
			return nil, fmt.Errorf("X11 error: %v", errReply)
		}
		return nil, fmt.Errorf("unexpected reply type: %T", msg)
	}

	if reply.Sequence != expectedSequence {
		return nil, fmt.Errorf("unexpected reply sequence number %d != %d", reply.Sequence, expectedSequence)
	}

	colors := make([]uint16, len(reply.Colors)*3)
	for i, color := range reply.Colors {
		colors[i*3] = color.Red
		colors[i*3+1] = color.Green
		colors[i*3+2] = color.Blue
	}

	return colors, nil
}

func (s *sshServer) installColormap(channel ssh.Channel, cmap uint32) error {
	req := &wire.InstallColormapRequest{
		Cmap: wire.Colormap(cmap),
	}
	_, err := s.sendRequest(channel, req)
	return err
}

func (s *sshServer) listInstalledColormaps(channel ssh.Channel, replyChan <-chan wire.ServerMessage) ([]uint32, error) {
	req := &wire.ListInstalledColormapsRequest{
		Window: wire.Window(s.clientXID(1)), // dummy window
	}

	expectedSequence, err := s.sendRequest(channel, req)
	if err != nil {
		return nil, err
	}

	msg := s.readReply(replyChan)
	reply, ok := msg.(*wire.ListInstalledColormapsReply)
	if !ok {
		if errReply, ok := msg.(wire.Error); ok {
			return nil, fmt.Errorf("X11 error: %v", errReply)
		}
		return nil, fmt.Errorf("unexpected reply type: %T", msg)
	}

	if reply.Sequence != expectedSequence {
		return nil, fmt.Errorf("unexpected reply sequence number %d != %d", reply.Sequence, expectedSequence)
	}

	return reply.Colormaps, nil
}

func (s *sshServer) freeColors(channel ssh.Channel, cmap, planeMask uint32, pixels []uint32) error {
	req := &wire.FreeColorsRequest{
		Cmap:      wire.Colormap(cmap),
		PlaneMask: planeMask,
		Pixels:    pixels,
	}
	_, err := s.sendRequest(channel, req)
	return err
}

func (s *sshServer) createGCWithAttributes(channel ssh.Channel, gcID, drawable uint32, values map[uint32]uint32) error {
	if foregroundColor, ok := values[wire.GCForeground]; ok {
		gcColors[gcID] = foregroundColor
	}

	// Calculate mask and map values to wire.GC
	var valueMask uint32
	gc := wire.GC{}

	for mask, val := range values {
		valueMask |= mask
		switch mask {
		case wire.GCFunction:
			gc.Function = val
		case wire.GCPlaneMask:
			gc.PlaneMask = val
		case wire.GCForeground:
			gc.Foreground = val
		case wire.GCBackground:
			gc.Background = val
		case wire.GCLineWidth:
			gc.LineWidth = val
		case wire.GCLineStyle:
			gc.LineStyle = val
		case wire.GCCapStyle:
			gc.CapStyle = val
		case wire.GCJoinStyle:
			gc.JoinStyle = val
		case wire.GCFillStyle:
			gc.FillStyle = val
		case wire.GCFillRule:
			gc.FillRule = val
		case wire.GCTile:
			gc.Tile = val
		case wire.GCStipple:
			gc.Stipple = val
		case wire.GCTileStipXOrigin:
			gc.TileStipXOrigin = val
		case wire.GCTileStipYOrigin:
			gc.TileStipYOrigin = val
		case wire.GCFont:
			gc.Font = val
		case wire.GCSubwindowMode:
			gc.SubwindowMode = val
		case wire.GCGraphicsExposures:
			gc.GraphicsExposures = val
		case wire.GCClipXOrigin:
			gc.ClipXOrigin = int32(val)
		case wire.GCClipYOrigin:
			gc.ClipYOrigin = int32(val)
		case wire.GCClipMask:
			gc.ClipMask = val
		case wire.GCDashOffset:
			gc.DashOffset = val
		case wire.GCDashes:
			gc.Dashes = val
		case wire.GCArcMode:
			gc.ArcMode = val
		}
	}

	x11Operations = append(x11Operations, X11Operation{
		Type: "createGC",
		Args: []any{gcID, valueMask, gcValuesToMap(values)},
	})

	req := &wire.CreateGCRequest{
		Cid:       wire.GContext(gcID),
		Drawable:  wire.Drawable(drawable),
		ValueMask: valueMask,
		Values:    gc,
	}

	_, err := s.sendRequest(channel, req)
	return err
}

func (s *sshServer) setDashes(channel ssh.Channel, gcID uint32, dashOffset uint16, dashes []byte) error {
	x11Operations = append(x11Operations, X11Operation{
		Type: "setDashes",
		Args: []any{gcID, dashOffset, base64.StdEncoding.EncodeToString(dashes)},
	})

	req := &wire.SetDashesRequest{
		GC:         wire.GContext(gcID),
		DashOffset: dashOffset,
		Dashes:     dashes,
	}

	_, err := s.sendRequest(channel, req)
	return err
}

func (s *sshServer) createPixmap(channel ssh.Channel, pid, drawable, width, height, depth uint32) error {
	x11Operations = append(x11Operations, X11Operation{
		Type: "createPixmap",
		Args: []any{pid, drawable, width, height, depth},
	})

	req := &wire.CreatePixmapRequest{
		Pid:      wire.Pixmap(pid),
		Drawable: wire.Drawable(drawable),
		Width:    uint16(width),
		Height:   uint16(height),
		Depth:    byte(depth),
	}

	_, err := s.sendRequest(channel, req)
	return err
}

func gcValuesToMap(values map[uint32]uint32) map[string]interface{} {
	m := make(map[string]interface{})
	if v, ok := values[wire.GCFunction]; ok {
		m["Function"] = v
	}
	if v, ok := values[wire.GCPlaneMask]; ok {
		m["PlaneMask"] = v
	}
	if v, ok := values[wire.GCForeground]; ok {
		m["Foreground"] = v
	}
	if v, ok := values[wire.GCBackground]; ok {
		m["Background"] = v
	}
	if v, ok := values[wire.GCLineWidth]; ok {
		m["LineWidth"] = v
	}
	if v, ok := values[wire.GCLineStyle]; ok {
		m["LineStyle"] = v
	}
	if v, ok := values[wire.GCCapStyle]; ok {
		m["CapStyle"] = v
	}
	if v, ok := values[wire.GCJoinStyle]; ok {
		m["JoinStyle"] = v
	}
	if v, ok := values[wire.GCFillStyle]; ok {
		m["FillStyle"] = v
	}
	if v, ok := values[wire.GCFillRule]; ok {
		m["FillRule"] = v
	}
	if v, ok := values[wire.GCTile]; ok {
		m["Tile"] = v
	}
	if v, ok := values[wire.GCStipple]; ok {
		m["Stipple"] = v
	}
	if v, ok := values[wire.GCTileStipXOrigin]; ok {
		m["TileStipXOrigin"] = v
	}
	if v, ok := values[wire.GCTileStipYOrigin]; ok {
		m["TileStipYOrigin"] = v
	}
	if v, ok := values[wire.GCFont]; ok {
		m["Font"] = v
	}
	if v, ok := values[wire.GCSubwindowMode]; ok {
		m["SubwindowMode"] = v
	}
	if v, ok := values[wire.GCGraphicsExposures]; ok {
		m["GraphicsExposures"] = v
	}
	if v, ok := values[wire.GCClipXOrigin]; ok {
		m["ClipXOrigin"] = v
	}
	if v, ok := values[wire.GCClipYOrigin]; ok {
		m["ClipYOrigin"] = v
	}
	if v, ok := values[wire.GCClipMask]; ok {
		m["ClipMask"] = v
	}
	if v, ok := values[wire.GCDashOffset]; ok {
		m["DashOffset"] = v
	}
	if v, ok := values[wire.GCDashes]; ok {
		m["Dashes"] = v
	}
	if v, ok := values[wire.GCArcMode]; ok {
		m["ArcMode"] = v
	}
	return m
}

func (s *sshServer) simulateGCOperations(channel ssh.Channel) {
	s.t.Log("Simulating GC operations")

	// Create a new window for GC tests
	gcWindowID := s.clientXID(30)
	if err := s.createWindow(channel, gcWindowID, s.clientXID(1), 220, 220, 300, 300); err != nil {
		s.t.Errorf("Failed to create GC test window: %v", err)
		return
	}
	if err := s.mapWindow(channel, gcWindowID); err != nil {
		s.t.Errorf("Failed to map GC test window: %v", err)
		return
	}

	// Create GCs with different attributes
	// GC for thick red line
	gcThickRed := s.clientXID(300)
	if err := s.createGCWithAttributes(channel, gcThickRed, gcWindowID, map[uint32]uint32{
		wire.GCForeground: 0xFF0000,
		wire.GCLineWidth:  5,
	}); err != nil {
		s.t.Errorf("Failed to create thick red GC: %v", err)
		return
	}
	s.polyLine(channel, gcWindowID, gcThickRed, 0, []int16{10, 10, 100, 10})

	// GC for dashed blue line with round caps and joins
	gcDashedBlue := s.clientXID(301)
	if err := s.createGCWithAttributes(channel, gcDashedBlue, gcWindowID, map[uint32]uint32{
		wire.GCForeground: 0x0000FF,
		wire.GCCapStyle:   2, // Round
		wire.GCJoinStyle:  1, // Round
		wire.GCDashes:     4,
	}); err != nil {
		s.t.Errorf("Failed to create dashed blue GC: %v", err)
		return
	}
	if err := s.setDashes(channel, gcDashedBlue, 0, []byte{4, 4}); err != nil {
		s.t.Errorf("Failed to set dashes: %v", err)
		return
	}
	s.polyLine(channel, gcWindowID, gcDashedBlue, 0, []int16{10, 30, 100, 30, 100, 50})

	// GC for winding fill rule
	gcWindingFill := s.clientXID(302)
	if err := s.createGCWithAttributes(channel, gcWindingFill, gcWindowID, map[uint32]uint32{
		wire.GCForeground: 0x00FF00,
		wire.GCFillRule:   1, // Winding
	}); err != nil {
		s.t.Errorf("Failed to create winding fill GC: %v", err)
		return
	}
	points := []int16{150, 10, 180, 60, 120, 60, 150, 10}
	s.fillPoly(channel, gcWindowID, gcWindingFill, 0, points)

	// Tiled rectangle
	tilePixmapID := s.clientXID(400)
	s.createPixmap(channel, tilePixmapID, gcWindowID, 8, 8, 24)
	gcTile := s.clientXID(303)
	if err := s.createGCWithAttributes(channel, gcTile, tilePixmapID, map[uint32]uint32{
		wire.GCForeground: 0xFF00FF,
	}); err != nil {
		s.t.Errorf("Failed to create tile GC: %v", err)
		return
	}
	s.polyFillRectangle(channel, tilePixmapID, gcTile, []int16{0, 0, 4, 4})
	s.polyFillRectangle(channel, tilePixmapID, gcTile, []int16{4, 4, 4, 4})
	gcTiledFill := s.clientXID(304)
	if err := s.createGCWithAttributes(channel, gcTiledFill, gcWindowID, map[uint32]uint32{
		wire.GCFillStyle: 1, // Tiled
		wire.GCTile:      tilePixmapID,
	}); err != nil {
		s.t.Errorf("Failed to create tiled fill GC: %v", err)
		return
	}
	s.polyFillRectangle(channel, gcWindowID, gcTiledFill, []int16{10, 70, 100, 50})

	// Stippled rectangle
	stipplePixmapID := s.clientXID(401)
	s.createPixmap(channel, stipplePixmapID, gcWindowID, 8, 8, 1)
	gcStipple := s.clientXID(305)
	if err := s.createGCWithAttributes(channel, gcStipple, stipplePixmapID, map[uint32]uint32{
		wire.GCForeground: 0x000000,
	}); err != nil {
		s.t.Errorf("Failed to create stipple GC: %v", err)
		return
	}
	s.polyPoint(channel, stipplePixmapID, gcStipple, 0, []int16{0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7})
	gcStippledFill := s.clientXID(306)
	if err := s.createGCWithAttributes(channel, gcStippledFill, gcWindowID, map[uint32]uint32{
		wire.GCForeground: 0x800080, // Purple
		wire.GCFillStyle:  2,        // Stippled
		wire.GCStipple:    stipplePixmapID,
	}); err != nil {
		s.t.Errorf("Failed to create stippled fill GC: %v", err)
		return
	}
	s.polyFillRectangle(channel, gcWindowID, gcStippledFill, []int16{120, 70, 100, 50})

	// GC for XOR function
	gcXOR := s.clientXID(307)
	if err := s.createGCWithAttributes(channel, gcXOR, gcWindowID, map[uint32]uint32{
		wire.GCFunction:   6, // GXxor
		wire.GCForeground: 0xFF00FF,
	}); err != nil {
		s.t.Errorf("Failed to create XOR GC: %v", err)
		return
	}
	s.polyFillRectangle(channel, gcWindowID, gcXOR, []int16{10, 130, 50, 50})
	s.polyFillRectangle(channel, gcWindowID, gcXOR, []int16{40, 160, 50, 50})

	// GC for ArcMode and font
	fontID := s.clientXID(402)
	s.openFont(channel, fontID, "-*-helvetica-bold-r-normal--25-*-*-*-*-*-iso8859-1")
	gcArcFont := s.clientXID(308)
	if err := s.createGCWithAttributes(channel, gcArcFont, gcWindowID, map[uint32]uint32{
		wire.GCForeground: 0x000000,
		wire.GCArcMode:    1, // PieSlice
		wire.GCFont:       fontID,
	}); err != nil {
		s.t.Errorf("Failed to create arc/font GC: %v", err)
		return
	}
	s.polyFillArc(channel, gcWindowID, gcArcFont, []int16{120, 130, 100, 100, 0, 90 * 64})
	s.imageText8(channel, gcWindowID, gcArcFont, 120, 250, []byte("Arc"))
	s.closeFont(channel, fontID)
}

func (s *sshServer) grabPointer(channel ssh.Channel, grabWindow uint32, ownerEvents bool, eventMask uint16, pointerMode, keyboardMode byte, confineTo, cursor uint32, time uint32) error {
	x11Operations = append(x11Operations, X11Operation{
		Type: "grabPointer",
		Args: []any{grabWindow, ownerEvents, eventMask, pointerMode, keyboardMode, confineTo, cursor, time},
	})

	req := &wire.GrabPointerRequest{
		OwnerEvents:  ownerEvents,
		GrabWindow:   wire.Window(grabWindow),
		EventMask:    eventMask,
		PointerMode:  pointerMode,
		KeyboardMode: keyboardMode,
		ConfineTo:    wire.Window(confineTo),
		Cursor:       wire.Cursor(cursor),
		Time:         wire.Timestamp(time),
	}

	_, err := s.sendRequest(channel, req)
	return err
}

func (s *sshServer) ungrabPointer(channel ssh.Channel, time uint32) error {
	x11Operations = append(x11Operations, X11Operation{
		Type: "ungrabPointer",
		Args: []any{time},
	})

	req := &wire.UngrabPointerRequest{
		Time: wire.Timestamp(time),
	}

	_, err := s.sendRequest(channel, req)
	return err
}

