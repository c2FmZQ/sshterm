//go:build x11

package wire

import (
	"encoding/binary"
	"fmt"
)

// The X11 protocol defines a set of errors that can be returned by the server.
// Each error has a unique code, and some errors have additional data.
// The following structs define the errors that can be returned by the server.

// Error is an interface that all X11 errors implement.
type Error interface {
	// Code returns the error code.
	Code() byte
	// Sequence returns the sequence number of the request that caused the error.
	Sequence() uint16
	// BadValue returns the bad value that caused the error, if any.
	BadValue() uint32
	// MinorOp returns the minor opcode of the request that caused the error.
	MinorOp() byte
	// MajorOp returns the major opcode of the request that caused the error.
	MajorOp() byte
	// EncodeMessage encodes the error message into a byte slice.
	EncodeMessage(order binary.ByteOrder) []byte

	error
}

// baseError is a helper struct that implements the Error interface.
type baseError struct {
	seq      uint16
	badValue uint32
	minorOp  byte
	majorOp  ReqCode
	code     byte
}

func (e baseError) Code() byte       { return e.code }
func (e baseError) Sequence() uint16 { return e.seq }
func (e baseError) BadValue() uint32 { return e.badValue }
func (e baseError) MinorOp() byte    { return e.minorOp }
func (e baseError) MajorOp() byte    { return byte(e.majorOp) }
func (e baseError) Error() string {
	return fmt.Sprintf("X11 error: %d", e.code)
}

func (e *baseError) EncodeMessage(order binary.ByteOrder) []byte {
	reply := make([]byte, 32)
	reply[0] = 0 // Error type
	reply[1] = e.Code()
	order.PutUint16(reply[2:4], e.Sequence())
	order.PutUint32(reply[4:8], e.BadValue())
	order.PutUint16(reply[8:10], uint16(e.MinorOp()))
	reply[10] = e.MajorOp()
	return reply
}

// ParseError parses an X11 error message from a byte slice.
func ParseError(buf []byte, order binary.ByteOrder) (Error, error) {
	if len(buf) < 32 {
		return nil, fmt.Errorf("error message too short: %d", len(buf))
	}
	code := buf[1]
	seq := order.Uint16(buf[2:4])
	badValue := order.Uint32(buf[4:8])
	minorOp := byte(order.Uint16(buf[8:10]))
	majorOp := ReqCode(buf[10])
	return NewError(code, seq, badValue, Opcodes{Major: majorOp, Minor: minorOp}), nil
}

// RequestError: 1. The major or minor opcode does not specify a valid request.
type RequestError struct {
	baseError
}

// ValueError: 2. Some numeric value falls outside the range of values accepted by the request.
type ValueError struct {
	baseError
}

// WindowError: 3. A value for a Window argument does not name a defined Window.
type WindowError struct {
	baseError
}

// PixmapError: 4. A value for a Pixmap argument does not name a defined Pixmap.
type PixmapError struct {
	baseError
}

// AtomError: 5. A value for an Atom argument does not name a defined Atom.
type AtomError struct {
	baseError
}

// CursorError: 6. A value for a Cursor argument does not name a defined Cursor.
type CursorError struct {
	baseError
}

// FontError: 7. A value for a Font argument does not name a defined Font.
type FontError struct {
	baseError
}

// MatchError: 8. An InputOnly window is used as a Drawable, or arguments don't match (e.g. depth).
type MatchError struct {
	baseError
}

// DrawableError: 9. A value for a Drawable argument does not name a defined Window or Pixmap.
type DrawableError struct {
	baseError
}

// AccessError: 10. A client attempts to grab a key/button combination already grabbed by another client.
type AccessError struct {
	baseError
}

// AllocError: 11. The server failed to allocate the requested resource (insufficient memory).
type AllocError struct {
	baseError
}

// ColormapError: 12. A value for a Colormap argument does not name a defined Colormap.
type ColormapError struct {
	baseError
}

// GContextError: 13. A value for a GContext argument does not name a defined GContext.
type GContextError struct {
	baseError
}

// IDChoiceError: 14. The value chosen for a resource identifier either is not included in the range assigned to the client or is already in use.
type IDChoiceError struct {
	baseError
}

// NameError: 15. A font or color name does not exist.
type NameError struct {
	baseError
}

// LengthError: 16. The length of a request is shorter or longer than that required to minimally contain the arguments.
type LengthError struct {
	baseError
}

// ImplementationError: 17. The server does not implement the requested action.
type ImplementationError struct {
	baseError
}

// DeviceError: 20. A value for a Device argument does not name a valid device.
type DeviceError struct {
	baseError
}

// NewError creates a new X11 error based on the error code.
func NewError(code byte, seq uint16, badValue uint32, opcodes Opcodes) Error {
	base := baseError{
		code:     code,
		seq:      seq,
		badValue: badValue,
		minorOp:  opcodes.Minor,
		majorOp:  opcodes.Major,
	}
	switch code {
	case 1:
		return &RequestError{base}
	case ValueErrorCode:
		return &ValueError{base}
	case WindowErrorCode:
		return &WindowError{base}
	case PixmapErrorCode:
		return &PixmapError{base}
	case 5:
		return &AtomError{base}
	case CursorErrorCode:
		return &CursorError{base}
	case 7:
		return &FontError{base}
	case 8:
		return &MatchError{base}
	case 9:
		return &DrawableError{base}
	case 10:
		return &AccessError{base}
	case 11:
		return &AllocError{base}
	case ColormapErrorCode:
		return &ColormapError{base}
	case GContextErrorCode:
		return &GContextError{base}
	case IDChoiceErrorCode:
		return &IDChoiceError{base}
	case 15:
		return &NameError{base}
	case 16:
		return &LengthError{base}
	case 17:
		return &ImplementationError{base}
	case DeviceErrorCode:
		return &DeviceError{base}
	default:
		return NewGenericError(seq, badValue, opcodes.Minor, opcodes.Major, code)
	}
}

// NewGenericError creates a generic error for unknown error codes.
func NewGenericError(seq uint16, badValue uint32, minorOp byte, majorOp ReqCode, code byte) *GenericError {
	return &GenericError{
		seq:      seq,
		badValue: badValue,
		minorOp:  minorOp,
		majorOp:  majorOp,
		code:     code,
	}
}

// GenericError is used for unknown errors.
type GenericError struct {
	seq      uint16
	badValue uint32
	minorOp  byte
	majorOp  ReqCode
	code     byte
}

func (e GenericError) Code() byte       { return e.code }
func (e GenericError) Sequence() uint16 { return e.seq }
func (e GenericError) BadValue() uint32 { return e.badValue }
func (e GenericError) MinorOp() byte    { return e.minorOp }
func (e GenericError) MajorOp() byte    { return byte(e.majorOp) }
func (e GenericError) Error() string {
	return fmt.Sprintf("unknown X11 error: %d", e.code)
}

func (e *GenericError) EncodeMessage(order binary.ByteOrder) []byte {
	reply := make([]byte, 32)
	reply[0] = 0 // Error type
	reply[1] = e.Code()
	order.PutUint16(reply[2:4], e.Sequence())
	order.PutUint32(reply[4:8], e.BadValue())
	order.PutUint16(reply[8:10], uint16(e.MinorOp()))
	reply[10] = e.MajorOp()
	return reply
}
