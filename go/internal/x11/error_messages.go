//go:build x11

package x11

type BadColor struct {
	seq      uint16
	badValue uint32
	minorOp  byte
	majorOp  reqCode
}

func (e BadColor) Code() byte       { return ColormapError }
func (e BadColor) Sequence() uint16 { return e.seq }
func (e BadColor) BadValue() uint32 { return e.badValue }
func (e BadColor) MinorOp() byte    { return e.minorOp }
func (e BadColor) MajorOp() byte    { return byte(e.majorOp) }

type GenericError struct {
	seq      uint16
	badValue uint32
	minorOp  byte
	majorOp  reqCode
	code     byte
}

func (e GenericError) Code() byte       { return e.code }
func (e GenericError) Sequence() uint16 { return e.seq }
func (e GenericError) BadValue() uint32 { return e.badValue }
func (e GenericError) MinorOp() byte    { return e.minorOp }
func (e GenericError) MajorOp() byte    { return byte(e.majorOp) }
