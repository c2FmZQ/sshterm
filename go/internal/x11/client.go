//go:build x11

package x11

import (
	"encoding/binary"
	"fmt"
	"io"
	"sync"

	"github.com/c2FmZQ/sshterm/internal/x11/wire"
)

// messageEncoder is an interface for types that can encode themselves into a byte slice.
type messageEncoder interface {
	EncodeMessage(order binary.ByteOrder) []byte
}

type x11Client struct {
	id                 uint32
	conn               io.ReadWriteCloser
	writeMu            sync.Mutex
	sequence           uint16
	byteOrder          binary.ByteOrder
	bigRequestsEnabled bool
	saveSet            map[uint32]bool
	openDevices        map[byte]*wire.DeviceInfo
	xi2EventMasks      map[uint32]map[uint16][]uint32 // window ID -> device ID -> mask
}

// send sends a message to the client.
func (c *x11Client) send(m messageEncoder) error {
	byteOrder := c.byteOrder
	if byteOrder == nil {
		byteOrder = binary.LittleEndian
	}
	encodedMsg := m.EncodeMessage(byteOrder)
	debugf("X11DEBUG: client.send(%#v) encoded: %x", m, encodedMsg)
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if _, err := c.conn.Write(encodedMsg); err != nil {
		return fmt.Errorf("failed to write message to client: %w", err)
	}
	return nil
}
