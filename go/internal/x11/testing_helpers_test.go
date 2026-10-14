//go:build x11 && !wasm

package x11

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/c2FmZQ/sshterm/internal/x11/wire"
)

// drainMessages reads all messages from the buffer and returns them as a slice of decoded messages.
func drainMessages(t *testing.T, buf *bytes.Buffer, order binary.ByteOrder) []interface{} {
	t.Helper()
	var messages []interface{}
	for buf.Len() > 0 {
		msg := decodeOneMessage(t, buf, order)
		if msg != nil {
			messages = append(messages, msg)
		}
	}
	return messages
}

// decodeOneMessage decodes a single X11 message from the buffer.
func decodeOneMessage(t *testing.T, buf *bytes.Buffer, order binary.ByteOrder) interface{} {
	t.Helper()
	if buf.Len() < 32 {
		return nil // Not enough data for a full message
	}

	var header [32]byte
	_, err := io.ReadFull(buf, header[:])
	if err == io.EOF {
		return nil
	}
	require.NoError(t, err)

	fullBuf := header[:]
	if header[0]&0x7f == byte(wire.GenericEvent) {
		extraWords := order.Uint32(header[4:8])
		extraBytes := int(extraWords) * 4
		if extraBytes > 0 && buf.Len() >= extraBytes {
			extra := make([]byte, extraBytes)
			_, err := io.ReadFull(buf, extra)
			require.NoError(t, err)
			fullBuf = append(append([]byte(nil), header[:]...), extra...)
		}
	}

	// Use wire.ParseEvent to decode the message
	event, err := wire.ParseEvent(fullBuf, order)
	if err != nil {
		// For unknown message types or parsing errors, return a raw event
		return &wire.X11RawEvent{Data: fullBuf}
	}
	return event
}
