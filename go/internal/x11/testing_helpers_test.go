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

	// For now, we assume all events in these tests are 32 bytes.
	// In a real scenario, we'd need to peek at the header to determine length (e.g. for GenericEvent).
	var header [32]byte
	_, err := io.ReadFull(buf, header[:])
	if err == io.EOF {
		return nil
	}
	require.NoError(t, err)

	// Use wire.ParseEvent to decode the message
	event, err := wire.ParseEvent(header[:], order)
	if err != nil {
		// For unknown message types or parsing errors, return a raw event
		return &wire.X11RawEvent{Data: header[:]}
	}
	return event
}
