//go:build x11

package wire

import "encoding/binary"

const (
	// BigRequestsExtensionName is the name of the Big Requests extension.
	BigRequestsExtensionName = "BIG-REQUESTS"
)

// EnableBigRequestsRequest represents a request to enable the Big Requests extension.
type EnableBigRequestsRequest struct{}

// OpCode returns the opcode for the Big Requests extension.
func (r *EnableBigRequestsRequest) OpCode() ReqCode {
	return BigRequestsOpcode
}

// ParseEnableBigRequestsRequest parses an EnableBigRequests request.
func ParseEnableBigRequestsRequest(order binary.ByteOrder, raw []byte, seq uint16) (*EnableBigRequestsRequest, error) {
	return &EnableBigRequestsRequest{}, nil
}

// BigRequestsEnableReply represents a reply to an EnableBigRequests request.
type BigRequestsEnableReply struct {
	Sequence         uint16 // Sequence number.
	MaxRequestLength uint32 // Maximum request length supported by the server.
}

// EncodeMessage encodes the BigRequestsEnableReply into a byte slice.
func (r *BigRequestsEnableReply) EncodeMessage(order binary.ByteOrder) []byte {
	reply := make([]byte, 32)
	reply[0] = 1 // Reply
	order.PutUint16(reply[2:4], r.Sequence)
	order.PutUint32(reply[8:12], r.MaxRequestLength)
	return reply
}
