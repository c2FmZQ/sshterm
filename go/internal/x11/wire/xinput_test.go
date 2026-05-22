//go:build x11

package wire

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
)







func TestParseChangeKeyboardDeviceRequest(t *testing.T) {
	t.Run("valid request", func(t *testing.T) {
		order := binary.LittleEndian
		request := &ChangeKeyboardDeviceRequest{
			DeviceID: 5,
		}

		encoded := request.EncodeMessage(order)
		decoded, err := ParseChangeKeyboardDeviceRequest(order, encoded[4:], 1)
		assert.NoError(t, err)
		assert.NotNil(t, decoded)
		assert.Equal(t, request, decoded)
	})

	t.Run("invalid length", func(t *testing.T) {
		_, err := ParseChangeKeyboardDeviceRequest(binary.LittleEndian, []byte{1, 2}, 1)
		assert.Error(t, err)
		assert.IsType(t, &LengthError{}, err)
	})
}

func TestParseListInputDevicesRequest(t *testing.T) {
	t.Run("valid request", func(t *testing.T) {
		order := binary.LittleEndian
		request := &ListInputDevicesRequest{}

		encoded := request.EncodeMessage(order)
		decoded, err := ParseListInputDevicesRequest(order, encoded[4:], 1)
		assert.NoError(t, err)
		assert.NotNil(t, decoded)
		assert.Equal(t, request, decoded)
	})

	t.Run("invalid length", func(t *testing.T) {
		_, err := ParseListInputDevicesRequest(binary.LittleEndian, []byte{1, 2}, 1)
		assert.Error(t, err)
		assert.IsType(t, &LengthError{}, err)
	})
}

func TestParseOpenDeviceRequest(t *testing.T) {
	t.Run("valid request", func(t *testing.T) {
		order := binary.LittleEndian
		request := &OpenDeviceRequest{
			DeviceID: 5,
		}

		encoded := request.EncodeMessage(order)
		decoded, err := ParseOpenDeviceRequest(order, encoded[4:], 1)
		assert.NoError(t, err)
		assert.NotNil(t, decoded)
		assert.Equal(t, request, decoded)
	})

	t.Run("invalid length", func(t *testing.T) {
		_, err := ParseOpenDeviceRequest(binary.LittleEndian, []byte{1, 2}, 1)
		assert.Error(t, err)
		assert.IsType(t, &LengthError{}, err)
	})
}

func TestParseSetDeviceModeRequest(t *testing.T) {
	t.Run("valid request", func(t *testing.T) {
		order := binary.LittleEndian
		request := &SetDeviceModeRequest{
			DeviceID: 5,
			Mode:     1,
		}

		encoded := request.EncodeMessage(order)
		decoded, err := ParseSetDeviceModeRequest(order, encoded[4:], 1)
		assert.NoError(t, err)
		assert.NotNil(t, decoded)
		assert.Equal(t, request, decoded)
	})

	t.Run("invalid length", func(t *testing.T) {
		_, err := ParseSetDeviceModeRequest(binary.LittleEndian, []byte{1, 2}, 1)
		assert.Error(t, err)
		assert.IsType(t, &LengthError{}, err)
	})
}

func TestParseSetDeviceValuatorsRequest(t *testing.T) {
	t.Run("valid request", func(t *testing.T) {
		order := binary.LittleEndian
		request := &SetDeviceValuatorsRequest{
			DeviceID:      5,
			FirstValuator: 1,
			NumValuators:  2,
			Valuators:     []int32{100, 200},
		}

		encoded := request.EncodeMessage(order)
		decoded, err := ParseSetDeviceValuatorsRequest(order, encoded[4:], 1)
		assert.NoError(t, err)
		assert.NotNil(t, decoded)
		assert.Equal(t, request, decoded)
	})

	t.Run("invalid length", func(t *testing.T) {
		_, err := ParseSetDeviceValuatorsRequest(binary.LittleEndian, []byte{1, 2}, 1)
		assert.Error(t, err)
		assert.IsType(t, &LengthError{}, err)
	})
}

func TestParseGetDeviceControlRequest(t *testing.T) {
	t.Run("valid request", func(t *testing.T) {
		order := binary.LittleEndian
		request := &GetDeviceControlRequest{
			DeviceID: 5,
			Control:  1,
		}

		encoded := request.EncodeMessage(order)
		decoded, err := ParseGetDeviceControlRequest(order, encoded[4:], 1)
		assert.NoError(t, err)
		assert.NotNil(t, decoded)
		assert.Equal(t, request, decoded)
	})
}

func TestParseChangeDeviceControlRequest(t *testing.T) {
	t.Run("valid device resolution control", func(t *testing.T) {
		order := binary.LittleEndian
		request := &ChangeDeviceControlRequest{
			DeviceID: 10,
			Control: &DeviceResolutionControl{
				FirstValuator: 1,
				NumValuators:  2,
				Resolutions:   []uint32{100, 200},
			},
		}

		encoded := request.EncodeMessage(order)
		decoded, err := ParseChangeDeviceControlRequest(order, encoded[4:], 1)
		assert.NoError(t, err)
		assert.NotNil(t, decoded)
		assert.Equal(t, request, decoded)
	})

	t.Run("invalid control id", func(t *testing.T) {
		buf := new(bytes.Buffer)
		buf.WriteByte(10) // device ID
		buf.WriteByte(0)  // padding
		binary.Write(buf, binary.LittleEndian, uint16(99)) // invalid control ID
		_, err := ParseChangeDeviceControlRequest(binary.LittleEndian, buf.Bytes(), 1)
		assert.Error(t, err)
		assert.IsType(t, &ValueError{}, err)
		e := err.(Error)
		assert.Equal(t, byte(ValueErrorCode), e.Code())
	})

	t.Run("invalid length", func(t *testing.T) {
		buf := new(bytes.Buffer)
		buf.WriteByte(10) // device ID
		buf.WriteByte(0)  // padding
		binary.Write(buf, binary.LittleEndian, uint16(DeviceResolution))
		binary.Write(buf, binary.LittleEndian, uint16(10)) // invalid length
		_, err := ParseChangeDeviceControlRequest(binary.LittleEndian, buf.Bytes(), 1)
		assert.Error(t, err)
		assert.IsType(t, &LengthError{}, err)
		e := err.(Error)
		assert.Equal(t, byte(LengthErrorCode), e.Code())
	})
}

func TestParseChangePointerDeviceRequest(t *testing.T) {
	t.Run("valid request", func(t *testing.T) {
		order := binary.LittleEndian
		request := &ChangePointerDeviceRequest{
			XAxis:    1,
			YAxis:    2,
			DeviceID: 5,
		}

		encoded := request.EncodeMessage(order)
		decoded, err := ParseChangePointerDeviceRequest(order, encoded[4:], 1)
		assert.NoError(t, err)
		assert.NotNil(t, decoded)
		assert.Equal(t, request, decoded)
	})

	t.Run("invalid length", func(t *testing.T) {
		_, err := ParseChangePointerDeviceRequest(binary.LittleEndian, []byte{1, 2}, 1)
		assert.Error(t, err)
		assert.IsType(t, &LengthError{}, err)
	})
}

func TestParseGetDeviceFocusRequest(t *testing.T) {
	t.Run("valid request", func(t *testing.T) {
		order := binary.LittleEndian
		request := &GetDeviceFocusRequest{
			DeviceID: 5,
		}

		encoded := request.EncodeMessage(order)
		decoded, err := ParseGetDeviceFocusRequest(order, encoded[4:], 1)
		assert.NoError(t, err)
		assert.NotNil(t, decoded)
		assert.Equal(t, request, decoded)
	})
}

func TestParseSetDeviceFocusRequest(t *testing.T) {
	t.Run("valid request", func(t *testing.T) {
		order := binary.LittleEndian
		request := &SetDeviceFocusRequest{
			Focus:    123,
			Time:     100,
			RevertTo: 1,
			DeviceID: 5,
		}

		encoded := request.EncodeMessage(order)
		decoded, err := ParseSetDeviceFocusRequest(order, encoded[4:], 1)
		assert.NoError(t, err)
		assert.NotNil(t, decoded)
		assert.Equal(t, request, decoded)
	})
}

func TestParseGetFeedbackControlRequest(t *testing.T) {
	t.Run("valid request", func(t *testing.T) {
		order := binary.LittleEndian
		request := &GetFeedbackControlRequest{
			DeviceID: 5,
		}

		encoded := request.EncodeMessage(order)
		decoded, err := ParseGetFeedbackControlRequest(order, encoded[4:], 1)
		assert.NoError(t, err)
		assert.NotNil(t, decoded)
		assert.Equal(t, request, decoded)
	})
}

func TestParseChangeFeedbackControlRequest(t *testing.T) {
	t.Run("valid request", func(t *testing.T) {
		order := binary.LittleEndian
		request := &ChangeFeedbackControlRequest{
			Mask:      1,
			DeviceID:  5,
			ControlID: 10,
			Control:   []byte{1, 2, 3, 4},
		}

		encoded := request.EncodeMessage(order)
		decoded, err := ParseChangeFeedbackControlRequest(order, encoded[4:], 1)
		assert.NoError(t, err)
		assert.NotNil(t, decoded)
		assert.Equal(t, request, decoded)
	})
}

func TestParseGetDeviceKeyMappingRequest(t *testing.T) {
	t.Run("valid request", func(t *testing.T) {
		order := binary.LittleEndian
		request := &GetDeviceKeyMappingRequest{
			DeviceID: 5,
			FirstKey: 10,
			Count:    2,
		}

		encoded := request.EncodeMessage(order)
		decoded, err := ParseGetDeviceKeyMappingRequest(order, encoded[4:], 1)
		assert.NoError(t, err)
		assert.NotNil(t, decoded)
		assert.Equal(t, request, decoded)
	})
}

func TestParseChangeDeviceKeyMappingRequest(t *testing.T) {
	t.Run("valid request", func(t *testing.T) {
		order := binary.LittleEndian
		request := &ChangeDeviceKeyMappingRequest{
			DeviceID:          5,
			FirstKey:          10,
			KeysymsPerKeycode: 2,
			KeycodeCount:      2,
			Keysyms:           []uint32{1, 2, 3, 4},
		}

		encoded := request.EncodeMessage(order)
		decoded, err := ParseChangeDeviceKeyMappingRequest(order, encoded[4:], 1)
		assert.NoError(t, err)
		assert.NotNil(t, decoded)
		assert.Equal(t, request, decoded)
	})
}

func TestParseGetDeviceModifierMappingRequest(t *testing.T) {
	t.Run("valid request", func(t *testing.T) {
		order := binary.LittleEndian
		request := &GetDeviceModifierMappingRequest{
			DeviceID: 5,
		}

		encoded := request.EncodeMessage(order)
		decoded, err := ParseGetDeviceModifierMappingRequest(order, encoded[4:], 1)
		assert.NoError(t, err)
		assert.NotNil(t, decoded)
		assert.Equal(t, request, decoded)
	})
}

func TestParseSetDeviceModifierMappingRequest(t *testing.T) {
	t.Run("valid request", func(t *testing.T) {
		order := binary.LittleEndian
		request := &SetDeviceModifierMappingRequest{
			DeviceID: 5,
			Keycodes: []byte{1, 2, 3, 4, 5, 6, 7, 8},
		}

		encoded := request.EncodeMessage(order)
		decoded, err := ParseSetDeviceModifierMappingRequest(order, encoded[4:], 1)
		assert.NoError(t, err)
		assert.NotNil(t, decoded)
		assert.Equal(t, request, decoded)
	})
}

func TestParseGetDeviceButtonMappingRequest(t *testing.T) {
	t.Run("valid request", func(t *testing.T) {
		order := binary.LittleEndian
		request := &GetDeviceButtonMappingRequest{
			DeviceID: 5,
		}

		encoded := request.EncodeMessage(order)
		decoded, err := ParseGetDeviceButtonMappingRequest(order, encoded[4:], 1)
		assert.NoError(t, err)
		assert.NotNil(t, decoded)
		assert.Equal(t, request, decoded)
	})
}

func TestParseSetDeviceButtonMappingRequest(t *testing.T) {
	t.Run("valid request", func(t *testing.T) {
		order := binary.LittleEndian
		request := &SetDeviceButtonMappingRequest{
			DeviceID: 5,
			Map:      []byte{1, 3, 2},
		}

		encoded := request.EncodeMessage(order)
		decoded, err := ParseSetDeviceButtonMappingRequest(order, encoded[4:], 1)
		assert.NoError(t, err)
		assert.NotNil(t, decoded)
		assert.Equal(t, request, decoded)
	})
}

func TestParseQueryDeviceStateRequest(t *testing.T) {
	t.Run("valid request", func(t *testing.T) {
		order := binary.LittleEndian
		request := &QueryDeviceStateRequest{
			DeviceID: 5,
		}

		encoded := request.EncodeMessage(order)
		decoded, err := ParseQueryDeviceStateRequest(order, encoded[4:], 1)
		assert.NoError(t, err)
		assert.NotNil(t, decoded)
		assert.Equal(t, request, decoded)
	})
}

func TestParseSendExtensionEventRequest(t *testing.T) {
	t.Run("valid request", func(t *testing.T) {
		order := binary.LittleEndian
		request := &SendExtensionEventRequest{
			Destination: 123,
			DeviceID:    5,
			Propagate:   true,
			NumClasses:  0,
			NumEvents:   1,
			Events:      []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
			Classes:     []uint32{},
		}

		encoded := request.EncodeMessage(order)
		decoded, err := ParseSendExtensionEventRequest(order, encoded[4:], 1)
		assert.NoError(t, err)
		assert.NotNil(t, decoded)
		assert.Equal(t, request, decoded)
	})
}

func TestParseDeviceBellRequest(t *testing.T) {
	t.Run("valid request", func(t *testing.T) {
		order := binary.LittleEndian
		request := &DeviceBellRequest{
			DeviceID:      5,
			FeedbackID:    10,
			FeedbackClass: 1,
			Percent:       50,
		}

		encoded := request.EncodeMessage(order)
		decoded, err := ParseDeviceBellRequest(order, encoded[4:], 1)
		assert.NoError(t, err)
		assert.NotNil(t, decoded)
		assert.Equal(t, request, decoded)
	})
}

func TestParseXIChangeHierarchyRequest(t *testing.T) {
	t.Run("valid request with detach slave", func(t *testing.T) {
		order := binary.LittleEndian
		request := &XIChangeHierarchyRequest{
			NumChanges: 1,
			Changes: []XIChangeHierarchyChange{
				&XIDetachSlave{
					Type:     4,
					Length:   8,
					DeviceID: 5,
				},
			},
		}

		encoded := request.EncodeMessage(order)
		decoded, err := ParseXIChangeHierarchyRequest(order, encoded[4:], 1)
		assert.NoError(t, err)
		assert.NotNil(t, decoded)
		assert.Equal(t, request, decoded)
	})
}

func TestGetExtensionVersionReply(t *testing.T) {
	order := binary.LittleEndian
	reply := &GetExtensionVersionReply{
		Sequence:     1,
		MajorVersion: 2,
		MinorVersion: 3,
	}

	encoded := reply.EncodeMessage(order)
	decoded, err := ParseGetExtensionVersionReply(order, encoded)
	assert.NoError(t, err)
	assert.Equal(t, reply, decoded)
}

func TestGetDeviceMotionEventsReply(t *testing.T) {
	order := binary.LittleEndian
	reply := &GetDeviceMotionEventsReply{
		Sequence: 1,
		NEvents:  2,
		Events: []TimeCoord{
			{Time: 1, X: 2, Y: 3},
			{Time: 4, X: 5, Y: 6},
		},
	}

	encoded := reply.EncodeMessage(order)
	decoded, err := ParseGetDeviceMotionEventsReply(order, encoded)
	assert.NoError(t, err)
	assert.Equal(t, reply, decoded)
}

func TestParseListInputDevicesReply(t *testing.T) {
	order := binary.LittleEndian
	reply := &ListInputDevicesReply{
		Sequence: 1,
		NDevices: 1,
		Devices: []*DeviceInfo{
			{
				Header: DeviceHeader{
					DeviceID:   2,
					DeviceType: 3,
					NumClasses: 1,
					Use:        4,
					Name:       "test",
				},
				Classes: []InputClassInfo{
					&KeyClassInfo{
						NumKeys:    10,
						MinKeycode: 8,
						MaxKeycode: 255,
					},
				},
			},
		},
	}

	encoded := reply.EncodeMessage(order)
	decoded, err := ParseListInputDevicesReply(order, encoded)
	assert.NoError(t, err)
	assert.Equal(t, reply, decoded)
}

func TestQueryDeviceStateReply(t *testing.T) {
	order := binary.LittleEndian
	reply := &QueryDeviceStateReply{
		Sequence:  1,
		NumEvents: 1,
		Classes: []InputClassInfo{
			&KeyClassInfo{
				NumKeys:    10,
				MinKeycode: 8,
				MaxKeycode: 255,
			},
		},
	}

	encoded := reply.EncodeMessage(order)
	decoded, err := ParseQueryDeviceStateReply(order, encoded)
	assert.NoError(t, err)
	assert.Equal(t, reply, decoded)
}

func TestGetDeviceButtonMappingReply(t *testing.T) {
	order := binary.LittleEndian
	reply := &GetDeviceButtonMappingReply{
		Sequence: 1,
		Map:      []byte{1, 2, 3, 4},
	}

	encoded := reply.EncodeMessage(order)
	decoded, err := ParseGetDeviceButtonMappingReply(order, encoded)
	assert.NoError(t, err)
	assert.Equal(t, reply, decoded)
}

func TestGetDeviceModifierMappingReply(t *testing.T) {
	order := binary.LittleEndian
	reply := &GetDeviceModifierMappingReply{
		Sequence:          1,
		NumKeycodesPerMod: 2,
		Keycodes:          []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
	}

	encoded := reply.EncodeMessage(order)
	decoded, err := ParseGetDeviceModifierMappingReply(order, encoded)
	assert.NoError(t, err)
	assert.Equal(t, reply, decoded)
}

func TestGetDeviceFocusReply(t *testing.T) {
	order := binary.LittleEndian
	reply := &GetDeviceFocusReply{
		Sequence: 1,
		Focus:    2,
		Time:     3,
		RevertTo: 4,
	}

	encoded := reply.EncodeMessage(order)
	decoded, err := ParseGetDeviceFocusReply(order, encoded)
	assert.NoError(t, err)
	assert.Equal(t, reply, decoded)
}

func TestOpenDeviceReply(t *testing.T) {
	order := binary.LittleEndian
	reply := &OpenDeviceReply{
		Sequence: 1,
		Classes: []InputClassInfo{
			&KeyClassInfo{
				NumKeys:    10,
				MinKeycode: 8,
				MaxKeycode: 255,
			},
		},
	}

	encoded := reply.EncodeMessage(order)
	decoded, err := ParseOpenDeviceReply(order, encoded)
	assert.NoError(t, err)
	assert.Equal(t, reply, decoded)
}

func TestSetDeviceModeReply(t *testing.T) {
	order := binary.LittleEndian
	reply := &SetDeviceModeReply{
		Sequence: 1,
		Status:   2,
	}

	encoded := reply.EncodeMessage(order)
	decoded, err := ParseSetDeviceModeReply(order, encoded)
	assert.NoError(t, err)
	assert.Equal(t, reply, decoded)
}

func TestSetDeviceValuatorsReply(t *testing.T) {
	order := binary.LittleEndian
	reply := &SetDeviceValuatorsReply{
		Sequence: 1,
		Status:   2,
	}

	encoded := reply.EncodeMessage(order)
	decoded, err := ParseSetDeviceValuatorsReply(order, encoded)
	assert.NoError(t, err)
	assert.Equal(t, reply, decoded)
}

func TestGetDeviceControlReply(t *testing.T) {
	order := binary.LittleEndian
	reply := &GetDeviceControlReply{
		Sequence: 1,
		Control: &DeviceResolutionState{
			NumValuators:   2,
			Resolutions:    []uint32{1, 2},
			MinResolutions: []uint32{1, 2},
			MaxResolutions: []uint32{1, 2},
		},
	}

	encoded := reply.EncodeMessage(order)
	decoded, err := ParseGetDeviceControlReply(order, encoded)
	assert.NoError(t, err)
	assert.Equal(t, reply, decoded)
}

func TestChangeDeviceControlReply(t *testing.T) {
	order := binary.LittleEndian
	reply := &ChangeDeviceControlReply{
		Sequence: 1,
		Status:   2,
	}

	encoded := reply.EncodeMessage(order)
	decoded, err := ParseChangeDeviceControlReply(order, encoded)
	assert.NoError(t, err)
	assert.Equal(t, reply, decoded)
}

func TestGetSelectedExtensionEventsReply(t *testing.T) {
	order := binary.LittleEndian
	reply := &GetSelectedExtensionEventsReply{
		Sequence:          1,
		ThisClientClasses: []uint32{1, 2},
		AllClientsClasses: []uint32{3, 4},
	}

	encoded := reply.EncodeMessage(order)
	decoded, err := ParseGetSelectedExtensionEventsReply(order, encoded)
	assert.NoError(t, err)
	assert.Equal(t, reply, decoded)
}

func TestGetDeviceDontPropagateListReply(t *testing.T) {
	order := binary.LittleEndian
	reply := &GetDeviceDontPropagateListReply{
		Sequence: 1,
		Classes:  []uint32{1, 2},
	}

	encoded := reply.EncodeMessage(order)
	decoded, err := ParseGetDeviceDontPropagateListReply(order, encoded)
	assert.NoError(t, err)
	assert.Equal(t, reply, decoded)
}

func TestCloseDeviceReply(t *testing.T) {
	order := binary.LittleEndian
	reply := &CloseDeviceReply{
		Sequence: 1,
	}

	encoded := reply.EncodeMessage(order)
	decoded, err := ParseCloseDeviceReply(order, encoded)
	assert.NoError(t, err)
	assert.Equal(t, reply, decoded)
}

func TestGrabDeviceReply(t *testing.T) {
	order := binary.LittleEndian
	reply := &GrabDeviceReply{
		Sequence: 1,
		Status:   2,
	}

	encoded := reply.EncodeMessage(order)
	decoded, err := ParseGrabDeviceReply(order, encoded)
	assert.NoError(t, err)
	assert.Equal(t, reply, decoded)
}

func TestGetDeviceKeyMappingReply(t *testing.T) {
	order := binary.LittleEndian
	reply := &GetDeviceKeyMappingReply{
		Sequence:          1,
		KeysymsPerKeycode: 2,
		Keysyms:           []uint32{1, 2},
	}

	encoded := reply.EncodeMessage(order)
	decoded, err := ParseGetDeviceKeyMappingReply(order, encoded)
	assert.NoError(t, err)
	assert.Equal(t, reply, decoded)
}

func TestSetDeviceModifierMappingReply(t *testing.T) {
	order := binary.LittleEndian
	b := []byte{0x01, 0x1b, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	want := &SetDeviceModifierMappingReply{
		Sequence: 1,
		Status:   2,
	}

	r, err := ParseSetDeviceModifierMappingReply(order, b)
	if err != nil {
		t.Fatalf("ParseSetDeviceModifierMappingReply failed: %v", err)
	}
	assert.Equal(t, want, r)

	roundtrip := r.EncodeMessage(order)
	if !bytes.Equal(b, roundtrip) {
		t.Errorf("EncodeMessage output %#v is not equal to %#v", roundtrip, b)
	}
}

func TestSetDeviceButtonMappingReply(t *testing.T) {
	order := binary.LittleEndian
	reply := &SetDeviceButtonMappingReply{
		Sequence: 1,
		Status:   2,
	}

	encoded := reply.EncodeMessage(order)
	decoded, err := ParseSetDeviceButtonMappingReply(order, encoded)
	assert.NoError(t, err)
	assert.Equal(t, reply, decoded)
}
func TestParseSelectExtensionEventRequest(t *testing.T) {
	t.Run("valid request", func(t *testing.T) {
		order := binary.LittleEndian
		request := &SelectExtensionEventRequest{
			Window:  123,
			Classes: []uint32{10, 20},
		}

		encoded := request.EncodeMessage(order)
		decoded, err := ParseSelectExtensionEventRequest(order, encoded[4:], 1)
		assert.NoError(t, err)
		assert.NotNil(t, decoded)
		assert.Equal(t, request, decoded)
	})

	t.Run("body too short", func(t *testing.T) {
		_, err := ParseSelectExtensionEventRequest(binary.LittleEndian, []byte{1, 2}, 1)
		assert.Error(t, err)
		assert.IsType(t, &LengthError{}, err)
	})

	t.Run("body length mismatch", func(t *testing.T) {
		buf := new(bytes.Buffer)
		binary.Write(buf, binary.LittleEndian, uint32(123)) // window
		binary.Write(buf, binary.LittleEndian, uint16(2))   // num_classes = 2
		buf.Write([]byte{0, 0})                             // padding
		binary.Write(buf, binary.LittleEndian, uint32(10))  // only one class

		_, err := ParseSelectExtensionEventRequest(binary.LittleEndian, buf.Bytes(), 1)
		assert.Error(t, err)
		assert.IsType(t, &LengthError{}, err)
	})
}
func TestParseGrabDeviceKeyRequest(t *testing.T) {
	t.Run("valid request", func(t *testing.T) {
		order := binary.LittleEndian
		request := &GrabDeviceKeyRequest{
			GrabWindow:      123,
			Modifiers:       0,
			Key:             10,
			DeviceID:        5,
			OwnerEvents:     true,
			ThisDeviceMode:  1,
			OtherDeviceMode: 0,
			NumClasses:      0,
			Classes:         []uint32{},
		}

		encoded := request.EncodeMessage(order)
		decoded, err := ParseGrabDeviceKeyRequest(order, encoded[4:], 1)
		assert.NoError(t, err)
		assert.NotNil(t, decoded)
		assert.Equal(t, request, decoded)
	})

	t.Run("invalid length", func(t *testing.T) {
		_, err := ParseGrabDeviceKeyRequest(binary.LittleEndian, []byte{1, 2, 3}, 1)
		assert.Error(t, err)
		assert.IsType(t, &LengthError{}, err)
	})

	t.Run("body length mismatch", func(t *testing.T) {
		buf := new(bytes.Buffer)
		binary.Write(buf, binary.LittleEndian, uint32(123)) // grab_window
		binary.Write(buf, binary.LittleEndian, uint16(2))   // num_classes = 2
		buf.WriteByte(1) // owner_events
		buf.WriteByte(1) // this_device_mode
		buf.WriteByte(0) // other_device_mode
		buf.WriteByte(5) // device_id
		binary.Write(buf, binary.LittleEndian, uint16(0)) // modifiers
		buf.WriteByte(10)   // key
		binary.Write(buf, binary.LittleEndian, uint32(10))  // only one class

		_, err := ParseGrabDeviceKeyRequest(binary.LittleEndian, buf.Bytes(), 1)
		assert.Error(t, err)
		assert.IsType(t, &LengthError{}, err)
	})
}
func TestParseUngrabDeviceKeyRequest(t *testing.T) {
	t.Run("valid request", func(t *testing.T) {
		order := binary.LittleEndian
		request := &UngrabDeviceKeyRequest{
			GrabWindow: 123,
			Modifiers:  1,
			DeviceID:   5,
			Key:        10,
		}

		encoded := request.EncodeMessage(order)
		decoded, err := ParseUngrabDeviceKeyRequest(order, encoded[4:], 1)
		assert.NoError(t, err)
		assert.NotNil(t, decoded)
		assert.Equal(t, request, decoded)
	})

	t.Run("invalid length", func(t *testing.T) {
		_, err := ParseUngrabDeviceKeyRequest(binary.LittleEndian, []byte{1, 2, 3}, 1)
		assert.Error(t, err)
		assert.IsType(t, &LengthError{}, err)
	})
}
func TestParseGrabDeviceButtonRequest(t *testing.T) {
	t.Run("valid request", func(t *testing.T) {
		order := binary.LittleEndian
		request := &GrabDeviceButtonRequest{
			GrabWindow:      123,
			Modifiers:       1,
			Button:          10,
			DeviceID:        5,
			OwnerEvents:     true,
			ThisDeviceMode:  1,
			OtherDeviceMode: 0,
			NumClasses:      0,
			Classes:         []uint32{},
		}

		encoded := request.EncodeMessage(order)
		decoded, err := ParseGrabDeviceButtonRequest(order, encoded[4:], 1)
		assert.NoError(t, err)
		assert.NotNil(t, decoded)
		assert.Equal(t, request, decoded)
	})
}
func TestParseAllowDeviceEventsRequest(t *testing.T) {
	t.Run("valid request", func(t *testing.T) {
		order := binary.LittleEndian
		request := &AllowDeviceEventsRequest{
			Time:     0,
			DeviceID: 5,
			Mode:     1,
		}

		encoded := request.EncodeMessage(order)
		decoded, err := ParseAllowDeviceEventsRequest(order, encoded[4:], 1)
		assert.NoError(t, err)
		assert.NotNil(t, decoded)
		assert.Equal(t, request, decoded)
	})
}
