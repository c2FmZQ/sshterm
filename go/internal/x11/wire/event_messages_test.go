//go:build x11 && !wasm

package wire

import (
	"encoding/binary"
	"reflect"
	"testing"
)

func TestEventMessages(t *testing.T) {
	testCases := []struct {
		name  string
		event Event
	}{
		{
			"KeyEvent",
			&KeyEvent{
				Opcode:     KeyPress,
				Detail:     1,
				Sequence:   2,
				Time:       3,
				Root:       4,
				Event:      5,
				Child:      6,
				RootX:      7,
				RootY:      8,
				EventX:     9,
				EventY:     10,
				State:      11,
				SameScreen: true,
			},
		},
		{
			"ButtonPressEvent",
			&ButtonPressEvent{
				Detail:     1,
				Sequence:   2,
				Time:       3,
				Root:       4,
				Event:      5,
				Child:      6,
				RootX:      7,
				RootY:      8,
				EventX:     9,
				EventY:     10,
				State:      11,
				SameScreen: true,
			},
		},
		{
			"ButtonReleaseEvent",
			&ButtonReleaseEvent{
				Detail:     1,
				Sequence:   2,
				Time:       3,
				Root:       4,
				Event:      5,
				Child:      6,
				RootX:      7,
				RootY:      8,
				EventX:     9,
				EventY:     10,
				State:      11,
				SameScreen: true,
			},
		},
		{
			"MotionNotifyEvent",
			&MotionNotifyEvent{
				Detail:     1,
				Sequence:   2,
				Time:       3,
				Root:       4,
				Event:      5,
				Child:      6,
				RootX:      7,
				RootY:      8,
				EventX:     9,
				EventY:     10,
				State:      11,
				SameScreen: true,
			},
		},
		{
			"EnterNotifyEvent",
			&EnterNotifyEvent{
				Detail:     1,
				Sequence:   2,
				Time:       3,
				Root:       4,
				Event:      5,
				Child:      6,
				RootX:      7,
				RootY:      8,
				EventX:     9,
				EventY:     10,
				State:      11,
				Mode:       12,
				SameScreen: true,
				Focus:      true,
			},
		},
		{
			"LeaveNotifyEvent",
			&LeaveNotifyEvent{
				Detail:     1,
				Sequence:   2,
				Time:       3,
				Root:       4,
				Event:      5,
				Child:      6,
				RootX:      7,
				RootY:      8,
				EventX:     9,
				EventY:     10,
				State:      11,
				Mode:       12,
				SameScreen: true,
				Focus:      true,
			},
		},
		{
			"ExposeEvent",
			&ExposeEvent{
				Sequence: 1,
				Window:   2,
				X:        3,
				Y:        4,
				Width:    5,
				Height:   6,
				Count:    7,
			},
		},
		{
			"ConfigureNotifyEvent",
			&ConfigureNotifyEvent{
				Sequence:         1,
				Event:            2,
				Window:           3,
				AboveSibling:     4,
				X:                5,
				Y:                6,
				Width:            7,
				Height:           8,
				BorderWidth:      9,
				OverrideRedirect: true,
			},
		},
		{
			"SelectionNotifyEvent",
			&SelectionNotifyEvent{
				Sequence:  1,
				Requestor: 2,
				Selection: 3,
				Target:    4,
				Property:  5,
				Time:      6,
			},
		},
		{
			"ColormapNotifyEvent",
			&ColormapNotifyEvent{
				Sequence: 1,
				Window:   2,
				Colormap: 3,
				New:      true,
				State:    4,
			},
		},
		{
			"ClientMessageEvent",
			&ClientMessageEvent{
				Sequence:    1,
				Format:      2,
				Window:      3,
				MessageType: 4,
				Data:        [20]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20},
			},
		},
		{
			"DeviceKeyPressEvent",
			&DeviceKeyPressEvent{
				BaseEventCode: 64,
				DeviceID:      1,
				Sequence:      2,
				Time:          3,
				Root:          4,
				Event:         5,
				Child:         6,
				RootX:         7,
				RootY:         8,
				EventX:        9,
				EventY:        10,
				State:         11,
				KeyCode:       12,
			},
		},
		{
			"DeviceKeyReleaseEvent",
			&DeviceKeyReleaseEvent{
				BaseEventCode: 64,
				DeviceID:      1,
				Sequence:      2,
				Time:          3,
				Root:          4,
				Event:         5,
				Child:         6,
				RootX:         7,
				RootY:         8,
				EventX:        9,
				EventY:        10,
				State:         11,
				KeyCode:       12,
			},
		},
		{
			"DeviceButtonPressEvent",
			&DeviceButtonPressEvent{
				BaseEventCode: 64,
				DeviceID:      1,
				Sequence:      2,
				Time:          3,
				Root:          4,
				Event:         5,
				Child:         6,
				RootX:         7,
				RootY:         8,
				EventX:        9,
				EventY:        10,
				State:         11,
				Detail:        12,
			},
		},
		{
			"DeviceButtonReleaseEvent",
			&DeviceButtonReleaseEvent{
				BaseEventCode: 64,
				Sequence:      2,
				DeviceID:      1,
				Time:          3,
				Button:        12,
				Root:          4,
				Event:         5,
				Child:         6,
				RootX:         7,
				RootY:         8,
				EventX:        9,
				EventY:        10,
				State:         11,
			},
		},
		{
			"DeviceMotionNotifyEvent",
			&DeviceMotionNotifyEvent{
				BaseEventCode: 64,
				Sequence:      2,
				DeviceID:      1,
				Time:          3,
				Detail:        12,
				Root:          4,
				Event:         5,
				Child:         6,
				RootX:         7,
				RootY:         8,
				EventX:        9,
				EventY:        10,
				State:         11,
			},
		},
		{
			"ProximityInEvent",
			&ProximityInEvent{
				BaseEventCode: 64,
				Sequence:      2,
				DeviceID:      1,
				Time:          3,
				Detail:        12,
				Root:          4,
				Event:         5,
				Child:         6,
				RootX:         7,
				RootY:         8,
				EventX:        9,
				EventY:        10,
				State:         11,
			},
		},
		{
			"ProximityOutEvent",
			&ProximityOutEvent{
				BaseEventCode: 64,
				Sequence:      2,
				DeviceID:      1,
				Time:          3,
				Detail:        12,
				Root:          4,
				Event:         5,
				Child:         6,
				RootX:         7,
				RootY:         8,
				EventX:        9,
				EventY:        10,
				State:         11,
			},
		},
		{
			"GraphicsExposureEvent",
			&GraphicsExposureEvent{
				Sequence:    1,
				Drawable:    2,
				X:           3,
				Y:           4,
				Width:       5,
				Height:      6,
				MinorOpcode: 7,
				Count:       8,
				MajorOpcode: 9,
			},
		},
		{
			"NoExposureEvent",
			&NoExposureEvent{
				Sequence:    1,
				Drawable:    2,
				MinorOpcode: 3,
				MajorOpcode: 4,
			},
		},
		{
			"VisibilityNotifyEvent",
			&VisibilityNotifyEvent{
				Sequence: 1,
				Window:   2,
				State:    3,
			},
		},
		{
			"CreateNotifyEvent",
			&CreateNotifyEvent{
				Sequence:         1,
				Parent:           2,
				Window:           3,
				X:                4,
				Y:                5,
				Width:            6,
				Height:           7,
				BorderWidth:      8,
				OverrideRedirect: true,
			},
		},
		{
			"DestroyNotifyEvent",
			&DestroyNotifyEvent{
				Sequence: 1,
				Event:    2,
				Window:   3,
			},
		},
		{
			"UnmapNotifyEvent",
			&UnmapNotifyEvent{
				Sequence:    1,
				Event:       2,
				Window:      3,
				FromConfigure: true,
			},
		},
		{
			"MapNotifyEvent",
			&MapNotifyEvent{
				Sequence:         1,
				Event:            2,
				Window:           3,
				OverrideRedirect: true,
			},
		},
		{
			"MapRequestEvent",
			&MapRequestEvent{
				Sequence: 1,
				Parent:   2,
				Window:   3,
			},
		},
		{
			"ReparentNotifyEvent",
			&ReparentNotifyEvent{
				Sequence:         1,
				Event:            2,
				Window:           3,
				Parent:           4,
				X:                5,
				Y:                6,
				OverrideRedirect: true,
			},
		},
		{
			"ConfigureRequestEvent",
			&ConfigureRequestEvent{
				Sequence:    1,
				StackMode:   2,
				Parent:      3,
				Window:      4,
				Sibling:     5,
				X:           6,
				Y:           7,
				Width:       8,
				Height:      9,
				BorderWidth: 10,
				ValueMask:   11,
			},
		},
		{
			"GravityNotifyEvent",
			&GravityNotifyEvent{
				Sequence: 1,
				Event:    2,
				Window:   3,
				X:        4,
				Y:        5,
			},
		},
		{
			"ResizeRequestEvent",
			&ResizeRequestEvent{
				Sequence: 1,
				Window:   2,
				Width:    3,
				Height:   4,
			},
		},
		{
			"CirculateNotifyEvent",
			&CirculateNotifyEvent{
				Sequence: 1,
				Event:    2,
				Window:   3,
				Place:    4,
			},
		},
		{
			"CirculateRequestEvent",
			&CirculateRequestEvent{
				Sequence: 1,
				Parent:   2,
				Window:   3,
				Place:    4,
			},
		},
		{
			"PropertyNotifyEvent",
			&PropertyNotifyEvent{
				Sequence: 1,
				Window:   2,
				Atom:     3,
				Time:     4,
				State:    5,
			},
		},
		{
			"SelectionClearEvent",
			&SelectionClearEvent{
				Sequence:  1,
				Owner:     2,
				Selection: 3,
				Time:      4,
			},
		},
		{
			"SelectionRequestEvent",
			&SelectionRequestEvent{
				Sequence:  1,
				Owner:     2,
				Requestor: 3,
				Selection: 4,
				Target:    5,
				Property:  6,
				Time:      7,
			},
		},
		{
			"MappingNotifyEvent",
			&MappingNotifyEvent{
				Sequence:     1,
				Request:      2,
				FirstKeycode: 3,
				Count:        4,
			},
		},
		{
			"GenericEvent",
			&GenericEventData{
				Sequence:  1,
				Extension: 2,
				EventType: 3,
				Length:    0,
				EventData: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20},
			},
		},
		{
			"GenericEventWithLength",
			&GenericEventData{
				Sequence:  1,
				Extension: 2,
				EventType: 3,
				Length:    4,
				EventData: []byte{
					1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
					21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36,
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			encoded := tc.event.EncodeMessage(binary.LittleEndian)
			decoded, err := ParseEvent(encoded, binary.LittleEndian)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(tc.event, decoded) {
				t.Errorf("got %v, want %v", decoded, tc.event)
			}
		})
	}
}
