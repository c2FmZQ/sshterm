//go:build x11

package x11

import (
	"github.com/c2FmZQ/sshterm/internal/x11/wire"
)

func (s *x11Server) handleXInputRequest(client *x11Client, req wire.Request, seq uint16) (reply messageEncoder) {
	switch p := req.(type) {
	case *wire.GetExtensionVersionRequest:
		return &wire.GetExtensionVersionReply{
			Sequence:     seq,
			MajorVersion: 2,
			MinorVersion: 2,
		}

	case *wire.ListInputDevicesRequest:
		return &wire.ListInputDevicesReply{
			Sequence: seq,
			Devices:  []*wire.DeviceInfo{virtualPointer, virtualKeyboard},
		}

	case *wire.OpenDeviceRequest:
		var selectedDevice *wire.DeviceInfo
		if p.DeviceID == virtualPointer.Header.DeviceID {
			selectedDevice = virtualPointer
		} else if p.DeviceID == virtualKeyboard.Header.DeviceID {
			selectedDevice = virtualKeyboard
		} else {
			return wire.NewError(wire.ValueErrorCode, seq, uint32(p.DeviceID), wire.Opcodes{Major: wire.XInputOpcode, Minor: wire.XOpenDevice})
		}

		// Create a new deviceInfo instance for the client, so event masks are not shared.
		newClasses := make([]wire.InputClassInfo, len(selectedDevice.Classes))
		copy(newClasses, selectedDevice.Classes)
		newDeviceInfo := &wire.DeviceInfo{
			Header:     selectedDevice.Header,
			Classes:    newClasses,
			EventMasks: make(map[uint32]uint32),
		}
		client.openDevices[p.DeviceID] = newDeviceInfo
		return &wire.OpenDeviceReply{Sequence: seq, Classes: newDeviceInfo.Classes}

	case *wire.SetDeviceModeRequest:
		device, ok := client.openDevices[p.DeviceID]
		if !ok {
			return wire.NewError(wire.ValueErrorCode, seq, uint32(p.DeviceID), wire.Opcodes{Major: wire.XInputOpcode, Minor: wire.XSetDeviceMode})
		}
		var valuatorInfo *wire.ValuatorClassInfo
		for _, class := range device.Classes {
			if vc, ok := class.(*wire.ValuatorClassInfo); ok {
				valuatorInfo = vc
				break
			}
		}
		if valuatorInfo == nil {
			return wire.NewError(wire.MatchErrorCode, seq, 0, wire.Opcodes{Major: wire.XInputOpcode, Minor: wire.XSetDeviceMode})
		}
		valuatorInfo.Mode = p.Mode
		return &wire.SetDeviceModeReply{Sequence: seq, Status: wire.GrabSuccess}

	case *wire.SetDeviceValuatorsRequest:
		device, ok := client.openDevices[p.DeviceID]
		if !ok {
			return wire.NewError(wire.ValueErrorCode, seq, uint32(p.DeviceID), wire.Opcodes{Major: wire.XInputOpcode, Minor: wire.XSetDeviceValuators})
		}
		var valuatorInfo *wire.ValuatorClassInfo
		for _, class := range device.Classes {
			if vc, ok := class.(*wire.ValuatorClassInfo); ok {
				valuatorInfo = vc
				break
			}
		}
		if valuatorInfo == nil {
			return wire.NewError(wire.MatchErrorCode, seq, 0, wire.Opcodes{Major: wire.XInputOpcode, Minor: wire.XSetDeviceValuators})
		}
		if int(p.FirstValuator)+int(p.NumValuators) > len(valuatorInfo.Axes) {
			return wire.NewError(wire.ValueErrorCode, seq, 0, wire.Opcodes{Major: wire.XInputOpcode, Minor: wire.XSetDeviceValuators})
		}
		for i := 0; i < int(p.NumValuators); i++ {
			valuatorInfo.Axes[int(p.FirstValuator)+i].Value = p.Valuators[i]
		}
		return &wire.SetDeviceValuatorsReply{Sequence: seq, Status: wire.GrabSuccess}

	case *wire.GetDeviceControlRequest:
		device, ok := client.openDevices[p.DeviceID]
		if !ok {
			return wire.NewError(wire.ValueErrorCode, seq, uint32(p.DeviceID), wire.Opcodes{Major: wire.XInputOpcode, Minor: wire.XGetDeviceControl})
		}
		var valuatorInfo *wire.ValuatorClassInfo
		for _, class := range device.Classes {
			if vc, ok := class.(*wire.ValuatorClassInfo); ok {
				valuatorInfo = vc
				break
			}
		}
		if valuatorInfo == nil {
			return wire.NewError(wire.MatchErrorCode, seq, 0, wire.Opcodes{Major: wire.XInputOpcode, Minor: wire.XGetDeviceControl})
		}
		resolutions := make([]uint32, len(valuatorInfo.Axes))
		minResolutions := make([]uint32, len(valuatorInfo.Axes))
		maxResolutions := make([]uint32, len(valuatorInfo.Axes))
		for i, axis := range valuatorInfo.Axes {
			resolutions[i] = axis.Resolution
			minResolutions[i] = 0
			maxResolutions[i] = 1000
		}
		return &wire.GetDeviceControlReply{
			Sequence: seq,
			Control: &wire.DeviceResolutionState{
				NumValuators:   byte(len(valuatorInfo.Axes)),
				Resolutions:    resolutions,
				MinResolutions: minResolutions,
				MaxResolutions: maxResolutions,
			},
		}

	case *wire.ChangeDeviceControlRequest:
		device, ok := client.openDevices[p.DeviceID]
		if !ok {
			return wire.NewError(wire.ValueErrorCode, seq, uint32(p.DeviceID), wire.Opcodes{Major: wire.XInputOpcode, Minor: wire.XChangeDeviceControl})
		}
		var valuatorInfo *wire.ValuatorClassInfo
		for _, class := range device.Classes {
			if vc, ok := class.(*wire.ValuatorClassInfo); ok {
				valuatorInfo = vc
				break
			}
		}
		if valuatorInfo == nil {
			return wire.NewError(wire.MatchErrorCode, seq, 0, wire.Opcodes{Major: wire.XInputOpcode, Minor: wire.XChangeDeviceControl})
		}
		resolutionControl, ok := p.Control.(*wire.DeviceResolutionControl)
		if !ok {
			return wire.NewError(wire.ValueErrorCode, seq, 0, wire.Opcodes{Major: wire.XInputOpcode, Minor: wire.XChangeDeviceControl})
		}
		if int(resolutionControl.FirstValuator)+int(resolutionControl.NumValuators) > len(valuatorInfo.Axes) {
			return wire.NewError(wire.ValueErrorCode, seq, 0, wire.Opcodes{Major: wire.XInputOpcode, Minor: wire.XChangeDeviceControl})
		}
		for i := 0; i < int(resolutionControl.NumValuators); i++ {
			valuatorInfo.Axes[int(resolutionControl.FirstValuator)+i].Resolution = resolutionControl.Resolutions[i]
		}
		return &wire.ChangeDeviceControlReply{Sequence: seq, Status: wire.GrabSuccess}

	case *wire.GetSelectedExtensionEventsRequest:
		var thisClientClasses, allClientsClasses []uint32
		for _, dev := range client.openDevices {
			if mask, ok := dev.EventMasks[p.Window]; ok {
				class := (mask << 8) | uint32(dev.Header.DeviceID)
				thisClientClasses = append(thisClientClasses, class)
			}
		}
		for _, c := range s.clients {
			for _, dev := range c.openDevices {
				if mask, ok := dev.EventMasks[p.Window]; ok {
					class := (mask << 8) | uint32(dev.Header.DeviceID)
					allClientsClasses = append(allClientsClasses, class)
				}
			}
		}
		return &wire.GetSelectedExtensionEventsReply{
			Sequence:          seq,
			ThisClientClasses: thisClientClasses,
			AllClientsClasses: allClientsClasses,
		}

	case *wire.ChangeDeviceDontPropagateListRequest:
		win, ok := s.windows[xID(p.Window)]
		if !ok {
			return wire.NewError(wire.WindowErrorCode, seq, uint32(p.Window), wire.Opcodes{Major: wire.XInputOpcode, Minor: wire.XChangeDeviceDontPropagateList})
		}
		if win.dontPropagateDeviceEvents == nil {
			win.dontPropagateDeviceEvents = make(map[uint32]bool)
		}
		for _, class := range p.Classes {
			if p.Mode == 0 { // AddToList
				win.dontPropagateDeviceEvents[class] = true
			} else { // DeleteFromList
				delete(win.dontPropagateDeviceEvents, class)
			}
		}
		return nil

	case *wire.AllowDeviceEventsRequest:
		s.frontend.AllowEvents(client.id, p.Mode, p.Time)
		return nil

	case *wire.ChangeKeyboardDeviceRequest:
		return wire.NewError(wire.DeviceErrorCode, seq, 0, wire.Opcodes{Major: wire.XInputOpcode, Minor: wire.XChangeKeyboardDevice})

	case *wire.ChangePointerDeviceRequest:
		return wire.NewError(wire.DeviceErrorCode, seq, 0, wire.Opcodes{Major: wire.XInputOpcode, Minor: wire.XChangePointerDevice})

	case *wire.GetDeviceDontPropagateListRequest:
		win, ok := s.windows[xID(p.Window)]
		if !ok {
			return wire.NewError(wire.WindowErrorCode, seq, uint32(p.Window), wire.Opcodes{Major: wire.XInputOpcode, Minor: wire.XGetDeviceDontPropagateList})
		}
		classes := make([]uint32, 0, len(win.dontPropagateDeviceEvents))
		for class := range win.dontPropagateDeviceEvents {
			classes = append(classes, class)
		}
		return &wire.GetDeviceDontPropagateListReply{
			Sequence: seq,
			Classes:  classes,
		}

	case *wire.SendExtensionEventRequest:
		dest := p.Destination
		numEvents := p.NumEvents
		events := p.Events
		classes := p.Classes

		// Assuming a 1-to-1 mapping between events and classes
		for i := 0; i < int(numEvents); i++ {
			eventData := events[i*32 : (i+1)*32]
			class := classes[i] // classes array already holds uint32

			eventMask := class >> 8
			deviceID := byte(class & 0xFF)

			for _, c := range s.clients {
				if dev, ok := c.openDevices[deviceID]; ok {
					if mask, ok := dev.EventMasks[uint32(dest)]; ok { // Cast dest to uint32
						if (mask & eventMask) != 0 {
							// The client has selected for this event.
							// Send the raw event, but update the sequence number.
							c.byteOrder.PutUint16(eventData[2:4], c.sequence-1)
							rawEvent := &wire.X11RawEvent{Data: eventData}
							c.send(rawEvent)
						}
					}
				}
			}
		}
		return nil

	case *wire.CloseDeviceRequest:
		delete(client.openDevices, p.DeviceID)
		return &wire.CloseDeviceReply{Sequence: seq}

	case *wire.SelectExtensionEventRequest:
		windowID := uint32(p.Window) // p.Window is wire.Window, an alias for uint32
		// p.Classes is []uint32, so its length gives numClasses
		for _, class := range p.Classes {
			deviceID := byte(class & 0xFF)
			mask := class >> 8
			if dev, ok := client.openDevices[deviceID]; ok {
				if dev.EventMasks == nil {
					dev.EventMasks = make(map[uint32]uint32)
				}
				dev.EventMasks[windowID] = mask
			}
		}
		return nil

	case *wire.GrabDeviceRequest:
		if _, ok := s.deviceGrabs[p.DeviceID]; ok {
			return &wire.GrabDeviceReply{Sequence: seq, Status: wire.AlreadyGrabbed}
		}
		grabWindow := xID(p.GrabWindow)
		if err := s.checkWindow(grabWindow, seq, wire.XInputOpcode, byte(wire.XGrabDevice)); err != nil {
			return err
		}
		grab := &deviceGrab{
			clientID:    client.id,
			window:      grabWindow,
			ownerEvents: p.OwnerEvents,
			eventMask:   p.Classes,
			time:        p.Time,
		}
		s.deviceGrabs[p.DeviceID] = grab
		return &wire.GrabDeviceReply{Sequence: seq, Status: wire.GrabSuccess}

	case *wire.UngrabDeviceRequest:
		if grab, ok := s.deviceGrabs[p.DeviceID]; ok {
			if grab.clientID == client.id {
				delete(s.deviceGrabs, p.DeviceID)
			}
		}
		return nil

	case *wire.GrabDeviceKeyRequest:
		grabWindow := xID(p.GrabWindow)
		grab := &passiveDeviceGrab{
			clientID:  client.id,
			deviceID:  p.DeviceID,
			key:       wire.KeyCode(p.Key),
			modifiers: p.Modifiers,
			owner:     p.OwnerEvents,
			eventMask: p.Classes,
		}
		s.passiveDeviceGrabs[grabWindow] = append(s.passiveDeviceGrabs[grabWindow], grab)
		return nil

	case *wire.UngrabDeviceKeyRequest:
		grabWindow := xID(p.GrabWindow)
		if grabs, ok := s.passiveDeviceGrabs[grabWindow]; ok {
			newGrabs := make([]*passiveDeviceGrab, 0, len(grabs))
			for _, grab := range grabs {
				if !(grab.key == wire.KeyCode(p.Key) && (p.Modifiers == wire.AnyModifier || grab.modifiers == p.Modifiers)) {
					newGrabs = append(newGrabs, grab)
				}
			}
			s.passiveDeviceGrabs[grabWindow] = newGrabs
		}
		return nil

	case *wire.GrabDeviceButtonRequest:
		grabWindow := xID(p.GrabWindow)
		grab := &passiveDeviceGrab{
			clientID:  client.id,
			deviceID:  p.DeviceID,
			button:    p.Button,
			modifiers: p.Modifiers,
			owner:     p.OwnerEvents,
			eventMask: p.Classes,
		}
		s.passiveDeviceGrabs[grabWindow] = append(s.passiveDeviceGrabs[grabWindow], grab)
		return nil

	case *wire.UngrabDeviceButtonRequest:
		grabWindow := xID(p.GrabWindow)
		if grabs, ok := s.passiveDeviceGrabs[grabWindow]; ok {
			newGrabs := make([]*passiveDeviceGrab, 0, len(grabs))
			for _, grab := range grabs {
				if !(grab.button == p.Button && (p.Modifiers == wire.AnyModifier || grab.modifiers == p.Modifiers)) {
					newGrabs = append(newGrabs, grab)
				}
			}
			s.passiveDeviceGrabs[grabWindow] = newGrabs
		}
		return nil

	case *wire.GetDeviceFocusRequest:
		return &wire.GetDeviceFocusReply{
			Sequence: seq,
			Focus:    uint32(s.inputFocus),
			RevertTo: 1, // RevertToParent
		}

	case *wire.SetDeviceFocusRequest:
		s.inputFocus = xID(p.Focus)
		return nil

	case *wire.GetFeedbackControlRequest:
		feedbacks := s.frontend.GetFeedbackControl(p.DeviceID)
		return &wire.GetFeedbackControlReply{
			Sequence:  seq,
			Feedbacks: feedbacks,
			NumEvents: uint16(len(feedbacks)),
		}

	case *wire.ChangeFeedbackControlRequest:
		s.frontend.ChangeFeedbackControl(p.DeviceID, p.ControlID, p.Mask, p.Control)
		return nil

	case *wire.GetDeviceKeyMappingRequest:
		keysymsPerKeycode, keysyms := s.frontend.GetDeviceKeyMapping(p.DeviceID, p.FirstKey, p.Count)
		return &wire.GetDeviceKeyMappingReply{
			Sequence:          seq,
			KeysymsPerKeycode: keysymsPerKeycode,
			Keysyms:           keysyms,
		}

	case *wire.ChangeDeviceKeyMappingRequest:
		s.frontend.ChangeDeviceKeyMapping(p.DeviceID, p.FirstKey, p.KeysymsPerKeycode, p.KeycodeCount, p.Keysyms)
		return nil

	case *wire.GetDeviceModifierMappingRequest:
		numKeycodesPerMod, keycodes := s.frontend.GetDeviceModifierMapping(p.DeviceID)
		return &wire.GetDeviceModifierMappingReply{
			Sequence:          seq,
			NumKeycodesPerMod: numKeycodesPerMod,
			Keycodes:          keycodes,
		}

	case *wire.SetDeviceModifierMappingRequest:
		status := s.frontend.SetDeviceModifierMapping(p.DeviceID, p.Keycodes)
		return &wire.SetDeviceModifierMappingReply{
			Sequence: seq,
			Status:   status,
		}

	case *wire.GetDeviceButtonMappingRequest:
		buttonMap := s.frontend.GetDeviceButtonMapping(p.DeviceID)
		return &wire.GetDeviceButtonMappingReply{
			Sequence: seq,
			Map:      buttonMap,
		}

	case *wire.SetDeviceButtonMappingRequest:
		status := s.frontend.SetDeviceButtonMapping(p.DeviceID, p.Map)
		return &wire.SetDeviceButtonMappingReply{
			Sequence: seq,
			Status:   status,
		}

	case *wire.QueryDeviceStateRequest:
		classes := s.frontend.QueryDeviceState(p.DeviceID)
		return &wire.QueryDeviceStateReply{
			Sequence:  seq,
			Classes:   classes,
			NumEvents: uint16(len(classes)),
		}

	case *wire.DeviceBellRequest:
		s.frontend.DeviceBell(p.DeviceID, p.FeedbackID, p.FeedbackClass, int8(p.Percent))
		return nil

	case *wire.XIGrabDeviceRequest:
		if _, ok := s.deviceGrabs[byte(p.DeviceID)]; ok {
			return &wire.XIGrabDeviceReply{Sequence: seq, Status: wire.AlreadyGrabbed}
		}

		maskU32 := make([]uint32, (len(p.Mask)+3)/4)
		for i := 0; i < len(p.Mask); i++ {
			maskU32[i/4] |= uint32(p.Mask[i]) << ((i % 4) * 8)
		}

		grabWindow := xID(p.GrabWindow)
		if err := s.checkWindow(grabWindow, seq, wire.XInputOpcode, byte(wire.XIGrabDevice)); err != nil {
			return err
		}

		grab := &deviceGrab{
			clientID:     client.id,
			window:       grabWindow,
			ownerEvents:  p.OwnerEvents,
			xi2EventMask: maskU32,
			time:         p.Time,
		}
		s.deviceGrabs[byte(p.DeviceID)] = grab
		return &wire.XIGrabDeviceReply{Sequence: seq, Status: wire.GrabSuccess}

	case *wire.XIUngrabDeviceRequest:
		if grab, ok := s.deviceGrabs[byte(p.DeviceID)]; ok {
			if grab.clientID == client.id {
				delete(s.deviceGrabs, byte(p.DeviceID))
			}
		}
		return nil

	case *wire.XIPassiveGrabDeviceRequest:
		grabWindow := xID(p.GrabWindow)

		maskU32 := make([]uint32, (len(p.Mask)+3)/4)
		for i := 0; i < len(p.Mask); i++ {
			maskU32[i/4] |= uint32(p.Mask[i]) << ((i % 4) * 8)
		}

		modifiers := make([]uint32, p.NumModifiers)
		if len(p.Modifiers) >= int(p.NumModifiers)*4 {
			for i := 0; i < int(p.NumModifiers); i++ {
				modifiers[i] = client.byteOrder.Uint32(p.Modifiers[i*4 : (i+1)*4])
			}
		}

		if p.NumModifiers == 0 {
			grab := &passiveDeviceGrab{
				clientID:     client.id,
				deviceID:     byte(p.DeviceID),
				detail:       p.Detail,
				xi2Modifiers: []uint32{}, // AnyModifier
				owner:        p.OwnerEvents,
				xi2EventMask: maskU32,
				xi2GrabType:  int(p.GrabType),
			}
			s.passiveDeviceGrabs[grabWindow] = append(s.passiveDeviceGrabs[grabWindow], grab)
		} else {
			for _, mod := range modifiers {
				grab := &passiveDeviceGrab{
					clientID:     client.id,
					deviceID:     byte(p.DeviceID),
					detail:       p.Detail,
					xi2Modifiers: []uint32{mod},
					owner:        p.OwnerEvents,
					xi2EventMask: maskU32,
					xi2GrabType:  int(p.GrabType),
				}
				s.passiveDeviceGrabs[grabWindow] = append(s.passiveDeviceGrabs[grabWindow], grab)
			}
		}

		replyMods := make([]wire.XIGrabModifierInfo, p.NumModifiers)
		for i := 0; i < int(p.NumModifiers); i++ {
			replyMods[i] = wire.XIGrabModifierInfo{
				Status:    wire.GrabSuccess,
				Modifiers: modifiers[i],
			}
		}

		return &wire.XIPassiveGrabDeviceReply{
			Sequence:     seq,
			NumModifiers: p.NumModifiers,
			Modifiers:    replyMods,
		}

	case *wire.XIPassiveUngrabDeviceRequest:
		grabWindow := xID(p.GrabWindow)
		if grabs, ok := s.passiveDeviceGrabs[grabWindow]; ok {
			newGrabs := make([]*passiveDeviceGrab, 0, len(grabs))

			requestModifiers := make([]uint32, p.NumModifiers)
			if len(p.Modifiers) >= int(p.NumModifiers)*4 {
				for i := 0; i < int(p.NumModifiers); i++ {
					requestModifiers[i] = client.byteOrder.Uint32(p.Modifiers[i*4 : (i+1)*4])
				}
			}

			for _, grab := range grabs {
				remove := false
				if grab.xi2GrabType != 0 && grab.deviceID == byte(p.DeviceID) && grab.detail == p.Detail && grab.xi2GrabType == int(p.GrabType) {
					if p.NumModifiers == 0 {
						remove = true
					} else {
						// Check if grab's modifier (single) is in request's list
						if len(grab.xi2Modifiers) > 0 {
							for _, reqMod := range requestModifiers {
								if grab.xi2Modifiers[0] == reqMod {
									remove = true
									break
								}
							}
						}
					}
				}
				if !remove {
					newGrabs = append(newGrabs, grab)
				}
			}
			s.passiveDeviceGrabs[grabWindow] = newGrabs
		}
		return nil

	case *wire.XIAllowEventsRequest:
		s.frontend.AllowEvents(client.id, p.EventMode, p.Time)
		return nil

	case *wire.XIChangeHierarchyRequest:
		s.frontend.XIChangeHierarchy(p.Changes)
		return nil

	case *wire.XIQueryVersionRequest:
		return &wire.XIQueryVersionReply{
			Sequence:     seq,
			MajorVersion: 2,
			MinorVersion: 2,
		}

	case *wire.XIQueryPointerRequest:
		xid := xID(p.Window)
		var winX, winY int32

		rootX := int32(s.pointerX)
		rootY := int32(s.pointerY)

		var child xID
		if uint32(xid) == s.rootWindowID() {
			winX = rootX
			winY = rootY
			child = s.findTopLevelWindowAt(s.pointerX, s.pointerY)
		} else {
			absX, absY, ok := s.getAbsoluteWindowCoords(xid)
			if !ok {
				return wire.NewError(wire.WindowErrorCode, seq, uint32(p.Window), wire.Opcodes{Major: wire.XInputOpcode, Minor: wire.XIQueryPointer})
			}

			// Pointer coordinates relative to the window's origin
			winX = rootX - int32(absX)
			winY = rootY - int32(absY)

			// findDirectChildWindowAt expects coordinates relative to the parent window's origin,
			// which is exactly what winX/winY are.
			child = s.findDirectChildWindowAt(xid, int16(winX), int16(winY))
		}

		mods := wire.ModifierInfo{
			Base:      uint32(s.pointerState),
			Latched:   0,
			Locked:    0,
			Effective: uint32(s.pointerState),
		}

		buttonMask := uint32(0)
		if s.pointerState&wire.Button1Mask != 0 {
			buttonMask |= (1 << 0)
		}
		if s.pointerState&wire.Button2Mask != 0 {
			buttonMask |= (1 << 1)
		}
		if s.pointerState&wire.Button3Mask != 0 {
			buttonMask |= (1 << 2)
		}
		if s.pointerState&wire.Button4Mask != 0 {
			buttonMask |= (1 << 3)
		}
		if s.pointerState&wire.Button5Mask != 0 {
			buttonMask |= (1 << 4)
		}

		buttons := []uint32{buttonMask}

		return &wire.XIQueryPointerReply{
			Sequence:   seq,
			Root:       wire.Window(s.rootWindowID()),
			Child:      wire.Window(uint32(child)),
			RootX:      rootX << 16,
			RootY:      rootY << 16,
			WinX:       winX << 16,
			WinY:       winY << 16,
			SameScreen: true,
			Mods:       mods,
			Group:      wire.GroupInfo{},
			Buttons:    buttons,
		}

	case *wire.XISelectEventsRequest:
		windowID := uint32(p.Window)
		fullWindowID := xID(windowID)
		if err := s.checkWindow(fullWindowID, seq, wire.XInputOpcode, byte(wire.XISelectEvents)); err != nil {
			return err
		}
		for _, mask := range p.Masks {
			if client.xi2EventMasks == nil {
				client.xi2EventMasks = make(map[uint32]map[uint16][]uint32)
			}
			if _, ok := client.xi2EventMasks[windowID]; !ok {
				client.xi2EventMasks[windowID] = make(map[uint16][]uint32)
			}
			client.xi2EventMasks[windowID][mask.DeviceID] = mask.Mask
		}
		return nil

	default:
		return wire.NewError(wire.RequestErrorCode, seq, 0, wire.Opcodes{Major: wire.XInputOpcode, Minor: 0})
	}
}
