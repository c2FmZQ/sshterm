//go:build x11

package main

import (
	"time"

	"github.com/c2FmZQ/sshterm/internal/x11/wire"
	"golang.org/x/crypto/ssh"
)

func (s *sshServer) simulateGrabOperations(channel ssh.Channel) {
	s.t.Log("Simulating Grab operations")
	
	// Use existing window (Client 1, ID 1) from previous simulation
	grabWindowID := s.clientXID(1)

	// 1. Grab Pointer
	// GrabPointer(grabWindow, ownerEvents, eventMask, pointerMode, keyboardMode, confineTo, cursor, time)
	err := s.grabPointer(channel, grabWindowID, false, wire.ButtonPressMask|wire.ButtonReleaseMask, wire.GrabModeAsync, wire.GrabModeAsync, 0, 0, 0)
	if err != nil {
		s.t.Errorf("Failed to grab pointer: %v", err)
		return
	}
	
	// Wait a bit to ensure the grab is processed and active on the client side
	time.Sleep(100 * time.Millisecond)

	// 2. Ungrab Pointer
	// UngrabPointer(time)
	err = s.ungrabPointer(channel, 0)
	if err != nil {
		s.t.Errorf("Failed to ungrab pointer: %v", err)
		return
	}
}
