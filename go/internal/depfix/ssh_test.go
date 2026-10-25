// MIT License
//
// Copyright (c) 2026 TTBT Enterprises LLC
// Copyright (c) 2026 Robin Thellend <rthellend@rthellend.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package depfix

import (
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh/agent"
)

type nopAgent struct {
	agent.Agent
}

func (nopAgent) List() ([]*agent.Key, error) {
	return nil, nil
}

func TestSSHAgentGuard(t *testing.T) {
	// Oversized agent frame length header (> MaxAgentRequestBytes).
	t.Run("OversizedFrame/VulnerabilityWithoutRemediation", func(t *testing.T) {
		WithDisabled(&EnableSSHAgentGuard, func() {
			c1, s1 := net.Pipe()
			defer c1.Close()
			defer s1.Close()
			errCh := make(chan error, 1)
			go func() {
				errCh <- ServeAgent(nopAgent{}, s1)
			}()
			// Send a 4-byte length header of MaxAgentRequestBytes + 100 (still <= 16 MiB).
			var hdr [4]byte
			binary.BigEndian.PutUint32(hdr[:], MaxAgentRequestBytes+100)
			if _, err := c1.Write(hdr[:]); err != nil {
				t.Fatal(err)
			}
			// ServeAgent pre-allocates make([]byte, l) and blocks in io.ReadFull waiting for payload.
			select {
			case err := <-errCh:
				t.Fatalf("expected ServeAgent to accept header > MaxAgentRequestBytes and wait for payload, but got %v", err)
			case <-time.After(50 * time.Millisecond):
				_ = c1.Close()
			}
		})
	})

	t.Run("OversizedFrame/RemediationEnabled", func(t *testing.T) {
		c1, s1 := net.Pipe()
		defer c1.Close()
		defer s1.Close()
		errCh := make(chan error, 1)
		go func() {
			errCh <- ServeAgent(nopAgent{}, s1)
		}()
		var hdr [4]byte
		binary.BigEndian.PutUint32(hdr[:], MaxAgentRequestBytes+100)
		_, _ = c1.Write(hdr[:])
		select {
		case err := <-errCh:
			if !errors.Is(err, ErrAgentRequestTooLarge) {
				t.Fatalf("expected ErrAgentRequestTooLarge, got %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for ServeAgent to reject oversized frame header")
		}
	})
}
