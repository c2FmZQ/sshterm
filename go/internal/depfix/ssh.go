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
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var (
	// MaxConcurrentAgentChannels is the maximum number of concurrent
	// "auth-agent@openssh.com" channels accepted from a remote SSH server
	// when EnableSSHAgentGuard is true.
	MaxConcurrentAgentChannels = 8

	// MaxAgentRequestBytes is the maximum frame size accepted on a
	// forwarded agent channel before passing the request to
	// agent.ServeAgent (which otherwise pre-allocates up to 16 MiB per
	// channel upon reading a 4-byte length header).
	MaxAgentRequestBytes uint32 = 256 * 1024

	ErrAgentRequestTooLarge = errors.New("ssh/agent: request exceeds maximum allowed size")
)

// ForwardToAgent routes incoming "auth-agent@openssh.com" channels on client to
// keyring. When EnableSSHAgentGuard is true, it limits concurrent agent
// channels and caps request frame sizes to MaxAgentRequestBytes.
func ForwardToAgent(client *ssh.Client, keyring agent.Agent) error {
	if !EnableSSHAgentGuard {
		return agent.ForwardToAgent(client, keyring)
	}
	channels := client.HandleChannelOpen("auth-agent@openssh.com")
	if channels == nil {
		return errors.New("agent: already have handler for auth-agent@openssh.com")
	}
	sem := make(chan struct{}, MaxConcurrentAgentChannels)
	go func() {
		for newChan := range channels {
			select {
			case sem <- struct{}{}:
			default:
				_ = newChan.Reject(ssh.ResourceShortage, "too many concurrent agent channels")
				continue
			}
			ch, reqs, err := newChan.Accept()
			if err != nil {
				<-sem
				continue
			}
			go ssh.DiscardRequests(reqs)
			go io.Copy(io.Discard, ch.Stderr())
			go func(c ssh.Channel) {
				defer func() {
					_ = c.Close()
					<-sem
				}()
				_ = ServeAgent(keyring, c)
			}(ch)
		}
	}()
	return nil
}

// ServeAgent serves the SSH agent protocol over c. When EnableSSHAgentGuard is
// true, it wraps c in an agentSafeChannel that enforces MaxAgentRequestBytes
// before agent.ServeAgent pre-allocates the request buffer.
func ServeAgent(keyring agent.Agent, c io.ReadWriter) error {
	if !EnableSSHAgentGuard {
		return agent.ServeAgent(keyring, c)
	}
	return agent.ServeAgent(keyring, &agentSafeChannel{rw: c})
}

type agentSafeChannel struct {
	rw  io.ReadWriter
	buf bytes.Buffer
	err error
}

func (a *agentSafeChannel) Write(p []byte) (int, error) {
	return a.rw.Write(p)
}

func (a *agentSafeChannel) Read(p []byte) (int, error) {
	for a.buf.Len() == 0 {
		if a.err != nil {
			return 0, a.err
		}
		if err := a.readNextFrame(); err != nil {
			a.err = err
			return 0, err
		}
	}
	return a.buf.Read(p)
}

func (a *agentSafeChannel) readNextFrame() error {
	var hdr [4]byte
	if _, err := io.ReadFull(a.rw, hdr[:]); err != nil {
		return err
	}
	length := binary.BigEndian.Uint32(hdr[:])
	if length == 0 || length > MaxAgentRequestBytes {
		return fmt.Errorf("%w: %d bytes", ErrAgentRequestTooLarge, length)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(a.rw, payload); err != nil {
		if errors.Is(err, io.EOF) {
			return io.ErrUnexpectedEOF
		}
		return err
	}
	a.buf.Write(hdr[:])
	a.buf.Write(payload)
	return nil
}
