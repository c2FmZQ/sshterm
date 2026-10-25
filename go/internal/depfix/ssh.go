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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const (
	agentFailureMsg        = 5
	agentRequestIdentities = 11
	agentSignRequest       = 13
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

	ErrAgentRequestTooLarge  = errors.New("ssh/agent: request exceeds maximum allowed size")
	ErrDeprecatedCertSigAlgo = errors.New("certificate signature uses deprecated algorithm")
	ErrInvalidCertSignature  = errors.New("certificate signature is invalid")
)

// ForwardToAgent routes incoming "auth-agent@openssh.com" channels on client to
// keyring. When EnableSSHAgentGuard is true, it limits concurrent agent
// channels, caps request frame sizes to MaxAgentRequestBytes, and rejects
// non-list/sign requests before agent.ServeAgent parses private key payloads.
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
// and filters out disallowed message types before agent.ServeAgent reads them.
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
	for {
		var hdr [4]byte
		if _, err := io.ReadFull(a.rw, hdr[:]); err != nil {
			return err
		}
		length := binary.BigEndian.Uint32(hdr[:])
		if length == 0 || length > MaxAgentRequestBytes {
			return fmt.Errorf("%w: %d bytes", ErrAgentRequestTooLarge, length)
		}
		var msgType [1]byte
		if _, err := io.ReadFull(a.rw, msgType[:]); err != nil {
			if errors.Is(err, io.EOF) {
				return io.ErrUnexpectedEOF
			}
			return err
		}
		// Only allow RequestIdentities (11) and SignRequest (13) to reach
		// agent.ServeAgent. For any other message type (such as AddIdentity
		// which triggers expensive RSA key validation in ServeAgent before
		// forwardedAgent.Add is called), discard the payload and return
		// SSH_AGENT_FAILURE immediately.
		if msgType[0] != agentRequestIdentities && msgType[0] != agentSignRequest {
			if length > 1 {
				if _, err := io.CopyN(io.Discard, a.rw, int64(length-1)); err != nil {
					return err
				}
			}
			if _, err := a.rw.Write([]byte{0, 0, 0, 1, agentFailureMsg}); err != nil {
				return err
			}
			continue
		}
		payload := make([]byte, length-1)
		if _, err := io.ReadFull(a.rw, payload); err != nil {
			if errors.Is(err, io.EOF) {
				return io.ErrUnexpectedEOF
			}
			return err
		}
		a.buf.Write(hdr[:])
		a.buf.Write(msgType[:])
		a.buf.Write(payload)
		return nil
	}
}

// WrapSSHConn wraps an ssh.Conn so that when EnableSSHSessionExitGuard is true,
// malformed "exit-status" or "exit-signal" channel requests on "session"
// channels close the session channel and drain remaining channel requests
// rather than deadlocking the connection's multiplexer loop.
func WrapSSHConn(c ssh.Conn) ssh.Conn {
	if !EnableSSHSessionExitGuard {
		return c
	}
	return &safeSSHConn{Conn: c}
}

type safeSSHConn struct {
	ssh.Conn
}

func (s *safeSSHConn) OpenChannel(name string, data []byte) (ssh.Channel, <-chan *ssh.Request, error) {
	ch, reqs, err := s.Conn.OpenChannel(name, data)
	if err != nil || name != "session" || !EnableSSHSessionExitGuard {
		return ch, reqs, err
	}
	out := make(chan *ssh.Request)
	go func() {
		defer close(out)
		for msg := range reqs {
			malformedExit := false
			switch msg.Type {
			case "exit-status":
				if len(msg.Payload) < 4 {
					malformedExit = true
				}
			case "exit-signal":
				var sigval struct {
					Signal     string
					CoreDumped bool
					Error      string
					Lang       string
				}
				if err := ssh.Unmarshal(msg.Payload, &sigval); err != nil {
					malformedExit = true
				}
			}
			out <- msg
			if malformedExit {
				// (*ssh.Session).wait returns early upon receiving a
				// malformed exit-status/exit-signal without closing the
				// channel or draining reqs. Close ch to unblock
				// (*ssh.Session).Wait's copyFuncs and drain remaining
				// requests so mux.loop() cannot block.
				_ = ch.Close()
				go ssh.DiscardRequests(reqs)
				return
			}
		}
	}()
	return ch, out, nil
}

// VerifyCertificateSignature checks the cryptographic signature on cert. When
// EnableCertSignatureGuard is true, it rejects weak SHA-1 (ssh-rsa) and DSA
// (ssh-dss) CA signatures and accepts security-key (sk-*) CA signatures that
// omit the UserPresence flag (matching OpenSSH and ssh.CertChecker.CheckCert).
func VerifyCertificateSignature(cert *ssh.Certificate) error {
	if cert == nil || cert.SignatureKey == nil || cert.Signature == nil {
		return ErrInvalidCertSignature
	}
	if EnableCertSignatureGuard {
		switch cert.Signature.Format {
		case ssh.KeyAlgoRSA, ssh.KeyAlgoDSA:
			return fmt.Errorf("%w: %s", ErrDeprecatedCertSigAlgo, cert.Signature.Format)
		}
	}
	c2 := *cert
	c2.Signature = nil
	signBytes := c2.Marshal()
	if len(signBytes) < 4 {
		return ErrInvalidCertSignature
	}
	signedData := signBytes[:len(signBytes)-4]
	err := cert.SignatureKey.Verify(signedData, cert.Signature)
	if err == nil {
		return nil
	}
	if EnableCertSignatureGuard {
		switch cert.SignatureKey.Type() {
		case ssh.KeyAlgoSKECDSA256, ssh.KeyAlgoSKED25519:
			if verifySKSignatureWithoutUP(cert.SignatureKey, signedData, cert.Signature) == nil {
				return nil
			}
		}
	}
	return ErrInvalidCertSignature
}

func verifySKSignatureWithoutUP(pub ssh.PublicKey, data []byte, sig *ssh.Signature) error {
	if sig == nil || sig.Format != pub.Type() {
		return ErrInvalidCertSignature
	}
	cryptoPub, ok := pub.(ssh.CryptoPublicKey)
	if !ok {
		return ErrInvalidCertSignature
	}
	var skf struct {
		Flags   byte
		Counter uint32
	}
	if err := ssh.Unmarshal(sig.Rest, &skf); err != nil {
		return err
	}
	switch pub.Type() {
	case ssh.KeyAlgoSKECDSA256:
		var w struct {
			Name        string
			Curve       string
			KeyBytes    []byte
			Application string
		}
		if err := ssh.Unmarshal(pub.Marshal(), &w); err != nil {
			return err
		}
		var ecSig struct {
			R *big.Int
			S *big.Int
		}
		if err := ssh.Unmarshal(sig.Blob, &ecSig); err != nil {
			return err
		}
		ecPub, ok := cryptoPub.CryptoPublicKey().(*ecdsa.PublicKey)
		if !ok {
			return ErrInvalidCertSignature
		}
		appDigest := sha256.Sum256([]byte(w.Application))
		dataDigest := sha256.Sum256(data)
		blob := ssh.Marshal(struct {
			ApplicationDigest []byte `ssh:"rest"`
			Flags             byte
			Counter           uint32
			MessageDigest     []byte `ssh:"rest"`
		}{appDigest[:], skf.Flags, skf.Counter, dataDigest[:]})
		digest := sha256.Sum256(blob)
		if ecdsa.Verify(ecPub, digest[:], ecSig.R, ecSig.S) {
			return nil
		}
	case ssh.KeyAlgoSKED25519:
		var w struct {
			Name        string
			KeyBytes    []byte
			Application string
		}
		if err := ssh.Unmarshal(pub.Marshal(), &w); err != nil {
			return err
		}
		var edSig struct {
			Signature []byte `ssh:"rest"`
		}
		if err := ssh.Unmarshal(sig.Blob, &edSig); err != nil {
			return err
		}
		edPub, ok := cryptoPub.CryptoPublicKey().(ed25519.PublicKey)
		if !ok {
			return ErrInvalidCertSignature
		}
		appDigest := sha256.Sum256([]byte(w.Application))
		dataDigest := sha256.Sum256(data)
		blob := ssh.Marshal(struct {
			ApplicationDigest []byte `ssh:"rest"`
			Flags             byte
			Counter           uint32
			MessageDigest     []byte `ssh:"rest"`
		}{appDigest[:], skf.Flags, skf.Counter, dataDigest[:]})
		if ed25519.Verify(edPub, blob, edSig.Signature) {
			return nil
		}
	}
	return ErrInvalidCertSignature
}
