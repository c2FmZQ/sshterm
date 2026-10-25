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
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type spyAgent struct {
	agent.Agent
	addCalled atomic.Int32
}

func (s *spyAgent) List() ([]*agent.Key, error) {
	return nil, nil
}

func (s *spyAgent) Add(key agent.AddedKey) error {
	s.addCalled.Add(1)
	return errors.New("operation not permitted on forwarded agent")
}

func TestSSHAgentGuard(t *testing.T) {
	// 1. Disallowed AddIdentity message triggers key parsing & Add() when
	// EnableSSHAgentGuard is disabled, and is blocked at the framing layer
	// when EnableSSHAgentGuard is enabled.
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("AddIdentityPreParse/VulnerabilityWithoutRemediation", func(t *testing.T) {
		WithDisabled(&EnableSSHAgentGuard, func() {
			c1, s1 := net.Pipe()
			defer c1.Close()
			defer s1.Close()
			spy := &spyAgent{}
			go func() {
				_ = ServeAgent(spy, s1)
			}()
			client := agent.NewClient(c1)
			_ = client.Add(agent.AddedKey{PrivateKey: edPriv, Comment: "attacker-key"})
			if spy.addCalled.Load() == 0 {
				t.Fatal("expected x/crypto/ssh/agent ServeAgent to parse key and call Add when EnableSSHAgentGuard is disabled; if fixed upstream, remove EnableSSHAgentGuard")
			}
		})
	})

	t.Run("AddIdentityPreParse/RemediationEnabled", func(t *testing.T) {
		c1, s1 := net.Pipe()
		defer c1.Close()
		defer s1.Close()
		spy := &spyAgent{}
		go func() {
			_ = ServeAgent(spy, s1)
		}()
		client := agent.NewClient(c1)
		if err := client.Add(agent.AddedKey{PrivateKey: edPriv, Comment: "attacker-key"}); err == nil {
			t.Fatal("expected Add to fail on forwarded agent")
		}
		if got := spy.addCalled.Load(); got != 0 {
			t.Fatalf("expected agentSafeChannel to reject AddIdentity before ServeAgent called Add, got addCalled=%d", got)
		}
		// Subsequent List() on the same channel still succeeds.
		if _, err := client.List(); err != nil {
			t.Fatalf("List after rejected Add: %v", err)
		}
	})

	// 2. Oversized agent frame length header (> MaxAgentRequestBytes).
	t.Run("OversizedFrame/VulnerabilityWithoutRemediation", func(t *testing.T) {
		WithDisabled(&EnableSSHAgentGuard, func() {
			c1, s1 := net.Pipe()
			defer c1.Close()
			defer s1.Close()
			errCh := make(chan error, 1)
			go func() {
				errCh <- ServeAgent(&spyAgent{}, s1)
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
			errCh <- ServeAgent(&spyAgent{}, s1)
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

func TestSSHSessionExitGuard(t *testing.T) {
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatal(err)
	}

	startMalformedExitServer := func(t *testing.T) (*ssh.Client, func()) {
		t.Helper()
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		srvCfg := &ssh.ServerConfig{NoClientAuth: true}
		srvCfg.AddHostKey(hostSigner)

		done := make(chan struct{})
		go func() {
			defer close(done)
			s1, err := ln.Accept()
			if err != nil {
				return
			}
			defer s1.Close()
			_, chans, reqs, err := ssh.NewServerConn(s1, srvCfg)
			if err != nil {
				return
			}
			go ssh.DiscardRequests(reqs)
			for newChan := range chans {
				if newChan.ChannelType() != "session" {
					_ = newChan.Reject(ssh.UnknownChannelType, "unsupported")
					continue
				}
				ch, chReqs, err := newChan.Accept()
				if err != nil {
					return
				}
				go func() {
					for req := range chReqs {
						if req.Type == "exec" {
							_ = req.Reply(true, nil)
							// Send a malformed 1-byte exit-status (needs 4 bytes), then
							// send 20 extra channel requests without closing ch.
							_, _ = ch.SendRequest("exit-status", false, []byte{0})
							for range 20 {
								_, _ = ch.SendRequest("keepalive@openssh.com", false, nil)
							}
							return
						}
						_ = req.Reply(false, nil)
					}
				}()
			}
		}()

		c1, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			_ = ln.Close()
			t.Fatalf("Dial: %v", err)
		}
		cliCfg := &ssh.ClientConfig{
			User:            "test",
			HostKeyCallback: ssh.FixedHostKey(hostSigner.PublicKey()),
		}
		conn, chans, reqs, err := ssh.NewClientConn(c1, "localhost", cliCfg)
		if err != nil {
			_ = c1.Close()
			_ = ln.Close()
			t.Fatalf("NewClientConn: %v", err)
		}
		client := ssh.NewClient(WrapSSHConn(conn), chans, reqs)
		cleanup := func() {
			_ = client.Close()
			_ = c1.Close()
			_ = ln.Close()
			<-done
		}
		return client, cleanup
	}

	t.Run("VulnerabilityWithoutRemediation", func(t *testing.T) {
		WithDisabled(&EnableSSHSessionExitGuard, func() {
			client, cleanup := startMalformedExitServer(t)
			defer cleanup()

			sess, err := client.NewSession()
			if err != nil {
				t.Fatalf("NewSession: %v", err)
			}
			sess.Stdout = io.Discard
			if err := sess.Start("cmd"); err != nil {
				t.Fatalf("Start: %v", err)
			}
			waitCh := make(chan error, 1)
			go func() {
				waitCh <- sess.Wait()
			}()
			select {
			case err := <-waitCh:
				t.Fatalf("expected (*ssh.Session).Wait to hang on malformed exit-status when EnableSSHSessionExitGuard is disabled (got %v); if fixed upstream, remove WrapSSHConn", err)
			case <-time.After(150 * time.Millisecond):
				// Expected hang in vulnerable mode.
			}
		})
	})

	t.Run("RemediationEnabled", func(t *testing.T) {
		client, cleanup := startMalformedExitServer(t)
		defer cleanup()

		sess, err := client.NewSession()
		if err != nil {
			t.Fatalf("NewSession: %v", err)
		}
		sess.Stdout = io.Discard
		if err := sess.Start("cmd"); err != nil {
			t.Fatalf("Start: %v", err)
		}
		waitCh := make(chan error, 1)
		go func() {
			waitCh <- sess.Wait()
		}()
		select {
		case err := <-waitCh:
			if err == nil {
				t.Fatal("expected error from Wait on malformed exit-status")
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for sess.Wait() with EnableSSHSessionExitGuard enabled")
		}

		// Verify the connection multiplexer is not deadlocked by sending a global request.
		reqDone := make(chan error, 1)
		go func() {
			_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
			reqDone <- err
		}()
		select {
		case err := <-reqDone:
			if err != nil {
				t.Fatalf("client.SendRequest failed: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("SSH connection multiplexer deadlocked after malformed exit-status")
		}
	})
}

type rsaSHA1Signer struct {
	ssh.Signer
}

func (s rsaSHA1Signer) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	return s.Signer.(ssh.AlgorithmSigner).SignWithAlgorithm(rand, data, ssh.KeyAlgoRSA)
}

func TestCertSignatureGuard(t *testing.T) {
	// 1. RSA SHA-1 ("ssh-rsa") CA signature.
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaSigner, err := ssh.NewSignerFromKey(rsaPriv)
	if err != nil {
		t.Fatal(err)
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}

	sha1Cert := &ssh.Certificate{
		Key:         sshPub,
		CertType:    ssh.HostCert,
		ValidBefore: ssh.CertTimeInfinity,
	}
	if err := sha1Cert.SignCert(rand.Reader, rsaSHA1Signer{rsaSigner}); err != nil {
		t.Fatal(err)
	}
	if sha1Cert.Signature.Format != ssh.KeyAlgoRSA {
		t.Fatalf("Signature.Format = %q, want %q", sha1Cert.Signature.Format, ssh.KeyAlgoRSA)
	}

	t.Run("RSASHA1/VulnerabilityWithoutRemediation", func(t *testing.T) {
		WithDisabled(&EnableCertSignatureGuard, func() {
			if err := VerifyCertificateSignature(sha1Cert); err != nil {
				t.Fatalf("expected legacy VerifyCertificateSignature to accept ssh-rsa CA signature, got %v", err)
			}
		})
	})

	t.Run("RSASHA1/RemediationEnabled", func(t *testing.T) {
		if err := VerifyCertificateSignature(sha1Cert); !errors.Is(err, ErrDeprecatedCertSigAlgo) {
			t.Fatalf("expected ErrDeprecatedCertSigAlgo for ssh-rsa CA signature, got %v", err)
		}
		// Verify RSA SHA-256/512 signed certificate succeeds.
		sha2Cert := &ssh.Certificate{
			Key:         sshPub,
			CertType:    ssh.HostCert,
			ValidBefore: ssh.CertTimeInfinity,
		}
		if err := sha2Cert.SignCert(rand.Reader, rsaSigner); err != nil {
			t.Fatal(err)
		}
		if err := VerifyCertificateSignature(sha2Cert); err != nil {
			t.Fatalf("VerifyCertificateSignature(rsa-sha2-512): %v", err)
		}
	})

	// 2. Security-key (sk-ssh-ed25519@openssh.com) CA signature without UserPresence flag (Flags = 0).
	skEdPub, skEdPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	skPubBlob := ssh.Marshal(struct {
		Name        string
		KeyBytes    []byte
		Application string
	}{
		Name:        ssh.KeyAlgoSKED25519,
		KeyBytes:    skEdPub,
		Application: "ssh:ca",
	})
	skPubKey, err := ssh.ParsePublicKey(skPubBlob)
	if err != nil {
		t.Fatalf("ParsePublicKey(sk-ed25519): %v", err)
	}
	skCert := &ssh.Certificate{
		Nonce:        make([]byte, 32),
		Key:          sshPub,
		CertType:     ssh.HostCert,
		ValidBefore:  ssh.CertTimeInfinity,
		SignatureKey: skPubKey,
	}
	c2 := *skCert
	c2.Signature = nil
	raw := c2.Marshal()
	signedBytes := raw[:len(raw)-4]
	appDigest := sha256.Sum256([]byte("ssh:ca"))
	dataDigest := sha256.Sum256(signedBytes)
	skSignedBlob := ssh.Marshal(struct {
		ApplicationDigest []byte `ssh:"rest"`
		Flags             byte
		Counter           uint32
		MessageDigest     []byte `ssh:"rest"`
	}{appDigest[:], 0x00 /* Flags = 0 (no-touch-required) */, 1, dataDigest[:]})
	edSig := ed25519.Sign(skEdPriv, skSignedBlob)
	skCert.Signature = &ssh.Signature{
		Format: ssh.KeyAlgoSKED25519,
		Blob:   edSig,
		Rest: ssh.Marshal(struct {
			Flags   byte
			Counter uint32
		}{0x00, 1}),
	}

	t.Run("SKNoTouchCA/VulnerabilityWithoutRemediation", func(t *testing.T) {
		WithDisabled(&EnableCertSignatureGuard, func() {
			if err := VerifyCertificateSignature(skCert); err == nil {
				t.Fatal("expected PublicKey.Verify to reject sk-ssh-ed25519 CA signature with Flags=0 when EnableCertSignatureGuard is disabled")
			}
		})
	})

	t.Run("SKNoTouchCA/RemediationEnabled", func(t *testing.T) {
		if err := VerifyCertificateSignature(skCert); err != nil {
			t.Fatalf("expected VerifyCertificateSignature to accept sk-ssh-ed25519 CA signature with Flags=0, got %v", err)
		}
	})
}
