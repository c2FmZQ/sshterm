// MIT License
//
// Copyright (c) 2024 TTBT Enterprises LLC
// Copyright (c) 2024 Robin Thellend <rthellend@rthellend.com>
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

package app

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestCheckCertificate(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("ssh.NewSignerFromKey: %v", err)
	}

	now := time.Now()
	earlier := uint64(now.Add(-time.Hour).Unix())
	later := uint64(now.Add(time.Hour).Unix())

	for i, tc := range []struct {
		cert      *ssh.Certificate
		certType  uint32
		badSig    bool
		expectErr bool
	}{
		{cert: &ssh.Certificate{Key: sshPub, CertType: ssh.HostCert}},
		{cert: &ssh.Certificate{Key: sshPub, CertType: ssh.HostCert, ValidAfter: earlier, ValidBefore: later}},
		{cert: &ssh.Certificate{Key: sshPub, CertType: ssh.HostCert, ValidAfter: earlier}},
		{cert: &ssh.Certificate{Key: sshPub, CertType: ssh.HostCert, ValidBefore: later}},
		{cert: &ssh.Certificate{Key: sshPub, CertType: ssh.HostCert, ValidAfter: later}, expectErr: true},
		{cert: &ssh.Certificate{Key: sshPub, CertType: ssh.HostCert, ValidBefore: earlier}, expectErr: true},
		{cert: &ssh.Certificate{Key: sshPub, CertType: ssh.HostCert}, badSig: true, expectErr: true},
		{cert: &ssh.Certificate{Key: sshPub, CertType: ssh.HostCert, Permissions: ssh.Permissions{CriticalOptions: map[string]string{"foo": ""}}}, expectErr: true},
		{cert: &ssh.Certificate{Key: sshPub, CertType: ssh.HostCert}, certType: ssh.UserCert, expectErr: true},
		{cert: &ssh.Certificate{Key: sshPub, CertType: ssh.UserCert}, certType: ssh.HostCert, expectErr: true},
		{cert: &ssh.Certificate{Key: sshPub, CertType: ssh.HostCert, ValidAfter: later, ValidBefore: earlier}, badSig: true, expectErr: true},
	} {
		tc.cert.SignCert(rand.Reader, signer)
		if tc.badSig {
			tc.cert.KeyId = "foo"
		}
		if tc.certType == 0 {
			tc.certType = tc.cert.CertType
		}
		err := checkCertificate(tc.cert, tc.certType)
		if (err != nil) != tc.expectErr {
			t.Errorf("[#%d] checkCertificate(): %v", i, err)
			continue
		}
		t.Logf("[#%d] OK checkCertificate(): %v", i, err)
	}
}
