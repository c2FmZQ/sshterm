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

//go:build wasm

package tests

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/pem"
	"testing"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/ssh"

	"github.com/c2FmZQ/sshterm/internal/app"
)

func TestMalformedFiles(t *testing.T) {
	a, err := app.New(appConfig)
	if err != nil {
		t.Fatalf("app.New: %v", err)
	}
	result := make(chan error)
	go func() {
		result <- a.Run()
	}()
	t.Cleanup(a.Stop)

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	webauthnKey := func(point []byte, numIter uint32) []byte {
		pub := ssh.Marshal(struct {
			Name        string
			ID          string
			Key         []byte
			Application string
		}{"webauthn-sk-ecdsa-sha2-nistp256@openssh.com", "nistp256", point, "example.com"})
		b := cryptobyte.NewBuilder([]byte{1})
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(pub)
		})
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(make([]byte, 16))
			b.AddUint32(numIter)
			b.AddBytes(make([]byte, 40))
		})
		return pem.EncodeToMemory(&pem.Block{Type: "WEBAUTHN ENCRYPTED KEY", Bytes: b.BytesOrPanic()})
	}
	script(t, []line{
		{Expect: prompt},
		{Type: "db wipe\n", Expect: `Continue\?`},
		{Type: "Y\n", Expect: prompt},
	})
	for _, tc := range []struct {
		name    string
		content []byte
		cmd     string
		expect  string
	}{
		{"nopem.key", []byte("-----BEGIN WEBAUTHN KEY-----\nfoo\n"), "keys import bad\n", "invalid PEM data"},
		{"badpoint.key", webauthnKey([]byte{4, 1, 2, 3}, 1000), "keys import bad\n", "invalid public key"},
		{"hugeiter.key", webauthnKey(elliptic.Marshal(elliptic.P256(), priv.X, priv.Y), 0xffffffff), "keys import bad\n", "invalid iteration count"},
		{"short.backup", []byte{0xe2, 0x9b, 0x94, '0', 1, 2, 3}, "db restore\n", "invalid backup file"},
	} {
		fileUploader.enqueue(tc.name, "application/octet-stream", int64(len(tc.content)), tc.content)
		script(t, []line{
			{Type: tc.cmd, Expect: "(?s)" + tc.expect + ".*sshterm> "},
		})
	}
	script(t, []line{
		{Type: "exit\n"},
	})
	if err := <-result; err != nil {
		t.Fatalf("Run(): %v", err)
	}
}
