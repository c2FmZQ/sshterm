// MIT License
//
// Copyright (c) 2025 TTBT Enterprises LLC
// Copyright (c) 2025 Robin Thellend <rthellend@rthellend.com>
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

package app

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/ssh"

	"github.com/c2FmZQ/sshterm/internal/jsutil"
	"github.com/c2FmZQ/sshterm/internal/webauthn"
)

var (
	errTooShort = errors.New("too short")
)

type webAuthnKey struct {
	Typ    string
	ID     []byte
	PubKey *ecdsa.PublicKey
	RPID   []byte
}

func createWebAuthnKey(name string) (*webAuthnKey, error) {
	challenge := make([]byte, 32)
	rand.Read(challenge)
	resp, err := jsutil.WebAuthnCreate(jsutil.CreateOptions{
		Challenge: challenge,
		Alg:       webauthn.AlgES256,
		UserID:    []byte(name),
		UserName:  name,
	})
	if err != nil {
		return nil, fmt.Errorf("WebAuthnCreate: %w", err)
	}
	cd, err := webauthn.ParseClientData(resp.ClientDataJSON)
	if err != nil {
		return nil, fmt.Errorf("ParseClientData: %w", err)
	}
	if cd.Type != "webauthn.create" {
		return nil, fmt.Errorf("unexpected client data type %q", cd.Type)
	}
	att, err := webauthn.ParseAttestationObject(resp.AttestationObject)
	if err != nil {
		return nil, fmt.Errorf("ParseAttestationObject: %w", err)
	}
	ac := att.AuthData.AttestedCredentials
	if ac == nil {
		return nil, errors.New("ParseAttestationObject: no attested credentials")
	}
	pk, err := ac.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("PublicKey: %w", err)
	}
	ecpk, ok := pk.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("PublicKey: unexpected public key type %T", pk)
	}
	return &webAuthnKey{
		Typ:    "webauthn-sk-ecdsa-sha2-nistp256@openssh.com",
		ID:     ac.ID,
		PubKey: ecpk,
		RPID:   []byte(jsutil.Hostname()),
	}, nil
}

func unmarshalWebAuthnKey(priv, pub []byte, name string, rp func(string) (string, error)) (*webAuthnKey, error) {
	key := &webAuthnKey{}

	if priv != nil {
		block, _ := pem.Decode(priv)
		switch block.Type {
		case "WEBAUTHN KEY ID":
			key.ID = block.Bytes

		case "WEBAUTHN ENCRYPTED KEY ID":
			str := cryptobyte.String(block.Bytes)
			salt := make([]byte, 16)
			if !str.ReadBytes(&salt, 16) {
				return nil, errTooShort
			}
			var numIter uint32
			if !str.ReadUint32(&numIter) {
				return nil, errTooShort
			}
			passphrase, err := rp("Enter passphrase for " + name + ": ")
			if err != nil {
				return nil, err
			}
			dk := pbkdf2.Key([]byte(passphrase), salt, int(numIter), 32, sha256.New)
			block, err := aes.NewCipher(dk)
			if err != nil {
				return nil, errTooShort
			}
			gcm, err := cipher.NewGCM(block)
			if err != nil {
				return nil, errTooShort
			}
			nonce := make([]byte, gcm.NonceSize())
			if !str.ReadBytes(&nonce, len(nonce)) {
				return nil, errTooShort
			}
			keyID, err := gcm.Open(nil, nonce, []byte(str), nil)
			if err != nil {
				return nil, errTooShort
			}
			key.ID = keyID
		default:
			return nil, errors.New("invalid webauthn key ID")
		}
	}

	var data struct {
		Name        string
		ID          string
		Key         []byte
		Application string
	}
	if err := ssh.Unmarshal(pub, &data); err != nil {
		return nil, fmt.Errorf("Unmarshal: %w", err)
	}
	key.Typ = data.Name
	key.RPID = []byte(data.Application)

	x, y := elliptic.Unmarshal(elliptic.P256(), data.Key)
	key.PubKey = &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}
	return key, nil
}

func (k *webAuthnKey) Private(passphrase string) (*pem.Block, error) {
	if passphrase == "" {
		return &pem.Block{
			Type:  "WEBAUTHN KEY ID",
			Bytes: k.ID,
		}, nil
	}
	salt := make([]byte, 16)
	rand.Read(salt)
	numIter := 100000
	dk := pbkdf2.Key([]byte(passphrase), salt, numIter, 32, sha256.New)
	block, err := aes.NewCipher(dk)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)
	encID := gcm.Seal(nonce, nonce, k.ID, nil)
	buf := cryptobyte.NewBuilder(nil)
	buf.AddBytes(salt)
	buf.AddUint32(uint32(numIter))
	buf.AddBytes(encID)
	data, err := buf.Bytes()
	if err != nil {
		return nil, err
	}
	return &pem.Block{
		Type:  "WEBAUTHN ENCRYPTED KEY ID",
		Bytes: data,
	}, nil
}

func (k *webAuthnKey) Type() string {
	return k.Typ
}

func (k *webAuthnKey) Marshal() []byte {
	w := struct {
		Name        string
		ID          string
		Key         []byte
		Application string
	}{
		k.Type(),
		"nistp256",
		elliptic.Marshal(k.PubKey.Curve, k.PubKey.X, k.PubKey.Y),
		string(k.RPID),
	}
	return ssh.Marshal(&w)
}

func (k *webAuthnKey) Verify(data []byte, sig *ssh.Signature) error {
	return errors.New("verify not implemented")
}

func (k *webAuthnKey) PublicKey() ssh.PublicKey {
	return k
}

func (k *webAuthnKey) Sign(_ io.Reader, data []byte) (*ssh.Signature, error) {
	opts := jsutil.GetOptions{Challenge: data}
	if len(k.ID) > 0 {
		opts.Allow = [][]byte{k.ID}
	}
	resp, err := jsutil.WebAuthnGet(opts)
	if err != nil {
		return nil, fmt.Errorf("WebAuthnGet: %w", err)
	}
	var ad webauthn.AuthenticatorData
	if err := webauthn.ParseAuthenticatorData(resp.AuthenticatorData, &ad); err != nil {
		return nil, fmt.Errorf("ParseAuthenticatorData: %w", err)
	}
	cd, err := webauthn.ParseClientData(resp.ClientDataJSON)
	if err != nil {
		return nil, fmt.Errorf("ParseClientData: %w", err)
	}
	if cd.Type != "webauthn.get" {
		return nil, fmt.Errorf("ParseClientData: unexpected client data type %q", cd.Type)
	}

	var sig struct {
		R, S *big.Int
	}
	if _, err := asn1.Unmarshal(resp.Signature, &sig); err != nil {
		return nil, fmt.Errorf("signature: %w", err)
	}

	return &ssh.Signature{
		Format: k.Type(),
		Blob:   ssh.Marshal(sig),
		Rest: ssh.Marshal(struct {
			Flags      byte
			Counter    uint32
			Origin     string
			ClientData string
			Extensions string
		}{
			Flags:      ad.Flags,
			Counter:    ad.SignCount,
			Origin:     cd.Origin,
			ClientData: string(resp.ClientDataJSON),
		}),
	}, nil
}
