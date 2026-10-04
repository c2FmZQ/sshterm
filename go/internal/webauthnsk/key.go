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

package webauthnsk

import (
	"bytes"
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
	"strings"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/ssh"

	"github.com/c2FmZQ/sshterm/internal/jsutil"
)

const ecdsa256KeyType = "webauthn-sk-ecdsa-sha2-nistp256@openssh.com"

type Key struct {
	typ    string
	id     []byte
	pubKey *ecdsa.PublicKey
	rpID   []byte
}

func Create(name string, resident bool) (*Key, error) {
	challenge := make([]byte, 32)
	rand.Read(challenge)
	var uid []byte
	if len(name) > 0 && len(name) <= 64 {
		uid = []byte(name)
	} else {
		uid = make([]byte, 32)
		rand.Read(uid)
	}
	resp, err := jsutil.WebAuthnCreate(jsutil.CreateOptions{
		Challenge: challenge,
		Alg:       algES256,
		UserID:    uid,
		UserName:  name,
		Resident:  resident,
	})
	if err != nil {
		return nil, fmt.Errorf("WebAuthnCreate: %w", err)
	}
	cd, err := parseClientData(resp.ClientDataJSON)
	if err != nil {
		return nil, fmt.Errorf("ParseClientData: %w", err)
	}
	if cd.Type != "webauthn.create" {
		return nil, fmt.Errorf("unexpected client data type %q", cd.Type)
	}
	att, err := parseAttestationObject(resp.AttestationObject)
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
	return &Key{
		typ:    ecdsa256KeyType,
		id:     ac.ID,
		pubKey: ecpk,
		rpID:   []byte(jsutil.Hostname()),
	}, nil
}

// Discover discovers a resident key on an authenticator by performing
// two assertions to recover and verify the public key.
// It returns the Key, the username from userHandle (if available), and any error.
func Discover(promptTouch func(string)) (*Key, string, error) {
	challenge1 := make([]byte, 32)
	if _, err := rand.Read(challenge1); err != nil {
		return nil, "", err
	}
	if promptTouch != nil {
		promptTouch("Touch your security key to discover resident keys...\n")
	}
	resp1, err := jsutil.WebAuthnGet(jsutil.GetOptions{
		Challenge: challenge1,
		Allow:     nil,
	})
	if err != nil {
		return nil, "", fmt.Errorf("WebAuthnGet: %w", err)
	}

	challenge2 := make([]byte, 32)
	if _, err := rand.Read(challenge2); err != nil {
		return nil, "", err
	}
	if promptTouch != nil {
		promptTouch("Touch your security key again to verify public key...\n")
	}
	resp2, err := jsutil.WebAuthnGet(jsutil.GetOptions{
		Challenge: challenge2,
		Allow:     [][]byte{resp1.ID},
	})
	if err != nil {
		return nil, "", fmt.Errorf("WebAuthnGet: %w", err)
	}

	pk, err := RecoverPublicKey(resp1.AuthenticatorData, resp1.ClientDataJSON, resp1.Signature, resp2.AuthenticatorData, resp2.ClientDataJSON, resp2.Signature)
	if err != nil {
		return nil, "", fmt.Errorf("RecoverPublicKey: %w", err)
	}

	var userName string
	if len(resp1.UserHandle) > 0 {
		cand := strings.TrimSpace(string(resp1.UserHandle))
		isPrintable := true
		for _, r := range cand {
			if r < 32 || r > 126 {
				isPrintable = false
				break
			}
		}
		if isPrintable {
			userName = cand
		}
	}

	key := &Key{
		typ:    ecdsa256KeyType,
		id:     resp1.ID,
		pubKey: pk,
		rpID:   []byte(jsutil.Hostname()),
	}
	return key, userName, nil
}

func Unmarshal(priv []byte, name string, rp func(string) (string, error)) (*Key, error) {
	if !bytes.HasPrefix(priv, []byte("-----BEGIN WEBAUTHN ")) {
		return nil, errors.New("unexpected key format")
	}
	block, _ := pem.Decode(priv)
	str := cryptobyte.String(block.Bytes)
	var ver uint8
	if !str.ReadUint8(&ver) {
		return nil, errTooShort
	}
	if ver != 1 {
		return nil, fmt.Errorf("unexpected version %d", ver)
	}
	var pubBytes cryptobyte.String
	if !str.ReadUint16LengthPrefixed(&pubBytes) {
		return nil, errTooShort
	}
	key, err := UnmarshalPublic(pubBytes)
	if err != nil {
		return nil, err
	}

	var privBytes cryptobyte.String
	if !str.ReadUint16LengthPrefixed(&privBytes) {
		return nil, errTooShort
	}

	switch block.Type {
	case "WEBAUTHN KEY":
		key.id = privBytes

	case "WEBAUTHN ENCRYPTED KEY":
		salt := make([]byte, 16)
		if !privBytes.ReadBytes(&salt, 16) {
			return nil, errTooShort
		}
		var numIter uint32
		if !privBytes.ReadUint32(&numIter) {
			return nil, errTooShort
		}
		passphrase, err := rp("Enter the passphrase for " + name + ": ")
		if err != nil {
			return nil, err
		}
		dk := pbkdf2.Key([]byte(passphrase), salt, int(numIter), 32, sha256.New)
		block, err := aes.NewCipher(dk)
		if err != nil {
			return nil, err
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		nonce := make([]byte, gcm.NonceSize())
		if !privBytes.ReadBytes(&nonce, len(nonce)) {
			return nil, errTooShort
		}
		keyID, err := gcm.Open(nil, nonce, []byte(privBytes), nil)
		if err != nil {
			return nil, errors.New("invalid passphrase")
		}
		key.id = keyID
	default:
		return nil, errors.New("invalid webauthn key ID")
	}
	return key, nil
}

func UnmarshalPublic(pub []byte) (*Key, error) {
	var data struct {
		Name        string
		ID          string
		Key         []byte
		Application string
	}
	if err := ssh.Unmarshal(pub, &data); err != nil {
		return nil, fmt.Errorf("Unmarshal: %w", err)
	}
	if data.Name != ecdsa256KeyType || data.ID != "nistp256" {
		return nil, fmt.Errorf("unexpected key type %q", data.Name)
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), data.Key)
	return &Key{
		typ:  data.Name,
		rpID: []byte(data.Application),
		pubKey: &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     x,
			Y:     y,
		},
	}, nil
}

func (k *Key) MarshalPrivate(passphrase string) (*pem.Block, error) {
	if passphrase == "" {
		buf := cryptobyte.NewBuilder([]byte{1})
		buf.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(k.Marshal())
		})
		buf.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(k.id)
		})
		data, err := buf.Bytes()
		if err != nil {
			return nil, err
		}
		return &pem.Block{
			Type:  "WEBAUTHN KEY",
			Bytes: data,
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
	encID := gcm.Seal(nonce, nonce, k.id, nil)
	buf := cryptobyte.NewBuilder([]byte{1})
	buf.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(k.Marshal())
	})
	buf.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(salt)
		b.AddUint32(uint32(numIter))
		b.AddBytes(encID)
	})
	data, err := buf.Bytes()
	if err != nil {
		return nil, err
	}
	return &pem.Block{
		Type:  "WEBAUTHN ENCRYPTED KEY",
		Bytes: data,
	}, nil
}

func (k *Key) Type() string {
	return k.typ
}

func (k *Key) Marshal() []byte {
	w := struct {
		Name        string
		ID          string
		Key         []byte
		Application string
	}{
		k.Type(),
		"nistp256",
		elliptic.Marshal(k.pubKey.Curve, k.pubKey.X, k.pubKey.Y),
		string(k.rpID),
	}
	return ssh.Marshal(&w)
}

func (k *Key) Verify(data []byte, sig *ssh.Signature) error {
	return errors.New("verify not implemented")
}

func (k *Key) PublicKey() ssh.PublicKey {
	return k
}

func (k *Key) Sign(_ io.Reader, data []byte) (*ssh.Signature, error) {
	opts := jsutil.GetOptions{Challenge: data}
	if len(k.id) > 0 {
		opts.Allow = [][]byte{k.id}
	}
	resp, err := jsutil.WebAuthnGet(opts)
	if err != nil {
		return nil, fmt.Errorf("WebAuthnGet: %w", err)
	}
	var ad authenticatorData
	if err := parseAuthenticatorData(resp.AuthenticatorData, &ad); err != nil {
		return nil, fmt.Errorf("ParseAuthenticatorData: %w", err)
	}
	cd, err := parseClientData(resp.ClientDataJSON)
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
