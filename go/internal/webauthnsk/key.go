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

package webauthnsk

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/ssh"
)

const (
	ecdsa256KeyType         = ssh.KeyAlgoSKECDSA256
	webauthnSignatureFormat = ssh.SigAlgoWebAuthnSKECDSA256
)

type Key struct {
	typ    string
	id     []byte
	pubKey *ecdsa.PublicKey
	rpID   []byte
}

const (
	// minIter is the minimum number of PBKDF2 iterations accepted when
	// decrypting keys.
	minIter = 1000
	// defaultIter is the number of PBKDF2 iterations used to encrypt keys.
	defaultIter = 100000
	// maxIter is the maximum number of PBKDF2 iterations accepted when
	// decrypting keys. It protects against crafted files that would hang
	// the app.
	maxIter = 1000000
)

func Unmarshal(priv []byte, name string, rp func(string) (string, error)) (*Key, error) {
	if !bytes.HasPrefix(priv, []byte("-----BEGIN WEBAUTHN ")) {
		return nil, errors.New("unexpected key format")
	}
	block, _ := pem.Decode(priv)
	if block == nil {
		return nil, errors.New("invalid PEM data")
	}
	str := cryptobyte.String(block.Bytes)
	var ver uint8
	if !str.ReadUint8(&ver) {
		return nil, errTooShort
	}
	if ver != 1 && ver != 2 {
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
	if !str.ReadUint16LengthPrefixed(&privBytes) || !str.Empty() {
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
		if numIter < minIter || numIter > maxIter {
			return nil, fmt.Errorf("invalid iteration count %d", numIter)
		}
		if rp == nil {
			return nil, errors.New("passphrase required")
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
		var aad []byte
		if ver >= 2 {
			aad = []byte(pubBytes)
		}
		keyID, err := gcm.Open(nil, nonce, []byte(privBytes), aad)
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
	if (data.Name != ecdsa256KeyType && data.Name != webauthnSignatureFormat) || data.ID != "nistp256" {
		return nil, fmt.Errorf("unexpected key type %q", data.Name)
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), data.Key)
	if x == nil {
		return nil, errors.New("invalid public key")
	}
	return &Key{
		typ:  ecdsa256KeyType,
		rpID: []byte(data.Application),
		pubKey: &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     x,
			Y:     y,
		},
	}, nil
}

func (k *Key) MarshalPrivate(passphrase string) (*pem.Block, error) {
	pubBytes := k.Marshal()
	if passphrase == "" {
		buf := cryptobyte.NewBuilder([]byte{2})
		buf.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(pubBytes)
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
	numIter := defaultIter
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
	encID := gcm.Seal(nonce, nonce, k.id, pubBytes)
	buf := cryptobyte.NewBuilder([]byte{2})
	buf.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(pubBytes)
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
	var ecSig struct {
		R, S *big.Int
	}
	if err := ssh.Unmarshal(sig.Blob, &ecSig); err != nil {
		return err
	}
	appHash := sha256.Sum256(k.rpID)
	var signed cryptobyte.Builder
	signed.AddBytes(appHash[:])

	switch sig.Format {
	case ecdsa256KeyType:
		var extra struct {
			Flags   byte
			Counter uint32
		}
		if err := ssh.Unmarshal(sig.Rest, &extra); err != nil {
			return err
		}
		if (extra.Flags & 0x01) == 0 {
			return errors.New("ssh: missing user presence flag")
		}
		dataHash := sha256.Sum256(data)
		signed.AddUint8(extra.Flags)
		signed.AddUint32(extra.Counter)
		signed.AddBytes(dataHash[:])

	case webauthnSignatureFormat:
		var extra struct {
			Flags      byte
			Counter    uint32
			Origin     string
			ClientData string
			Extensions string
		}
		if err := ssh.Unmarshal(sig.Rest, &extra); err != nil {
			return err
		}
		if (extra.Flags & 0x01) == 0 {
			return errors.New("ssh: missing user presence flag")
		}
		if (extra.Flags & 0x40) != 0 {
			return errors.New("ssh: unexpected attested credential data flag in assertion")
		}
		if ((extra.Flags & 0x80) != 0) != (len(extra.Extensions) != 0) {
			return errors.New("ssh: extension data flag does not match extensions length")
		}
		if (!strings.HasPrefix(extra.Origin, "https://") && !strings.HasPrefix(extra.Origin, "http://")) || strings.IndexByte(extra.Origin, '"') != -1 {
			return errors.New("ssh: invalid origin")
		}
		expectedPrefix := fmt.Sprintf(`{"type":"webauthn.get","challenge":"%s","origin":"%s"`,
			base64.RawURLEncoding.EncodeToString(data), extra.Origin)
		if len(extra.ClientData) <= len(expectedPrefix) || !strings.HasPrefix(extra.ClientData, expectedPrefix) ||
			(extra.ClientData[len(expectedPrefix)] != '}' && extra.ClientData[len(expectedPrefix)] != ',') {
			return errors.New("ssh: clientData does not match expected WebAuthn format")
		}
		cd, err := verifyClientData([]byte(extra.ClientData), "webauthn.get", data)
		if err != nil {
			return err
		}
		if cd.Origin != extra.Origin {
			return errors.New("ssh: invalid client data origin")
		}
		clientDataHash := sha256.Sum256([]byte(extra.ClientData))
		signed.AddUint8(extra.Flags)
		signed.AddUint32(extra.Counter)
		signed.AddBytes([]byte(extra.Extensions))
		signed.AddBytes(clientDataHash[:])

	default:
		return fmt.Errorf("ssh: signature type %s for key type %s", sig.Format, k.Type())
	}

	msg, err := signed.Bytes()
	if err != nil {
		return err
	}
	hash := sha256.Sum256(msg)
	if !ecdsa.Verify(k.pubKey, hash[:], ecSig.R, ecSig.S) {
		return errors.New("ssh: signature did not verify")
	}
	return nil
}

func (k *Key) PublicKey() ssh.PublicKey {
	return k
}
