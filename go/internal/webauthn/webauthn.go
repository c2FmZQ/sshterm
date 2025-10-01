// MIT License
//
// Copyright (c) 2023 TTBT Enterprises LLC
// Copyright (c) 2023 Robin Thellend <rthellend@rthellend.com>
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

package webauthn

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	cbor "github.com/fxamacker/cbor/v2"
)

const AlgES256 = -7

var errTooShort = errors.New("too short")

// ClientData is a decoded ClientDataJSON object.
type ClientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
}

// Attestation. https://w3c.github.io/webauthn/#sctn-attestation
type Attestation struct {
	Format      string          `cbor:"fmt"`
	AttStmt     cbor.RawMessage `cbor:"attStmt"`
	RawAuthData []byte          `cbor:"authData"`

	AuthData AuthenticatorData `cbor:"-"`
}

// AuthenticatorData is the authenticator data provided during attestation and
// assertion. https://w3c.github.io/webauthn/#sctn-authenticator-data
type AuthenticatorData struct {
	Flags                  byte
	RPIDHash               []byte               `json:"rpIdHash"`
	UserPresence           bool                 `json:"up"`
	BackupEligible         bool                 `json:"be"`
	BackupState            bool                 `json:"bs"`
	UserVerification       bool                 `json:"uv"`
	AttestedCredentialData bool                 `json:"at"`
	ExtensionData          bool                 `json:"ed"`
	SignCount              uint32               `json:"signCount"`
	AttestedCredentials    *AttestedCredentials `json:"attestedCredentialData"`
}

// AttestedCredentials. https://w3c.github.io/webauthn/#sctn-attested-credential-data
type AttestedCredentials struct {
	AAGUID  []byte `json:"AAGUID"`
	ID      []byte `json:"credentialId"`
	COSEKey []byte `json:"credentialPublicKey"`
}

func (c AttestedCredentials) PublicKey() (crypto.PublicKey, error) {
	var kty struct {
		KTY int `cbor:"1,keyasint"`
	}
	if err := cbor.Unmarshal(c.COSEKey, &kty); err != nil {
		return nil, fmt.Errorf("cbor.Unmarshal(%v): %w", c.COSEKey, err)
	}
	switch kty.KTY {
	case 2: // ECDSA public key
		var ecKey struct {
			KTY   int    `cbor:"1,keyasint"`
			ALG   int    `cbor:"3,keyasint"`
			Curve int    `cbor:"-1,keyasint"`
			X     []byte `cbor:"-2,keyasint"`
			Y     []byte `cbor:"-3,keyasint"`
		}
		if err := cbor.Unmarshal(c.COSEKey, &ecKey); err != nil {
			return nil, err
		}
		if ecKey.ALG != AlgES256 {
			return nil, errors.New("unexpected EC key alg")
		}
		if ecKey.Curve != 1 { // P-256
			return nil, errors.New("unexpected EC key curve")
		}
		publicKey := &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(ecKey.X),
			Y:     new(big.Int).SetBytes(ecKey.Y),
		}
		if !publicKey.Curve.IsOnCurve(publicKey.X, publicKey.Y) {
			return nil, errors.New("invalid public key")
		}
		return publicKey, nil

	default:
		return nil, errors.New("unsupported key type")
	}
}

// ParseAttestationObject parses an attestationObject. Passkeys don't typically
// provide attestation statements.
func ParseAttestationObject(attestationObject []byte) (*Attestation, error) {
	var att Attestation
	if err := cbor.Unmarshal(attestationObject, &att); err != nil {
		return nil, fmt.Errorf("cbor.Unmarshal: %w", err)
	}
	if err := ParseAuthenticatorData(att.RawAuthData, &att.AuthData); err != nil {
		return nil, fmt.Errorf("parseAuthenticatorData: %w", err)
	}
	return &att, nil
}

func ParseAuthenticatorData(raw []byte, ad *AuthenticatorData) error {
	// https://w3c.github.io/webauthn/#sctn-authenticator-data
	if len(raw) < 37 {
		return errTooShort
	}
	ad.RPIDHash = raw[:32]
	raw = raw[32:]
	ad.Flags = raw[0]
	ad.UserPresence = raw[0]&1 != 0
	ad.UserVerification = (raw[0]>>2)&1 != 0
	ad.BackupEligible = (raw[0]>>3)&1 != 0
	ad.BackupState = (raw[0]>>4)&1 != 0
	ad.AttestedCredentialData = (raw[0]>>6)&1 != 0
	ad.ExtensionData = (raw[0]>>7)&1 != 0
	raw = raw[1:]
	ad.SignCount = binary.BigEndian.Uint32(raw[:4])
	raw = raw[4:]

	if ad.AttestedCredentialData {
		// https://w3c.github.io/webauthn/#sctn-attested-credential-data
		if len(raw) < 18 {
			return errTooShort
		}
		ad.AttestedCredentials = &AttestedCredentials{}
		ad.AttestedCredentials.AAGUID = raw[:16]
		raw = raw[16:]

		sz := binary.BigEndian.Uint16(raw[:2])
		raw = raw[2:]
		if sz > 1023 {
			return errors.New("invalid credentialId length")
		}
		if len(raw) < int(sz) {
			return errTooShort
		}
		ad.AttestedCredentials.ID = raw[:int(sz)]
		raw = raw[int(sz):]

		var coseKey cbor.RawMessage
		var err error
		if raw, err = cbor.UnmarshalFirst(raw, &coseKey); err != nil {
			return err
		}
		ad.AttestedCredentials.COSEKey = []byte(coseKey)
	}
	if ad.ExtensionData {
		// Parse extensions
	}
	return nil
}

func ParseClientData(js []byte) (*ClientData, error) {
	var out ClientData
	err := json.Unmarshal(js, &out)
	return &out, err
}
