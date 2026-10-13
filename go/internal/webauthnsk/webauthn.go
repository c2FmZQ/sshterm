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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	cbor "github.com/fxamacker/cbor/v2"
)

const algES256 = -7

var errTooShort = errors.New("too short")

// ClientData is a decoded ClientDataJSON object.
type clientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
}

// Attestation. https://w3c.github.io/webauthn/#sctn-attestation
type attestation struct {
	Format      string          `cbor:"fmt"`
	AttStmt     cbor.RawMessage `cbor:"attStmt"`
	RawAuthData []byte          `cbor:"authData"`

	AuthData authenticatorData `cbor:"-"`
}

// AuthenticatorData is the authenticator data provided during attestation and
// assertion. https://w3c.github.io/webauthn/#sctn-authenticator-data
type authenticatorData struct {
	Flags                  byte
	RPIDHash               []byte               `json:"rpIdHash"`
	UserPresence           bool                 `json:"up"`
	BackupEligible         bool                 `json:"be"`
	BackupState            bool                 `json:"bs"`
	UserVerification       bool                 `json:"uv"`
	AttestedCredentialData bool                 `json:"at"`
	ExtensionData          bool                 `json:"ed"`
	SignCount              uint32               `json:"signCount"`
	AttestedCredentials    *attestedCredentials `json:"attestedCredentialData"`
}

// AttestedCredentials. https://w3c.github.io/webauthn/#sctn-attested-credential-data
type attestedCredentials struct {
	AAGUID  []byte `json:"AAGUID"`
	ID      []byte `json:"credentialId"`
	COSEKey []byte `json:"credentialPublicKey"`
}

func (c attestedCredentials) PublicKey() (crypto.PublicKey, error) {
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
		if ecKey.ALG != algES256 {
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

// parseAttestationObject parses an attestationObject. Passkeys don't typically
// provide attestation statements.
func parseAttestationObject(attestationObject []byte) (*attestation, error) {
	var att attestation
	if err := cbor.Unmarshal(attestationObject, &att); err != nil {
		return nil, fmt.Errorf("cbor.Unmarshal: %w", err)
	}
	if err := parseAuthenticatorData(att.RawAuthData, &att.AuthData); err != nil {
		return nil, fmt.Errorf("parseAuthenticatorData: %w", err)
	}
	return &att, nil
}

func parseAuthenticatorData(raw []byte, ad *authenticatorData) error {
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
		ad.AttestedCredentials = &attestedCredentials{}
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

func parseClientData(js []byte) (*clientData, error) {
	var out clientData
	err := json.Unmarshal(js, &out)
	return &out, err
}

// verifyClientData checks that a ClientDataJSON blob belongs to the ceremony
// the caller just requested, i.e. that it has the expected type and echoes back
// the challenge that was sent.
func verifyClientData(js []byte, wantType string, wantChallenge []byte) error {
	cd, err := parseClientData(js)
	if err != nil {
		return fmt.Errorf("ParseClientData: %w", err)
	}
	if cd.Type != wantType {
		return fmt.Errorf("unexpected client data type %q", cd.Type)
	}
	challenge, err := base64.RawURLEncoding.DecodeString(cd.Challenge)
	if err != nil {
		return fmt.Errorf("invalid client data challenge: %w", err)
	}
	if !bytes.Equal(challenge, wantChallenge) {
		return errors.New("client data challenge doesn't match")
	}
	return nil
}

// isPrintableASCII reports whether s consists only of printable ASCII
// characters. It deliberately works a byte at a time so that any non-ASCII
// byte, including a fragment of a truncated multi-byte rune, is rejected.
func isPrintableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 32 || s[i] > 126 {
			return false
		}
	}
	return true
}

// recoverCandidatesP256 returns every ECDSA public key that could have produced
// the signature (r, s) over hash. There are up to four, and a second signature
// over a different hash is needed to tell them apart.
//
// The implementation is specific to P-256: it relies on the curve equation
// having a == -3, and on p ≡ 3 (mod 4) so that a square root modulo p can be
// computed as ySq^((p+1)/4).
func recoverCandidatesP256(hash []byte, r, s *big.Int) []*ecdsa.PublicKey {
	curve := elliptic.P256()
	params := curve.Params()
	p := params.P
	n := params.N

	// r and s are used below both as a curve coordinate and as scalars, and
	// crypto/elliptic panics (rather than returning an error) when handed a
	// point that is not on the curve. Callers validate these too; this guard
	// keeps the panic unreachable if a new caller forgets.
	if r.Sign() <= 0 || r.Cmp(n) >= 0 || s.Sign() <= 0 || s.Cmp(n) >= 0 {
		return nil
	}

	e := new(big.Int).SetBytes(hash)
	e.Mod(e, n)
	rInv := new(big.Int).ModInverse(r, n)
	if rInv == nil {
		return nil
	}

	eGx, eGy := curve.ScalarBaseMult(e.Bytes())
	// Negate eG. crypto/elliptic represents the point at infinity as (0, 0),
	// whose negation must stay (0, 0) rather than becoming (0, p).
	neGy := new(big.Int)
	if eGy.Sign() != 0 {
		neGy.Sub(p, eGy)
	}

	var res []*ecdsa.PublicKey

	xs := []*big.Int{r}
	if rPlusN := new(big.Int).Add(r, n); rPlusN.Cmp(p) < 0 {
		xs = append(xs, rPlusN)
	}

	for _, x := range xs {
		x3 := new(big.Int).Mul(x, x)
		x3.Mul(x3, x)
		threeX := new(big.Int).Mul(big.NewInt(3), x)
		ySq := new(big.Int).Sub(x3, threeX)
		ySq.Add(ySq, params.B)
		ySq.Mod(ySq, p)

		exp := new(big.Int).Add(p, big.NewInt(1))
		exp.Div(exp, big.NewInt(4))
		y := new(big.Int).Exp(ySq, exp, p)

		check := new(big.Int).Exp(y, big.NewInt(2), p)
		if check.Cmp(ySq) != 0 {
			// ySq is not a quadratic residue, so this x is not on the curve.
			continue
		}

		yCands := []*big.Int{y}
		if y.Sign() != 0 {
			yCands = append(yCands, new(big.Int).Sub(p, y))
		}

		for _, yCand := range yCands {
			sRx, sRy := curve.ScalarMult(x, yCand, s.Bytes())
			diffX, diffY := curve.Add(sRx, sRy, eGx, neGy)
			qx, qy := curve.ScalarMult(diffX, diffY, rInv.Bytes())
			if qx.Sign() == 0 && qy.Sign() == 0 {
				// Point at infinity; not a usable public key.
				continue
			}
			res = append(res, &ecdsa.PublicKey{
				Curve: curve,
				X:     qx,
				Y:     qy,
			})
		}
	}
	return res
}

// RecoverPublicKey recovers the ECDSA P-256 public key from two WebAuthn assertions
// using different challenges. Two assertions are required to uniquely identify the
// public key among the mathematically possible ECDSA recovery candidates.
func RecoverPublicKey(authData1, clientDataJSON1, sig1Bytes, authData2, clientDataJSON2, sig2Bytes []byte) (*ecdsa.PublicKey, error) {
	curve := elliptic.P256()
	n := curve.Params().N

	var sig1, sig2 struct {
		R, S *big.Int
	}
	if _, err := asn1.Unmarshal(sig1Bytes, &sig1); err != nil {
		return nil, fmt.Errorf("sig1: %w", err)
	}
	if _, err := asn1.Unmarshal(sig2Bytes, &sig2); err != nil {
		return nil, fmt.Errorf("sig2: %w", err)
	}
	// asn1.Unmarshal accepts negative integers and values larger than the group
	// order. Both are out of range for ECDSA and would panic inside
	// crypto/elliptic, so reject them here with a usable error message.
	for i, sig := range []struct{ R, S *big.Int }{sig1, sig2} {
		if sig.R.Sign() <= 0 || sig.R.Cmp(n) >= 0 || sig.S.Sign() <= 0 || sig.S.Cmp(n) >= 0 {
			return nil, fmt.Errorf("sig%d: signature value out of range", i+1)
		}
	}

	h1 := sha256.Sum256(clientDataJSON1)
	signed1 := append(append([]byte(nil), authData1...), h1[:]...)
	hash1 := sha256.Sum256(signed1)

	h2 := sha256.Sum256(clientDataJSON2)
	signed2 := append(append([]byte(nil), authData2...), h2[:]...)
	hash2 := sha256.Sum256(signed2)

	cands1 := recoverCandidatesP256(hash1[:], sig1.R, sig1.S)
	cands2 := recoverCandidatesP256(hash2[:], sig2.R, sig2.S)

	seen := make(map[string]bool)
	var matches []*ecdsa.PublicKey
	for _, c1 := range cands1 {
		for _, c2 := range cands2 {
			if c1.X.Cmp(c2.X) != 0 || c1.Y.Cmp(c2.Y) != 0 {
				continue
			}
			k := string(elliptic.Marshal(curve, c1.X, c1.Y))
			if seen[k] {
				continue
			}
			seen[k] = true
			matches = append(matches, c1)
		}
	}

	if len(matches) == 0 {
		return nil, errors.New("no matching public key found from assertions")
	}
	if len(matches) > 1 {
		return nil, fmt.Errorf("multiple matching public keys found (%d)", len(matches))
	}
	pk := matches[0]
	if !ecdsa.Verify(pk, hash1[:], sig1.R, sig1.S) || !ecdsa.Verify(pk, hash2[:], sig2.R, sig2.S) {
		return nil, errors.New("recovered public key failed signature verification")
	}
	return pk, nil
}
