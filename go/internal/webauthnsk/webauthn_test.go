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

package webauthnsk

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"math/big"
	"testing"

	"golang.org/x/crypto/cryptobyte"
)

func TestRecoverPublicKey(t *testing.T) {
	curve := elliptic.P256()

	for iter := 0; iter < 50; iter++ {
		priv, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}

		ad1 := []byte(fmt.Sprintf("authenticatorData1-%d", iter))
		cd1 := []byte(fmt.Sprintf(`{"type":"webauthn.get","challenge":"chal1-%d"}`, iter))
		h1 := sha256.Sum256(cd1)
		signed1 := append(append([]byte(nil), ad1...), h1[:]...)
		hash1 := sha256.Sum256(signed1)
		r1, s1, err := ecdsa.Sign(rand.Reader, priv, hash1[:])
		if err != nil {
			t.Fatalf("Sign 1: %v", err)
		}
		sig1, err := asn1.Marshal(struct{ R, S *big.Int }{r1, s1})
		if err != nil {
			t.Fatalf("asn1.Marshal 1: %v", err)
		}

		ad2 := []byte(fmt.Sprintf("authenticatorData2-%d", iter))
		cd2 := []byte(fmt.Sprintf(`{"type":"webauthn.get","challenge":"chal2-%d"}`, iter))
		h2 := sha256.Sum256(cd2)
		signed2 := append(append([]byte(nil), ad2...), h2[:]...)
		hash2 := sha256.Sum256(signed2)
		r2, s2, err := ecdsa.Sign(rand.Reader, priv, hash2[:])
		if err != nil {
			t.Fatalf("Sign 2: %v", err)
		}
		sig2, err := asn1.Marshal(struct{ R, S *big.Int }{r2, s2})
		if err != nil {
			t.Fatalf("asn1.Marshal 2: %v", err)
		}

		pk, err := RecoverPublicKey(ad1, cd1, sig1, ad2, cd2, sig2)
		if err != nil {
			t.Fatalf("iteration %d: RecoverPublicKey failed: %v", iter, err)
		}
		if pk.X.Cmp(priv.PublicKey.X) != 0 || pk.Y.Cmp(priv.PublicKey.Y) != 0 {
			t.Fatalf("iteration %d: recovered public key does not match", iter)
		}
	}
}

// signAssertion returns a DER ECDSA signature over the same bytes a WebAuthn
// authenticator signs, along with the authenticator data and client data.
func signAssertion(t *testing.T, priv *ecdsa.PrivateKey, tag string) (authData, clientDataJSON, sig []byte) {
	t.Helper()
	authData = []byte("authenticatorData-" + tag)
	clientDataJSON = []byte(`{"type":"webauthn.get","challenge":"` + tag + `"}`)
	h := sha256.Sum256(clientDataJSON)
	hash := sha256.Sum256(append(append([]byte(nil), authData...), h[:]...))
	r, s, err := ecdsa.Sign(rand.Reader, priv, hash[:])
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if sig, err = asn1.Marshal(struct{ R, S *big.Int }{r, s}); err != nil {
		t.Fatalf("asn1.Marshal: %v", err)
	}
	return authData, clientDataJSON, sig
}

func TestRecoverPublicKeyRejectsOutOfRangeSignature(t *testing.T) {
	curve := elliptic.P256()
	p := curve.Params().P
	n := curve.Params().N

	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	ad, cd, good := signAssertion(t, priv, "good")

	for _, tc := range []struct {
		name string
		r, s *big.Int
	}{
		{"negative r", big.NewInt(-5), big.NewInt(7)},
		{"negative s", big.NewInt(7), big.NewInt(-5)},
		{"zero r", big.NewInt(0), big.NewInt(7)},
		{"zero s", big.NewInt(7), big.NewInt(0)},
		{"r >= n", new(big.Int).Add(n, big.NewInt(1)), big.NewInt(7)},
		{"s >= n", big.NewInt(7), new(big.Int).Add(n, big.NewInt(1))},
		{"r > p", new(big.Int).Add(p, big.NewInt(12345)), big.NewInt(7)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad, err := asn1.Marshal(struct{ R, S *big.Int }{tc.r, tc.s})
			if err != nil {
				t.Fatalf("asn1.Marshal: %v", err)
			}
			// Must return an error rather than panicking: an unrecovered panic
			// under wasm takes down the whole app.
			for _, args := range [][2][]byte{{bad, good}, {good, bad}, {bad, bad}} {
				if _, err := RecoverPublicKey(ad, cd, args[0], ad, cd, args[1]); err == nil {
					t.Errorf("RecoverPublicKey(%v) = nil error, want error", tc.name)
				}
			}
		})
	}
}

func TestRecoverPublicKeyRejectsMalformedSignature(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	ad, cd, good := signAssertion(t, priv, "good")

	for _, tc := range []struct {
		name string
		sig  []byte
	}{
		{"empty", nil},
		{"garbage", []byte{0xff, 0xff, 0xff, 0xff}},
		{"truncated", good[:len(good)/2]},
		// An Ed25519 or RS256 credential produces a raw signature, not DER.
		{"not DER", make([]byte, 64)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := RecoverPublicKey(ad, cd, tc.sig, ad, cd, good); err == nil {
				t.Errorf("RecoverPublicKey(%v) = nil error, want error", tc.name)
			}
		})
	}
}

func TestRecoverPublicKeyRejectsMismatchedKeys(t *testing.T) {
	privA, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	privB, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	ad1, cd1, sig1 := signAssertion(t, privA, "one")
	ad2, cd2, sig2 := signAssertion(t, privB, "two")

	// Two valid assertions from two different keys must not resolve to either.
	if _, err := RecoverPublicKey(ad1, cd1, sig1, ad2, cd2, sig2); err == nil {
		t.Error("RecoverPublicKey with two different keys = nil error, want error")
	}
}

func TestRecoverPublicKeyRejectsTamperedAuthData(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	ad1, cd1, sig1 := signAssertion(t, priv, "one")
	ad2, cd2, sig2 := signAssertion(t, priv, "two")

	// A signature that doesn't cover the data it is presented with recovers
	// some other public key, which then can't match the second assertion.
	if _, err := RecoverPublicKey(append(ad1, 'x'), cd1, sig1, ad2, cd2, sig2); err == nil {
		t.Error("RecoverPublicKey with tampered authData = nil error, want error")
	}
}

func TestVerifyClientData(t *testing.T) {
	challenge := []byte("0123456789abcdef")
	encoded := base64.RawURLEncoding.EncodeToString(challenge)
	// Mutate the last character's unused padding bits so standard RawURLEncoding
	// would decode it to the same bytes, but Strict() rejects it.
	nonCanonical := encoded[:len(encoded)-1] + "h"

	for _, tc := range []struct {
		name    string
		js      string
		wantErr bool
	}{
		{"ok", `{"type":"webauthn.get","challenge":"` + encoded + `"}`, false},
		{"ok crossOrigin false", `{"type":"webauthn.get","challenge":"` + encoded + `","crossOrigin":false}`, false},
		{"crossOrigin true", `{"type":"webauthn.get","challenge":"` + encoded + `","crossOrigin":true}`, true},
		{"non-canonical base64url", `{"type":"webauthn.get","challenge":"` + nonCanonical + `"}`, true},
		{"wrong type", `{"type":"webauthn.create","challenge":"` + encoded + `"}`, true},
		{"wrong challenge", `{"type":"webauthn.get","challenge":"` + base64.RawURLEncoding.EncodeToString([]byte("nope")) + `"}`, true},
		{"missing challenge", `{"type":"webauthn.get"}`, true},
		{"unparsable challenge", `{"type":"webauthn.get","challenge":"!!!!"}`, true},
		{"not json", `nope`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := verifyClientData([]byte(tc.js), "webauthn.get", challenge)
			if got := err != nil; got != tc.wantErr {
				t.Errorf("verifyClientData() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestParseAuthenticatorData(t *testing.T) {
	rpHash := sha256.Sum256([]byte("example.com"))
	makeAuthData := func(flags byte, counter uint32, tail []byte) []byte {
		var b cryptobyte.Builder
		b.AddBytes(rpHash[:])
		b.AddUint8(flags)
		b.AddUint32(counter)
		b.AddBytes(tail)
		return b.BytesOrPanic()
	}

	// Valid minimal authenticatorData (UP=1)
	var ad authenticatorData
	if err := parseAuthenticatorData(makeAuthData(0x01, 7, nil), &ad); err != nil {
		t.Fatalf("parseAuthenticatorData(minimal) failed: %v", err)
	}
	if !ad.UserPresence || ad.SignCount != 7 || len(ad.Extensions) != 0 {
		t.Errorf("unexpected parsed authenticatorData: %+v", ad)
	}

	// Trailing bytes without ED/AT flags must be rejected
	if err := parseAuthenticatorData(makeAuthData(0x01, 7, []byte{0x00}), &ad); err == nil {
		t.Error("parseAuthenticatorData with trailing bytes succeeded; want error")
	}

	// Valid CBOR extension map {1: true} -> 0xa1 0x01 0xf5
	cborExt := []byte{0xa1, 0x01, 0xf5}
	var adExt authenticatorData
	if err := parseAuthenticatorData(makeAuthData(0x81, 8, cborExt), &adExt); err != nil {
		t.Fatalf("parseAuthenticatorData(with extensions) failed: %v", err)
	}
	if !adExt.ExtensionData || !bytes.Equal(adExt.Extensions, cborExt) {
		t.Errorf("parseAuthenticatorData extensions = %x, want %x", adExt.Extensions, cborExt)
	}

	// ED flag set but no extension bytes
	if err := parseAuthenticatorData(makeAuthData(0x81, 8, nil), &adExt); err == nil {
		t.Error("parseAuthenticatorData(ED=1, empty) succeeded; want error")
	}

	// ED flag set with trailing bytes after CBOR object
	if err := parseAuthenticatorData(makeAuthData(0x81, 8, append(append([]byte(nil), cborExt...), 0x00)), &adExt); err == nil {
		t.Error("parseAuthenticatorData(ED=1, trailing bytes) succeeded; want error")
	}

	// ED flag set with non-map CBOR item (e.g., integer 1 -> 0x01) must be rejected
	if err := parseAuthenticatorData(makeAuthData(0x81, 8, []byte{0x01}), &adExt); err == nil {
		t.Error("parseAuthenticatorData(ED=1, non-map CBOR) succeeded; want error")
	}
}

func TestIsPrintableASCII(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{"", true},
		{"default", true},
		{"my key 1", true},
		{"~!@#$%^&*()", true},
		{"caf\xc3\xa9", false},
		{"caf\xc3", false}, // truncated multi-byte rune
		{"tab\there", false},
		{"nl\n", false},
		{"nul\x00", false},
		{"del\x7f", false},
	} {
		if got := isPrintableASCII(tc.in); got != tc.want {
			t.Errorf("isPrintableASCII(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
