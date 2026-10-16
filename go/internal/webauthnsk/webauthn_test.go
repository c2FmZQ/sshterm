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
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"math/big"
	"testing"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/pbkdf2"
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

	for _, tc := range []struct {
		name    string
		js      string
		wantErr bool
	}{
		{"ok", `{"type":"webauthn.get","challenge":"` + encoded + `"}`, false},
		{"wrong type", `{"type":"webauthn.create","challenge":"` + encoded + `"}`, true},
		{"wrong challenge", `{"type":"webauthn.get","challenge":"` + base64.RawURLEncoding.EncodeToString([]byte("nope")) + `"}`, true},
		{"missing challenge", `{"type":"webauthn.get"}`, true},
		{"unparsable challenge", `{"type":"webauthn.get","challenge":"!!!!"}`, true},
		{"not json", `nope`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := verifyClientData([]byte(tc.js), "webauthn.get", challenge)
			if got := err != nil; got != tc.wantErr {
				t.Errorf("verifyClientData() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
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

func TestKeyMarshalUnmarshal(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	orig := &Key{
		typ:    ecdsa256KeyType,
		id:     []byte("credential-id-12345"),
		rpID:   []byte("ssh:default"),
		pubKey: &priv.PublicKey,
	}
	passphrase := "secret-passphrase"
	rp := func(string) (string, error) { return passphrase, nil }

	// Round-trip without passphrase
	block, err := orig.MarshalPrivate("")
	if err != nil {
		t.Fatalf("MarshalPrivate(\"\"): %v", err)
	}
	got, err := Unmarshal(pem.EncodeToMemory(block), "test", rp)
	if err != nil {
		t.Fatalf("Unmarshal(unencrypted): %v", err)
	}
	if got.typ != orig.typ || !bytes.Equal(got.rpID, orig.rpID) || !bytes.Equal(got.id, orig.id) {
		t.Errorf("Unmarshal(unencrypted) mismatch: got %+v, want %+v", got, orig)
	}

	// Round-trip with passphrase
	block, err = orig.MarshalPrivate(passphrase)
	if err != nil {
		t.Fatalf("MarshalPrivate(passphrase): %v", err)
	}
	got, err = Unmarshal(pem.EncodeToMemory(block), "test", rp)
	if err != nil {
		t.Fatalf("Unmarshal(passphrase): %v", err)
	}
	if got.typ != orig.typ || !bytes.Equal(got.rpID, orig.rpID) || !bytes.Equal(got.id, orig.id) {
		t.Errorf("Unmarshal(passphrase) mismatch: got %+v, want %+v", got, orig)
	}

	// Tampered pubBytes must fail AES-GCM authentication (AAD binding)
	pubLen := int(binary.BigEndian.Uint16(block.Bytes[1:3]))
	// Flip a bit in the application string at the end of pubBytes so UnmarshalPublic still succeeds
	tampered := append([]byte(nil), block.Bytes...)
	tampered[1+2+pubLen-1] ^= 0x01
	tamperedPEM := pem.EncodeToMemory(&pem.Block{Type: block.Type, Bytes: tampered})
	if _, err := Unmarshal(tamperedPEM, "test", rp); err == nil {
		t.Error("Unmarshal with tampered pubBytes succeeded; want AAD failure")
	}

	// Downgrading a v2 key to v1 must also fail AES-GCM authentication
	downgraded := append([]byte(nil), tampered...)
	downgraded[0] = 1
	downgradedPEM := pem.EncodeToMemory(&pem.Block{Type: block.Type, Bytes: downgraded})
	if _, err := Unmarshal(downgradedPEM, "test", rp); err == nil {
		t.Error("Unmarshal with v2->v1 version downgrade succeeded; want AAD failure")
	}

	// Backward compatibility: a legacy v1 encrypted key (sealed with nil AAD) still unmarshals
	pubBytes := orig.Marshal()
	salt := make([]byte, 16)
	rand.Read(salt)
	dk := pbkdf2.Key([]byte(passphrase), salt, minIter, 32, sha256.New)
	cBlock, err := aes.NewCipher(dk)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	gcm, err := cipher.NewGCM(cBlock)
	if err != nil {
		t.Fatalf("cipher.NewGCM: %v", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)
	encIDv1 := gcm.Seal(nonce, nonce, orig.id, nil)
	v1Buf := cryptobyte.NewBuilder([]byte{1})
	v1Buf.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(pubBytes)
	})
	v1Buf.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(salt)
		b.AddUint32(uint32(minIter))
		b.AddBytes(encIDv1)
	})
	v1PEM := pem.EncodeToMemory(&pem.Block{Type: "WEBAUTHN ENCRYPTED KEY", Bytes: v1Buf.BytesOrPanic()})
	gotV1, err := Unmarshal(v1PEM, "test", rp)
	if err != nil {
		t.Fatalf("Unmarshal(legacy v1): %v", err)
	}
	if gotV1.typ != orig.typ || !bytes.Equal(gotV1.rpID, orig.rpID) || !bytes.Equal(gotV1.id, orig.id) {
		t.Errorf("Unmarshal(legacy v1) mismatch: got %+v, want %+v", gotV1, orig)
	}

	// Iteration count below minIter or above maxIter must be rejected
	iterOffset := 1 + 2 + pubLen + 2 + 16
	for _, badIter := range []uint32{0, 1, 999, maxIter + 1} {
		badBytes := append([]byte(nil), block.Bytes...)
		binary.BigEndian.PutUint32(badBytes[iterOffset:iterOffset+4], badIter)
		badPEM := pem.EncodeToMemory(&pem.Block{Type: block.Type, Bytes: badBytes})
		if _, err := Unmarshal(badPEM, "test", rp); err == nil {
			t.Errorf("Unmarshal with numIter=%d succeeded; want error", badIter)
		}
	}
}
