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
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"testing"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/ssh"
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
	downgraded := append([]byte(nil), block.Bytes...)
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

	// Backward compatibility: a legacy v2 encrypted key whose pubBytes used
	// "webauthn-sk-ecdsa-sha2-nistp256@openssh.com" as the public key type
	// still unmarshals (preserving AAD verification) and normalizes its Type()
	// to "sk-ecdsa-sha2-nistp256@openssh.com".
	legacyKey := &Key{
		typ:    webauthnSignatureFormat,
		id:     orig.id,
		rpID:   orig.rpID,
		pubKey: orig.pubKey,
	}
	legacyBlock, err := legacyKey.MarshalPrivate(passphrase)
	if err != nil {
		t.Fatalf("legacyKey.MarshalPrivate: %v", err)
	}
	gotLegacy, err := Unmarshal(pem.EncodeToMemory(legacyBlock), "test", rp)
	if err != nil {
		t.Fatalf("Unmarshal(legacy v2 key type): %v", err)
	}
	if gotLegacy.Type() != ecdsa256KeyType || !bytes.Equal(gotLegacy.rpID, orig.rpID) || !bytes.Equal(gotLegacy.id, orig.id) {
		t.Errorf("Unmarshal(legacy v2 key type) mismatch: got %+v, want %+v", gotLegacy, orig)
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

	// Encrypted key with nil passphrase callback must return an error, not panic
	if _, err := Unmarshal(pem.EncodeToMemory(block), "test", nil); err == nil {
		t.Error("Unmarshal(encrypted, nil rp) succeeded; want error")
	}

	// Trailing bytes after privBytes in outer binary container must be rejected
	trailingPEM := pem.EncodeToMemory(&pem.Block{
		Type:  block.Type,
		Bytes: append(append([]byte(nil), block.Bytes...), 0x00),
	})
	if _, err := Unmarshal(trailingPEM, "test", rp); err == nil {
		t.Error("Unmarshal with trailing container bytes succeeded; want error")
	}
}

func TestCertificateSigning(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	key := &Key{
		typ:    ecdsa256KeyType,
		id:     []byte("credential-id-12345"),
		rpID:   []byte("example.com"),
		pubKey: &priv.PublicKey,
	}

	// Marshal as authorized_keys line and parse with standard golang.org/x/crypto/ssh.
	authKey := ssh.MarshalAuthorizedKey(key)
	parsedPub, _, _, _, err := ssh.ParseAuthorizedKey(authKey)
	if err != nil {
		t.Fatalf("ssh.ParseAuthorizedKey: %v", err)
	}
	if !bytes.Equal(parsedPub.Marshal(), key.Marshal()) {
		t.Fatalf("parsed public key bytes do not match key.Marshal()")
	}

	// Sign an SSH user certificate for the WebAuthn public key.
	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	caSigner, err := ssh.NewSignerFromKey(caPriv)
	if err != nil {
		t.Fatalf("ssh.NewSignerFromKey: %v", err)
	}
	cert := &ssh.Certificate{
		Key:             parsedPub,
		Serial:          1,
		CertType:        ssh.UserCert,
		KeyId:           "testuser",
		ValidPrincipals: []string{"testuser"},
		ValidBefore:     ssh.CertTimeInfinity,
	}
	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		t.Fatalf("cert.SignCert: %v", err)
	}
	if got, want := cert.Type(), ssh.CertAlgoSKECDSA256v01; got != want {
		t.Errorf("cert.Type() = %q, want %q", got, want)
	}

	// Verify the marshaled certificate parses back and matches key.Marshal().
	parsedCertKey, _, _, _, err := ssh.ParseAuthorizedKey(ssh.MarshalAuthorizedKey(cert))
	if err != nil {
		t.Fatalf("ssh.ParseAuthorizedKey(cert): %v", err)
	}
	parsedCert, ok := parsedCertKey.(*ssh.Certificate)
	if !ok {
		t.Fatalf("parsed key is %T, want *ssh.Certificate", parsedCertKey)
	}
	if !bytes.Equal(parsedCert.Key.Marshal(), key.Marshal()) {
		t.Errorf("parsedCert.Key.Marshal() does not match key.Marshal()")
	}
}

func TestKeyVerify(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	key := &Key{
		typ:    ecdsa256KeyType,
		id:     []byte("credential-id-12345"),
		rpID:   []byte("example.com"),
		pubKey: &priv.PublicKey,
	}
	data := []byte("ssh-session-data-to-sign")
	appHash := sha256.Sum256(key.rpID)
	flags := byte(0x05)
	counter := uint32(42)

	// 1. Verify webauthn-sk-ecdsa-sha2-nistp256@openssh.com signature.
	origin := "https://example.com"
	clientData := fmt.Sprintf(`{"type":"webauthn.get","challenge":%q,"origin":%q}`,
		base64.RawURLEncoding.EncodeToString(data), origin)
	cdHash := sha256.Sum256([]byte(clientData))

	var webauthnSigned cryptobyte.Builder
	webauthnSigned.AddBytes(appHash[:])
	webauthnSigned.AddUint8(flags)
	webauthnSigned.AddUint32(counter)
	webauthnSigned.AddBytes(cdHash[:])
	webauthnHash := sha256.Sum256(webauthnSigned.BytesOrPanic())
	r, s, err := ecdsa.Sign(rand.Reader, priv, webauthnHash[:])
	if err != nil {
		t.Fatalf("ecdsa.Sign: %v", err)
	}
	webauthnSig := &ssh.Signature{
		Format: webauthnSignatureFormat,
		Blob:   ssh.Marshal(struct{ R, S *big.Int }{r, s}),
		Rest: ssh.Marshal(struct {
			Flags      byte
			Counter    uint32
			Origin     string
			ClientData string
			Extensions string
		}{
			Flags:      flags,
			Counter:    counter,
			Origin:     origin,
			ClientData: clientData,
		}),
	}
	if err := key.Verify(data, webauthnSig); err != nil {
		t.Errorf("key.Verify(webauthnSig) failed: %v", err)
	}
	if err := key.Verify([]byte("wrong-data"), webauthnSig); err == nil {
		t.Error("key.Verify(wrong-data) succeeded; want error")
	}

	// Verify that standard golang.org/x/crypto/ssh parsed PublicKey also verifies
	// the WebAuthn signature.
	stdPub, err := ssh.ParsePublicKey(key.Marshal())
	if err != nil {
		t.Fatalf("ssh.ParsePublicKey(key.Marshal()): %v", err)
	}
	if err := stdPub.Verify(data, webauthnSig); err != nil {
		t.Errorf("stdPub.Verify(webauthnSig) failed: %v", err)
	}
	if err := stdPub.Verify([]byte("wrong-data"), webauthnSig); err == nil {
		t.Error("stdPub.Verify(wrong-data) succeeded; want error")
	}

	// 2. Verify sk-ecdsa-sha2-nistp256@openssh.com signature.
	dataHash := sha256.Sum256(data)
	var skSigned cryptobyte.Builder
	skSigned.AddBytes(appHash[:])
	skSigned.AddUint8(flags)
	skSigned.AddUint32(counter)
	skSigned.AddBytes(dataHash[:])
	skHash := sha256.Sum256(skSigned.BytesOrPanic())
	r2, s2, err := ecdsa.Sign(rand.Reader, priv, skHash[:])
	if err != nil {
		t.Fatalf("ecdsa.Sign: %v", err)
	}
	skSig := &ssh.Signature{
		Format: ecdsa256KeyType,
		Blob:   ssh.Marshal(struct{ R, S *big.Int }{r2, s2}),
		Rest: ssh.Marshal(struct {
			Flags   byte
			Counter uint32
		}{
			Flags:   flags,
			Counter: counter,
		}),
	}
	if err := key.Verify(data, skSig); err != nil {
		t.Errorf("key.Verify(skSig) failed: %v", err)
	}
	if err := key.Verify([]byte("wrong-data"), skSig); err == nil {
		t.Error("key.Verify(wrong-data) succeeded; want error")
	}

	// 3. Verify WebAuthn signature with extensions (flags 0x85) succeeds.
	extBytes := string([]byte{0xa1, 0x01, 0xf5})
	var extSigned cryptobyte.Builder
	extSigned.AddBytes(appHash[:])
	extSigned.AddUint8(0x85)
	extSigned.AddUint32(counter)
	extSigned.AddBytes([]byte(extBytes))
	extSigned.AddBytes(cdHash[:])
	extHash := sha256.Sum256(extSigned.BytesOrPanic())
	rExt, sExt, err := ecdsa.Sign(rand.Reader, priv, extHash[:])
	if err != nil {
		t.Fatalf("ecdsa.Sign: %v", err)
	}
	extSig := &ssh.Signature{
		Format: webauthnSignatureFormat,
		Blob:   ssh.Marshal(struct{ R, S *big.Int }{rExt, sExt}),
		Rest: ssh.Marshal(struct {
			Flags      byte
			Counter    uint32
			Origin     string
			ClientData string
			Extensions string
		}{
			Flags:      0x85,
			Counter:    counter,
			Origin:     origin,
			ClientData: clientData,
			Extensions: extBytes,
		}),
	}
	if err := key.Verify(data, extSig); err != nil {
		t.Errorf("key.Verify(extSig) failed: %v", err)
	}
	if err := stdPub.Verify(data, extSig); err != nil {
		t.Errorf("stdPub.Verify(extSig) failed: %v", err)
	}

	// 4. Negative cases for WebAuthn & SK signature flags, origin, and clientData.
	signWebAuthn := func(f byte, orig, cd, ext string) *ssh.Signature {
		h := sha256.Sum256([]byte(cd))
		var b cryptobyte.Builder
		b.AddBytes(appHash[:])
		b.AddUint8(f)
		b.AddUint32(counter)
		b.AddBytes([]byte(ext))
		b.AddBytes(h[:])
		digest := sha256.Sum256(b.BytesOrPanic())
		rr, ss, err := ecdsa.Sign(rand.Reader, priv, digest[:])
		if err != nil {
			t.Fatalf("ecdsa.Sign: %v", err)
		}
		return &ssh.Signature{
			Format: webauthnSignatureFormat,
			Blob:   ssh.Marshal(struct{ R, S *big.Int }{rr, ss}),
			Rest: ssh.Marshal(struct {
				Flags      byte
				Counter    uint32
				Origin     string
				ClientData string
				Extensions string
			}{
				Flags:      f,
				Counter:    counter,
				Origin:     orig,
				ClientData: cd,
				Extensions: ext,
			}),
		}
	}

	b64Chall := base64.RawURLEncoding.EncodeToString(data)
	for _, tc := range []struct {
		name string
		sig  *ssh.Signature
	}{
		{
			name: "webauthn missing UP flag",
			sig:  signWebAuthn(0x04, origin, clientData, ""),
		},
		{
			name: "webauthn AT flag set",
			sig:  signWebAuthn(0x41, origin, clientData, ""),
		},
		{
			name: "webauthn ED flag set with empty extensions",
			sig:  signWebAuthn(0x81, origin, clientData, ""),
		},
		{
			name: "webauthn ED flag clear with non-empty extensions",
			sig:  signWebAuthn(0x01, origin, clientData, extBytes),
		},
		{
			name: "webauthn invalid origin scheme",
			sig:  signWebAuthn(0x01, "ftp://example.com", fmt.Sprintf(`{"type":"webauthn.get","challenge":%q,"origin":"ftp://example.com"}`, b64Chall), ""),
		},
		{
			name: "webauthn crossOrigin true",
			sig:  signWebAuthn(0x01, origin, fmt.Sprintf(`{"type":"webauthn.get","challenge":%q,"origin":%q,"crossOrigin":true}`, b64Chall, origin), ""),
		},
		{
			name: "webauthn reordered clientData fields",
			sig:  signWebAuthn(0x01, origin, fmt.Sprintf(`{"origin":%q,"type":"webauthn.get","challenge":%q}`, origin, b64Chall), ""),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := key.Verify(data, tc.sig); err == nil {
				t.Errorf("key.Verify(%s) succeeded; want error", tc.name)
			}
		})
	}

	// SK signature missing UP flag (0x00) must also fail
	var skNoUP cryptobyte.Builder
	skNoUP.AddBytes(appHash[:])
	skNoUP.AddUint8(0x00)
	skNoUP.AddUint32(counter)
	skNoUP.AddBytes(dataHash[:])
	skNoUPHash := sha256.Sum256(skNoUP.BytesOrPanic())
	rNoUP, sNoUP, err := ecdsa.Sign(rand.Reader, priv, skNoUPHash[:])
	if err != nil {
		t.Fatalf("ecdsa.Sign: %v", err)
	}
	skNoUPSig := &ssh.Signature{
		Format: ecdsa256KeyType,
		Blob:   ssh.Marshal(struct{ R, S *big.Int }{rNoUP, sNoUP}),
		Rest: ssh.Marshal(struct {
			Flags   byte
			Counter uint32
		}{
			Flags:   0x00,
			Counter: counter,
		}),
	}
	if err := key.Verify(data, skNoUPSig); err == nil {
		t.Error("key.Verify(sk missing UP flag) succeeded; want error")
	}
}

type mockWebAuthnSigner struct {
	key  *Key
	priv *ecdsa.PrivateKey
}

func (s *mockWebAuthnSigner) PublicKey() ssh.PublicKey {
	return s.key
}

func (s *mockWebAuthnSigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	const origin = "https://example.com"
	clientData := fmt.Sprintf(`{"type":"webauthn.get","challenge":%q,"origin":%q}`,
		base64.RawURLEncoding.EncodeToString(data), origin)
	appHash := sha256.Sum256(s.key.rpID)
	cdHash := sha256.Sum256([]byte(clientData))
	const flags byte = 0x05 // UP | UV
	const counter uint32 = 1

	var signed cryptobyte.Builder
	signed.AddBytes(appHash[:])
	signed.AddUint8(flags)
	signed.AddUint32(counter)
	signed.AddBytes(cdHash[:])
	digest := sha256.Sum256(signed.BytesOrPanic())

	r, ss, err := ecdsa.Sign(rand, s.priv, digest[:])
	if err != nil {
		return nil, err
	}
	return &ssh.Signature{
		Format: webauthnSignatureFormat,
		Blob:   ssh.Marshal(struct{ R, S *big.Int }{r, ss}),
		Rest: ssh.Marshal(struct {
			Flags      byte
			Counter    uint32
			Origin     string
			ClientData string
			Extensions string
		}{
			Flags:      flags,
			Counter:    counter,
			Origin:     origin,
			ClientData: clientData,
		}),
	}, nil
}

func TestSSHServerAuthInterop(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	key := &Key{
		typ:    ecdsa256KeyType,
		id:     []byte("credential-id-12345"),
		rpID:   []byte("ssh:example.com"),
		pubKey: &priv.PublicKey,
	}
	signer := &mockWebAuthnSigner{key: key, priv: priv}

	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatalf("ssh.NewSignerFromKey: %v", err)
	}

	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	caSigner, err := ssh.NewSignerFromKey(caPriv)
	if err != nil {
		t.Fatalf("ssh.NewSignerFromKey: %v", err)
	}

	parsedPub, _, _, _, err := ssh.ParseAuthorizedKey(ssh.MarshalAuthorizedKey(key))
	if err != nil {
		t.Fatalf("ssh.ParseAuthorizedKey: %v", err)
	}

	checker := &ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			return bytes.Equal(auth.Marshal(), caSigner.PublicKey().Marshal())
		},
		UserKeyFallback: func(conn ssh.ConnMetadata, pub ssh.PublicKey) (*ssh.Permissions, error) {
			if bytes.Equal(pub.Marshal(), parsedPub.Marshal()) {
				return &ssh.Permissions{}, nil
			}
			return nil, errors.New("unknown public key")
		},
	}

	tryHandshake := func(t *testing.T, clientSigner ssh.Signer) {
		t.Helper()
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("net.Listen: %v", err)
		}
		defer ln.Close()

		serverConf := &ssh.ServerConfig{
			PublicKeyCallback: checker.Authenticate,
		}
		serverConf.AddHostKey(hostSigner)

		errCh := make(chan error, 1)
		go func() {
			c1, err := ln.Accept()
			if err != nil {
				errCh <- err
				return
			}
			defer c1.Close()
			sc, _, _, err := ssh.NewServerConn(c1, serverConf)
			if sc != nil {
				sc.Close()
			}
			errCh <- err
		}()

		c2, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("net.Dial: %v", err)
		}
		defer c2.Close()

		clientConf := &ssh.ClientConfig{
			User:            "testuser",
			Auth:            []ssh.AuthMethod{ssh.PublicKeys(clientSigner)},
			HostKeyCallback: ssh.FixedHostKey(hostSigner.PublicKey()),
		}
		cc, _, _, clientErr := ssh.NewClientConn(c2, "example.com:22", clientConf)
		if cc != nil {
			cc.Close()
		}
		serverErr := <-errCh
		if clientErr != nil || serverErr != nil {
			t.Fatalf("SSH auth failed: clientErr=%v, serverErr=%v", clientErr, serverErr)
		}
	}

	t.Run("raw webauthn key", func(t *testing.T) {
		tryHandshake(t, signer)
	})

	t.Run("webauthn user certificate", func(t *testing.T) {
		cert := &ssh.Certificate{
			Key:             parsedPub,
			Serial:          1,
			CertType:        ssh.UserCert,
			KeyId:           "testuser",
			ValidPrincipals: []string{"testuser"},
			ValidBefore:     ssh.CertTimeInfinity,
		}
		if err := cert.SignCert(rand.Reader, caSigner); err != nil {
			t.Fatalf("cert.SignCert: %v", err)
		}
		certSigner, err := ssh.NewCertSigner(cert, signer)
		if err != nil {
			t.Fatalf("ssh.NewCertSigner: %v", err)
		}
		tryHandshake(t, certSigner)
	})
}
