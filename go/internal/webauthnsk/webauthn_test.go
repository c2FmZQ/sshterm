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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"fmt"
	"math/big"
	"testing"
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
