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
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/c2FmZQ/sshterm/internal/jsutil"
)

func Create(name string, resident bool) (*Key, error) {
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return nil, err
	}
	// user.id is the only field that an assertion returns (as userHandle), so
	// for a discoverable credential it carries the key name and lets Discover
	// restore it. The spec asks for an opaque value that doesn't identify the
	// user, so this is limited to resident keys, where it buys something;
	// everything else gets a random handle.
	//
	// Note that authenticators key discoverable credentials on
	// (rpID, user.id), so creating a resident key replaces any existing one
	// with the same name. Callers are expected to confirm overwrites.
	var uid []byte
	if resident && len(name) > 0 && len(name) <= 64 && isPrintableASCII(name) {
		uid = []byte(name)
	} else {
		uid = make([]byte, 32)
		if _, err := rand.Read(uid); err != nil {
			return nil, err
		}
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
	if err := verifyClientData(resp.ClientDataJSON, "webauthn.create", challenge); err != nil {
		return nil, err
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
	if err := verifyClientData(resp1.ClientDataJSON, "webauthn.get", challenge1); err != nil {
		return nil, "", fmt.Errorf("assertion 1: %w", err)
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
	if err := verifyClientData(resp2.ClientDataJSON, "webauthn.get", challenge2); err != nil {
		return nil, "", fmt.Errorf("assertion 2: %w", err)
	}
	if !bytes.Equal(resp1.ID, resp2.ID) {
		return nil, "", errors.New("the authenticator returned a different credential for the second assertion")
	}

	pk, err := RecoverPublicKey(resp1.AuthenticatorData, resp1.ClientDataJSON, resp1.Signature, resp2.AuthenticatorData, resp2.ClientDataJSON, resp2.Signature)
	if err != nil {
		// An assertion with an empty allow list can return any discoverable
		// credential for this origin, including one that isn't an ES256 key.
		// Those fail while parsing the ECDSA signature, which is worth
		// translating into something the user can act on.
		var structErr asn1.StructuralError
		var syntaxErr asn1.SyntaxError
		if errors.As(err, &structErr) || errors.As(err, &syntaxErr) {
			return nil, "", errors.New("the selected credential is not an ECDSA P-256 key; only ecdsa-sk keys can be discovered")
		}
		return nil, "", fmt.Errorf("RecoverPublicKey: %w", err)
	}

	// The user handle holds the key name when the credential was created by
	// Create. Anything else is treated as not having a name.
	var userName string
	if cand := strings.TrimSpace(string(resp1.UserHandle)); cand != "" && isPrintableASCII(cand) {
		userName = cand
	}

	key := &Key{
		typ:    ecdsa256KeyType,
		id:     resp1.ID,
		pubKey: pk,
		rpID:   []byte(jsutil.Hostname()),
	}
	return key, userName, nil
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
	if err := verifyClientData(resp.ClientDataJSON, "webauthn.get", data); err != nil {
		return nil, err
	}
	cd, err := parseClientData(resp.ClientDataJSON)
	if err != nil {
		return nil, fmt.Errorf("ParseClientData: %w", err)
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
