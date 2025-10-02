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

package jsutil

import (
	"errors"
	"syscall/js"
)

type CreateOptions struct {
	Challenge []byte
	Alg       int
	UserID    []byte
	UserName  string
	Exclude   [][]byte
}

type CreateResponse struct {
	ClientDataJSON    []byte
	AttestationObject []byte
}

func WebAuthnCreate(opts CreateOptions) (*CreateResponse, error) {
	cc := js.Global().Get("navigator").Get("credentials")
	if !cc.Truthy() {
		return nil, errors.New("CredentialsContainer is unavailable")
	}

	exclude := make([]any, 0, len(opts.Exclude))
	for _, v := range opts.Exclude {
		exclude = append(exclude, NewObject(map[string]any{
			"id":   Uint8ArrayFromBytes(v),
			"type": "public-key",
		}))
	}
	host := Hostname()
	creationOptions := NewObject(map[string]any{
		"publicKey": NewObject(map[string]any{
			"attestation":        "none",
			"residentKey":        "preferred",
			"userVerification":   "required",
			"challenge":          Uint8ArrayFromBytes(opts.Challenge),
			"excludeCredentials": NewArray(exclude),
			"pubKeyCredParams": NewArray([]any{
				NewObject(map[string]any{
					"alg":  opts.Alg,
					"type": "public-key",
				}),
				NewObject(map[string]any{
					"alg":  -257, // RSA, just to remove a warning from chrome
					"type": "public-key",
				}),
			}),
			"rp": NewObject(map[string]any{
				"id":   host,
				"name": host,
			}),
			"timeout": 120000,
			"user": NewObject(map[string]any{
				"displayName": "SSHTERM KEY: " + opts.UserName,
				"id":          Uint8ArrayFromBytes(opts.UserID),
				"name":        opts.UserName,
			}),
		}),
	})
	creds, err := Await(cc.Call("create", creationOptions))
	if err != nil {
		return nil, err
	}
	pkc := creds.Get("response")
	return &CreateResponse{
		ClientDataJSON:    Uint8ArrayToBytes(Uint8Array.New(pkc.Get("clientDataJSON"))),
		AttestationObject: Uint8ArrayToBytes(Uint8Array.New(pkc.Get("attestationObject"))),
	}, nil
}

type GetOptions struct {
	Challenge []byte
	Allow     [][]byte
}

type GetResponse struct {
	ID                []byte
	AuthenticatorData []byte
	ClientDataJSON    []byte
	Signature         []byte
	UserHandle        []byte
}

func WebAuthnGet(opts GetOptions) (*GetResponse, error) {
	cc := js.Global().Get("navigator").Get("credentials")
	if !cc.Truthy() {
		return nil, errors.New("CredentialsContainer is unavailable")
	}

	allow := make([]any, 0, len(opts.Allow))
	for _, v := range opts.Allow {
		allow = append(allow, NewObject(map[string]any{
			"id":   Uint8ArrayFromBytes(v),
			"type": "public-key",
		}))
	}
	creds, err := Await(cc.Call("get",
		NewObject(map[string]any{
			"publicKey": NewObject(map[string]any{
				"allowCredentials": NewArray(allow),
				"challenge":        Uint8ArrayFromBytes(opts.Challenge),
				"timeout":          120000,
				"userVerification": "required",
			}),
		}),
	))
	if err != nil {
		return nil, err
	}
	pkc := creds.Get("response")
	return &GetResponse{
		ID:                Uint8ArrayToBytes(Uint8Array.New(creds.Get("rawId"))),
		AuthenticatorData: Uint8ArrayToBytes(Uint8Array.New(pkc.Get("authenticatorData"))),
		ClientDataJSON:    Uint8ArrayToBytes(Uint8Array.New(pkc.Get("clientDataJSON"))),
		Signature:         Uint8ArrayToBytes(Uint8Array.New(pkc.Get("signature"))),
		UserHandle:        Uint8ArrayToBytes(Uint8Array.New(pkc.Get("userHandle"))),
	}, nil
}
