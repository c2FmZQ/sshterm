// MIT License
//
// Copyright (c) 2024 TTBT Enterprises LLC
// Copyright (c) 2024 Robin Thellend <rthellend@rthellend.com>
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

package app

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"slices"
	"sync"

	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func (a *App) agentCommand() *cli.App {
	return &cli.App{
		Name:            "agent",
		Usage:           "Manage keys in SSH agent",
		UsageText:       "agent <list|add|remove|lock|unlock>",
		Description:     "The agent command adds or removes keys from the in-memory\nSSH agent. Keys can be used without entering a passphrase while\nin the agent. Access to the agent can be forwarded to remote\nsessions with ssh -A.\n\nKeys remain in the agent until they are removed or the page\nis reloaded.",
		HideHelpCommand: true,
		DefaultCommand:  "list",
		Commands: []*cli.Command{
			{
				Name:      "list",
				Usage:     "List the keys currently in the agent",
				UsageText: "agent list",
				Action: func(ctx *cli.Context) error {
					keys, err := globalAgent.List()
					if err != nil {
						return fmt.Errorf("agent.List: %w", err)
					}
					if len(keys) == 0 {
						a.term.Printf("<none>\n")
						return nil
					}
					maxSize := 5
					for _, k := range keys {
						maxSize = max(maxSize, len(k.Comment))
					}
					for _, k := range keys {
						a.term.Printf("%*s %s\n", -maxSize, k.Comment, k.Format)
					}
					return nil
				},
			},
			{
				Name:        "add",
				Usage:       "Add a key to the agent",
				UsageText:   "agent add <name>",
				Description: "The add command adds the named key to the agent.",
				Action: func(ctx *cli.Context) error {
					if ctx.Args().Len() != 1 {
						cli.ShowSubcommandHelp(ctx)
						return nil
					}
					name := ctx.Args().Get(0)
					key, exists := a.data.Keys[name]
					if !exists {
						return fmt.Errorf("key %q not found", name)
					}
					signer, err := key.Signer(a.term.ReadPassword)
					if err != nil {
						return fmt.Errorf("key.Signer: %w", err)
					}
					return globalAgent.(*keyRing).AddSigner(signer, name)
				},
			},
			{
				Name:      "remove",
				Usage:     "Remove a key from the agent",
				UsageText: "agent remove [-all] [<name>]",
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:  "all",
						Value: false,
						Usage: "Remove all keys.",
					},
				},
				Action: func(ctx *cli.Context) error {
					if ctx.Args().Len() != 1 && (ctx.Args().Len() != 0 || !ctx.Bool("all")) {
						cli.ShowSubcommandHelp(ctx)
						return nil
					}
					if ctx.Bool("all") {
						if err := globalAgent.RemoveAll(); err != nil {
							return fmt.Errorf("agent.RemoveAll: %w", err)
						}
						return nil
					}
					name := ctx.Args().Get(0)
					key, exists := a.data.Keys[name]
					if !exists {
						return fmt.Errorf("key %q not found", name)
					}
					pub, err := ssh.ParsePublicKey(key.Public)
					if err != nil {
						return fmt.Errorf("ssh.ParsePublicKey: %w", err)
					}
					if err := globalAgent.Remove(pub); err != nil {
						return fmt.Errorf("agent.Remove: %w", err)
					}
					return nil
				},
			},
			{
				Name:      "lock",
				Usage:     "Lock the SSH agent",
				UsageText: "agent lock",
				Action: func(ctx *cli.Context) error {
					if ctx.Args().Len() != 0 {
						cli.ShowSubcommandHelp(ctx)
						return nil
					}
					passphrase, err := a.term.ReadPassword("Enter lock passphrase: ")
					if err != nil {
						return err
					}
					return globalAgent.Lock([]byte(passphrase))
				},
			},
			{
				Name:      "unlock",
				Usage:     "Unlock the SSH agent",
				UsageText: "agent unlock",
				Action: func(ctx *cli.Context) error {
					if ctx.Args().Len() != 0 {
						cli.ShowSubcommandHelp(ctx)
						return nil
					}
					passphrase, err := a.term.ReadPassword("Enter lock passphrase: ")
					if err != nil {
						return err
					}
					return globalAgent.Unlock([]byte(passphrase))
				},
			},
		},
	}
}

// keyRing is an ssh Agent implementation very similar to the one from
// https://cs.opensource.google/go/x/crypto/+/refs/tags/v0.30.0:ssh/agent/keyring.go;l=37
// but with extra functionality to interact with the SSH CA from tlsproxy.
//
// The original license is:
// https://cs.opensource.google/go/x/crypto/+/refs/tags/v0.30.0:LICENSE
//
// Copyright 2009 The Go Authors.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//   - Redistributions of source code must retain the above copyright
//
// notice, this list of conditions and the following disclaimer.
//   - Redistributions in binary form must reproduce the above
//
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//   - Neither the name of Google LLC nor the names of its
//
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
type keyRing struct {
	mu     sync.Mutex
	keys   []agentKey
	locked bool
	pp     []byte
}

var _ agent.Agent = (*keyRing)(nil)

var errAgentLocked = errors.New("agent is locked")
var errAgentNotLocked = errors.New("agent is not locked")
var errAgentKeyNotFound = errors.New("key not found")

type agentKey struct {
	signer  ssh.Signer
	comment string
}

func (r *keyRing) List() ([]*agent.Key, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.locked {
		return nil, nil
	}
	out := make([]*agent.Key, 0, len(r.keys))
	for _, k := range r.keys {
		pub := k.signer.PublicKey()
		out = append(out, &agent.Key{
			Format:  pub.Type(),
			Blob:    pub.Marshal(),
			Comment: k.comment},
		)
	}
	return out, nil
}

func (r *keyRing) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.locked {
		return nil, errAgentLocked
	}
	v := key.Marshal()
	i := slices.IndexFunc(r.keys, func(k agentKey) bool {
		return bytes.Equal(v, k.signer.PublicKey().Marshal())
	})
	if i < 0 {
		return nil, errAgentKeyNotFound
	}
	return r.keys[i].signer.Sign(rand.Reader, data)
}

func (r *keyRing) AddSigner(signer ssh.Signer, comment string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.locked {
		return errAgentLocked
	}
	realPub := func(pub ssh.PublicKey) ssh.PublicKey {
		if cert, ok := pub.(*ssh.Certificate); ok {
			return cert.Key
		}
		return pub
	}
	pub := realPub(signer.PublicKey()).Marshal()
	for i, k := range r.keys {
		kPub := realPub(k.signer.PublicKey()).Marshal()
		if !bytes.Equal(pub, kPub) {
			continue
		}
		r.keys[i].signer = signer
		r.keys[i].comment = comment
		return nil
	}
	r.keys = append(r.keys, agentKey{
		signer:  signer,
		comment: comment,
	})
	return nil
}

func (r *keyRing) Add(key agent.AddedKey) error {
	return errors.New("not implemented")
}

func (r *keyRing) Remove(key ssh.PublicKey) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.locked {
		return errAgentLocked
	}
	v := key.Marshal()
	found := false
	r.keys = slices.DeleteFunc(r.keys, func(k agentKey) bool {
		pub := k.signer.PublicKey()
		if cert, ok := pub.(*ssh.Certificate); ok && bytes.Equal(v, cert.Key.Marshal()) {
			found = true
			return true
		}
		if bytes.Equal(v, pub.Marshal()) {
			found = true
			return true
		}
		return false
	})
	if !found {
		return errAgentKeyNotFound
	}
	return nil
}

func (r *keyRing) RemoveAll() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.locked {
		return errAgentLocked
	}
	r.keys = nil
	return nil
}

func (r *keyRing) Lock(passphrase []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.locked {
		return errAgentLocked
	}
	r.locked = true
	r.pp = passphrase
	return nil
}

func (r *keyRing) Unlock(passphrase []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.locked {
		return errAgentNotLocked
	}
	if subtle.ConstantTimeCompare(passphrase, r.pp) != 1 {
		return errors.New("incorrect passphrase")
	}
	r.locked = false
	r.pp = nil
	return nil
}

func (r *keyRing) Signers() ([]ssh.Signer, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.locked {
		return nil, errAgentLocked
	}
	out := make([]ssh.Signer, 0, len(r.keys))
	for _, k := range r.keys {
		out = append(out, k.signer)
	}
	return out, nil
}
