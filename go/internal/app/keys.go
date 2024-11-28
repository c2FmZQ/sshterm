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
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/ssh"
)

func (a *App) keysCommand() *cli.App {
	return &cli.App{
		Name:            "keys",
		Usage:           "Manage keys",
		UsageText:       "keys <list|generate|delete|import|export>",
		Description:     "The keys command is used to manage private and public keys.",
		HideHelpCommand: true,
		DefaultCommand:  "list",
		Commands: []*cli.Command{
			{
				Name:      "list",
				Usage:     "List all keys",
				UsageText: "keys list",
				Action: func(ctx *cli.Context) error {
					if len(a.data.Keys) == 0 {
						a.term.Printf("<none>\n")
						return nil
					}
					names := make([]string, 0, len(a.data.Keys))
					for _, key := range a.data.Keys {
						names = append(names, key.Name)
					}
					sort.Strings(names)
					for _, n := range names {
						key := a.data.Keys[n]
						pub, err := ssh.ParsePublicKey(key.Public)
						if err != nil {
							a.term.Errorf("ssh.ParsePublicKey: %v", err)
							continue
						}
						m := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
						a.term.Printf("%s %s\n", m, n)
					}
					return nil
				},
			},
			{
				Name:        "generate",
				Aliases:     []string{"add", "gen"},
				Usage:       "Generate a new key",
				UsageText:   "keys generate <name>",
				Description: "The <name> of the key is used to refer the key. The ssh command\nwill use the key named 'default' if it exists.",
				Action: func(ctx *cli.Context) error {
					if ctx.Args().Len() != 1 {
						cli.ShowSubcommandHelp(ctx)
						return nil
					}
					name := ctx.Args().Get(0)
					pub, priv, err := ed25519.GenerateKey(rand.Reader)
					if err != nil {
						return fmt.Errorf("ed25519.GenerateKey: %w", err)
					}
					sshPub, err := ssh.NewPublicKey(pub)
					if err != nil {
						return fmt.Errorf("ssh.NewPublicKey: %w", err)
					}
					passphrase, err := a.term.ReadPassword("Enter passphrase for private key: ")
					if err != nil {
						return fmt.Errorf("ReadPassword: %w", err)
					}
					passphrase2, err := a.term.ReadPassword("Re-enter the same passphrase: ")
					if err != nil {
						return fmt.Errorf("ReadPassword: %w", err)
					}
					if passphrase != passphrase2 {
						return fmt.Errorf("passphrase doesn't match")
					}
					var privPEM *pem.Block
					if passphrase == "" {
						if privPEM, err = ssh.MarshalPrivateKey(priv, ""); err != nil {
							return fmt.Errorf("ssh.MarshalPrivateKey: %w", err)
						}
					} else if privPEM, err = ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte(passphrase)); err != nil {
						return fmt.Errorf("ssh.MarshalPrivateKeyWithPassphrase: %w", err)
					}
					a.data.Keys[name] = key{Name: name, Public: sshPub.Marshal(), Private: pem.EncodeToMemory(privPEM)}
					if err := a.saveKeys(); err != nil {
						return err
					}
					a.term.Printf("New key %q added\n", name)
					return nil
				},
			},
			{
				Name:      "delete",
				Usage:     "Delete a key",
				UsageText: "keys delete <name>",
				Action: func(ctx *cli.Context) error {
					if ctx.Args().Len() != 1 {
						cli.ShowSubcommandHelp(ctx)
						return nil
					}
					name := ctx.Args().Get(0)
					delete(a.data.Keys, name)
					return a.saveKeys()
				},
			},
			{
				Name:      "import",
				Usage:     "Import private key",
				UsageText: "keys import <name>",
				Action: func(ctx *cli.Context) error {
					if ctx.Args().Len() != 1 {
						cli.ShowSubcommandHelp(ctx)
						return nil
					}
					name := ctx.Args().Get(0)

					files := a.importFiles("", false)
					if len(files) == 0 {
						return nil
					}
					f := files[0]
					if f.Size > 20480 {
						return fmt.Errorf("file %q is too large: %d", f.Name, f.Size)
					}
					content, err := f.ReadAll()
					if err != nil {
						return fmt.Errorf("%q: %w", f.Name, err)
					}
					key := key{Name: name, Private: content}
					priv, err := a.privKey(key)
					if err != nil {
						return fmt.Errorf("%q: %w", f.Name, err)
					}
					type privateKey interface {
						Public() crypto.PublicKey
					}
					var pub crypto.PublicKey
					if k, ok := priv.(privateKey); ok {
						pub = k.Public()
					} else {
						return fmt.Errorf("key type %T is not supported", priv)
					}
					sshPub, err := ssh.NewPublicKey(pub)
					if err != nil {
						return fmt.Errorf("ssh.NewPublicKey: %w", err)
					}
					key.Public = sshPub.Marshal()
					a.data.Keys[name] = key
					if err := a.saveKeys(); err != nil {
						return err
					}
					a.term.Printf("New key %q imported from %q\n", name, f.Name)
					return nil
				},
			},
			{
				Name:      "export",
				Usage:     "Export a private key",
				UsageText: "keys export <name>",
				Action: func(ctx *cli.Context) error {
					if ctx.Args().Len() != 1 {
						cli.ShowSubcommandHelp(ctx)
						return nil
					}
					name := ctx.Args().Get(0)
					key, exists := a.data.Keys[name]
					if !exists {
						return fmt.Errorf("unknown key %q", name)
					}
					if !a.term.Confirm(fmt.Sprintf("You are about to export the PRIVATE key %q\nContinue?", name), false) {
						return errors.New("aborted")
					}
					return a.exportFile(key.Private, name+".key", "application/octet-stream")
				},
			},
		},
	}
}
