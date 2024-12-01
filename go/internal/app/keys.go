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
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/ssh"
)

func (a *App) keysCommand() *cli.App {
	return &cli.App{
		Name:            "keys",
		Usage:           "Manage keys",
		UsageText:       "keys <list|generate|delete|import|import-cert|export>",
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
					if !a.term.Confirm(fmt.Sprintf("You are about to delete key %q\nContinue?", name), false) {
						return errors.New("aborted")
					}
					delete(a.data.Keys, name)
					return a.saveKeys()
				},
			},
			{
				Name:      "show",
				Usage:     "Show a key",
				UsageText: "keys show <name>",
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
					pub, err := ssh.ParsePublicKey(key.Public)
					if err != nil {
						return err
					}
					a.term.Printf("Public key:\n  %s %s\nFingerprint:\n  %s\n", strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))), name, ssh.FingerprintSHA256(pub))
					if key.Certificate != nil {
						cert, err := ssh.ParsePublicKey(key.Certificate)
						if err != nil {
							return err
						}
						a.term.Printf("Certificate:\n  %s %s\nDetails:\n", strings.TrimSpace(string(ssh.MarshalAuthorizedKey(cert))), name)
						a.printCertificate(cert.(*ssh.Certificate))
					}
					return nil
				},
			},
			{
				Name:      "import",
				Usage:     "Import a key",
				UsageText: "keys import <name>",
				Action: func(ctx *cli.Context) error {
					if ctx.Args().Len() != 1 {
						cli.ShowSubcommandHelp(ctx)
						return nil
					}
					name := ctx.Args().Get(0)
					if _, exists := a.data.Keys[name]; exists {
						if !a.term.Confirm(fmt.Sprintf("Key %q already exists. Overwrite?", name), false) {
							return errors.New("aborted")
						}
					}
					files := a.importFiles(".pub", false)
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
				Usage:     "Export a key",
				UsageText: "keys export <name>",
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:  "private",
						Value: false,
						Usage: "Export the private key.",
					},
				},
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
					if ctx.Bool("private") {
						if !a.term.Confirm(fmt.Sprintf("You are about to export the PRIVATE key %q\nContinue?", name), false) {
							return errors.New("aborted")
						}
						return a.exportFile(key.Private, name+".key", "application/octet-stream")
					}
					pub, err := ssh.ParsePublicKey(key.Public)
					if err != nil {
						return err
					}
					m := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
					out := fmt.Sprintf("%s %s\n", m, name)
					return a.exportFile([]byte(out), name+".pub", "application/octet-stream")
				},
			},
			{
				Name:      "import-cert",
				Usage:     "Import a certificate",
				UsageText: "keys import-cert <key-name>",
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

					files := a.importFiles(".pub", false)
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
					fmt.Fprintf(a.term, "CERT:\n%s\n", content)
					pcert, _, _, _, err := ssh.ParseAuthorizedKey(content)
					if err != nil {
						return fmt.Errorf("ssh.ParsePublicKey: %v", err)
					}
					cert, ok := pcert.(*ssh.Certificate)
					if !ok {
						return fmt.Errorf("file %q does not contain a valid certificate", f.Name)
					}
					pub, err := ssh.ParsePublicKey(key.Public)
					if err != nil {
						return err
					}
					if !bytes.Equal(cert.Key.Marshal(), pub.Marshal()) {
						return fmt.Errorf("the certificate in %q is for a different key", f.Name)
					}
					key.Certificate = cert.Marshal()
					a.data.Keys[name] = key

					if err := a.saveKeys(); err != nil {
						return err
					}
					a.term.Printf("New certificate for key %q imported from %q\n", name, f.Name)
					a.printCertificate(cert)
					return nil
				},
			},
		},
	}
}

func (a *App) printCertificate(cert *ssh.Certificate) {
	a.term.Printf("  Serial: %x\n", cert.Serial)
	a.term.Printf("  Type: %s\n", cert.Type())
	a.term.Printf("  KeyId: %s\n", cert.KeyId)
	a.term.Printf("  ValidPrincipals: %s\n", cert.ValidPrincipals)
	a.term.Printf("  Validity: %s - %s (UTC)\n",
		time.Unix(int64(cert.ValidAfter), 0).UTC().Format(time.DateTime),
		time.Unix(int64(cert.ValidBefore), 0).UTC().Format(time.DateTime))
	if len(cert.CriticalOptions) > 0 {
		var keys []string
		for k := range cert.CriticalOptions {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		a.term.Printf("  Critical options:\n")
		for _, k := range keys {
			if v := cert.CriticalOptions[k]; v != "" {
				a.term.Printf("    %s: %s\n", k, v)
			} else {
				a.term.Printf("    %s\n", k)
			}
		}
	}
	if len(cert.Extensions) > 0 {
		var keys []string
		for k := range cert.Extensions {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		a.term.Printf("  Extensions:\n")
		for _, k := range keys {
			if v := cert.Extensions[k]; v != "" {
				a.term.Printf("    %s: %s\n", k, v)
			} else {
				a.term.Printf("    %s\n", k)
			}
		}
	}
}
