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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/ssh"

	"github.com/c2FmZQ/sshterm/internal/jsutil"
	"github.com/c2FmZQ/sshterm/internal/webauthnsk"
)

func (a *App) generateKey(name, passphrase, idp, typ string, bits int) (*key, error) {
	var sshPub ssh.PublicKey
	var privPEM *pem.Block

	if typ == "ecdsa-sk" {
		if bits != 0 && bits != 256 {
			return nil, fmt.Errorf("invalid key length %d", bits)
		}
		sk, err := webauthnsk.Create(name)
		if err != nil {
			return nil, fmt.Errorf("webauthnsk.Create: %w", err)
		}
		pp, err := sk.MarshalPrivate(passphrase)
		if err != nil {
			return nil, fmt.Errorf("sk.MarshalPrivate: %w", err)
		}
		privPEM = pp
		sshPub = sk.PublicKey()
	} else {
		pub, priv, err := createKey(typ, bits)
		if err != nil {
			return nil, err
		}
		if sshPub, err = ssh.NewPublicKey(pub); err != nil {
			return nil, fmt.Errorf("ssh.NewPublicKey: %w", err)
		}
		if passphrase == "" {
			if privPEM, err = ssh.MarshalPrivateKey(priv, ""); err != nil {
				return nil, fmt.Errorf("ssh.MarshalPrivateKey: %w", err)
			}
		} else if privPEM, err = ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte(passphrase)); err != nil {
			return nil, fmt.Errorf("ssh.MarshalPrivateKeyWithPassphrase: %w", err)
		}
	}
	k := &key{
		Name:     name,
		Public:   sshPub.Marshal(),
		Private:  pem.EncodeToMemory(privPEM),
		Provider: idp,
		errorf:   a.term.Errorf,
	}
	a.data.Keys[name] = k
	return k, nil
}

func (a *App) keysCommand() *cli.App {
	return &cli.App{
		Name:            "keys",
		Usage:           "Manage user keys and certificates",
		UsageText:       "keys <list|generate|delete|show|change-pass|import|import-cert|export>",
		Description:     "The keys command is used to manage user keys and certificates.",
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
						pub, err := key.sshPublicKey()
						if err != nil {
							a.term.Errorf("sshPublicKey: %v", err)
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
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "type",
						Aliases: []string{"t"},
						Value:   "ed25519",
						Usage:   "The type of key to generate: ecdsa, ecdsa-sk, ed25519, or rsa.",
					},
					&cli.IntFlag{
						Name:    "bits",
						Aliases: []string{"b"},
						Usage:   "The key size in bits.",
					},
					&cli.StringFlag{
						Name:  "idp",
						Usage: "The URL of the identity provider to use.",
					},
				},
				Action: func(ctx *cli.Context) error {
					if ctx.Args().Len() != 1 {
						cli.ShowSubcommandHelp(ctx)
						return nil
					}
					name := ctx.Args().Get(0)
					passphrase, err := a.term.ReadPassword("Enter a passphrase for the private key: ")
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

					if _, err := a.generateKey(name, passphrase, ctx.String("idp"), ctx.String("type"), ctx.Int("bits")); err != nil {
						return err
					}
					if err := a.saveKeys(true); err != nil {
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
					return a.saveKeys(true)
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
					pub, err := key.sshPublicKey()
					if err != nil {
						return err
					}
					a.term.Printf("Public key:  %s %s\n", strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))), name)
					a.term.Printf("Fingerprint: %s\n", ssh.FingerprintSHA256(pub))
					if cert := key.Certificate(); cert != nil {
						a.term.Printf("Certificate: %s\n", strings.TrimSpace(string(key.CertBytes)))
						a.term.Printf("Details:\n")
						a.printCertificate(cert)
						if err := checkCertificate(cert, ssh.UserCert); err != nil {
							a.term.Errorf("%v", err)
						}
					}
					if key.Provider != "" {
						a.term.Printf("Identity Provider: %s\n", key.Provider)
					}
					return nil
				},
			},
			{
				Name:      "change-pass",
				Usage:     "Change a key's passphrase",
				UsageText: "keys change-pass <name>",
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
					prompt := func() (string, error) {
						passphrase, err := a.term.ReadPassword("Enter a NEW passphrase for the private key: ")
						if err != nil {
							return "", fmt.Errorf("ReadPassword: %w", err)
						}
						passphrase2, err := a.term.ReadPassword("Re-enter the same new passphrase: ")
						if err != nil {
							return "", fmt.Errorf("ReadPassword: %w", err)
						}
						if passphrase != passphrase2 {
							return "", fmt.Errorf("passphrase doesn't match")
						}
						return passphrase, nil
					}
					var privPEM *pem.Block
					if bytes.HasPrefix(key.Private, []byte("-----BEGIN WEBAUTHN ")) {
						sk, err := webauthnsk.Unmarshal(key.Private, name, a.term.ReadPassword)
						if err != nil {
							return fmt.Errorf("webauthnsk.Unmarshal: %w", err)
						}
						pp, err := prompt()
						if err != nil {
							return err
						}
						if privPEM, err = sk.MarshalPrivate(pp); err != nil {
							return err
						}
					} else {
						priv, err := key.PrivateKey(a.term.ReadPassword)
						if err != nil {
							return fmt.Errorf("%q: %w", name, err)
						}
						pp, err := prompt()
						if err != nil {
							return err
						}
						if pp == "" {
							if privPEM, err = ssh.MarshalPrivateKey(priv, ""); err != nil {
								return fmt.Errorf("ssh.MarshalPrivateKey: %w", err)
							}
						} else if privPEM, err = ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte(pp)); err != nil {
							return fmt.Errorf("ssh.MarshalPrivateKeyWithPassphrase: %w", err)
						}
					}
					key.Private = pem.EncodeToMemory(privPEM)
					a.data.Keys[name] = key
					if err := a.saveKeys(true); err != nil {
						return err
					}
					a.term.Printf("Passphrase changed for key %q\n", name)
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
					key := &key{
						Name:    name,
						Private: content,
						errorf:  a.term.Errorf,
					}
					if bytes.HasPrefix(content, []byte("-----BEGIN WEBAUTHN ")) {
						sk, err := webauthnsk.Unmarshal(content, name, a.term.ReadPassword)
						if err != nil {
							return fmt.Errorf("webauthnsk.Unmarshal: %w", err)
						}
						key.Public = sk.Marshal()
					} else {
						priv, err := key.PrivateKey(a.term.ReadPassword)
						if err != nil {
							return fmt.Errorf("%q: %w", f.Name, err)
						}
						var pub crypto.PublicKey
						if k, ok := priv.(crypto.Signer); ok {
							pub = k.Public()
						} else {
							return fmt.Errorf("key type %T is not supported", priv)
						}
						sshPub, err := ssh.NewPublicKey(pub)
						if err != nil {
							return fmt.Errorf("ssh.NewPublicKey: %w", err)
						}
						key.Public = sshPub.Marshal()
					}
					a.data.Keys[name] = key
					if err := a.saveKeys(true); err != nil {
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
					pub, err := key.sshPublicKey()
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
					if key.Provider != "" {
						return errors.New("key is using an identity provider")
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
					pcert, _, _, _, err := ssh.ParseAuthorizedKey(content)
					if err != nil {
						return fmt.Errorf("ssh.ParseAuthorizedKey: %v", err)
					}
					cert, ok := pcert.(*ssh.Certificate)
					if !ok {
						return fmt.Errorf("file %q does not contain a valid certificate", f.Name)
					}
					pub, err := key.sshPublicKey()
					if err != nil {
						return err
					}
					if subtle.ConstantTimeCompare(cert.Key.Marshal(), pub.Marshal()) != 1 {
						return fmt.Errorf("the certificate in %q is for a different key", f.Name)
					}
					key.CertBytes = content
					a.data.Keys[name] = key

					if err := a.saveKeys(true); err != nil {
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

func createKey(t string, b int) (crypto.PublicKey, crypto.PrivateKey, error) {
	switch t {
	case "ed25519", "":
		return ed25519.GenerateKey(rand.Reader)

	case "ecdsa":
		if b == 0 {
			b = 256
		}
		var curve elliptic.Curve
		switch b {
		case 256:
			curve = elliptic.P256()
		case 384:
			curve = elliptic.P384()
		case 521:
			curve = elliptic.P521()
		default:
			return nil, nil, fmt.Errorf("invalid key length %d", b)
		}

		k, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		return k.Public(), k, nil

	case "rsa":
		if b == 0 {
			b = 3072
		}
		k, err := rsa.GenerateKey(rand.Reader, b)
		if err != nil {
			return nil, nil, err
		}
		return k.Public(), k, nil

	default:
		return nil, nil, fmt.Errorf("unknown key type %q", t)
	}
}

func (a *App) printCertificate(cert *ssh.Certificate) {
	a.term.Printf("  Serial:.......... 0x%x (%d)\n", cert.Serial, cert.Serial)
	a.term.Printf("  Public key:...... %s", ssh.MarshalAuthorizedKey(cert.Key))
	a.term.Printf("  Public key fp:... %s\n", ssh.FingerprintSHA256(cert.Key))
	a.term.Printf("  Type:............ %s\n", cert.Type())
	a.term.Printf("  Key ID:.......... %s\n", cert.KeyId)
	if cert.ValidBefore != 0 {
		a.term.Printf("  Validity:........ %s - %s (UTC)\n",
			time.Unix(int64(cert.ValidAfter), 0).UTC().Format(time.DateTime),
			time.Unix(int64(cert.ValidBefore), 0).UTC().Format(time.DateTime))
	}
	a.term.Printf("  Authority key:... %s", ssh.MarshalAuthorizedKey(cert.SignatureKey))
	a.term.Printf("  Authority key fp: %s\n", ssh.FingerprintSHA256(cert.SignatureKey))
	if len(cert.ValidPrincipals) > 0 {
		a.term.Printf("  Principals:\n")
		for _, p := range cert.ValidPrincipals {
			a.term.Printf("    %s\n", p)
		}
	}
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

type key struct {
	Name      string `json:"name"`
	Public    []byte `json:"public"`
	Private   []byte `json:"private"`
	Provider  string `json:"provider,omitempty"`
	CertBytes []byte `json:"certificate,omitempty"`

	errorf func(string, ...any)
}

func (k *key) isWebAuthn() bool {
	return bytes.HasPrefix(k.Private, []byte("-----BEGIN WEBAUTHN "))
}

func (k *key) sshPublicKey() (ssh.PublicKey, error) {
	if k.isWebAuthn() {
		return webauthnsk.UnmarshalPublic(k.Public)
	}
	return ssh.ParsePublicKey(k.Public)
}

func (k *key) Certificate() (cert *ssh.Certificate) {
	parseCert := func() *ssh.Certificate {
		c, _, _, _, err := ssh.ParseAuthorizedKey(k.CertBytes)
		if err != nil {
			return nil
		}
		if cert, ok := c.(*ssh.Certificate); ok {
			return cert
		}
		return nil
	}
	cert = parseCert()
	if cert != nil && cert.ValidBefore > uint64(time.Now().Add(5*time.Minute).Unix()) {
		return
	}
	if err := k.updateCert(); err != nil {
		k.errorf("certificate update: %v", err)
		return
	}
	return parseCert()
}

func (k *key) updateCert() error {
	if k.Provider == "" {
		return nil
	}
	pub, err := k.sshPublicKey()
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", k.Provider, bytes.NewReader(ssh.MarshalAuthorizedKey(pub)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "text/plain")
	if sid := jsutil.TLSProxySID(); sid != "" {
		req.Header.Set("x-csrf-token", sid)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("%q: %w", k.Provider, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "text/plain" {
		if resp.StatusCode == http.StatusForbidden {
			msg, _ := io.ReadAll(&io.LimitedReader{R: resp.Body, N: 1024})
			return fmt.Errorf("%q: %s: %s", k.Provider, resp.Status, maskControl(string(msg)))
		}
		return fmt.Errorf("%q: status code %q content-type %q", k.Provider, resp.Status, resp.Header.Get("Content-Type"))
	}
	certBytes, err := io.ReadAll(&io.LimitedReader{R: resp.Body, N: 20480})
	if err != nil {
		return fmt.Errorf("%q: %w", k.Provider, err)
	}
	if c, _, _, _, err := ssh.ParseAuthorizedKey(certBytes); err != nil {
		return fmt.Errorf("%q: %w", k.Provider, err)
	} else if cert, ok := c.(*ssh.Certificate); !ok {
		return fmt.Errorf("%q: returned data is not a certificate", k.Provider)
	} else if !bytes.Equal(cert.Key.Marshal(), pub.Marshal()) {
		return fmt.Errorf("%q: certificate key doesn't match", k.Provider)
	} else if err := checkCertificate(cert, ssh.UserCert); err != nil {
		return fmt.Errorf("%q: %w", k.Provider, err)
	}
	k.CertBytes = certBytes
	return nil
}

func (k *key) PrivateKey(rp func(string) (string, error)) (any, error) {
	priv, err := ssh.ParseRawPrivateKey(k.Private)
	if err == nil {
		return priv, nil
	}
	if _, ok := err.(*ssh.PassphraseMissingError); !ok || rp == nil {
		return nil, err
	}
	passphrase, err := rp("Enter the passphrase for " + k.Name + ": ")
	if err != nil {
		return nil, err
	}
	return ssh.ParseRawPrivateKeyWithPassphrase(k.Private, []byte(passphrase))
}

func (k *key) Signer(rp func(string) (string, error)) (ssh.Signer, error) {
	if k.isWebAuthn() {
		sk, err := webauthnsk.Unmarshal(k.Private, k.Name, rp)
		if err != nil {
			return nil, err
		}
		return &dynSigner{
			Signer: sk,
			key:    k,
		}, nil
	}
	priv, err := k.PrivateKey(rp)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, fmt.Errorf("NewSignerFromKey: %w", err)
	}
	return &dynSigner{
		Signer: signer,
		key:    k,
	}, nil
}

type dynSigner struct {
	ssh.Signer
	key *key
}

func (s *dynSigner) PublicKey() ssh.PublicKey {
	if cert := s.key.Certificate(); cert != nil {
		return cert
	}
	return s.Signer.PublicKey()
}
