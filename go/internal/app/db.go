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
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/pbkdf2"
)

func (a *App) dbCommand() *cli.App {
	ret := &cli.App{
		Name:            "db",
		Usage:           "Manage database",
		UsageText:       "db <persist|wipe|backup|restore>",
		Description:     "The db command is used to manage the database.",
		HideHelpCommand: true,
		Commands: []*cli.Command{
			{
				Name:      "persist",
				Usage:     "Show or change the database persistence to local storage.",
				UsageText: "db persist [on|off|toggle]",
				Action: func(ctx *cli.Context) error {
					if ctx.Args().Len() > 1 {
						cli.ShowSubcommandHelp(ctx)
						return nil
					}
					if ctx.Args().Len() == 1 && a.cfg.Persist == nil {
						switch v := ctx.Args().Get(0); v {
						case "on":
							a.data.Persist = true
							if err := a.initDB(); err != nil {
								return err
							}
						case "off":
							a.data.Persist = false
							if err := a.initDB(); err != nil {
								return err
							}
						case "toggle":
							a.data.Persist = !a.data.Persist
							if err := a.initDB(); err != nil {
								return err
							}
						default:
							cli.ShowSubcommandHelp(ctx)
							return nil
						}
					}
					if a.data.Persist {
						a.term.Printf("The database is persisted to local storage.\n")
					} else {
						a.term.Printf("The database is NOT persisted to local storage.\n")
					}
					return nil
				},
			},
			{
				Name:      "wipe",
				Usage:     "Delete everything from the database.",
				UsageText: "db wipe",
				Action: func(ctx *cli.Context) error {
					if ctx.Args().Len() != 0 {
						cli.ShowSubcommandHelp(ctx)
						return nil
					}
					if !a.term.Confirm("You are about to WIPE the database.\nContinue? ", false) {
						return errors.New("aborted")
					}
					a.agent = &keyRing{}
					a.data.Authorities = make(map[string]*authority)
					a.data.Endpoints = make(map[string]*endpoint)
					a.data.Hosts = make(map[string]*host)
					a.data.Keys = make(map[string]*key)
					if err := a.saveAll(); err != nil {
						return err
					}
					return nil
				},
			},
			{
				Name:      "backup",
				Usage:     "Backup the database.",
				UsageText: "db backup",
				Flags: []cli.Flag{
					&cli.IntFlag{
						Name:  "iter",
						Value: 50000,
						Usage: "The number of pbkdf2 iterations.",
					},
				},
				Action: func(ctx *cli.Context) error {
					if ctx.Args().Len() != 0 {
						cli.ShowSubcommandHelp(ctx)
						return nil
					}
					passphrase, err := a.term.ReadPassword("Enter a passphrase for the backup: ")
					if err != nil {
						return fmt.Errorf("ReadPassword: %w", err)
					}
					passphrase2, err := a.term.ReadPassword("Enter the same passphrase: ")
					if err != nil {
						return fmt.Errorf("ReadPassword: %w", err)
					}
					if passphrase != passphrase2 {
						return fmt.Errorf("passphrase doesn't match")
					}

					payload, err := json.Marshal(a.data)
					if err != nil {
						return fmt.Errorf("json.Marshal: %w", err)
					}

					salt := make([]byte, 40)
					if _, err := io.ReadFull(rand.Reader, salt); err != nil {
						return fmt.Errorf("rand.ReadFull: %v", err)
					}
					iter := ctx.Int("iter")
					if iter < 0 || iter > 1000000 {
						return fmt.Errorf("invalid iter value")
					}
					copy(salt[:4], backupMagic)
					binary.BigEndian.PutUint32(salt[12:16], uint32(iter))
					dk := pbkdf2.Key([]byte(passphrase), salt[4:12], iter, 32, sha256.New)
					var nonce [24]byte
					var key [32]byte
					copy(nonce[:], salt[16:40])
					copy(key[:], dk)
					enc := secretbox.Seal(salt, payload, &nonce, &key)
					return a.exportFile(enc, fmt.Sprintf("sshterm-%s.backup", time.Now().UTC().Format(time.DateOnly)), "application/octet-stream")
				},
			},
			{
				Name:      "restore",
				Usage:     "Restore the database from backup.",
				UsageText: "db restore",
				Action: func(ctx *cli.Context) error {
					if ctx.Args().Len() != 0 {
						cli.ShowSubcommandHelp(ctx)
						return nil
					}
					if len(a.data.Endpoints) > 0 || len(a.data.Keys) > 0 {
						if !a.term.Confirm("Restoring a backup will OVERWRITE the database. Data may be lost.\nContinue? ", false) {
							return errors.New("aborted")
						}
					}
					files := a.importFiles(".backup", false)
					if len(files) == 0 {
						return nil
					}
					f := files[0]
					if f.Size > 102400 {
						return fmt.Errorf("file %q is too large: %d", f.Name, f.Size)
					}
					enc, err := f.ReadAll()
					if err != nil {
						return fmt.Errorf("%q: %w", f.Name, err)
					}
					if !bytes.Equal(enc[:4], backupMagic) {
						return fmt.Errorf("invalid backup file")
					}
					passphrase, err := a.term.ReadPassword("Enter the passphrase for the backup: ")
					if err != nil {
						return fmt.Errorf("ReadPassword: %w", err)
					}
					iter := binary.BigEndian.Uint32(enc[12:16])
					if iter > 1000000 {
						return fmt.Errorf("invalid iter value")
					}
					dk := pbkdf2.Key([]byte(passphrase), enc[4:12], int(iter), 32, sha256.New)

					var nonce [24]byte
					var key [32]byte
					copy(nonce[:], enc[16:40])
					copy(key[:], dk)
					payload, ok := secretbox.Open(nil, enc[40:], &nonce, &key)
					if !ok {
						return fmt.Errorf("unable to decrypt file")
					}
					a.agent = &keyRing{}
					a.data.Endpoints = nil
					a.data.Keys = nil
					if err := json.Unmarshal(payload, &a.data); err != nil {
						return fmt.Errorf("json.Unmarshal: %w", err)
					}
					return a.saveAll()
				},
			},
		},
	}
	if a.cfg.Persist != nil {
		ret.Commands[0].Usage = "Show the database persistence to local storage."
		ret.Commands[0].UsageText = "db persist"
	}
	return ret
}
