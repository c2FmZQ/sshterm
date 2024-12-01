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
	"fmt"

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
		Commands: []*cli.Command{
			{
				Name:      "list",
				Usage:     "List the keys currently in the agent",
				UsageText: "agent list",
				Action: func(ctx *cli.Context) error {
					keys, err := a.agent.List()
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
					priv, err := a.privKey(key)
					if err != nil {
						return fmt.Errorf("private key: %w", err)
					}
					addedKey := agent.AddedKey{
						PrivateKey: priv,
						Comment:    name,
					}
					if len(key.Certificate) > 0 {
						cert, _, _, _, err := ssh.ParseAuthorizedKey(key.Certificate)
						if err != nil {
							return fmt.Errorf("ssh.ParsePublicKey: %v", err)
						}
						if c, ok := cert.(*ssh.Certificate); ok {
							addedKey.Certificate = c
						}
					}
					if err := a.agent.Add(addedKey); err != nil {
						return err
					}
					return nil
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
						if err := a.agent.RemoveAll(); err != nil {
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
					if err := a.agent.Remove(pub); err != nil {
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
					return a.agent.Lock([]byte(passphrase))
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
					return a.agent.Unlock([]byte(passphrase))
				},
			},
		},
	}
}
