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
	"sort"

	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/ssh"
)

func (a *App) addHost(name, key string) error {
	var hk []byte
	if key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(key)); err == nil {
		hk = key.Marshal()
	}
	a.data.Hosts[name] = &host{Name: name, Key: hk}
	return nil
}

func (a *App) hostsCommand() *cli.App {
	return &cli.App{
		Name:            "hosts",
		Usage:           "Manage known hosts",
		UsageText:       "hosts <list|delete>",
		Description:     "The hosts command is used to manage known hosts.",
		HideHelpCommand: true,
		DefaultCommand:  "list",
		Commands: []*cli.Command{
			{
				Name:      "list",
				Usage:     "List all known hosts",
				UsageText: "hosts list",
				Action: func(ctx *cli.Context) error {
					if len(a.data.Hosts) == 0 {
						a.term.Printf("<none>\n")
						return nil
					}
					names := make([]string, 0, len(a.data.Hosts))
					szName := 5
					for _, host := range a.data.Hosts {
						names = append(names, host.Name)
						szName = max(szName, len(host.Name))
					}
					sort.Strings(names)
					a.term.Printf("%*s %s\n", -szName, "Name", "Host key fingerprint")
					for _, n := range names {
						host := a.data.Hosts[n]
						fp := "n/a"
						if key, err := ssh.ParsePublicKey(host.Key); err == nil {
							fp = ssh.FingerprintSHA256(key)
						}
						a.term.Printf("%*s %s\n", -szName, host.Name, fp)
					}
					return nil
				},
			},
			{
				Name:      "delete",
				Usage:     "Delete a known host",
				UsageText: "hosts delete <name>",
				Action: func(ctx *cli.Context) error {
					if ctx.Args().Len() != 1 {
						cli.ShowSubcommandHelp(ctx)
						return nil
					}
					name := ctx.Args().Get(0)
					delete(a.data.Hosts, name)
					return a.saveHosts(true)
				},
			},
		},
	}
}
