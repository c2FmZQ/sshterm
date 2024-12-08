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
	"errors"
	"sort"
	"strings"

	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/ssh"
)

func (a *App) addEndpoint(name, url, hostKey string) error {
	var hk []byte
	if key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(hostKey)); err == nil {
		hk = key.Marshal()
	}
	a.data.Endpoints[name] = &endpoint{Name: name, URL: url, HostKey: hk}
	return nil
}

func (a *App) epCommand() *cli.App {
	return &cli.App{
		Name:            "ep",
		Usage:           "Manage server endpoints",
		UsageText:       "ep <list|add|delete>",
		Description:     "The ep command is used to manage server endpoints.",
		HideHelpCommand: true,
		DefaultCommand:  "list",
		Commands: []*cli.Command{
			{
				Name:      "list",
				Usage:     "List all server endpoints",
				UsageText: "ep list",
				Action: func(ctx *cli.Context) error {
					if len(a.data.Endpoints) == 0 {
						a.term.Printf("<none>\n")
						return nil
					}
					names := make([]string, 0, len(a.data.Endpoints))
					szName, szURL := 5, 15
					for _, ep := range a.data.Endpoints {
						names = append(names, ep.Name)
						szName = max(szName, len(ep.Name))
						szURL = max(szURL, len(ep.URL))
					}
					sort.Strings(names)
					a.term.Printf("%*s %*s %s\n", -szName, "Name", -szURL, "URL", "Host key fingerprint")
					for _, n := range names {
						ep := a.data.Endpoints[n]
						fp := "n/a"
						if key, err := ssh.ParsePublicKey(ep.HostKey); err == nil {
							fp = ssh.FingerprintSHA256(key)
						}
						a.term.Printf("%*s %*s %s\n", -szName, ep.Name, -szURL, ep.URL, fp)
					}
					return nil
				},
			},
			{
				Name:        "add",
				Usage:       "Add a new server endpoint",
				UsageText:   "ep add <name> <url>",
				Description: "This command adds a server endpoint to the client.\n\nThe value of <name> is used for host certificate validation, and\nshould match one of the principals listed therein (if any). The\n<url> is one that is configured on the proxy, e.g.\nwss://ssh.example.com/myserver.",
				Action: func(ctx *cli.Context) error {
					if ctx.Args().Len() != 2 {
						cli.ShowSubcommandHelp(ctx)
						return nil
					}
					name := ctx.Args().Get(0)
					if strings.Index(name, ":") != -1 {
						return errors.New("endpoint name cannot contain \":\"")
					}
					url := ctx.Args().Get(1)
					if err := a.addEndpoint(name, url, ""); err != nil {
						return err
					}
					return a.saveEndpoints()
				},
			},
			{
				Name:      "delete",
				Usage:     "Delete a server endpoint",
				UsageText: "ep delete <name>",
				Action: func(ctx *cli.Context) error {
					if ctx.Args().Len() != 1 {
						cli.ShowSubcommandHelp(ctx)
						return nil
					}
					name := ctx.Args().Get(0)
					delete(a.data.Endpoints, name)
					return a.saveEndpoints()
				},
			},
		},
	}
}
