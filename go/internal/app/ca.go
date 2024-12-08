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
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/ssh"
)

func (a *App) addAuthority(name, publicKey string, hostnames []string) error {
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(publicKey))
	if err != nil {
		return err
	}
	fp := ssh.FingerprintSHA256(key)
	a.data.Authorities[fp] = &authority{
		Name:        name,
		Fingerprint: fp,
		Public:      key.Marshal(),
		Hostnames:   hostnames,
	}
	return nil
}

func (a *App) caCommand() *cli.App {
	return &cli.App{
		Name:            "ca",
		Usage:           "Manage certificate authorities",
		UsageText:       "ca <list|import|delete|add-hostname|remove-hostname>",
		Description:     "The ca command is used to manage certificate authorities.",
		HideHelpCommand: true,
		DefaultCommand:  "list",
		Commands: []*cli.Command{
			{
				Name:      "list",
				Usage:     "List all certificate authorities",
				UsageText: "ca list",
				Action: func(ctx *cli.Context) error {
					if len(a.data.Authorities) == 0 {
						a.term.Printf("<none>\n")
						return nil
					}
					cas := make([]*authority, 0, len(a.data.Authorities))
					for _, ca := range a.data.Authorities {
						cas = append(cas, ca)
					}
					sort.Slice(cas, func(i, j int) bool {
						return cas[i].Name < cas[j].Name
					})
					if len(cas) == 0 {
						a.term.Printf("<none>\n")
						return nil
					}
					lenName, lenFP := 5, 15
					for _, ca := range cas {
						lenName = max(lenName, len(ca.Name))
						lenFP = max(lenFP, len(ca.Fingerprint))
					}
					a.term.Printf("%*s %*s %s\n", -lenName, "Name", -lenFP, "Key fingerprint", "Hostnames")
					for _, ca := range cas {
						hostnames := strings.Join(ca.Hostnames, ",")
						if hostnames == "" {
							hostnames = "<none>"
						}
						a.term.Printf("%*s %*s %s\n", -lenName, ca.Name, -lenFP, ca.Fingerprint, hostnames)
					}
					return nil
				},
			},
			{
				Name:        "import",
				Usage:       "Import a certificate authority",
				UsageText:   "ca import <name> [<hostname> <hostname> ...]",
				Description: "This command imports the public key of a certificate authority\nthat signs host certificates. The list of hostnames can be\nmodified with \"add-hostname\" and \"remove-hostname\".\n\nHostnames may contain wildcards.\n\nOnce imported, host certificates signed by this authority will\nautomatically be trusted for the given hostnames.",
				Action: func(ctx *cli.Context) error {
					if ctx.Args().Len() == 0 {
						cli.ShowSubcommandHelp(ctx)
						return nil
					}
					name := ctx.Args().Get(0)
					for _, v := range a.data.Authorities {
						if v.Name == name {
							return errors.New("already exists")
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
					if err := a.addAuthority(name, string(content), ctx.Args().Slice()[1:]); err != nil {
						return err
					}
					if err := a.saveAuthorities(); err != nil {
						return err
					}
					a.term.Printf("New CA %q imported from %q\n", name, f.Name)
					return nil
				},
			},
			{
				Name:      "delete",
				Usage:     "Delete a certificate authority",
				UsageText: "ca delete <name>",
				Action: func(ctx *cli.Context) error {
					if ctx.Args().Len() != 1 {
						cli.ShowSubcommandHelp(ctx)
						return nil
					}
					name := ctx.Args().Get(0)
					if !a.term.Confirm(fmt.Sprintf("You are about to delete CA %q\nContinue?", name), false) {
						return errors.New("aborted")
					}
					for k, v := range a.data.Authorities {
						if v.Name == name {
							delete(a.data.Authorities, k)
						}
					}
					return a.saveAuthorities()
				},
			},
			{
				Name:      "add-hostname",
				Usage:     "Add hostnames to a certificate authority",
				UsageText: "ca add-hostname <name> <hostname> [<hostname> ...]",
				Action: func(ctx *cli.Context) error {
					if ctx.Args().Len() < 2 {
						cli.ShowSubcommandHelp(ctx)
						return nil
					}
					name := ctx.Args().Get(0)
					var fp string
					for k, v := range a.data.Authorities {
						if v.Name == name {
							fp = k
							break
						}
					}
					if fp == "" {
						return fmt.Errorf("certificate authority %q not found", name)
					}
					ca := a.data.Authorities[fp]
					ca.Hostnames = append(ca.Hostnames, ctx.Args().Slice()[1:]...)
					a.data.Authorities[fp] = ca
					return a.saveAuthorities()
				},
			},
			{
				Name:      "remove-hostname",
				Usage:     "Remove hostnames from a certificate authority",
				UsageText: "ca remove-hostname <name> <hostname> [<hostname> ...]",
				Action: func(ctx *cli.Context) error {
					if ctx.Args().Len() < 2 {
						cli.ShowSubcommandHelp(ctx)
						return nil
					}
					name := ctx.Args().Get(0)
					var fp string
					for k, v := range a.data.Authorities {
						if v.Name == name {
							fp = k
							break
						}
					}
					if fp == "" {
						return fmt.Errorf("certificate authority %q not found", name)
					}
					ca := a.data.Authorities[fp]
					for _, h := range ctx.Args().Slice()[1:] {
						ca.Hostnames = slices.DeleteFunc(ca.Hostnames, func(hh string) bool {
							return h == hh
						})
					}
					a.data.Authorities[fp] = ca
					return a.saveAuthorities()
				},
			},
		},
	}
}
