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
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
	"path"
	"strings"

	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/c2FmZQ/sshterm/internal/websocket"
)

func (a *App) sshCommand() *cli.App {
	return &cli.App{
		Name:            "ssh",
		Usage:           "Start an SSH connection",
		UsageText:       "ssh [-i <keyname>] username@<endpoint> [command]",
		Description:     "The ssh command starts an SSH connection with a remote server.\nUse the -i flag to select a key (see the keys command). If a key\nwith the name 'default' exists, it will be used by default.\n\nThe <endpoint> must have been configured with the ep command.",
		HideHelpCommand: true,
		Action:          a.ssh,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "identity",
				Aliases: []string{"i"},
				Usage:   "The key to use for authentication.",
			},
			&cli.BoolFlag{
				Name:    "forward-agent",
				Aliases: []string{"A"},
				Value:   false,
				Usage:   "Forward access to the local SSH agent. Use with caution.",
			},
		},
	}
}

func (a *App) ssh(ctx *cli.Context) error {
	t := a.term
	if ctx.Args().Len() == 0 {
		cli.ShowSubcommandHelp(ctx)
		return nil
	}
	target := ctx.Args().Get(0)
	var command string
	if ctx.Args().Len() >= 2 {
		command = strings.Join(ctx.Args().Slice()[1:], " ")
	}
	keyName := ctx.String("identity")

	cctx, cancel := context.WithCancel(ctx.Context)
	defer cancel()

	client, err := a.sshClient(cctx, target, keyName)
	if err != nil {
		return err
	}

	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("client.NewSession: %w", err)
	}
	defer func() {
		session.Close()
	}()

	if ctx.Bool("A") {
		if err := agent.ForwardToAgent(client, a.agent); err != nil {
			return fmt.Errorf("agent.ForwardToAgent: %w", err)
		}
		if err := agent.RequestAgentForwarding(session); err != nil {
			return fmt.Errorf("agent.RequestAgentForwarding: %w", err)
		}
	}

	session.Stdin = t
	session.Stdout = t
	session.Stderr = t

	if command != "" {
		return session.Run(command)
	}
	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.ICRNL:         1,
		ssh.IXON:          1,
		ssh.IXANY:         1,
		ssh.IMAXBEL:       1,
		ssh.OPOST:         1,
		ssh.ONLCR:         1,
		ssh.ISIG:          1,
		ssh.ICANON:        1,
		ssh.IEXTEN:        1,
		ssh.ECHOE:         1,
		ssh.ECHOK:         1,
		ssh.ECHOCTL:       1,
		ssh.ECHOKE:        1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	if err := session.RequestPty("xterm", t.Rows(), t.Cols(), modes); err != nil {
		t.Errorf("%v", err)
	} else {
		t.OnResize(cctx, session.WindowChange)
	}
	a.inShell.Store(true)
	defer a.inShell.Store(false)
	if err := session.Shell(); err != nil {
		return fmt.Errorf("session.Shell: %w", err)
	}
	return session.Wait()
}

func (a *App) sshClient(ctx context.Context, target, keyName string) (*ssh.Client, error) {
	t := a.term
	username, epName, ok := strings.Cut(target, "@")
	if !ok {
		return nil, fmt.Errorf("invalid target %q", target)
	}
	ep, exists := a.data.Endpoints[epName]
	if !exists {
		return nil, fmt.Errorf("unknown endpoint %q", epName)
	}

	ws, err := websocket.New(ctx, ep.URL, t)
	if err != nil {
		return nil, err
	}

	signers, err := a.agent.Signers()
	if err != nil {
		t.Errorf("%v", err)
	}
	if len(signers) == 0 || keyName != "" {
		origKeyName := keyName
		if keyName == "" {
			keyName = "default"
		}
		if key, exists := a.data.Keys[keyName]; exists {
			signer, err := key.Signer(a.term.ReadPassword)
			if err != nil {
				return nil, fmt.Errorf("key.signer: %w", err)
			}
			signers = append(signers, signer)
		} else if origKeyName != "" {
			t.Errorf("unknown key %q", keyName)
		}
	}

	conn, chans, reqs, err := ssh.NewClientConn(ws, ep.Name, &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signers...),
			ssh.RetryableAuthMethod(ssh.KeyboardInteractive(
				func(name, instruction string, questions []string, echos []bool) ([]string, error) {
					if name != "" {
						t.Printf("%s\n", maskControl(name))
					}
					if instruction != "" {
						t.Printf("%s\n", maskControl(instruction))
					}
					ans := make([]string, len(questions))
					for i, q := range questions {
						var err error
						if echos[i] {
							ans[i], err = t.Prompt(maskControl(q))
						} else {
							ans[i], err = t.ReadPassword(maskControl(q))
						}
						if err != nil {
							return nil, err
						}
					}
					return ans, nil
				},
			), 5),
		},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			cert, ok := key.(*ssh.Certificate)
			if ok {
				return a.hostCertificateCallback(ep, hostname, cert)
			}
			return a.hostKeyCallback(ep, hostname, key)
		},
		BannerCallback: func(message string) error {
			t.Printf("%s\n", message)
			return nil
		},
	})
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, io.EOF
		}
		return nil, err
	}

	return ssh.NewClient(conn, chans, reqs), nil
}

func (a *App) hostCertificateCallback(ep endpoint, hostname string, cert *ssh.Certificate) error {
	var errs []error
	if err := checkCertificate(cert, ssh.HostCert); err != nil {
		errs = append(errs, err)
	}
	caFP := ssh.FingerprintSHA256(cert.SignatureKey)
	caIsTrusted := false
	ca, exists := a.data.Authorities[caFP]
	if !exists {
		errs = append(errs, fmt.Errorf("host certificate is signed by an unknown authority"))
	} else {
		ok := false
		for _, h := range ca.Hostnames {
			if matched, err := path.Match(h, hostname); err == nil && matched {
				ok = true
				break
			}
		}
		caIsTrusted = ok
		if !ok {
			errs = append(errs, fmt.Errorf("host certificate is signed by an authority that is not trusted for hostname %q", hostname))
		}
	}

	err := errors.Join(errs...)
	if err == nil {
		a.term.Printf("Host certificate is trusted.\n")
		return nil
	}

	a.term.Printf("Host certificate:\n")
	a.printCertificate(cert)
	a.term.Print("\n")

	a.term.Errorf("Host certificate is NOT trusted:\n  %v\n", strings.ReplaceAll(err.Error(), "\n", "\n  "))

	a.term.Printf("Options:\n")
	a.term.Printf(" 1- Abort the connection (default)\n")
	a.term.Printf(" 2- Continue, this time only.\n")
	if !caIsTrusted {
		a.term.Printf(" 3- Continue, and trust this authority in the future.\n")
	}

	switch ans, _ := a.term.Prompt("Choice> "); ans {
	case "2":
		return nil
	case "3":
		if caIsTrusted {
			return err
		}
		if ca, exists := a.data.Authorities[caFP]; exists {
			ca.Hostnames = append(ca.Hostnames, hostname)
			a.data.Authorities[caFP] = ca
			return a.saveAuthorities()
		}
		a.data.Authorities[caFP] = authority{
			Fingerprint: caFP,
			Name:        caFP[len(caFP)-8:],
			Public:      cert.SignatureKey.Marshal(),
			Hostnames: []string{
				hostname,
			},
		}
		return a.saveAuthorities()
	default:
		return err
	}
}

func (a *App) hostKeyCallback(ep endpoint, hostname string, key ssh.PublicKey) error {
	hk := key.Marshal()
	var err error
	if ep.HostKey != nil {
		if subtle.ConstantTimeCompare(ep.HostKey, hk) == 1 {
			a.term.Printf("Host key is trusted.\n")
			return nil
		}
		var old ssh.PublicKey
		if old, err = ssh.ParsePublicKey(ep.HostKey); err != nil {
			return err
		}
		err = fmt.Errorf("host key changed, was %s, now is %s", ssh.FingerprintSHA256(old), ssh.FingerprintSHA256(key))
	}
	a.term.Printf("Host key for %s is not trusted\n%s %s\n\n", hostname, key.Type(), ssh.FingerprintSHA256(key))
	if err != nil {
		a.term.Errorf("%v\n", err)
	}

	a.term.Printf("Options:\n")
	a.term.Printf(" 1- Abort the connection (default)\n")
	a.term.Printf(" 2- Continue, this time only.\n")
	a.term.Printf(" 3- Continue, and trust this host key in the future.\n")

	switch ans, _ := a.term.Prompt("Choice> "); ans {
	case "2":
		return nil
	case "3":
		ep.HostKey = hk
		a.data.Endpoints[ep.Name] = ep
		return a.saveEndpoints()
	default:
		return errors.New("host key rejected by user")
	}
}

func maskControl(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\t' || r == '\n' || r >= ' ':
			return r
		default:
			return '#'
		}
	}, s)
}
