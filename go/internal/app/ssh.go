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
	"time"

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
			priv, err := a.privKey(key)
			if err != nil {
				return nil, fmt.Errorf("private key: %w", err)
			}
			signer, err := ssh.NewSignerFromKey(priv)
			if err != nil {
				return nil, fmt.Errorf("NewSignerFromKey: %w", err)
			}
			if key.Certificate != nil {
				cert, _, _, _, err := ssh.ParseAuthorizedKey(key.Certificate)
				if err != nil {
					return nil, fmt.Errorf("ssh.ParseAuthorizedKey: %v", err)
				}
				if signer, err = ssh.NewCertSigner(cert.(*ssh.Certificate), signer); err != nil {
					return nil, fmt.Errorf("ssh.NewCertSigner: %v", err)
				}
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
	if err := a.checkCertificate(cert); err != nil {
		errs = append(errs, err)
	}
	caFP := ssh.FingerprintSHA256(cert.SignatureKey)
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

	if !a.term.Confirm("Do you want to connect anyway? ", false) {
		return err
	}
	return nil
}

func (a *App) hostKeyCallback(ep endpoint, hostname string, key ssh.PublicKey) error {
	hk := key.Marshal()
	if ep.HostKey != nil {
		if subtle.ConstantTimeCompare(ep.HostKey, hk) != 1 {
			return errors.New("host key changed")
		}
		return nil
	}
	a.term.Printf("Host key for %s\n%s %s\n\n", hostname, key.Type(), ssh.FingerprintSHA256(key))
	if !a.term.Confirm("Do you TRUST this host? ", false) {
		return errors.New("host key rejected by user")
	}
	if a.term.Confirm("Remember this decision? ", false) {
		ep.HostKey = hk
		a.data.Endpoints[ep.Name] = ep
		return a.saveEndpoints()
	}
	return nil
}

func (a *App) privKey(key key) (any, error) {
	priv, err := ssh.ParseRawPrivateKey(key.Private)
	if _, ok := err.(*ssh.PassphraseMissingError); ok {
		passphrase, err2 := a.term.ReadPassword("Enter passphrase for " + key.Name + ": ")
		if err2 != nil {
			return nil, fmt.Errorf("ReadPassword: %w", err2)
		}
		priv, err = ssh.ParseRawPrivateKeyWithPassphrase(key.Private, []byte(passphrase))
	}
	return priv, err
}

func (a *App) checkCertificate(cert *ssh.Certificate) error {
	var errs []error
	if cert.CertType != ssh.HostCert {
		errs = append(errs, fmt.Errorf("certificate has wrong type: %d", cert.CertType))
	}
	now := uint64(time.Now().Unix())
	if cert.ValidAfter > now {
		errs = append(errs, fmt.Errorf("certificate is not yet valid"))
	}
	if cert.ValidBefore > 0 && now > cert.ValidBefore {
		errs = append(errs, fmt.Errorf("certificate is expired"))
	}
	c2 := *cert
	c2.Signature = nil
	signBytes := c2.Marshal()
	if err := cert.SignatureKey.Verify(signBytes[:len(signBytes)-4], cert.Signature); err != nil {
		errs = append(errs, fmt.Errorf("certificate signature is invalid"))
	}
	return errors.Join(errs...)
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
