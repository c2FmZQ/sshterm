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
	"strconv"
	"strings"
	"time"

	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/c2FmZQ/sshterm/internal/termsafe"
	"github.com/c2FmZQ/sshterm/internal/websocket"
)

func (a *App) sshCommand() *cli.App {
	return &cli.App{
		Name:            "ssh",
		Usage:           "Start an SSH connection",
		UsageText:       "ssh [-i <keyname>] <username>@<hostname> [command]",
		Description:     "The ssh command starts an SSH connection with a remote server.\nUse the -i flag to select a key (see the keys command). If a key\nwith the name 'default' exists, it will be used by default.\n\nThe <hostname> must have been configured with the ep command,\nunless --jump-host is used, in which case, the first jump host\nmust be a configured endpoint.",
		HideHelpCommand: true,
		Action:          a.ssh,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "identity",
				Aliases: []string{"i"},
				Usage:   "The key to use for authentication.",
			},
			&cli.StringFlag{
				Name:    "jump-hosts",
				Aliases: []string{"J"},
				Usage:   "Connect by going through jump hosts.",
			},
			&cli.BoolFlag{
				Name:    "forward-agent",
				Aliases: []string{"A"},
				Value:   false,
				Usage:   "Forward access to the local SSH agent. Use with caution.",
			},
			&cli.BoolFlag{
				Name:    "zmodem",
				Aliases: []string{"z"},
				Value:   false,
				Usage:   "Enable ZMODEM support for file transfers (rz/sz).",
			},
		},
	}
}

func (a *App) ssh(ctx *cli.Context) error {
	if ctx.Args().Len() == 0 {
		cli.ShowSubcommandHelp(ctx)
		return nil
	}
	var command string
	if ctx.Args().Len() >= 2 {
		command = strings.Join(ctx.Args().Slice()[1:], " ")
	}

	return a.runSSH(ctx.Context, ctx.Args().Get(0), ctx.String("identity"), command, ctx.Bool("forward-agent"), ctx.String("jump-hosts"), ctx.Bool("zmodem"))
}

func (a *App) runSSH(ctx context.Context, target, keyName, command string, forwardAgent bool, jumpHosts string, enableZmodem bool) (err error) {
	t := a.term
	ctx, cancel := context.WithCancelCause(ctx)
	defer func() {
		if e := context.Cause(ctx); e != nil {
			err = e
		}
		cancel(nil)
	}()

	client, err := a.sshClient(ctx, target, keyName, jumpHosts)
	if err != nil {
		return err
	}
	go sshKeepAlive(ctx, client, cancel)

	t.Printf("\x1b]0;ssh %s\x07", target)
	defer t.Printf("\x1b]0;sshterm\x07")

	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("client.NewSession: %w", err)
	}
	defer func() {
		session.Close()
	}()

	if forwardAgent {
		_, hostname, _ := parseUserHost(target)
		fwd := &forwardedAgent{
			agent:  globalAgent,
			host:   hostname,
			notify: t.Printf,
		}
		if err := agent.ForwardToAgent(client, fwd); err != nil {
			return fmt.Errorf("agent.ForwardToAgent: %w", err)
		}
		if err := agent.RequestAgentForwarding(session); err != nil {
			return fmt.Errorf("agent.RequestAgentForwarding: %w", err)
		}
	}

	var sessionStdin io.Reader = t
	var sessionStdout io.Writer = t
	if enableZmodem {
		filter := a.newZModemFilter()
		sessionStdin = filter
		sessionStdout = filter
	}

	session.Stdin = sessionStdin
	session.Stdout = sessionStdout
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
		t.OnResize(ctx, session.WindowChange)
	}
	a.inShell.Store(true)
	defer a.inShell.Store(false)
	if err := session.Shell(); err != nil {
		return fmt.Errorf("session.Shell: %w", err)
	}
	return session.Wait()
}

// parseUserHost splits a string in the form "user@host" at the last '@'.
// This allows the user part to contain '@' characters.
// If no '@' is present, it returns the original string as the first return
// value, an empty string as the second, and false.
func parseUserHost(target string) (string, string, bool) {
	p := strings.LastIndex(target, "@")
	if p == -1 {
		return target, "", false
	}
	return target[:p], target[p+1:], true
}

func (a *App) sshClient(ctx context.Context, target, keyName, jumpHosts string) (*ssh.Client, error) {
	username, hostname, ok := parseUserHost(target)
	if !ok {
		return nil, fmt.Errorf("invalid target %q", target)
	}
	type userhost struct {
		u, h string
	}
	var hops []userhost
	if jumpHosts != "" {
		for _, jh := range strings.Split(jumpHosts, ",") {
			jh = strings.TrimSpace(jh)
			u, h, ok := parseUserHost(jh)
			if !ok {
				u = username
				h = jh
			}
			hops = append(hops, userhost{u, h})
		}
	}
	hops = append(hops, userhost{username, hostname})

	ep, exists := a.data.Endpoints[hops[0].h]
	if !exists {
		return nil, fmt.Errorf("unknown endpoint %q", hops[0].h)
	}

	signers, err := a.sshSigners(keyName)
	if err != nil {
		return nil, err
	}

	if len(hops) > 1 {
		a.term.Printf("[1] Connecting %s@%s...", hops[0].u, hops[0].h)
	}
	ws, err := websocket.New(ctx, ep.URL, a.term)
	if err != nil {
		return nil, err
	}
	if len(hops) > 1 {
		a.term.Printf("✅\n")
	}
	context.AfterFunc(ctx, func() { ws.Close() })

	client, err := a.sshClientFromConn(ctx, ws, hops[0].u, hops[0].h, ep, signers)
	if err != nil {
		return nil, err
	}

	for i := 1; i < len(hops); i++ {
		addr := hops[i].h
		if !strings.Contains(addr, ":") {
			addr += ":22"
		}
		a.term.Printf("[%d] Connecting %s@%s...", i+1, hops[i].u, hops[i].h)
		conn, err := client.DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, err
		}
		a.term.Printf("✅\n")
		context.AfterFunc(ctx, func() { conn.Close() })
		if client, err = a.sshClientFromConn(ctx, conn, hops[i].u, hops[i].h, nil, signers); err != nil {
			return nil, err
		}
	}

	return client, nil
}

func (a *App) sshSigners(keyName string) ([]ssh.Signer, error) {
	signers, err := globalAgent.Signers()
	if err != nil {
		a.term.Errorf("%v", err)
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
			return nil, fmt.Errorf("unknown key %q", keyName)
		}
	}
	return signers, nil
}

// sshClientFromConn creates an SSH client using an existing connection. ep is
// the endpoint used for the connection, if any.
func (a *App) sshClientFromConn(ctx context.Context, c net.Conn, username, hostname string, ep *endpoint, signers []ssh.Signer) (*ssh.Client, error) {
	t := a.term
	conn, chans, reqs, err := ssh.NewClientConn(c, hostname, &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signers...),
			ssh.RetryableAuthMethod(ssh.KeyboardInteractive(
				func(name, instruction string, questions []string, echos []bool) ([]string, error) {
					if name != "" {
						t.Printf("%s\n", termsafe.Text(name))
					}
					if instruction != "" {
						t.Printf("%s\n", termsafe.Text(instruction))
					}
					ans := make([]string, len(questions))
					for i, q := range questions {
						q := fmt.Sprintf("%s[%s]%s %s", t.Escape.Green, hostname, t.Escape.Reset, termsafe.Text(q))
						var err error
						if echos[i] {
							ans[i], err = t.Prompt(q)
						} else {
							ans[i], err = t.ReadPassword(q)
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
				return a.hostCertificateCallback(hostname, ep, cert)
			}
			return a.hostKeyCallback(hostname, key)
		},
		BannerCallback: func(message string) error {
			t.Printf("%s\n", termsafe.Text(message))
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

func (a *App) hostCertificateCallback(hostname string, ep *endpoint, cert *ssh.Certificate) error {
	// The certificate must be valid for the endpoint's hostname, which may
	// be different from the name used to connect.
	certHostname := hostname
	if ep != nil {
		certHostname = ep.certHostname()
	}
	displayName := hostname
	if certHostname != hostname {
		displayName = fmt.Sprintf("%s (%s)", hostname, certHostname)
	}

	var errs []error
	certErr := checkCertificate(cert, ssh.HostCert)
	if certErr != nil {
		errs = append(errs, certErr)
	}
	principalErr := checkHostCertPrincipal(cert, certHostname)
	if principalErr != nil {
		errs = append(errs, principalErr)
	}
	caFP := ssh.FingerprintSHA256(cert.SignatureKey)
	ca, caExists := a.data.Authorities[caFP]
	// caTrustedFor returns true if the authority is trusted for any of the
	// names.
	caTrustedFor := func(names ...string) bool {
		if !caExists {
			return false
		}
		for _, h := range ca.Hostnames {
			for _, n := range names {
				if matched, err := path.Match(h, n); err == nil && matched {
					return true
				}
			}
		}
		return false
	}
	caIsTrusted := caTrustedFor(hostname, certHostname)
	if !caExists {
		errs = append(errs, fmt.Errorf("host certificate is signed by an unknown authority"))
	} else if !caIsTrusted {
		errs = append(errs, fmt.Errorf("host certificate is signed by an authority that is not trusted for hostname %q", certHostname))
	}

	err := errors.Join(errs...)
	if err == nil {
		a.term.Printf("Host certificate for %s is trusted.\n", displayName)
		return nil
	}

	a.term.Printf("Host certificate for %s:\n", displayName)
	a.printCertificate(cert)
	a.term.Print("\n")

	a.term.Errorf("Host certificate for %s is NOT trusted:\n  %v\n", displayName, strings.ReplaceAll(err.Error(), "\n", "\n  "))

	a.term.Printf("Options:\n")
	a.term.Printf(" 1- Abort the connection (default)\n")
	a.term.Printf(" 2- Continue, this time only.\n")

	// Trusting the authority only helps if the certificate itself is valid.
	canTrustCA := certErr == nil && principalErr == nil && !caIsTrusted
	if canTrustCA {
		a.term.Printf(" 3- Continue, and trust this authority in the future.\n")
	}
	// If the only problem is that the certificate is for a different
	// hostname, offer to use one of its principals as the endpoint's
	// hostname.
	var hostnames []string
	if ep != nil && certErr == nil && principalErr != nil {
		for _, p := range cert.ValidPrincipals {
			if strings.ContainsAny(p, "*?[") || termsafe.Name(p) != p {
				continue
			}
			if caTrustedFor(hostname, p) {
				hostnames = append(hostnames, p)
			}
		}
	}
	for i, h := range hostnames {
		a.term.Printf(" %d- Continue, and set the hostname of endpoint %s to %s.\n", i+3, ep.Name, h)
	}

	ans, _ := a.term.Prompt("Choice> ")
	if ans == "2" {
		return nil
	}
	if ans == "3" && canTrustCA {
		if caExists {
			ca.Hostnames = append(ca.Hostnames, certHostname)
			return a.saveAuthorities(true)
		}
		a.data.Authorities[caFP] = &authority{
			Fingerprint: caFP,
			Name:        caFP[len(caFP)-8:],
			Public:      cert.SignatureKey.Marshal(),
			Hostnames: []string{
				certHostname,
			},
		}
		return a.saveAuthorities(true)
	}
	if n, e := strconv.Atoi(ans); e == nil && n >= 3 && n-3 < len(hostnames) {
		ep.Hostname = hostnames[n-3]
		a.data.Endpoints[ep.Name] = ep
		return a.saveEndpoints(true)
	}
	return err
}

func (a *App) hostKeyCallback(hostname string, key ssh.PublicKey) error {
	hk := key.Marshal()
	var err error
	if host, exists := a.data.Hosts[hostname]; exists && host.Key != nil {
		if subtle.ConstantTimeCompare(host.Key, hk) == 1 {
			a.term.Printf("Host key for %s is trusted.\n", hostname)
			return nil
		}
		var old ssh.PublicKey
		if old, err = ssh.ParsePublicKey(host.Key); err != nil {
			return err
		}
		err = fmt.Errorf("host key for %s changed, was %s, now is %s", hostname, ssh.FingerprintSHA256(old), ssh.FingerprintSHA256(key))
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
		h, ok := a.data.Hosts[hostname]
		if !ok {
			h = &host{Name: hostname}
			a.data.Hosts[hostname] = h
		}
		h.Key = hk
		return a.saveHosts(true)
	default:
		return errors.New("host key rejected by user")
	}
}

func sshKeepAlive(ctx context.Context, client *ssh.Client, cancel context.CancelCauseFunc) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(30 * time.Second):
		}
		ch := make(chan struct{})
		go func() {
			select {
			case <-ch:
			case <-time.After(30 * time.Second):
				cancel(errors.New("remote server not responding"))
			}
		}()
		_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
		close(ch)
		if err != nil {
			cancel(errors.New("remote server not responding"))
			return
		}
	}
}
