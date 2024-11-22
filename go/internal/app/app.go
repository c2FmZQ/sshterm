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
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"syscall/js"

	"github.com/mattn/go-shellwords"
	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/c2FmZQ/sshterm/internal/indexeddb"
	"github.com/c2FmZQ/sshterm/internal/jsutil"
	"github.com/c2FmZQ/sshterm/internal/terminal"
	"github.com/c2FmZQ/sshterm/internal/websocket"
)

type Config struct {
	Term js.Value
}

func New(cfg *Config) (*App, error) {
	app := &App{
		cfg:       *cfg,
		agent:     agent.NewKeyring(),
		endpoints: make(map[string]endpoint),
		keys:      make(map[string]key),
	}
	return app, nil
}

type App struct {
	cfg   Config
	ctx   context.Context
	term  *terminal.Terminal
	agent agent.Agent
	db    *indexeddb.DB

	endpoints map[string]endpoint
	keys      map[string]key
}

type endpoint struct {
	Name    string `json:"name"`
	URL     string `json:"url"`
	HostKey []byte `json:"hostKey"`
}

type key struct {
	Name    string `json:"name"`
	Public  []byte `json:"public"`
	Private []byte `json:"private"`
}

func (a *App) Run() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
	}()
	a.term = terminal.New(ctx, a.cfg.Term)
	t := a.term
	a.ctx = ctx
	db, err := indexeddb.New("sshterm", t)
	if err != nil {
		t.Printf("Error opening database: %v\n", err)
		return fmt.Errorf("indexeddb.New: %w", err)
	}
	defer db.Close()
	a.db = db

	if err := db.Get("endpoints", &a.endpoints); err != nil && err != indexeddb.ErrNotFound {
		return fmt.Errorf("endpoints load: %w", err)
	}
	if err := db.Get("keys", &a.keys); err != nil && err != indexeddb.ErrNotFound {
		return fmt.Errorf("keys load: %w", err)
	}

	p := shellwords.NewParser()

	commands := []*cli.App{
		{
			Name:            "clear",
			Usage:           "Clear the terminal",
			UsageText:       "clear",
			Description:     "",
			HideHelpCommand: true,
			Action: func(ctx *cli.Context) error {
				t.Clear()
				return nil
			},
		},
		{
			Name:            "reload",
			Usage:           "Reload the page",
			UsageText:       "reload",
			Description:     "",
			HideHelpCommand: true,
			Action: func(ctx *cli.Context) error {
				js.Global().Get("location").Call("reload")
				return nil
			},
		},
		{
			Name:            "ssh",
			Usage:           "Start an SSH connection",
			UsageText:       "ssh [-i <keyname>] username@<endpoint>",
			Description:     "The ssh command starts an SSH connection with a remote server.\nUse the -i flag to select a key (see the keys command). If a key\nwith the name 'default' exists, it will be used by default.\n\nThe <endpoint> must have been configured with the ep command.",
			HideHelpCommand: true,
			Action:          a.ssh,
			Flags: []cli.Flag{
				&cli.BoolFlag{
					Name:    "verbose",
					Aliases: []string{"v"},
					Value:   false,
					Usage:   "Verbose logging.",
				},
				&cli.StringFlag{
					Name:    "identity",
					Aliases: []string{"i", "key"},
					Usage:   "The key to use for authentication.",
				},
				&cli.BoolFlag{
					Name:  "A",
					Value: false,
					Usage: "Forward access to the local SSH agent. Use with caution.",
				},
			},
		},
		{
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
						if len(a.endpoints) == 0 {
							t.Printf("<none>\n")
							return nil
						}
						names := make([]string, 0, len(a.endpoints))
						szName, szURL := 5, 15
						for _, ep := range a.endpoints {
							names = append(names, ep.Name)
							szName = max(szName, len(ep.Name))
							szURL = max(szURL, len(ep.URL))
						}
						sort.Strings(names)
						t.Printf("%*s %*s %s\n", -szName, "Name", -szURL, "URL", "Fingerprint")
						for _, n := range names {
							ep := a.endpoints[n]
							fp := "n/a"
							if key, err := ssh.ParsePublicKey(ep.HostKey); err == nil {
								fp = ssh.FingerprintSHA256(key)
							}
							t.Printf("%*s %*s %s\n", -szName, ep.Name, -szURL, ep.URL, fp)
						}
						return nil
					},
				},
				{
					Name:        "add",
					Usage:       "Add a new server endpoint",
					UsageText:   "ep add <name> <url>",
					Description: "This command adds a server endpoint to the client.\n\nThe <name> is used to refer to the endpoint. The <url> is one that\nis configured on the proxy, e.g. wss://ssh.example.com/myserver.",
					Action: func(ctx *cli.Context) error {
						if ctx.Args().Len() != 2 {
							cli.ShowSubcommandHelp(ctx)
							return nil
						}
						name := ctx.Args().Get(0)
						url := ctx.Args().Get(1)
						a.endpoints[name] = endpoint{Name: name, URL: url}
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
						delete(a.endpoints, name)
						return a.saveEndpoints()
					},
				},
			},
		},
		{
			Name:            "keys",
			Usage:           "Manage keys",
			UsageText:       "keys <list|generate|delete|import|export>",
			Description:     "The keys command is used to manage private and public keys.",
			HideHelpCommand: true,
			DefaultCommand:  "list",
			Commands: []*cli.Command{
				{
					Name:      "list",
					Usage:     "List all keys",
					UsageText: "keys list",
					Action: func(ctx *cli.Context) error {
						if len(a.keys) == 0 {
							t.Printf("<none>\n")
							return nil
						}
						names := make([]string, 0, len(a.keys))
						for _, key := range a.keys {
							names = append(names, key.Name)
						}
						sort.Strings(names)
						for _, n := range names {
							key := a.keys[n]
							pub, err := ssh.ParsePublicKey(key.Public)
							if err != nil {
								t.Errorf("ssh.ParsePublicKey: %v", err)
								continue
							}
							m := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
							t.Printf("%s %s\n", m, n)
						}
						return nil
					},
				},
				{
					Name:        "generate",
					Aliases:     []string{"add", "gen"},
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
						passphrase, err := t.ReadPassword("Enter passphrase for private key: ")
						if err != nil {
							return fmt.Errorf("ReadPassword: %w", err)
						}
						passphrase2, err := t.ReadPassword("Re-enter the same passphrase: ")
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
						a.keys[name] = key{Name: name, Public: sshPub.Marshal(), Private: pem.EncodeToMemory(privPEM)}
						if err := a.saveKeys(); err != nil {
							return err
						}
						t.Printf("New key %q added\n", name)
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
						delete(a.keys, name)
						return a.saveKeys()
					},
				},
				{
					Name:      "import",
					Usage:     "Import private key",
					UsageText: "keys import <name>",
					Action: func(ctx *cli.Context) error {
						if ctx.Args().Len() != 1 {
							cli.ShowSubcommandHelp(ctx)
							return nil
						}
						name := ctx.Args().Get(0)

						files := jsutil.ImportFiles("", false)
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
						var pub crypto.PublicKey
						switch key := priv.(type) {
						case *rsa.PrivateKey:
							pub = key.Public()
						case *ecdsa.PrivateKey:
							pub = key.Public()
						case ed25519.PrivateKey:
							pub = key.Public()
						case *ed25519.PrivateKey:
							pub = key.Public()
						default:
							return fmt.Errorf("key type %T is not supported", priv)
						}
						sshPub, err := ssh.NewPublicKey(pub)
						if err != nil {
							return fmt.Errorf("ssh.NewPublicKey: %w", err)
						}
						key.Public = sshPub.Marshal()
						a.keys[name] = key
						if err := a.saveKeys(); err != nil {
							return err
						}
						t.Printf("New key %q imported from %q\n", name, f.Name)
						return nil
					},
				},
				{
					Name:      "export",
					Usage:     "Export a private key",
					UsageText: "keys export <name>",
					Action: func(ctx *cli.Context) error {
						if ctx.Args().Len() != 1 {
							cli.ShowSubcommandHelp(ctx)
							return nil
						}
						name := ctx.Args().Get(0)
						key, exists := a.keys[name]
						if !exists {
							return fmt.Errorf("unknown key %q", name)
						}
						line, err := t.Prompt(fmt.Sprintf("You are about to export the PRIVATE key %q\nContinue? [y/N] ", name))
						if err != nil {
							return err
						}
						if v := strings.ToUpper(line); v != "Y" && v != "YES" {
							return errors.New("aborted")
						}
						jsutil.ExportFile(key.Private, name+".key", "application/octet-stream")
						return nil
					},
				},
			},
		},
		{
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
							t.Printf("<none>\n")
							return nil
						}
						maxSize := 5
						for _, k := range keys {
							maxSize = max(maxSize, len(k.Comment))
						}
						for _, k := range keys {
							t.Printf("%*s %s\n", -maxSize, k.Comment, k.Format)
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
						key, exists := a.keys[name]
						if !exists {
							return fmt.Errorf("key %q not found", name)
						}
						priv, err := a.privKey(key)
						if err != nil {
							return fmt.Errorf("private key: %w", err)
						}
						if err := a.agent.Add(agent.AddedKey{
							PrivateKey: priv,
							Comment:    name,
						}); err != nil {
							return fmt.Errorf("agent.Add: %w", err)
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
						key, exists := a.keys[name]
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
		},
	}
	sort.Slice(commands, func(i, j int) bool {
		return commands[i].Name < commands[j].Name
	})

	commandMap := make(map[string]*cli.App)
	for _, c := range commands {
		c.Writer = t
		c.CommandNotFound = func(ctx *cli.Context, name string) {
			t.Errorf("Unknown command %q. Try \"help\"", name)
		}
		commandMap[c.Name] = c
	}

	t.Focus()
	for {
		line, err := t.ReadLine()
		if err != nil {
			return err
		}
		args, err := p.Parse(line)
		if err != nil {
			t.Printf("p.Parse: %v\n", err)
		}
		if len(args) == 0 {
			continue
		}
		switch name := args[0]; name {
		case "help", "?":
			t.Printf("Available commands:\n")
			for _, c := range commands {
				t.Printf("  %s - %s\n", c.Name, c.Usage)
			}
			t.Printf("Run any command with --help for more details.\n")

		case "exit":
			t.Greenf("Goodbye\n")
			return nil

		default:
			if cmd, ok := commandMap[name]; ok {
				if err := cmd.Run(args); err != nil {
					t.Errorf("%v", err)
				}
			} else {
				t.Errorf("Unknown command %q. Try \"help\"", name)
			}
		}
	}
}

func (a *App) saveEndpoints() error {
	return a.db.Set("endpoints", a.endpoints)
}

func (a *App) saveKeys() error {
	return a.db.Set("keys", a.keys)
}

func (a *App) ssh(ctx *cli.Context) error {
	t := a.term
	if ctx.Args().Len() != 1 {
		cli.ShowSubcommandHelp(ctx)
		return nil
	}
	target := ctx.Args().Get(0)
	verbose := ctx.Bool("verbose")
	keyName := ctx.String("identity")

	username, epName, ok := strings.Cut(target, "@")
	if !ok {
		cli.ShowSubcommandHelp(ctx)
		return nil
	}
	ep, exists := a.endpoints[epName]
	if !exists {
		return fmt.Errorf("unknown endpoint %q", epName)
	}

	cctx, cancel := context.WithCancel(a.ctx)
	defer cancel()
	if verbose {
		t.Printf("Connecting to %s (%s)\n\n", ep.Name, ep.URL)
	}

	ws, err := websocket.New(cctx, ep.URL, t)
	if err != nil {
		return err
	}

	defer func() {
		if verbose {
			t.Print("\nDisconnected\n")
		}
	}()

	signers, err := a.agent.Signers()
	if err != nil {
		t.Errorf("%v", err)
	}
	if len(signers) == 0 || keyName != "" {
		if keyName == "" {
			keyName = "default"
		}
		if key, exists := a.keys[keyName]; exists {
			priv, err := a.privKey(key)
			if err != nil {
				return fmt.Errorf("private key: %w", err)
			}
			signer, err := ssh.NewSignerFromKey(priv)
			if err != nil {
				return fmt.Errorf("NewSignerFromKey: %w", err)
			}
			signers = append(signers, signer)
		} else if ctx.String("identity") != "" {
			t.Errorf("unknown key %q", keyName)
		}
	}

	conn, chans, reqs, err := ssh.NewClientConn(ws, ep.URL, &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signers...),
			ssh.RetryableAuthMethod(ssh.KeyboardInteractive(
				func(name, instruction string, questions []string, echos []bool) ([]string, error) {
					if name != "" {
						t.Printf("%s\n", name)
					}
					if instruction != "" {
						t.Printf("%s\n", instruction)
					}
					ans := make([]string, len(questions))
					for i, q := range questions {
						var err error
						if echos[i] {
							ans[i], err = t.Prompt(q + ": ")
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
			hk := key.Marshal()
			if ep.HostKey != nil {
				if bytes.Equal(ep.HostKey, hk) {
					return nil
				} else {
					t.Errorf("Host key changed. New fingerprint: %s", ssh.FingerprintSHA256(key))
					return errors.New("host key changed")
				}
			}
			line, err := t.Prompt(fmt.Sprintf("Host key for %s\n%s %s\n\nContinue? [Y/n] ", hostname, key.Type(), ssh.FingerprintSHA256(key)))
			if err != nil {
				return fmt.Errorf("ReadLine: %w", err)
			}
			if line == "" || line == "Y" || line == "y" {
				ep.HostKey = key.Marshal()
				a.endpoints[ep.Name] = ep
				return a.saveEndpoints()
			}
			return errors.New("host key rejected by user")
		},
		BannerCallback: func(message string) error {
			t.Printf("%s\n", message)
			return nil
		},
	})
	if err != nil {
		if errors.Is(err, io.EOF) {
			return io.EOF
		}
		return err
	}

	client := ssh.NewClient(conn, chans, reqs)
	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("client.NewSession: %w", err)
	}
	defer func() {
		session.Close()
	}()

	if ctx.Bool("A") {
		if verbose {
			t.Printf("Requesting agent forwarding")
		}
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
		return fmt.Errorf("session.RequestPty: %w", err)
	}
	t.OnResize(session.WindowChange)
	if err := session.Shell(); err != nil {
		return fmt.Errorf("session.Shell: %w", err)
	}
	return session.Wait()
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
