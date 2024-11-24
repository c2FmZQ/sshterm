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
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"sort"
	"strings"
	"syscall/js"
	"time"

	"github.com/mattn/go-shellwords"
	"github.com/pkg/sftp"
	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/c2FmZQ/sshterm/internal/indexeddb"
	"github.com/c2FmZQ/sshterm/internal/jsutil"
	"github.com/c2FmZQ/sshterm/internal/terminal"
	"github.com/c2FmZQ/sshterm/internal/websocket"
)

var backupMagic = []byte{0xe2, 0x9b, 0x94, '0'}

type Config struct {
	Term js.Value
}

func New(cfg *Config) (*App, error) {
	app := &App{
		cfg:   *cfg,
		agent: agent.NewKeyring(),
		data: appData{
			Persist:   true,
			Endpoints: make(map[string]endpoint),
			Keys:      make(map[string]key),
		},
		streamHelper: jsutil.NewStreamHelper(),
	}
	return app, nil
}

type appData struct {
	Persist   bool                `json:"persist"`
	Endpoints map[string]endpoint `json:"endpoints"`
	Keys      map[string]key      `json:"keys"`
}

type App struct {
	cfg   Config
	ctx   context.Context
	term  *terminal.Terminal
	agent agent.Agent
	db    *indexeddb.DB
	data  appData

	streamHelper *jsutil.StreamHelper
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

const dbName = "sshterm"

func (a *App) initDB() error {
	if !a.data.Persist {
		if a.db != nil {
			a.db.Close()
			a.db = nil
		}
		return indexeddb.Delete(dbName)
	}
	db, err := indexeddb.New(dbName)
	if err != nil {
		return fmt.Errorf("indexeddb.New: %w", err)
	}
	a.db = db
	if len(a.data.Endpoints) > 0 || len(a.data.Keys) > 0 {
		if err := a.saveAll(); err != nil {
			a.term.Errorf("%v", err)
		}
	}
	if err := db.Get("endpoints", &a.data.Endpoints); err != nil && err != indexeddb.ErrNotFound {
		return fmt.Errorf("endpoints load: %w", err)
	}
	if err := db.Get("keys", &a.data.Keys); err != nil && err != indexeddb.ErrNotFound {
		return fmt.Errorf("keys load: %w", err)
	}
	return nil
}

func (a *App) Run() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
	}()
	a.term = terminal.New(ctx, a.cfg.Term)
	t := a.term
	a.ctx = ctx
	if err := a.initDB(); err != nil {
		t.Errorf("%v", err)
	}
	defer func() {
		if a.db != nil {
			a.db.Close()
		}
	}()

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
		},
		{
			Name:            "file",
			Usage:           "Copy files to or from a remote server.",
			UsageText:       "file [-i <keyname>] <upload|download> username@<endpoint>:<path>",
			Description:     "The file command copies files to or from a remote server.",
			HideHelpCommand: true,
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:    "identity",
					Aliases: []string{"i"},
					Usage:   "The key to use for authentication.",
				},
			},
			Commands: []*cli.Command{
				{
					Name:      "upload",
					Aliases:   []string{"up"},
					Usage:     "Copies files to a remote server.",
					UsageText: "file [-i <keyname>] upload username@<endpoint>:<dir>",
					Action:    a.sftpUpload,
				},
				{
					Name:      "download",
					Aliases:   []string{"down"},
					Usage:     "Copies a file from a remote server.",
					UsageText: "file [-i <keyname>] download username@<endpoint>:<file>",
					Action:    a.sftpDownload,
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
						if len(a.data.Endpoints) == 0 {
							t.Printf("<none>\n")
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
						t.Printf("%*s %*s %s\n", -szName, "Name", -szURL, "URL", "Fingerprint")
						for _, n := range names {
							ep := a.data.Endpoints[n]
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
						a.data.Endpoints[name] = endpoint{Name: name, URL: url}
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
						if len(a.data.Keys) == 0 {
							t.Printf("<none>\n")
							return nil
						}
						names := make([]string, 0, len(a.data.Keys))
						for _, key := range a.data.Keys {
							names = append(names, key.Name)
						}
						sort.Strings(names)
						for _, n := range names {
							key := a.data.Keys[n]
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
						a.data.Keys[name] = key{Name: name, Public: sshPub.Marshal(), Private: pem.EncodeToMemory(privPEM)}
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
						delete(a.data.Keys, name)
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
						type privateKey interface {
							Public() crypto.PublicKey
						}
						var pub crypto.PublicKey
						if k, ok := priv.(privateKey); ok {
							pub = k.Public()
						} else {
							return fmt.Errorf("key type %T is not supported", priv)
						}
						sshPub, err := ssh.NewPublicKey(pub)
						if err != nil {
							return fmt.Errorf("ssh.NewPublicKey: %w", err)
						}
						key.Public = sshPub.Marshal()
						a.data.Keys[name] = key
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
						key, exists := a.data.Keys[name]
						if !exists {
							return fmt.Errorf("unknown key %q", name)
						}
						if !t.Confirm(fmt.Sprintf("You are about to export the PRIVATE key %q\nContinue?", name), false) {
							return errors.New("aborted")
						}
						if a.streamHelper != nil {
							a.streamHelper.Download(io.NopCloser(bytes.NewReader(key.Private)), name+".key", "application/octet-stream", int64(len(key.Private)), nil)
						} else {
							jsutil.ExportFile(key.Private, name+".key", "application/octet-stream")
						}
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
						key, exists := a.data.Keys[name]
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
		},
		{
			Name:            "db",
			Usage:           "Manage database",
			UsageText:       "db <persist|wipe|backup|restore>",
			Description:     "The db command is used to manage the database.",
			HideHelpCommand: true,
			Commands: []*cli.Command{
				{
					Name:      "persist",
					Usage:     "Show or change the database persistence to local storage.",
					UsageText: "db persist [on|off]",
					Action: func(ctx *cli.Context) error {
						if ctx.Args().Len() > 1 {
							cli.ShowSubcommandHelp(ctx)
							return nil
						}
						if ctx.Args().Len() == 1 {
							switch v := ctx.Args().Get(0); v {
							case "on":
								a.data.Persist = true
								if err := a.initDB(); err != nil {
									t.Errorf("%v", err)
								}
							case "off":
								a.data.Persist = false
								if err := a.initDB(); err != nil {
									t.Errorf("%v", err)
								}
							default:
								cli.ShowSubcommandHelp(ctx)
								return nil
							}
						}
						if a.data.Persist {
							t.Printf("The database is persisted to local storage.\n")
						} else {
							t.Printf("The database is NOT persisted to local storage.\n")
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
						if !t.Confirm("You are about to WIPE the database.\nContinue? ", false) {
							return errors.New("aborted")
						}
						a.agent = agent.NewKeyring()
						a.data.Endpoints = make(map[string]endpoint)
						a.data.Keys = make(map[string]key)
						if err := a.saveAll(); err != nil {
							t.Errorf("%v", err)
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
						jsutil.ExportFile(enc, fmt.Sprintf("sshterm-%s.backup", time.Now().UTC().Format(time.DateOnly)), "application/octet-stream")
						return nil
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
							if !t.Confirm("Restoring a backup will OVERWRITE the database. Data may be lost.\nContinue? ", false) {
								return errors.New("aborted")
							}
						}
						files := jsutil.ImportFiles(".backup", false)
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
						a.agent = agent.NewKeyring()
						a.data.Endpoints = nil
						a.data.Keys = nil
						if err := json.Unmarshal(payload, &a.data); err != nil {
							return fmt.Errorf("json.Unmarshal: %w", err)
						}
						return a.saveAll()
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

func (a *App) saveAll() error {
	if err := a.saveEndpoints(); err != nil {
		return err
	}
	if err := a.saveKeys(); err != nil {
		return err
	}
	return nil
}

func (a *App) saveEndpoints() error {
	if a.db == nil {
		return nil
	}
	return a.db.Set("endpoints", a.data.Endpoints)
}

func (a *App) saveKeys() error {
	if a.db == nil {
		return nil
	}
	return a.db.Set("keys", a.data.Keys)
}

func (a *App) ssh(ctx *cli.Context) error {
	t := a.term
	if ctx.Args().Len() != 1 {
		cli.ShowSubcommandHelp(ctx)
		return nil
	}
	target := ctx.Args().Get(0)
	keyName := ctx.String("identity")

	cctx, cancel := context.WithCancel(a.ctx)
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

func (a *App) sftpUpload(ctx *cli.Context) error {
	t := a.term
	if ctx.Args().Len() != 1 {
		cli.ShowSubcommandHelp(ctx)
		return nil
	}
	targetPath := ctx.Args().Get(0)
	keyName := ctx.String("identity")

	target, p, ok := strings.Cut(targetPath, ":")
	if !ok {
		return fmt.Errorf("invalid target %q", target)
	}

	cctx, cancel := context.WithCancel(a.ctx)
	defer cancel()

	c, err := a.sshClient(cctx, target, keyName)
	if err != nil {
		return err
	}
	client, err := sftp.NewClient(c)
	if err != nil {
		return err
	}
	defer client.Close()

	st, err := client.Stat(p)
	if err != nil || !st.IsDir() {
		return fmt.Errorf("remote path %q is not a directory", p)
	}

	files := jsutil.ImportFiles("", true)
	cp := func(f jsutil.ImportedFile) error {
		defer f.Content.Close()
		fn := path.Join(p, f.Name)
		w, err := client.OpenFile(fn, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
		if err != nil {
			return fmt.Errorf("%s: %v", fn, err)
		}
		buf := make([]byte, 16384)
		var total int64
		for loop := 0; ; loop++ {
			n, err := f.Content.Read(buf)
			if n > 0 {
				if nn, err := w.Write(buf[:n]); err != nil {
					w.Close()
					return err
				} else if n != nn {
					return io.ErrShortWrite
				}
				total += int64(n)
				if loop%100 == 0 {
					t.Printf("%3.0f%%\b\b\b\b", 100*float64(total)/float64(f.Size))
				}
			}
			if err == io.EOF {
				t.Printf("%3.0f%%\n", 100*float64(total)/float64(f.Size))
				break
			}
			if err != nil {
				w.Close()
				return err
			}

		}
		return w.Close()
	}
	for _, f := range files {
		t.Printf("%s ", f.Name)
		if err := cp(f); err != nil {
			return err
		}
	}
	return nil
}

func (a *App) sftpDownload(ctx *cli.Context) error {
	t := a.term
	if ctx.Args().Len() != 1 {
		cli.ShowSubcommandHelp(ctx)
		return nil
	}
	targetPath := ctx.Args().Get(0)
	keyName := ctx.String("identity")

	target, p, ok := strings.Cut(targetPath, ":")
	if !ok {
		return fmt.Errorf("invalid target %q", target)
	}

	cctx, cancel := context.WithCancel(a.ctx)
	defer cancel()

	c, err := a.sshClient(cctx, target, keyName)
	if err != nil {
		return err
	}
	client, err := sftp.NewClient(c)
	if err != nil {
		return err
	}
	defer client.Close()

	r, err := client.Open(p)
	if err != nil {
		return fmt.Errorf("%s: %v", p, err)
	}
	defer r.Close()
	st, err := r.Stat()
	if err != nil {
		return fmt.Errorf("%s: %v", p, err)
	}
	size := st.Size()
	_, name := path.Split(r.Name())
	loop := 0
	progress := func(total int64) {
		if loop%100 == 0 {
			t.Printf("%3.0f%%\b\b\b\b", 100*float64(total)/float64(size))
		}
	}
	t.Printf("%s ", name)
	if err := a.streamHelper.Download(r, name, "application/octet-stream", size, progress); err != nil {
		return err
	}
	progress(size)
	t.Printf("\n")
	return nil
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
			signers = append(signers, signer)
		} else if origKeyName != "" {
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
			if t.Confirm(fmt.Sprintf("Host key for %s\n%s %s\n\nContinue? ", hostname, key.Type(), ssh.FingerprintSHA256(key)), true) {
				ep.HostKey = key.Marshal()
				a.data.Endpoints[ep.Name] = ep
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
			return nil, io.EOF
		}
		return nil, err
	}

	return ssh.NewClient(conn, chans, reqs), nil
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
