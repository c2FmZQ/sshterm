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
	"errors"
	"fmt"
	"runtime/debug"
	"slices"
	"sort"
	"strings"
	"sync/atomic"
	"syscall/js"

	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/ssh/agent"

	"github.com/c2FmZQ/sshterm/config"
	"github.com/c2FmZQ/sshterm/internal/indexeddb"
	"github.com/c2FmZQ/sshterm/internal/jsutil"
	"github.com/c2FmZQ/sshterm/internal/shellwords"
	"github.com/c2FmZQ/sshterm/internal/terminal"
)

var backupMagic = []byte{0xe2, 0x9b, 0x94, '0'}

const defaultDBName = "sshterm"

type Config struct {
	Term js.Value `json:"-"`
	config.Config

	// Used in tests
	UploadHook   func(accept string, multiple bool) []jsutil.ImportedFile `json:"-"`
	DownloadHook func(content []byte, name, typ string) error             `json:"-"`
	StreamHook   func(url string) error                                   `json:"-"`
}

var globalAgent agent.Agent = &keyRing{}

func New(cfg *Config) (*App, error) {
	app := &App{
		cfg: *cfg,
		data: appData{
			Persist:     true,
			Authorities: make(map[string]*authority),
			Endpoints:   make(map[string]*endpoint),
			Hosts:       make(map[string]*host),
			Keys:        make(map[string]*key),
			Params:      make(map[string]any),
		},
		inShell: new(atomic.Bool),
	}
	app.commands = []*cli.App{
		{
			Name:            "clear",
			Usage:           "Clear the terminal",
			UsageText:       "clear",
			HideHelpCommand: true,
			Action: func(ctx *cli.Context) error {
				app.term.Clear()
				return nil
			},
		},
		{
			Name:            "reload",
			Usage:           "Reload the page",
			UsageText:       "reload",
			HideHelpCommand: true,
			Action: func(ctx *cli.Context) error {
				js.Global().Get("location").Call("reload")
				return nil
			},
		},
		app.sshCommand(),
		app.sftpCommand(),
		app.caCommand(),
		app.epCommand(),
		app.hostsCommand(),
		app.keysCommand(),
		app.agentCommand(),
		app.dbCommand(),
		app.setCommand(),
	}
	app.autoCompleter = &autoCompleter{
		cmds:      app.commands,
		moreWords: app.autoCompleteWords,
	}
	sort.Slice(app.commands, func(i, j int) bool {
		return app.commands[i].Name < app.commands[j].Name
	})
	return app, nil
}

type App struct {
	cfg           Config
	ctx           context.Context
	cancel        context.CancelFunc
	term          *terminal.Terminal
	autoCompleter *autoCompleter
	db            *indexeddb.DB
	data          appData

	commands     []*cli.App
	streamHelper *jsutil.StreamHelper

	inShell    *atomic.Bool
	presetDone bool
}

type appData struct {
	Persist     bool                  `json:"persist"`
	Authorities map[string]*authority `json:"authorities"`
	Endpoints   map[string]*endpoint  `json:"endpoints"`
	Hosts       map[string]*host      `json:"hosts"`
	Keys        map[string]*key       `json:"keys"`
	Params      map[string]any        `json:"params"`
}

type authority struct {
	Name        string   `json:"name"`
	Fingerprint string   `json:"fingerprint"`
	Public      []byte   `json:"public"`
	Hostnames   []string `json:"hostnames"`
}

type endpoint struct {
	Name    string `json:"name"`
	URL     string `json:"url"`
	HostKey []byte `json:"hostKey,omitempty"` // deprecated
}

type host struct {
	Name string `json:"name"`
	Key  []byte `json:"key,omitempty"`
}

func (a *App) initPresetConfig() error {
	if a.presetDone {
		return nil
	}
	a.presetDone = true
	for i, ca := range a.cfg.Authorities {
		if err := a.addAuthority(ca.Name, ca.PublicKey, ca.Hostnames); err != nil {
			return fmt.Errorf("certificateAuthorities[%d]: %w", i, err)
		}
	}
	for i, ep := range a.cfg.Endpoints {
		if err := a.addEndpoint(ep.Name, ep.URL); err != nil {
			return fmt.Errorf("endpoints[%d]: %w", i, err)
		}
	}
	for i, host := range a.cfg.Hosts {
		if err := a.addHost(host.Name, host.Key); err != nil {
			return fmt.Errorf("hosts[%d]: %w", i, err)
		}
	}
	for i, k := range a.cfg.GenerateKeys {
		key, err := a.generateKey(k.Name, "", k.IdentityProvider, k.Type, k.Bits)
		if err != nil {
			return fmt.Errorf("generateKeys[%d]: %w", i, err)
		}
		if k.AddToAgent {
			signer, err := key.Signer(nil)
			if err != nil {
				return fmt.Errorf("generateKeys[%d]: %w", i, err)
			}
			if err := globalAgent.(*keyRing).AddSigner(signer, k.Name); err != nil {
				return fmt.Errorf("generateKeys[%d]: %w", i, err)
			}
		}
	}
	return a.saveAll()
}

func (a *App) initDB() error {
	if a.cfg.DBName == "" {
		a.cfg.DBName = defaultDBName
	}
	defer func() {
		for _, k := range a.data.Keys {
			k.errorf = a.term.Errorf
		}
	}()
	if a.cfg.Persist != nil {
		a.data.Persist = *a.cfg.Persist
	}
	if a.db != nil {
		a.db.Close()
		a.db = nil
	}
	if !a.data.Persist {
		return indexeddb.Delete(a.cfg.DBName)
	}
	db, err := indexeddb.New(a.cfg.DBName)
	if err != nil {
		return fmt.Errorf("indexeddb.New: %w", err)
	}
	a.db = db
	if err := db.Get("authorities", &a.data.Authorities); err != nil && err != indexeddb.ErrNotFound {
		return fmt.Errorf("authorities load: %w", err)
	}
	if err := db.Get("endpoints", &a.data.Endpoints); err != nil && err != indexeddb.ErrNotFound {
		return fmt.Errorf("endpoints load: %w", err)
	}
	if err := db.Get("hosts", &a.data.Hosts); err != nil && err != indexeddb.ErrNotFound {
		return fmt.Errorf("hosts load: %w", err)
	}
	if err := db.Get("keys", &a.data.Keys); err != nil && err != indexeddb.ErrNotFound {
		return fmt.Errorf("keys load: %w", err)
	}
	if err := db.Get("params", &a.data.Params); err != nil && err != indexeddb.ErrNotFound {
		return fmt.Errorf("params load: %w", err)
	}
	for k, v := range a.data.Endpoints {
		if len(v.HostKey) == 0 {
			continue
		}
		a.data.Hosts[k] = &host{
			Name: k,
			Key:  v.HostKey,
		}
		v.HostKey = nil
	}
	return nil
}

func (a *App) Stop() {
	if a.cancel != nil {
		a.cancel()
	}
}

func (a *App) Run() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a.ctx = ctx
	a.cancel = cancel
	a.term = terminal.New(ctx, a.cfg.Term)
	defer a.term.Close()
	t := a.term
	t.Focus()
	if err := a.initDB(); err != nil {
		t.Errorf("%v", err)
	}
	if err := a.initPresetConfig(); err != nil {
		t.Errorf("%v", err)
	}
	if theme, ok := a.data.Params["theme"].(string); ok {
		a.setTheme(theme)
	} else if theme := a.cfg.Theme; theme != "" {
		a.setTheme(theme)
	}
	jsutil.UnregisterServiceWorker()
	defer func() {
		if a.db != nil {
			a.db.Close()
		}
		jsutil.UnregisterServiceWorker()
	}()

	if a.cfg.AutoConnect != nil {
		jsutil.TryCatch(
			func() { // try
				ctx, cancel := context.WithCancel(ctx)
				defer a.ctrlC(cancel)()
				username := a.cfg.AutoConnect.Username
				for username == "" {
					username, _ = t.Prompt("Username: ")
				}
				target := username + "@" + a.cfg.AutoConnect.Hostname
				if err := a.runSSH(ctx, target, a.cfg.AutoConnect.Identity, a.cfg.AutoConnect.Command, a.cfg.AutoConnect.ForwardAgent, a.cfg.AutoConnect.JumpHosts); err != nil {
					t.Errorf("%v", err)
				}
			},
			func(err any) { // catch
				t.Errorf("%T %v", err, err)
				t.Errorf("%s", debug.Stack())
			},
		)
		t.Greenf("Goodbye\n")
		a.cfg.Term.Call("input", "\n")
		a.cfg.Term.Call("input", "\n")
		return nil
	}

	shortcuts := map[string]struct {
		cmd, desc string
	}{
		"\x12":     {"reload\r", "CTRL-R"},
		"\x0c":     {"clear\r", "CTRL-L"},
		"\x1bh":    {"help shortcuts\r", "ALT-H"},
		"\x1bp":    {"db persist toggle\r", "ALT-P"},
		"\x1bb":    {"db restore\r", "ALT-B"},
		"\x1b\x02": {"db backup\r", "CTRL-ALT-B"},
		"\x1b\x17": {"db wipe\rYES\r", "CTRL-ALT-W"},
	}
	done := t.OnData(func(k string) any {
		if a.inShell.Load() {
			return nil
		}
		if k == "\x12" {
			js.Global().Get("window").Get("location").Call("reload")
			return nil
		}
		if v, exists := shortcuts[k]; exists {
			return v.cmd
		}
		return nil
	})
	defer done()
	t.SetAutoComplete(a.autoCompleter.autoComplete)

	commandMap := make(map[string]*cli.App)
	for _, c := range a.commands {
		c.Writer = t
		c.CommandNotFound = func(ctx *cli.Context, name string) {
			t.Errorf("Unknown command %q. Try \"help\"", name)
		}
		commandMap[c.Name] = c
	}

	for {
		line, err := t.ReadLine()
		if err != nil {
			return err
		}
		args, _ := shellwords.Parse(line)
		if len(args) == 0 {
			continue
		}
		switch name := args[0]; name {
		case "help", "?":
			if len(args) == 2 && args[1] == "shortcuts" {
				t.Printf("Available shortcuts:\n")
				type pair struct {
					a, b string
				}
				var h []pair
				maxLen := 0
				for _, v := range shortcuts {
					cmd := strings.Trim(fmt.Sprintf("%q", v.cmd), `"`)
					maxLen = max(maxLen, len(cmd))
					h = append(h, pair{cmd, v.desc})
				}
				sort.Slice(h, func(i, j int) bool {
					return h[i].a < h[j].a
				})
				for _, c := range h {
					t.Printf("  %*s - %s\n", -maxLen, c.a, c.b)
				}
				continue
			}
			t.Printf("Available commands:\n")
			maxLen := 0
			for _, c := range a.commands {
				maxLen = max(maxLen, len(c.Name))
			}
			for _, c := range a.commands {
				t.Printf("  %*s - %s\n", -maxLen, c.Name, c.Usage)
			}
			t.Printf("Run any command with --help for more details.\n")

		case "exit":
			t.Greenf("Goodbye\n")
			return nil

		default:
			cmd, ok := commandMap[name]
			if !ok {
				t.Errorf("Unknown command %q. Try \"help\"", name)
				continue
			}
			jsutil.TryCatch(
				func() { // try
					ctx, cancel := context.WithCancel(a.ctx)
					defer a.ctrlC(cancel)()
					if err := cmd.RunContext(ctx, args); err != nil {
						if errors.Is(err, context.Canceled) {
							t.Errorf("Aborted")
						} else {
							t.Errorf("%v", err)
						}
					}
					a.cfg.Term.Call("input", "\n")
					a.cfg.Term.Call("input", "\n")
				},
				func(err any) { // catch
					t.Errorf("%T %v", err, err)
					t.Errorf("%s", debug.Stack())
				},
			)
		}
	}
}

func (a *App) ctrlC(cancel context.CancelFunc) context.CancelFunc {
	done := a.term.OnData(func(k string) any {
		if a.inShell.Load() {
			return nil
		}
		if k == "\x03" {
			cancel()
			return "\r"
		}
		return nil
	})
	return func() {
		done()
		cancel()
	}
}
func (a *App) saveAll() error {
	if err := a.saveAuthorities(); err != nil {
		return err
	}
	if err := a.saveEndpoints(); err != nil {
		return err
	}
	if err := a.saveHosts(); err != nil {
		return err
	}
	if err := a.saveKeys(); err != nil {
		return err
	}
	if err := a.saveParams(); err != nil {
		return err
	}
	return nil
}

func (a *App) saveAuthorities() error {
	if a.db == nil {
		return nil
	}
	return a.db.Set("authorities", a.data.Authorities)
}

func (a *App) saveEndpoints() error {
	if a.db == nil {
		return nil
	}
	return a.db.Set("endpoints", a.data.Endpoints)
}

func (a *App) saveHosts() error {
	if a.db == nil {
		return nil
	}
	return a.db.Set("hosts", a.data.Hosts)
}

func (a *App) saveKeys() error {
	if a.db == nil {
		return nil
	}
	return a.db.Set("keys", a.data.Keys)
}

func (a *App) saveParams() error {
	if a.db == nil {
		return nil
	}
	return a.db.Set("params", a.data.Params)
}

func (a *App) importFiles(accept string, multiple bool) []jsutil.ImportedFile {
	if a.cfg.UploadHook != nil {
		return a.cfg.UploadHook(accept, multiple)
	}
	return jsutil.ImportFiles(accept, multiple)
}

func (a *App) exportFile(data []byte, filename, mimeType string) error {
	if a.cfg.DownloadHook != nil {
		return a.cfg.DownloadHook(data, filename, mimeType)
	}
	return jsutil.ExportFile(data, filename, mimeType)
}

func (a *App) autoCompleteWords(args []string) []string {
	if len(args) == 0 {
		return nil
	}
	last := args[len(args)-1]
	if args[0] == "ep" && slices.Contains(args, "delete") {
		var words []string
		for _, ep := range a.data.Endpoints {
			if strings.HasPrefix(ep.Name, last) {
				words = append(words, ep.Name)
			}
		}
		return words
	}
	if args[0] == "hosts" && slices.Contains(args, "delete") {
		var words []string
		for _, h := range a.data.Hosts {
			if strings.HasPrefix(h.Name, last) {
				words = append(words, h.Name)
			}
		}
		return words
	}
	if args[0] == "keys" {
		if slices.Contains(args, "delete") || slices.Contains(args, "export") || slices.Contains(args, "show") || slices.Contains(args, "import-cert") {
			var words []string
			for _, k := range a.data.Keys {
				if strings.HasPrefix(k.Name, last) {
					words = append(words, k.Name)
				}
			}
			return words
		}
		if slices.Contains(args, "generate") {
			if strings.HasPrefix(last, "--type=") {
				var words []string
				for _, v := range []string{"ed25519", "ecdsa", "rsa"} {
					w := "--type=" + v
					if strings.HasPrefix(w, last) {
						words = append(words, w)
					}
				}
				return words
			}
			if slices.Contains(args, "--type=rsa") && strings.HasPrefix(last, "--bits=") {
				var words []string
				for _, v := range []string{"2048", "3072", "4096"} {
					w := "--bits=" + v
					if strings.HasPrefix(w, last) {
						words = append(words, w)
					}
				}
				return words
			}
			if slices.Contains(args, "--type=ecdsa") && strings.HasPrefix(last, "--bits=") {
				var words []string
				for _, v := range []string{"256", "384", "521"} {
					w := "--bits=" + v
					if strings.HasPrefix(w, last) {
						words = append(words, w)
					}
				}
				return words
			}
		}
	}
	if args[0] == "ca" && len(args) == 3 && (args[1] == "delete" || args[1] == "add-hostname" || args[1] == "remove-hostname") {
		var words []string
		for _, k := range a.data.Authorities {
			if strings.HasPrefix(k.Name, last) {
				words = append(words, k.Name)
			}
		}
		return words
	}
	if args[0] == "agent" && (slices.Contains(args, "add") || slices.Contains(args, "remove")) {
		var words []string
		for _, k := range a.data.Keys {
			if strings.HasPrefix(k.Name, last) {
				words = append(words, k.Name)
			}
		}
		return words
	}
	if (args[0] == "ssh" || args[0] == "sftp") && strings.Index(last, "@") > 0 {
		u, h, _ := strings.Cut(last, "@")
		var words []string
		for _, ep := range a.data.Endpoints {
			if strings.HasPrefix(ep.Name, h) {
				words = append(words, u+"@"+ep.Name)
			}
		}
		for _, host := range a.data.Hosts {
			if _, exists := a.data.Endpoints[host.Name]; exists {
				continue
			}
			if strings.HasPrefix(host.Name, h) {
				words = append(words, u+"@"+host.Name)
			}
		}
		return words
	}
	if strings.HasPrefix(last, "--identity=") {
		var words []string
		for _, k := range a.data.Keys {
			w := "--identity=" + k.Name
			if strings.HasPrefix(w, last) {
				words = append(words, w)
			}
		}
		return words
	}
	return nil
}
