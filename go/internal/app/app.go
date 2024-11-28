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
	"fmt"
	"runtime/debug"
	"slices"
	"sort"
	"strings"
	"sync/atomic"
	"syscall/js"

	"github.com/mattn/go-shellwords"
	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/ssh/agent"

	"github.com/c2FmZQ/sshterm/internal/indexeddb"
	"github.com/c2FmZQ/sshterm/internal/jsutil"
	"github.com/c2FmZQ/sshterm/internal/terminal"
)

var backupMagic = []byte{0xe2, 0x9b, 0x94, '0'}

const defaultDBName = "sshterm"

type Config struct {
	Term         js.Value
	DBName       string
	UploadHook   func(accept string, multiple bool) []jsutil.ImportedFile
	DownloadHook func(content []byte, name, typ string) error
	StreamHook   func(url string) error
}

func New(cfg *Config) (*App, error) {
	app := &App{
		cfg:    *cfg,
		agent:  agent.NewKeyring(),
		parser: shellwords.NewParser(),
		data: appData{
			Persist:   true,
			Endpoints: make(map[string]endpoint),
			Keys:      make(map[string]key),
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
		app.fileCommand(),
		app.epCommand(),
		app.keysCommand(),
		app.agentCommand(),
		app.dbCommand(),
	}
	app.autoCompleter = &autoCompleter{
		p:         app.parser,
		cmds:      app.commands,
		moreWords: app.autoCompleteWords,
	}
	sort.Slice(app.commands, func(i, j int) bool {
		return app.commands[i].Name < app.commands[j].Name
	})
	return app, nil
}

type appData struct {
	Persist   bool                `json:"persist"`
	Endpoints map[string]endpoint `json:"endpoints"`
	Keys      map[string]key      `json:"keys"`
}

type App struct {
	cfg           Config
	ctx           context.Context
	term          *terminal.Terminal
	agent         agent.Agent
	parser        *shellwords.Parser
	autoCompleter *autoCompleter
	db            *indexeddb.DB
	data          appData

	commands     []*cli.App
	streamHelper *jsutil.StreamHelper

	inShell *atomic.Bool
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

func (a *App) initDB() error {
	if a.cfg.DBName == "" {
		a.cfg.DBName = defaultDBName
	}
	if !a.data.Persist {
		if a.db != nil {
			a.db.Close()
			a.db = nil
		}
		return indexeddb.Delete(a.cfg.DBName)
	}
	db, err := indexeddb.New(a.cfg.DBName)
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
	jsutil.UnregisterServiceWorker()
	defer func() {
		if a.db != nil {
			a.db.Close()
		}
		jsutil.UnregisterServiceWorker()
	}()

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
	t.OnData(ctx, func(k string) any {
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
	t.SetAutoComplete(a.autoCompleter.autoComplete)

	commandMap := make(map[string]*cli.App)
	for _, c := range a.commands {
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
		args, err := a.parser.Parse(line)
		if err != nil {
			t.Printf("p.Parse: %v\n", err)
		}
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
					defer cancel()
					if err := cmd.RunContext(ctx, args); err != nil {
						t.Errorf("%v", err)
					}
				},
				func(err any) { // catch
					t.Errorf("%T %v", err, err)
					t.Errorf("%s", debug.Stack())
				},
			)
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
	if args[0] == "keys" && (slices.Contains(args, "delete") || slices.Contains(args, "export")) {
		var words []string
		for _, k := range a.data.Keys {
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
	if (args[0] == "ssh" || args[0] == "file") && strings.Index(last, "@") > 0 {
		u, h, _ := strings.Cut(last, "@")
		var words []string
		for _, ep := range a.data.Endpoints {
			if strings.HasPrefix(ep.Name, h) {
				words = append(words, u+"@"+ep.Name)
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
