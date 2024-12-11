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
	"io"
	"os"
	"path"
	"sort"
	"strings"
	"sync/atomic"

	"github.com/pkg/sftp"
	"github.com/urfave/cli/v2"
	"golang.org/x/term"

	"github.com/c2FmZQ/sshterm/internal/jsutil"
	"github.com/c2FmZQ/sshterm/internal/shellwords"
)

func (a *App) sftpCommand() *cli.App {
	return &cli.App{
		Name:            "sftp",
		Usage:           "Start an SFTP connection with a remote server.",
		UsageText:       "sftp [-i <keyname>] <username>@<hostname>",
		Description:     "The sftp command is used to copy files to or from a remote server.",
		HideHelpCommand: true,
		Action:          a.cmdSFTP,
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
		},
	}
}

func (a *App) cmdSFTP(ctx *cli.Context) error {
	if ctx.Args().Len() != 1 {
		cli.ShowSubcommandHelp(ctx)
		return nil
	}
	return a.runSFTP(ctx.Context, ctx.Args().Get(0), ctx.String("identity"), ctx.String("jump-hosts"))
}

func (a *App) runSFTP(ctx context.Context, target, keyName, jumpHosts string) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	c, err := a.sshClient(ctx, target, keyName, jumpHosts)
	if err != nil {
		return err
	}
	client, err := sftp.NewClient(c)
	if err != nil {
		return err
	}
	defer client.Close()

	raw := a.term.Raw()

	t := term.NewTerminal(raw, "sftp> ")
	cwd, err := client.Getwd()
	if err != nil {
		fmt.Fprintf(t, "Getwd: %v\n", err)
	}
	homeDir := cwd
	lastDir := cwd
	var prompt string
	setPrompt := func() {
		dir := cwd
		if strings.HasPrefix(dir, homeDir) {
			dir = "~" + dir[len(homeDir):]
		}
		prompt = fmt.Sprintf("\x1b[1;34m%s\x1b[1;32m sftp> \x1b[0m", dir)
		t.SetPrompt(prompt)
	}
	setPrompt()

	joinPath := func(a string, b ...string) string {
		base := path.Clean(a)
		for _, bb := range b {
			bb = path.Clean(bb)
			if bb == "~" {
				base = homeDir
				continue
			}
			if strings.HasPrefix(bb, "~/") {
				base = path.Join(homeDir, bb[2:])
				continue
			}
			if strings.HasPrefix(bb, "/") {
				base = bb
				continue
			}
			base = path.Clean(path.Join(base, bb))
		}
		return base
	}

	commands := []*cli.App{
		{
			Name:            "cd",
			Usage:           "Change directory",
			UsageText:       "cd [dir]",
			HideHelpCommand: true,
			Action: func(ctx *cli.Context) error {
				if ctx.Args().Len() > 1 {
					cli.ShowSubcommandHelp(ctx)
					return nil
				}
				if ctx.Args().Len() == 0 {
					lastDir = cwd
					cwd = homeDir
					setPrompt()
					return nil
				}
				dir := ctx.Args().Get(0)
				if dir == "-" {
					lastDir, cwd = cwd, lastDir
					setPrompt()
					return nil
				}
				realDir, err := client.RealPath(joinPath(cwd, dir))
				if err != nil {
					return err
				}
				lastDir = cwd
				cwd = realDir
				setPrompt()
				return nil
			},
		},
		{
			Name:            "pwd",
			Usage:           "Show the current working directory",
			UsageText:       "pwd",
			HideHelpCommand: true,
			Action: func(ctx *cli.Context) error {
				if ctx.Args().Len() != 0 {
					cli.ShowSubcommandHelp(ctx)
					return nil
				}
				fmt.Fprintf(t, "%s\n", cwd)
				return nil
			},
		},
		{
			Name:            "mkdir",
			Usage:           "Create a directory",
			UsageText:       "mkdir <name>",
			HideHelpCommand: true,
			Action: func(ctx *cli.Context) error {
				if ctx.Args().Len() != 1 {
					cli.ShowSubcommandHelp(ctx)
					return nil
				}
				var e error
				for _, dir := range ctx.Args().Slice() {
					if err := client.Mkdir(joinPath(cwd, dir)); err != nil {
						fmt.Fprintf(t, "%q: %v\n", dir, err)
						e = err
					}
				}
				return e
			},
		},
		{
			Name:            "rmdir",
			Usage:           "Remove a directory",
			UsageText:       "rmdir <name>",
			HideHelpCommand: true,
			Action: func(ctx *cli.Context) error {
				if ctx.Args().Len() == 0 {
					cli.ShowSubcommandHelp(ctx)
					return nil
				}
				var e error
				for _, dir := range ctx.Args().Slice() {
					if err := client.RemoveDirectory(joinPath(cwd, dir)); err != nil {
						fmt.Fprintf(t, "%q: %v\n", dir, err)
						e = err
					}
				}
				return e
			},
		},
		{
			Name:            "rm",
			Usage:           "Remove files",
			UsageText:       "rm <name>",
			HideHelpCommand: true,
			Action: func(ctx *cli.Context) error {
				if ctx.Args().Len() == 0 {
					cli.ShowSubcommandHelp(ctx)
					return nil
				}
				var e error
				for _, dir := range ctx.Args().Slice() {
					if err := client.Remove(joinPath(cwd, dir)); err != nil {
						fmt.Fprintf(t, "%q: %v\n", dir, err)
						e = err
					}
				}
				return e
			},
		},
		{
			Name:            "mv",
			Usage:           "Rename a file",
			UsageText:       "mv <oldname> <newname>\nmv <name> <directory>",
			HideHelpCommand: true,
			Action: func(ctx *cli.Context) error {
				if ctx.Args().Len() < 2 {
					cli.ShowSubcommandHelp(ctx)
					return nil
				}
				args := ctx.Args().Slice()
				dest := args[len(args)-1]
				files := args[:len(args)-1]
				if st, err := client.Stat(joinPath(cwd, dest)); err == nil && st.IsDir() {
					var e error
					for _, f := range files {
						if f == "" {
							continue
						}
						src := joinPath(cwd, f)
						dst := joinPath(cwd, dest, path.Base(src))
						if err := client.Rename(src, dst); err != nil {
							fmt.Fprintf(t, "%q -> %q: %v\n", src, dst, err)
							e = err
							continue
						}
					}
					return e
				}
				if len(files) > 1 {
					cli.ShowSubcommandHelp(ctx)
					return nil
				}
				src := joinPath(cwd, files[0])
				dst := joinPath(cwd, dest)
				if err := client.Rename(src, dst); err != nil {
					fmt.Fprintf(t, "%q -> %q: %v\n", src, dst, err)
					return err
				}
				return nil
			},
		},
		{
			Name:            "put",
			Usage:           "Upload a file",
			UsageText:       "put [dest]",
			HideHelpCommand: true,
			Action: func(ctx *cli.Context) error {
				if ctx.Args().Len() > 1 {
					cli.ShowSubcommandHelp(ctx)
					return nil
				}
				dest := cwd
				if ctx.Args().Len() == 1 {
					dest = joinPath(cwd, ctx.Args().Get(0))
				}
				isDir := false
				if st, err := client.Stat(dest); err == nil && st.IsDir() {
					isDir = true
				}

				cp := func(f jsutil.ImportedFile) error {
					defer f.Content.Close()
					var fn string
					if isDir {
						fn = joinPath(cwd, dest, f.Name)
					} else {
						fn = joinPath(cwd, dest)
					}
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
								w.Close()
								return io.ErrShortWrite
							}
							total += int64(n)
							if loop%100 == 0 {
								fmt.Fprintf(t, "%3d%%\b\b\b\b", 100*total/f.Size)
							}
						}
						if err == io.EOF {
							fmt.Fprintf(t, "%3d%%\n", 100*total/f.Size)
							break
						}
						if err != nil {
							w.Close()
							return err
						}

					}
					return w.Close()
				}
				for _, f := range a.importFiles("", isDir) {
					fmt.Fprintf(t, "%s ", f.Name)
					if err := cp(f); err != nil {
						return err
					}
				}
				return nil
			},
		},
		{
			Name:            "get",
			Usage:           "Download a file",
			UsageText:       "get <name>",
			HideHelpCommand: true,
			Action: func(ctx *cli.Context) error {
				if ctx.Args().Len() == 0 {
					cli.ShowSubcommandHelp(ctx)
					return nil
				}
				if a.streamHelper == nil {
					a.streamHelper = jsutil.NewStreamHelper()
					if a.streamHelper == nil {
						return errors.New("streaming download unavailable")
					}
				}
				get := func(p string) error {
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
					calls := new(atomic.Int32)
					progress := func(total int64) {
						if calls.Load()%100 == 0 {
							fmt.Fprintf(t, "%3d%%\b\b\b\b", 100*total/size)
						}
						calls.Add(1)
					}
					fmt.Fprintf(t, "%s ", name)
					if err := a.streamHelper.Download(r, name, size, progress, a.cfg.StreamHook); err != nil {
						return err
					}
					calls.Store(0)
					progress(size)
					fmt.Fprintln(t)
					return nil
				}
				for _, f := range ctx.Args().Slice() {
					if err := get(joinPath(cwd, f)); err != nil {
						return err
					}
				}
				return nil
			},
		},
		{
			Name:            "ls",
			Usage:           "List files",
			UsageText:       "ls [glob]",
			HideHelpCommand: true,
			Flags: []cli.Flag{
				&cli.BoolFlag{
					Name:  "l",
					Usage: "Long format.",
				},
			},
			Action: func(ctx *cli.Context) error {
				args := ctx.Args().Slice()
				if len(args) == 0 {
					args = []string{cwd}
				}
				type file struct {
					name string
					os.FileInfo
				}
				var list []file
				for _, arg := range args {
					info, err := client.Lstat(joinPath(cwd, arg))
					if err != nil {
						fmt.Fprintf(t, "%q: %v\n", arg, err)
						continue
					}
					if !info.IsDir() {
						list = append(list, file{name: strings.TrimPrefix(arg, cwd+"/"), FileInfo: info})
						continue
					}
					ll, err := client.ReadDirContext(ctx.Context, joinPath(cwd, arg))
					if err != nil {
						fmt.Fprintf(t, "%q: %v\n", arg, err)
						continue
					}
					for _, info := range ll {
						list = append(list, file{name: strings.TrimPrefix(joinPath(cwd, arg, info.Name()), cwd+"/"), FileInfo: info})
					}
				}
				sort.Slice(list, func(i, j int) bool {
					return list[i].name < list[j].name
				})
				for _, f := range list {
					var extra string
					if f.Mode()&os.ModeSymlink != 0 {
						if link, err := client.ReadLink(joinPath(cwd, f.name)); err == nil {
							extra = " -> " + link
						}
					}
					fmt.Fprintf(t, "%s %10d %s %s%s\n", f.Mode(), f.Size(), f.ModTime().Format("Jan 02 2006"), f.name, extra)
				}
				return nil
			},
		},
	}
	commandMap := make(map[string]*cli.App)
	for _, c := range commands {
		c.Writer = t
		c.CommandNotFound = func(ctx *cli.Context, name string) {
			fmt.Fprintf(t, "Unknown command %q. Try \"help\"\n", name)
		}
		commandMap[c.Name] = c
	}

	ac := &autoCompleter{
		cmds: commands,
		moreWords: func(args []string) []string {
			if len(args) < 2 {
				return nil
			}
			last := args[len(args)-1]
			var dir string
			if strings.HasPrefix(last, "/") {
				dir = last
			} else if strings.HasPrefix(last, "~/") {
				dir = homeDir + last[1:]
			} else {
				dir = cwd + "/" + last
			}
			if last != "" && !strings.HasSuffix(last, "/") {
				dir, _ = path.Split(dir)
			}
			ll, err := client.ReadDirContext(ctx, dir)
			if err != nil {
				return nil
			}
			dirOnly := args[0] == "cd" || args[0] == "rmdir" || args[0] == "put"
			var words []string
			for _, f := range ll {
				name := strings.TrimSuffix(dir, "/") + "/" + f.Name()
				if f.Mode()&os.ModeSymlink != 0 {
					st, err := client.Stat(name)
					if err == nil {
						f = st
					}
				}
				if strings.HasPrefix(last, "~/") && strings.HasPrefix(name, homeDir+"/") {
					name = "~" + name[len(homeDir):]
				} else if !strings.HasPrefix(last, "/") {
					name = strings.TrimPrefix(name, cwd+"/")
				}
				if f.IsDir() {
					name += "/"
				} else if dirOnly {
					continue
				}
				if strings.HasPrefix(name, last) {
					words = append(words, name)
				}
			}
			return words
		},
	}
	t.AutoCompleteCallback = func(line string, pos int, key rune) (newLine string, newPos int, ok bool) {
		var options []string
		newLine, newPos, options, ok = ac.autoComplete(line, pos, key)
		if len(options) > 0 {
			var w int
			for _, o := range options {
				w = max(len(o)+1, w)
			}
			step := max(a.term.Cols()/w, 1)
			fmt.Fprintf(raw, "\r\n")
			for i, o := range options {
				if (i+1)%step == 0 || i == len(options)-1 {
					fmt.Fprintf(raw, "%s\r\n", o)
				} else {
					fmt.Fprintf(raw, "%*s", -w, o)
				}
			}
			fmt.Fprintf(raw, "%s%s", prompt, line)
			if d := len(line) - pos; d > 0 {
				fmt.Fprintf(raw, "\x1b[%dD", d) // Move left d cols (CSI CUB)
			}
		}
		return
	}

	for {
		line, err := t.ReadLine()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		pArgs, _ := shellwords.Parse(line, shellwords.QuoteWild())
		if len(pArgs) == 0 {
			continue
		}
		var args []string
		for i, pa := range pArgs {
			if i == 0 {
				args = append(args, shellwords.UnquoteWild(pa))
				continue
			}
			matches, err := client.Glob(joinPath(cwd, pa))
			if err != nil || len(matches) == 0 {
				args = append(args, shellwords.UnquoteWild(pa))
				continue
			}
			for _, m := range matches {
				args = append(args, strings.TrimPrefix(m, cwd+"/"))
			}
		}
		switch name := args[0]; name {
		case "help", "?":
			fmt.Fprintf(t, "Available commands:\n")
			maxLen := 0
			for _, c := range commands {
				maxLen = max(maxLen, len(c.Name))
			}
			for _, c := range commands {
				fmt.Fprintf(t, "  %*s - %s\n", -maxLen, c.Name, c.Usage)
			}
			fmt.Fprintf(t, "Run any command with --help for more details.\n")

		case "debug":
			fmt.Fprintf(t, "cmdline parsing: %q -> %q\n", pArgs, args)

		case "exit", "quit", "bye":
			return nil

		default:
			cmd, ok := commandMap[name]
			if !ok {
				fmt.Fprintf(t, "Unknown command %q. Try \"help\"\n", name)
				continue
			}
			jsutil.TryCatch(
				func() { // try
					if err := cmd.RunContext(ctx, args); err != nil {
						fmt.Fprintf(t, "%v\n", err)
					}
				},
				func(err any) { // catch
					fmt.Fprintf(t, "%T %v\n", err, err)
				},
			)
		}
	}
}
