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

package app

import (
	"slices"
	"sort"
	"strings"

	"github.com/urfave/cli/v2"

	"github.com/c2FmZQ/sshterm/internal/shellwords"
)

type autoCompleter struct {
	cmds      []*cli.App
	moreWords func([]string) []string
}

func (ac *autoCompleter) autoComplete(line string, pos int, key rune) (newLine string, newPos int, options []string, ok bool) {
	if key != '\t' {
		return
	}
	left, right := line[:pos], line[pos:]
	newLine, newPos, options, ok = ac.autoCompleteLeft(left)
	newLine += strings.TrimSpace(right)
	return
}

func (ac *autoCompleter) autoCompleteLeft(line string) (newLine string, newPos int, options []string, ok bool) {
	args, argsRaw := shellwords.Parse(line)
	var lw string
	if len(argsRaw) > 0 {
		lw = argsRaw[len(argsRaw)-1]
	}
	if line == "" || lw == "" || line[len(line)-1] != lw[len(lw)-1] {
		args = append(args, "")
		argsRaw = append(argsRaw, "")
	}
	switch m := ac.findMatches(args); len(m) {
	case 0:
		return
	case 1:
		lastWord := argsRaw[len(argsRaw)-1]
		newLine = line[:len(line)-len(lastWord)] + maybeQuote(m[0])
		if !strings.HasSuffix(m[0], "=") && !strings.HasSuffix(m[0], "/") {
			newLine += " "
		}
		newPos = len(newLine)
		ok = true
		return
	default:
		lastWord := args[len(args)-1]
		lp := longestPrefix(m)
		if lp > len(lastWord) {
			lastWordRaw := argsRaw[len(argsRaw)-1]
			newLine = line[:len(line)-len(lastWordRaw)] + maybeQuote(m[0][:lp])
			newPos = len(newLine)
			ok = true
			return
		}
		options = nil
		for _, w := range m {
			options = append(options, maybeQuote(w))
		}
		sort.Strings(options)
	}
	return
}

func maybeQuote(s string) string {
	if strings.IndexAny(s, "\"'\\ \t") == -1 {
		return s
	}
	var n strings.Builder
	n.WriteRune('"')
	for _, c := range s {
		if c == '"' || c == '\\' {
			n.WriteRune('\\')
		}
		n.WriteRune(c)
	}
	n.WriteRune('"')
	return n.String()
}

func longestPrefix(words []string) int {
	if len(words) == 0 {
		return 0
	}
	for n := 0; ; n++ {
		for _, w := range words {
			if len(w) <= n || w[n] != words[0][n] {
				return n
			}
		}
	}
}

func (ac *autoCompleter) findMatches(args []string) []string {
	pos := 0
	if len(args) == 0 {
		return nil
	}
	var app *cli.App
	var pool []string
	for _, c := range ac.cmds {
		if c.Name == args[pos] {
			app = c
		}
		if strings.HasPrefix(c.Name, args[pos]) {
			pool = append(pool, c.Name)
		}
	}
	pos++
	if pos == len(args) {
		return pool
	}
	if app == nil {
		return nil
	}
	doCmds := func(pos int, args []string, cmds []*cli.Command, cmd **cli.Command, pool *[]string) {
		for _, c := range cmds {
			if c.Name == args[pos] {
				*cmd = c
			}
			if strings.HasPrefix(c.Name, args[pos]) {
				*pool = append(*pool, c.Name)
			}
		}
	}
	doFlags := func(pos int, args []string, flags []cli.Flag, pool *[]string) {
		if len(args[pos]) == 0 {
			return
		}
		for _, flag := range flags {
			n := "--" + flag.Names()[0]
			if _, ok := flag.(*cli.BoolFlag); ok {
				if strings.HasPrefix(n, args[pos]) {
					*pool = append(*pool, n)
				}
				continue
			}
			n += "="
			if args[pos] != "--"+flag.Names()[0]+"=" {
				if strings.HasPrefix(n, args[pos]) {
					*pool = append(*pool, n)
				}
				continue
			}
			aa := slices.Clone(args[:pos])
			mw := ac.moreWords(append(aa, n))
			if len(mw) == 0 {
				mw = []string{n}
			}
			for _, w := range mw {
				if strings.HasPrefix(w, args[pos]) {
					*pool = append(*pool, w)
				}
			}
		}
	}
	var cmd *cli.Command
	for pos < len(args) {
		var pool []string
		doCmds(pos, args, app.Commands, &cmd, &pool)
		doFlags(pos, args, app.Flags, &pool)
		if len(pool) == 0 && ac.moreWords != nil {
			pool = append(pool, ac.moreWords(args)...)
		}
		pos++
		if pos == len(args) {
			return pool
		}
		if cmd != nil {
			break
		}
	}
	if cmd == nil {
		return nil
	}
	var subCmd *cli.Command
	for pos < len(args) {
		var pool []string
		doCmds(pos, args, cmd.Subcommands, &subCmd, &pool)
		doFlags(pos, args, cmd.Flags, &pool)
		if len(pool) == 0 && ac.moreWords != nil {
			pool = append(pool, ac.moreWords(args)...)
		}
		pos++
		if pos == len(args) {
			return pool
		}
		if subCmd != nil {
			cmd = subCmd
			subCmd = nil
		}
	}
	return nil
}
