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
	"testing"

	"github.com/mattn/go-shellwords"
	"github.com/urfave/cli/v2"
)

func TestAutoComplete(t *testing.T) {
	p := shellwords.NewParser()
	cmds := []*cli.App{
		{Name: "accept"},
		{Name: "all"},
		{Name: "allow",
			Commands: []*cli.Command{
				{Name: "one",
					Subcommands: []*cli.Command{
						{Name: "alpha"},
					},
					Flags: []cli.Flag{
						&cli.BoolFlag{Name: "foo"},
					},
				},
				{Name: "two"},
			},
			Flags: []cli.Flag{
				&cli.BoolFlag{Name: "always"},
				&cli.BoolFlag{Name: "almost-always"},
				&cli.BoolFlag{Name: "not-often"},
				&cli.BoolFlag{Name: "never"},
				&cli.BoolFlag{Name: "meh"},
			},
		},
		{Name: "brake"},
		{Name: "break", Commands: []*cli.Command{
			{Name: "leg"},
			{Name: "nose"},
			{Name: "foot"},
			{Name: "face"},
		}},
	}
	ac := &autoCompleter{
		p:    p,
		cmds: cmds,
	}

	for _, tc := range []struct {
		line    string
		pos     int
		newLine string
		newPos  int
		options []string
		ok      bool
	}{
		{line: "", pos: 0, options: []string{"accept", "all", "allow", "brake", "break"}},
		{line: "x", pos: 1},
		{line: "a", pos: 1, options: []string{"accept", "all", "allow"}},
		{line: "al", pos: 2, newLine: "all", newPos: 3, ok: true},
		{line: "all", pos: 3, options: []string{"all", "allow"}},
		{line: "ac", pos: 2, newLine: "accept ", newPos: 7, ok: true},
		{line: "b", pos: 1, newLine: "br", newPos: 2, ok: true},
		{line: "br", pos: 2, options: []string{"brake", "break"}},
		{line: "break", pos: 5, newLine: "break ", newPos: 6, ok: true},
		{line: "break ", pos: 6, options: []string{"leg", "nose", "foot", "face"}},
		{line: "break f", pos: 7, options: []string{"foot", "face"}},
		{line: "break x", pos: 7},
		{line: "break fa", pos: 8, newLine: "break face ", newPos: 11, ok: true},
		{line: "break  fa", pos: 9, newLine: "break  face ", newPos: 12, ok: true},
		{line: "allow ", pos: 6, options: []string{"one", "two"}},
		{line: "allow o", pos: 7, newLine: "allow one ", newPos: 10, ok: true},
		{line: "allow --", pos: 8, options: []string{"--always", "--almost-always", "--not-often", "--never", "--meh"}},
		{line: "allow --a", pos: 9, newLine: "allow --al", newPos: 10, ok: true},
		{line: "allow --al", pos: 10, options: []string{"--always", "--almost-always"}},
		{line: "allow --m", pos: 9, newLine: "allow --meh ", newPos: 12, ok: true},
		{line: "allow --meh ", pos: 12, options: []string{"one", "two"}},
		{line: "allow --meh --", pos: 14, options: []string{"--always", "--almost-always", "--not-often", "--never", "--meh"}},
		{line: "allow --meh one", pos: 15, newLine: "allow --meh one ", newPos: 16, ok: true},
		{line: "allow --meh one ", pos: 16, newLine: "allow --meh one alpha ", newPos: 22, ok: true},
		{line: "allow --meh one --foo ", pos: 22, newLine: "allow --meh one --foo alpha ", newPos: 28, ok: true},
		{line: "allow --meh one --foo alpha ", pos: 28},
	} {
		nl, np, opt, ok := ac.autoComplete(tc.line, tc.pos, '\t')
		if nl != tc.newLine || np != tc.newPos || ok != tc.ok {
			t.Errorf("autoComplete(%q, %d, '\\t') = %q, %d, %v; want %q, %d, %v", tc.line, tc.pos, nl, np, ok, tc.newLine, tc.newPos, tc.ok)
		}
		if !slices.Equal(opt, tc.options) {
			t.Errorf("autoComplete(%q, %d, '\\t') options %#v; want %#v", tc.line, tc.pos, opt, tc.options)
		}
	}
}
