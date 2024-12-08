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

package internal

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall/js"

	"github.com/c2FmZQ/sshterm/internal/app"
	"github.com/c2FmZQ/sshterm/internal/jsutil"
)

func Start(this js.Value, args []js.Value) (result any) {
	defer func() {
		switch v := result.(type) {
		case error:
			jsErr := js.Global().Get("Error").New(fmt.Sprintf("Start: %v", v))
			result = js.Global().Get("Promise").Call("reject", jsErr)
		default:
		}
	}()
	if n := len(args); n != 1 {
		return fmt.Errorf("expected one argument, got %d", n)
	}
	if args[0].Type() != js.TypeObject {
		return errors.New("args[0] should be an Object")
	}
	arg := args[0]

	term := arg.Get("term")
	if term.Type() != js.TypeObject {
		return errors.New("term value is missing")
	}
	arg.Delete("term")

	jsArg := js.Global().Get("JSON").Call("stringify", arg).String()
	var cfg app.Config
	if err := json.Unmarshal([]byte(jsArg), &cfg); err != nil {
		return fmt.Errorf("json.Unmarshal: %w", err)
	}

	cfg.Term = term
	cfg.Term.Call("writeln", "\x1b[32m╔════════════════════════════════════╗\x1b[0m")
	cfg.Term.Call("writeln", "\x1b[32m║ SSH TERM \x1b[4;34mgithub.com/c2FmZQ/sshterm\x1b[0;32m ║\x1b[0m")
	cfg.Term.Call("writeln", "\x1b[32m╚════════════════════════════════════╝\x1b[0m")
	if cfg.AutoConnect == nil {
		cfg.Term.Call("writeln", "\x1b[32mWelcome! Type \x1b[1mhelp\x1b[0;32m for a list of commands\x1b[0m")
	}
	cfg.Term.Call("writeln", "")

	return jsutil.NewPromise(func() (any, error) {
		defer func() {
			fmt.Fprintf(os.Stderr, "Start Promise return\n")
		}()
		a, err := app.New(&cfg)
		if err != nil {
			return nil, err
		}
		for {
			if err = a.Run(); err != io.EOF {
				return "exited", err
			}
		}
	})
}
