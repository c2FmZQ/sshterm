//go:build wasm

package internal

import (
	"errors"
	"fmt"
	"io"
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

	if t := arg.Get("term"); t.Type() != js.TypeObject {
		return errors.New("term value is missing")
	}

	cfg := &app.Config{
		Term: arg.Get("term"),
	}
	cfg.Term.Call("writeln", "\x1b[32m╔════════════════════════════════════════════╗\x1b[0m")
	cfg.Term.Call("writeln", "\x1b[32m║ SSH TERM \x1b[4;34mhttps://github.com/c2FmZQ/sshterm\x1b[0;32m ║\x1b[0m")
	cfg.Term.Call("writeln", "\x1b[32m╚════════════════════════════════════════════╝\x1b[0m")
	cfg.Term.Call("writeln", "\x1b[32mWelcome! Type \x1b[1mhelp\x1b[0;32m for a list of commands\x1b[0m\n")

	return jsutil.NewPromise(func() (any, error) {
		a, err := app.New(cfg)
		if err != nil {
			return nil, err
		}
		for {
			if err = a.Run(); err != io.EOF {
				break
			}
		}
		return "exited", err
	})
}
