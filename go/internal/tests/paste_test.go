// MIT License
//
// Copyright (c) 2026 TTBT Enterprises LLC
// Copyright (c) 2026 Robin Thellend <rthellend@rthellend.com>
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

package tests

import (
	"syscall/js"
	"testing"

	"github.com/c2FmZQ/sshterm/internal/app"
	"github.com/c2FmZQ/sshterm/internal/jsutil"
)

func TestPaste(t *testing.T) {
	a, err := app.New(appConfig)
	if err != nil {
		t.Fatalf("app.New: %v", err)
	}
	result := make(chan error)
	go func() {
		result <- a.Run()
	}()
	t.Cleanup(a.Stop)

	paste := func(text string) {
		dt := js.Global().Get("DataTransfer").New()
		dt.Call("setData", "text/plain", text)
		ev := js.Global().Get("ClipboardEvent").New("paste", jsutil.NewObject(map[string]any{
			"clipboardData": dt,
			"bubbles":       true,
			"cancelable":    true,
		}))
		js.Global().Get("sshApp").Get("term").Get("textarea").Call("dispatchEvent", ev)
	}

	script(t, []line{
		{Expect: prompt},
		{Type: "db wipe\n", Expect: `Continue\?`},
		{Type: "Y\n", Expect: prompt},
	})
	// Escape characters are removed from pasted text.
	paste("ep add pa\x1bste ./websocket\r")
	script(t, []line{
		{Expect: prompt},
		{Type: "ep list\n", Expect: `(?s)paste +\./websocket.*sshterm> `},
		{Type: "exit\n"},
	})
	if err := <-result; err != nil {
		t.Fatalf("Run(): %v", err)
	}
}
