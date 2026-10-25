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
	"bytes"
	"net/http"
	"strings"
	"syscall/js"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/c2FmZQ/sshterm/internal/app"
	"github.com/c2FmZQ/sshterm/internal/jsutil"
)

func TestXtermWorkarounds(t *testing.T) {
	sshApp := js.Global().Get("sshApp")
	termCtor := sshApp.Get("Terminal")
	workarounds := sshApp.Get("workarounds")
	applyWorkarounds := sshApp.Get("applyXtermWorkarounds")
	if termCtor.IsUndefined() || workarounds.IsUndefined() || applyWorkarounds.IsUndefined() {
		t.Fatalf("missing sshApp.Terminal / workarounds / applyXtermWorkarounds exports")
	}
	doc := js.Global().Get("document")

	createTestTerm := func(t *testing.T, flags map[string]any) (js.Value, func()) {
		t.Helper()
		container := doc.Call("createElement", "div")
		container.Get("style").Set("width", "400px")
		container.Get("style").Set("height", "200px")
		doc.Get("body").Call("appendChild", container)
		term := termCtor.New(map[string]any{"cols": 40, "rows": 10})
		term.Call("open", container)
		disposables := applyWorkarounds.Invoke(term, flags)
		cleanup := func() {
			for i := 0; i < disposables.Length(); i++ {
				disposables.Index(i).Call("dispose")
			}
			term.Call("dispose")
			doc.Get("body").Call("removeChild", container)
		}
		return term, cleanup
	}

	writeTerm := func(t *testing.T, term js.Value, data string) {
		t.Helper()
		doneCh := make(chan struct{}, 1)
		cb := js.FuncOf(func(this js.Value, args []js.Value) any {
			select {
			case doneCh <- struct{}{}:
			default:
			}
			return nil
		})
		defer cb.Release()
		var writeErr any
		jsutil.TryCatch(func() {
			term.Call("write", data, cb)
		}, func(err any) {
			writeErr = err
		})
		if writeErr != nil {
			t.Fatalf("term.write threw: %v", writeErr)
		}
		select {
		case <-doneCh:
		case <-time.After(2 * time.Second):
			t.Fatalf("term.write callback timed out (WriteBuffer wedged)")
		}
	}

	// 1. CSI Ps b (REP / repeatPrecedingCharacter)
	t.Run("CSIRepGuard", func(t *testing.T) {
		t.Run("VulnerabilityWithoutRemediation", func(t *testing.T) {
			term, cleanup := createTestTerm(t, map[string]any{
				"csiRepGuard":  false,
				"csiLoopGuard": false,
			})
			defer cleanup()
			writeTerm(t, term, "a")

			paramsArr := js.Global().Get("Int32Array").New(1)
			paramsArr.SetIndex(0, 2147483647)
			var caught any
			jsutil.TryCatch(func() {
				term.Get("_core").Get("_inputHandler").Call("repeatPrecedingCharacter", map[string]any{
					"length": 1,
					"params": paramsArr,
				})
			}, func(err any) {
				caught = err
			})
			if caught == nil {
				t.Fatalf("expected @xterm/xterm repeatPrecedingCharacter(2147483647) to throw RangeError without csiRepGuard; if fixed upstream, remove csiRepGuard")
			}
		})

		t.Run("RemediationEnabled", func(t *testing.T) {
			term, cleanup := createTestTerm(t, map[string]any{
				"csiRepGuard":  true,
				"csiLoopGuard": true,
			})
			defer cleanup()
			writeTerm(t, term, "a\x1b[2147483647bOK")
		})
	})

	// 2. CSI Ps I/Z/L/M/S/T unbounded loop parameter clamping
	t.Run("CSILoopGuard", func(t *testing.T) {
		t.Run("VulnerabilityWithoutRemediation", func(t *testing.T) {
			term, cleanup := createTestTerm(t, map[string]any{
				"csiRepGuard":  true,
				"csiLoopGuard": false,
			})
			defer cleanup()

			seenParam := 0
			cb := js.FuncOf(func(this js.Value, args []js.Value) any {
				seenParam = args[0].Get("params").Index(0).Int()
				return true // intercept before built-in 2B loop freezes browser
			})
			defer cb.Release()
			disp := term.Get("_core").Call("registerCsiHandler", map[string]any{"final": "L"}, cb)
			writeTerm(t, term, "\x1b[2147483647L")
			disp.Call("dispose")
			if seenParam != 2147483647 {
				t.Fatalf("expected unclamped CSI L param 2147483647 without csiLoopGuard, got %d", seenParam)
			}
		})

		t.Run("RemediationEnabled", func(t *testing.T) {
			term, cleanup := createTestTerm(t, map[string]any{
				"csiRepGuard":  true,
				"csiLoopGuard": true,
			})
			defer cleanup()
			start := time.Now()
			writeTerm(t, term, "\x1b[2147483647I\x1b[2147483647Z\x1b[2147483647L\x1b[2147483647M\x1b[2147483647S\x1b[2147483647T")
			if elapsed := time.Since(start); elapsed > time.Second {
				t.Fatalf("CSI loop guard took too long: %v", elapsed)
			}
		})
	})

	// 3. Title sanitization and _showMessage toast DOM reuse
	t.Run("TitleOverlay", func(t *testing.T) {
		screen := doc.Call("querySelector", `[id^="screen-"]`)
		if screen.IsNull() || screen.IsUndefined() {
			t.Fatalf("screen element not found")
		}
		longTitle := strings.Repeat("A", 300) + "\nSPOOF"

		appConfig.Term.Call("showMessage", longTitle)
		appConfig.Term.Call("showMessage", longTitle)
		toasts := screen.Call("querySelectorAll", ".sshterm-toast")
		if got := toasts.Length(); got != 1 {
			t.Fatalf("expected exactly 1 .sshterm-toast element, got %d", got)
		}
		txt := toasts.Index(0).Get("textContent").String()
		if len([]rune(txt)) > 129 || strings.Contains(txt, "\n") {
			t.Fatalf("expected toast text to be truncated and sanitized, got len=%d %q", len(txt), txt)
		}
	})
}

func TestRSASHA2ForwardedAgent(t *testing.T) {
	a, err := app.New(appConfig)
	if err != nil {
		t.Fatalf("app.New: %v", err)
	}
	result := make(chan error)
	go func() {
		result <- a.Run()
	}()
	t.Cleanup(a.Stop)

	script(t, []line{
		{Expect: prompt},
		{Type: "db wipe\n", Expect: `Continue\?`},
		{Type: "Y\n", Expect: prompt},
		{Type: "ep add test-server websocket\n", Expect: prompt},
		{Type: "keys generate -t rsa rsatest\n", Expect: "Enter a passphrase"},
		{Type: "foobar\n", Expect: "Re-enter the same passphrase"},
		{Type: "foobar\n", Expect: prompt},
		{Type: "keys list\n", Expect: "ssh-rsa .* rsatest\r\n", Do: func(m []string) {
			pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(m[0]))
			if err != nil {
				t.Fatalf("ssh.ParseAuthorizedKey: %v", err)
			}
			if _, err := http.Post("/addkey", "text/pem", bytes.NewReader(pub.Marshal())); err != nil {
				t.Fatalf("http.Post: %v", err)
			}
		}},
		{Type: "agent add rsatest\n", Expect: "Enter the passphrase for rsatest:"},
		{Type: "foobar\n", Expect: prompt},
		{Type: "ssh -A testuser@test-server agent-test\n", Expect: `(?s)Host key for test-server.*Choice>`},
		{Type: "3\n", Expect: `\[agent\] test-server requested a signature with key "rsatest"`},
		{Expect: `(?s)agent-test: sign: ok \(ssh-rsa\).*agent-test: sign-sha512: ok \(rsa-sha2-512\).*agent-test: removeall: agent: failure`},
		{Wait: time.Second, Type: "\n\n", Expect: prompt},
		{Type: "exit\n"},
	})

	if err := <-result; err != nil {
		t.Fatalf("Run(): %v", err)
	}
}
