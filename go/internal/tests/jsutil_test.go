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
	"context"
	"errors"
	"strings"
	"sync"
	"syscall/js"
	"testing"
	"time"

	"github.com/c2FmZQ/sshterm/internal/jsutil"
)

func TestTLSProxySID(t *testing.T) {
	doc := js.Global().Get("document")
	setCookie := func(v string) {
		doc.Set("cookie", v)
		t.Cleanup(func() {
			doc.Set("cookie", v+"; max-age=0")
		})
	}

	setCookie("x__tlsproxySid=wrong")
	if got := jsutil.TLSProxySID(); got != "" {
		t.Errorf("TLSProxySID() = %q, want empty", got)
	}
	setCookie("__tlsproxySid=right")
	if got, want := jsutil.TLSProxySID(), "right"; got != want {
		t.Errorf("TLSProxySID() = %q, want %q", got, want)
	}
}

func TestIsSameOrigin(t *testing.T) {
	origin := js.Global().Get("location").Get("origin").String()
	for _, tc := range []struct {
		url  string
		want bool
	}{
		{"./cert", true},
		{"/cert", true},
		{origin + "/cert", true},
		{"https://example.com/cert", false},
		{"//example.com/cert", false},
		{"http://[invalid", false},
	} {
		if got := jsutil.IsSameOrigin(tc.url); got != tc.want {
			t.Errorf("IsSameOrigin(%q) = %v, want %v", tc.url, got, tc.want)
		}
	}
}

func TestServiceWorkerSingleton(t *testing.T) {
	sw := js.Global().Get("navigator").Get("serviceWorker")
	if sw.IsUndefined() {
		t.Skip("Service Worker not available")
	}
	h1 := jsutil.NewStreamHelper()
	cb1 := sw.Get("onmessage")
	h2 := jsutil.NewStreamHelper()
	cb2 := sw.Get("onmessage")
	if h1 != h2 {
		t.Errorf("NewStreamHelper() returned different instances: %p != %p", h1, h2)
	}
	if !cb1.Equal(cb2) {
		t.Error("serviceWorker.onmessage was overwritten by second NewStreamHelper() call")
	}
}

func TestCheckAuthRequired(t *testing.T) {
	doc := js.Global().Get("document")
	t.Cleanup(func() {
		doc.Set("cookie", "sso_expired=; path=/; max-age=0")
	})

	ctx := context.Background()
	doc.Set("cookie", "sso_expired=; path=/; max-age=0")
	if jsutil.CheckAuthRequired(ctx, "./websocket") {
		t.Error("CheckAuthRequired(./websocket) = true, want false when authenticated")
	}
	if jsutil.CheckAuthRequired(ctx, "./cert") {
		t.Error("CheckAuthRequired(./cert) = true, want false when authenticated")
	}
	if jsutil.CheckAuthRequired(ctx, "ws://[invalid") {
		t.Error("CheckAuthRequired(ws://[invalid) = true, want false")
	}

	doc.Set("cookie", "sso_expired=1; path=/")
	if !jsutil.CheckAuthRequired(ctx, "./websocket") {
		t.Error("CheckAuthRequired(./websocket) = false, want true when 403")
	}
	if !jsutil.CheckAuthRequired(ctx, "./websocket?redirect=true") {
		t.Error("CheckAuthRequired(./websocket?redirect=true) = false, want true when 302 redirect")
	}
	if !jsutil.CheckAuthRequired(ctx, "./cert") {
		t.Error("CheckAuthRequired(./cert) = false, want true when 403")
	}
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestLoginPopup(t *testing.T) {
	doc := js.Global().Get("document")
	win := js.Global().Get("window")
	t.Cleanup(func() {
		doc.Set("cookie", "sso_expired=; path=/; max-age=0")
		doc.Set("cookie", "__tlsproxySid=; path=/; max-age=0")
	})

	// 1. Direct popup open (not blocked).
	t.Run("DirectOpen", func(t *testing.T) {
		doc.Set("cookie", "sso_expired=1; path=/")
		doc.Set("cookie", "__tlsproxySid=old-sid; path=/")

		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		var buf syncBuffer
		if err := jsutil.LoginPopup(ctx, "./websocket", &buf); err != nil {
			t.Fatalf("LoginPopup() failed: %v", err)
		}
		if !strings.Contains(buf.String(), "Authentication required. Waiting for login...") {
			t.Errorf("unexpected log output: %q", buf.String())
		}
		if jsutil.CheckAuthRequired(ctx, "./websocket") {
			t.Error("CheckAuthRequired(./websocket) is still true after LoginPopup")
		}
		if got, want := jsutil.TLSProxySID(), "fresh-sid"; got != want {
			t.Errorf("TLSProxySID() = %q, want %q", got, want)
		}
	})

	// 2. The browser blocks the popup. LoginPopup fails right away.
	t.Run("PopupBlocked", func(t *testing.T) {
		doc.Set("cookie", "sso_expired=1; path=/")

		origOpen := win.Get("open")
		mockOpen := js.FuncOf(func(this js.Value, args []js.Value) any {
			return js.Null()
		})
		win.Set("open", mockOpen)
		t.Cleanup(func() {
			win.Set("open", origOpen)
			mockOpen.Release()
		})

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var buf syncBuffer
		err := jsutil.LoginPopup(ctx, "./websocket", &buf)
		if !errors.Is(err, jsutil.ErrAuthRequired) || errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("LoginPopup() = %v, want %v", err, jsutil.ErrAuthRequired)
		}
		if err == nil || !strings.Contains(err.Error(), "blocked") {
			t.Errorf("LoginPopup() = %v, want a blocked popup error", err)
		}
		if buf.String() != "" {
			t.Errorf("unexpected log output: %q", buf.String())
		}
	})

	// 3. The popup is closed without the login page announcing a login,
	// e.g. by the user. LoginPopup returns so that the caller retries.
	t.Run("Closed", func(t *testing.T) {
		doc.Set("cookie", "sso_expired=1; path=/")

		origOpen := win.Get("open")
		closeFn := js.FuncOf(func(this js.Value, args []js.Value) any { return nil })
		mockOpen := js.FuncOf(func(this js.Value, args []js.Value) any {
			return jsutil.NewObject(map[string]any{
				"closed": true,
				"close":  closeFn,
			})
		})
		win.Set("open", mockOpen)
		t.Cleanup(func() {
			win.Set("open", origOpen)
			mockOpen.Release()
			closeFn.Release()
		})

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var buf syncBuffer
		start := time.Now()
		if err := jsutil.LoginPopup(ctx, "./websocket", &buf); err != nil {
			t.Errorf("LoginPopup() = %v, want nil", err)
		}
		if d := time.Since(start); d > 2*time.Second {
			t.Errorf("LoginPopup() took %s, want a prompt return after the popup closed", d)
		}
	})

	// 4. The popup stays open and the login never completes. LoginPopup
	// gives up when the context expires.
	t.Run("Timeout", func(t *testing.T) {
		doc.Set("cookie", "sso_expired=1; path=/")

		origOpen := win.Get("open")
		closeFn := js.FuncOf(func(this js.Value, args []js.Value) any { return nil })
		mockOpen := js.FuncOf(func(this js.Value, args []js.Value) any {
			return jsutil.NewObject(map[string]any{
				"closed": false,
				"close":  closeFn,
			})
		})
		win.Set("open", mockOpen)
		t.Cleanup(func() {
			win.Set("open", origOpen)
			mockOpen.Release()
			closeFn.Release()
		})

		ctx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
		defer cancel()
		var buf syncBuffer
		err := jsutil.LoginPopup(ctx, "./websocket", &buf)
		if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, jsutil.ErrAuthRequired) {
			t.Errorf("LoginPopup() = %v, want %v and %v", err, jsutil.ErrAuthRequired, context.DeadlineExceeded)
		}
	})
}
