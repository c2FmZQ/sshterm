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

	// 2. Popup blocked initially, then opened on keydown user gesture.
	t.Run("PopupBlockedFallback", func(t *testing.T) {
		doc.Set("cookie", "sso_expired=1; path=/")
		doc.Set("cookie", "__tlsproxySid=old-sid; path=/")

		origOpen := win.Get("open")
		calls := 0
		mockOpen := js.FuncOf(func(this js.Value, args []js.Value) any {
			calls++
			if calls == 1 {
				return js.Null()
			}
			a := make([]any, len(args))
			for i := range args {
				a[i] = args[i]
			}
			return origOpen.Invoke(a...)
		})
		win.Set("open", mockOpen)
		t.Cleanup(func() {
			win.Set("open", origOpen)
			mockOpen.Release()
		})

		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		var buf syncBuffer
		errCh := make(chan error, 1)
		go func() {
			errCh <- jsutil.LoginPopup(ctx, "./websocket", &buf)
		}()

		for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
			if strings.Contains(buf.String(), "Press Enter or click to log in...") {
				break
			}
		}
		if !strings.Contains(buf.String(), "Press Enter or click to log in...") {
			t.Fatalf("expected popup blocked prompt, got %q", buf.String())
		}

		ev := js.Global().Get("KeyboardEvent").New("keydown", jsutil.NewObject(map[string]any{
			"key":        "Enter",
			"bubbles":    true,
			"cancelable": true,
		}))
		win.Call("dispatchEvent", ev)

		if err := <-errCh; err != nil {
			t.Fatalf("LoginPopup() failed: %v", err)
		}
		if calls < 2 {
			t.Errorf("window.open calls = %d, want >= 2", calls)
		}
		if jsutil.CheckAuthRequired(ctx, "./websocket") {
			t.Error("CheckAuthRequired(./websocket) is still true after LoginPopup")
		}
	})
}
