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

package jsutil

import (
	"context"
	"fmt"
	"io"
	"syscall/js"
	"time"
)

const popupFeatures = "popup,width=600,height=700"

var loginMu = make(chan struct{}, 1)

func toHTTPURL(rawURL string) (out string, err error) {
	TryCatch(
		func() {
			loc := Document.Get("location")
			u := URL.New(rawURL, loc.Get("href"))
			switch p := u.Get("protocol").String(); p {
			case "ws:":
				u.Set("protocol", "http:")
			case "wss:":
				u.Set("protocol", "https:")
			case "http:", "https:":
			default:
				err = fmt.Errorf("unsupported protocol %q", p)
				return
			}
			out = u.Get("href").String()
		},
		func(e any) {
			err = fmt.Errorf("%v", e)
		},
	)
	return
}

// CheckAuthRequired probes rawURL with a HEAD request (converting ws/wss to
// http/https) and returns true if the server responds with an authentication
// failure (401, 403) or a redirect (3xx / opaqueredirect).
func CheckAuthRequired(ctx context.Context, rawURL string) bool {
	httpURL, err := toHTTPURL(rawURL)
	if err != nil {
		return false
	}
	var abortController js.Value
	opts := map[string]any{
		"method":      "HEAD",
		"redirect":    "manual",
		"cache":       "no-store",
		"credentials": "include",
	}
	if acCtor := js.Global().Get("AbortController"); !acCtor.IsUndefined() {
		abortController = acCtor.New()
		opts["signal"] = abortController.Get("signal")
	}
	stop := context.AfterFunc(ctx, func() {
		if !abortController.IsUndefined() {
			TryCatch(func() { abortController.Call("abort") }, func(any) {})
		}
	})
	defer stop()

	var fetchPromise js.Value
	TryCatch(
		func() {
			fetchPromise = js.Global().Call("fetch", httpURL, NewObject(opts))
		},
		func(any) {},
	)
	if fetchPromise.IsUndefined() {
		return false
	}
	resp, err := Await(fetchPromise)
	if err != nil || resp.IsUndefined() || resp.IsNull() {
		return false
	}
	if resp.Get("type").String() == "opaqueredirect" {
		return true
	}
	status := resp.Get("status").Int()
	return status == 401 || status == 403 || (status >= 300 && status < 400)
}

func popupURLFor(ctx context.Context, rawURL string) (string, error) {
	httpURL, err := toHTTPURL(rawURL)
	if err != nil {
		return "", err
	}
	var ssoURL string
	TryCatch(
		func() {
			if IsSameOrigin(httpURL) {
				loc := Document.Get("location")
				ssoURL = URL.New("./?sso=1", loc.Get("href")).Get("href").String()
			} else {
				ssoURL = URL.New("/?sso=1", httpURL).Get("href").String()
			}
		},
		func(any) {},
	)
	if ssoURL != "" && CheckAuthRequired(ctx, ssoURL) {
		return ssoURL, nil
	}
	return httpURL, nil
}

// LoginPopup opens a popup window to authenticate the user for rawURL and
// waits until authentication completes, the popup is closed, or ctx is
// canceled.
func LoginPopup(ctx context.Context, rawURL string, log io.Writer) error {
	select {
	case loginMu <- struct{}{}:
		defer func() { <-loginMu }()
	case <-ctx.Done():
		return ctx.Err()
	}

	authRequiredInitially := CheckAuthRequired(ctx, rawURL)
	popupURL, err := popupURLFor(ctx, rawURL)
	if err != nil {
		return err
	}

	doneCh := make(chan struct{}, 1)
	notifyDone := func() {
		select {
		case doneCh <- struct{}{}:
		default:
		}
	}

	var bc js.Value
	var bcCb js.Func
	if broadcastChannel := js.Global().Get("BroadcastChannel"); !broadcastChannel.IsUndefined() {
		bc = broadcastChannel.New("sshterm_sso")
		bcCb = js.FuncOf(func(this js.Value, args []js.Value) any {
			notifyDone()
			return nil
		})
		bc.Set("onmessage", bcCb)
		defer func() {
			bc.Call("close")
			bcCb.Release()
		}()
	}

	win := js.Global().Get("window")
	origin := Document.Get("location").Get("origin").String()
	msgCb := js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) == 0 {
			return nil
		}
		ev := args[0]
		if ev.Get("origin").String() != origin {
			return nil
		}
		data := ev.Get("data")
		if data.Type() == js.TypeObject && data.Get("type").String() == "sshterm-sso-complete" {
			notifyDone()
		}
		return nil
	})
	win.Call("addEventListener", "message", msgCb)
	defer func() {
		win.Call("removeEventListener", "message", msgCb)
		msgCb.Release()
	}()

	var popup js.Value
	TryCatch(
		func() {
			popup = win.Call("open", popupURL, "sshterm_sso", popupFeatures)
		},
		func(any) {},
	)
	defer func() {
		if !popup.IsUndefined() && !popup.IsNull() {
			TryCatch(func() { popup.Call("close") }, func(any) {})
		}
	}()

	if popup.IsUndefined() || popup.IsNull() {
		if log != nil {
			fmt.Fprintf(log, "\nAuthentication required. Press Enter or click to log in...\n")
		}
		openedCh := make(chan js.Value, 1)
		openOnGesture := js.FuncOf(func(this js.Value, args []js.Value) any {
			if len(args) > 0 {
				ev := args[0]
				if ev.Get("type").String() == "keydown" {
					key := ev.Get("key").String()
					if key == "Control" || key == "Shift" || key == "Alt" || key == "Meta" {
						return nil
					}
					if ev.Get("ctrlKey").Truthy() && (key == "c" || key == "C") {
						return nil
					}
					ev.Call("preventDefault")
					ev.Call("stopPropagation")
				}
			}
			var p js.Value
			TryCatch(
				func() {
					p = win.Call("open", popupURL, "sshterm_sso", popupFeatures)
				},
				func(any) {},
			)
			if !p.IsUndefined() && !p.IsNull() {
				select {
				case openedCh <- p:
				default:
				}
			}
			return nil
		})
		win.Call("addEventListener", "keydown", openOnGesture, true)
		win.Call("addEventListener", "mousedown", openOnGesture, true)
		win.Call("addEventListener", "touchend", openOnGesture, true)
		cleanupGesture := func() {
			win.Call("removeEventListener", "keydown", openOnGesture, true)
			win.Call("removeEventListener", "mousedown", openOnGesture, true)
			win.Call("removeEventListener", "touchend", openOnGesture, true)
			openOnGesture.Release()
		}
		select {
		case <-ctx.Done():
			cleanupGesture()
			return ctx.Err()
		case <-doneCh:
			cleanupGesture()
			return nil
		case popup = <-openedCh:
			cleanupGesture()
			if log != nil {
				fmt.Fprintf(log, "Waiting for login...\n")
			}
		}
	} else if log != nil {
		fmt.Fprintf(log, "\nAuthentication required. Waiting for login...\n")
	}

	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	ticks := 0
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-doneCh:
			return nil
		case <-ticker.C:
			ticks++
			closed := false
			TryCatch(
				func() {
					closed = popup.Get("closed").Truthy()
				},
				func(any) {
					closed = true
				},
			)
			if closed {
				return nil
			}
			if ticks%2 == 0 && authRequiredInitially && !CheckAuthRequired(ctx, rawURL) {
				return nil
			}
		}
	}
}
