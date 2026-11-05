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
	"errors"
	"fmt"
	"io"
	"syscall/js"
	"time"
)

const (
	popupFeatures       = "popup,width=600,height=700"
	authCheckTimeout    = 5 * time.Second
	popupCheckInterval  = 500 * time.Millisecond
	defaultPopupTimeout = 5 * time.Minute
)

var ErrAuthRequired = errors.New("authentication required")

func toHTTPURL(rawURL string) (out string, err error) {
	TryCatch(
		func() {
			u := URL.New(rawURL, Document.Get("location").Get("href"))
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

// checkAuthStatus probes httpURL with a HEAD request and reports whether the
// server wants the user to authenticate. TLSPROXY answers unauthenticated
// non-GET requests with 403, and unauthenticated GET requests with a redirect
// to the login page, which fetch reports as an opaqueredirect response.
func checkAuthStatus(ctx context.Context, httpURL string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, authCheckTimeout)
	defer cancel()

	abortController := js.Global().Get("AbortController").New()
	stop := context.AfterFunc(ctx, func() {
		TryCatch(func() { abortController.Call("abort") }, func(any) {})
	})
	defer stop()

	var promise js.Value
	var err error
	TryCatch(
		func() {
			promise = js.Global().Call("fetch", httpURL, NewObject(map[string]any{
				"method":      "HEAD",
				"redirect":    "manual",
				"cache":       "no-store",
				"credentials": "include",
				"signal":      abortController.Get("signal"),
			}))
		},
		func(e any) {
			err = fmt.Errorf("%v", e)
		},
	)
	if err != nil {
		return false, err
	}
	resp, err := Await(promise)
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	if err != nil {
		return false, err
	}
	if resp.Get("type").String() == "opaqueredirect" {
		return true, nil
	}
	status := resp.Get("status").Int()
	return status == 401 || status == 403, nil
}

// CheckAuthRequired returns true if rawURL (ws, wss, http, or https) responds
// with an authentication failure.
func CheckAuthRequired(ctx context.Context, rawURL string) bool {
	httpURL, err := toHTTPURL(rawURL)
	if err != nil {
		return false
	}
	authReq, err := checkAuthStatus(ctx, httpURL)
	return err == nil && authReq
}

func wrapPopupErr(err error) error {
	if err == nil || errors.Is(err, context.Canceled) {
		return err
	}
	return fmt.Errorf("%w: %w", ErrAuthRequired, err)
}

// LoginPopup opens a popup window to authenticate the user for rawURL and
// waits until the popup is closed, either by the ./?sso=1 page after a
// same-origin login or by the user, or until ctx is canceled. The caller
// retries the failed operation when LoginPopup returns nil. It fails if the
// browser blocks the popup. Progress messages are written to log, which may
// be nil. Errors other than cancellation are wrapped in ErrAuthRequired.
func LoginPopup(ctx context.Context, rawURL string, log io.Writer) error {
	httpURL, err := toHTTPURL(rawURL)
	if err != nil {
		return wrapPopupErr(err)
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultPopupTimeout)
		defer cancel()
	}
	logf := func(format string, args ...any) {
		if log != nil {
			fmt.Fprintf(log, format, args...)
		}
	}
	win := js.Global().Get("window")

	// A same-origin login ends on ./?sso=1, which announces the completed
	// login on a BroadcastChannel and closes itself (see main.mjs). The
	// announcement is faster than noticing that the popup closed.
	popupURL := httpURL
	loginDone := make(chan struct{}, 1)
	if IsSameOrigin(httpURL) {
		TryCatch(
			func() {
				popupURL = URL.New("./?sso=1", Document.Get("location").Get("href")).Get("href").String()
			},
			func(any) {},
		)
		bc := js.Global().Get("BroadcastChannel").New("sshterm_sso")
		bcCb := js.FuncOf(func(this js.Value, args []js.Value) any {
			if len(args) > 0 && args[0].Get("data").String() == "authenticated" {
				select {
				case loginDone <- struct{}{}:
				default:
				}
			}
			return nil
		})
		bc.Set("onmessage", bcCb)
		defer func() {
			bc.Call("close")
			bcCb.Release()
		}()
	}

	// The window name makes concurrent logins, e.g. from several terminal
	// tabs, share one popup.
	var popup js.Value
	TryCatch(
		func() { popup = win.Call("open", popupURL, "sshterm_sso", popupFeatures) },
		func(any) {},
	)
	if !popup.Truthy() {
		return fmt.Errorf("%w: the browser blocked the login popup; allow popups for this site and try again", ErrAuthRequired)
	}
	defer func() {
		TryCatch(func() { popup.Call("close") }, func(any) {})
	}()
	logf("\nAuthentication required. Waiting for login... (Press Ctrl-C to abort)\n")

	ticker := time.NewTicker(popupCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return wrapPopupErr(ctx.Err())
		case <-loginDone:
			return nil
		case <-ticker.C:
			if popup.Get("closed").Truthy() {
				return nil
			}
		}
	}
}
