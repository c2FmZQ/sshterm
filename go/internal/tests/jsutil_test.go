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
