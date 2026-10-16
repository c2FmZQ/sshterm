// MIT License
//
// Copyright (c) 2025 TTBT Enterprises LLC
// Copyright (c) 2025 Robin Thellend <rthellend@rthellend.com>
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

//go:build x11 && wasm

package x11

import (
	"flag"
	"net/url"
	"os"
	"syscall/js"
	"testing"

	"github.com/c2FmZQ/sshterm/internal/jsutil"
)

var (
	testingM *testing.M
	done     chan struct{}
)

func TestMain(m *testing.M) {
	os.Stdout = os.Stderr
	flag.Parse()
	flag.Set("test.failfast", "true")
	flag.Set("test.v", "true")
	loc, err := url.Parse(js.Global().Get("location").Get("href").String())
	if err != nil {
		panic("location.href:" + err.Error())
	}
	if run := loc.Query().Get("run"); run != "" {
		flag.Set("test.run", run)
	}
	sshApp := js.Global().Get("sshApp")
	if sshApp.Type() != js.TypeObject {
		panic("sshApp object not found")
	}
	ready := sshApp.Get("sshIsReady")
	if ready.Type() != js.TypeFunction {
		panic("sshApp.sshIsReady not found")
	}
	sshApp.Set("start", js.FuncOf(start))
	done = make(chan struct{})
	testingM = m
	ready.Invoke()
	<-done
}

func start(this js.Value, args []js.Value) any {
	return jsutil.NewPromise(func() (any, error) {
		return testingM.Run(), nil
	})
}
