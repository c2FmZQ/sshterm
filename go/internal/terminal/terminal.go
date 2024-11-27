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

package terminal

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"syscall/js"

	"golang.org/x/term"

	"github.com/c2FmZQ/sshterm/internal/jsutil"
)

var ErrClosed = errors.New("terminal is closed")

func New(ctx context.Context, t js.Value) *Terminal {
	tt := &Terminal{
		tw: &termWrapper{
			ctx:      ctx,
			xt:       t,
			dataCh:   make(chan []byte, 100),
			closeCh:  make(chan struct{}),
			resizeCh: make(chan resizeEvent, 10),
			keyCh:    make(chan string, 10),
		},
	}
	tt.vt = term.NewTerminal(tt.tw, "")
	tt.setDefaultPrompt()

	disp := t.Call("onKey", js.FuncOf(func(this js.Value, args []js.Value) any {
		event := args[0]
		select {
		case <-tt.tw.ctx.Done():
		case <-tt.tw.closeCh:
		case tt.tw.keyCh <- event.Get("key").String():
		default:
			fmt.Fprintf(os.Stderr, "onkey buffer full\n")
			return nil
		}
		return nil
	}))
	tt.tw.dispose = append(tt.tw.dispose, disp)
	disp = t.Call("onBell", js.FuncOf(func(this js.Value, args []js.Value) any {
		fmt.Fprintf(os.Stderr, "onBell\n")
		return nil
	}))
	tt.tw.dispose = append(tt.tw.dispose, disp)
	disp = t.Call("onData", js.FuncOf(func(this js.Value, args []js.Value) any {
		select {
		case <-tt.tw.ctx.Done():
			return tt.tw.Close()
		case <-tt.tw.closeCh:
		case tt.tw.dataCh <- []byte(args[0].String()):
		default:
			fmt.Fprintf(os.Stderr, "input buffer full\n")
			return nil
		}
		return nil
	}))
	tt.tw.dispose = append(tt.tw.dispose, disp)
	disp = t.Call("onResize", js.FuncOf(func(this js.Value, args []js.Value) any {
		event := args[0]
		select {
		case <-tt.tw.ctx.Done():
		case <-tt.tw.closeCh:
		case tt.tw.resizeCh <- resizeEvent{cols: event.Get("cols").Int(), rows: event.Get("rows").Int()}:
		default:
			fmt.Fprintf(os.Stderr, "onresize buffer full\n")
			return nil
		}
		return nil
	}))
	tt.tw.dispose = append(tt.tw.dispose, disp)

	tt.vt.SetSize(tt.Cols(), tt.Rows())
	go func() {
		for resize := range tt.tw.resizeCh {
			tt.tw.mu.Lock()
			tt.vt.SetSize(resize.cols, resize.rows)
			if tt.tw.onResize != nil {
				select {
				case <-tt.tw.onResizeCtx.Done():
				default:
					tt.tw.onResize(resize.rows, resize.cols)
				}
			}
			tt.tw.mu.Unlock()
		}
	}()
	go func() {
		for key := range tt.tw.keyCh {
			tt.tw.mu.Lock()
			if tt.tw.onKey != nil {
				select {
				case <-tt.tw.onKeyCtx.Done():
				default:
					tt.tw.onKey(key)
				}
			}
			tt.tw.mu.Unlock()
		}
	}()
	return tt
}

var _ io.Reader = (*Terminal)(nil)
var _ io.Writer = (*Terminal)(nil)
var _ io.Closer = (*Terminal)(nil)

type Terminal struct {
	tw *termWrapper
	vt *term.Terminal
}

var _ io.Reader = (*termWrapper)(nil)
var _ io.Writer = (*termWrapper)(nil)
var _ io.Closer = (*termWrapper)(nil)

type termWrapper struct {
	ctx      context.Context
	xt       js.Value // xterm.Terminal
	dataCh   chan []byte
	closeCh  chan struct{}
	resizeCh chan resizeEvent
	keyCh    chan string
	dispose  []js.Value
	r        []byte

	mu          sync.Mutex
	onResizeCtx context.Context
	onResize    func(h, w int) error
	onKeyCtx    context.Context
	onKey       func(k string) error
}

func (t *termWrapper) isClosed() bool {
	select {
	case <-t.closeCh:
		return true
	default:
		return false
	}
}

func (t *termWrapper) Close() error {
	for _, d := range t.dispose {
		d.Call("dispose")
	}
	t.dispose = nil
	if !t.isClosed() {
		close(t.resizeCh)
		close(t.keyCh)
		close(t.closeCh)
	}
	return nil
}

func (t *termWrapper) readChunk() error {
	select {
	case <-t.ctx.Done():
		return t.ctx.Err()
	case b := <-t.dataCh:
		t.r = append(t.r, b...)
		return nil
	case <-t.closeCh:
		return io.EOF
	}
}

func (t *termWrapper) Read(b []byte) (int, error) {
	for len(t.r) == 0 || (len(b) > len(t.r) && len(t.dataCh) > 0) {
		t.readChunk()
	}
	n := copy(b, t.r)
	t.r = t.r[n:]
	return n, nil
}

func (t *termWrapper) Write(b []byte) (int, error) {
	if t.isClosed() {
		return 0, ErrClosed
	}
	ch := make(chan struct{})
	t.xt.Call("write", jsutil.Uint8ArrayFromBytes(b), js.FuncOf(func(this js.Value, args []js.Value) any {
		close(ch)
		return nil
	}))
	<-ch
	return len(b), nil
}

type resizeEvent struct {
	cols int
	rows int
}

func (t *Terminal) setDefaultPrompt() {
	t.vt.SetPrompt(string(t.vt.Escape.Green) + "sshterm> " + string(t.vt.Escape.Reset))
}

func (t *Terminal) OnResize(ctx context.Context, f func(h, w int) error) {
	t.tw.mu.Lock()
	defer t.tw.mu.Unlock()
	t.tw.onResizeCtx = ctx
	t.tw.onResize = f
}

func (t *Terminal) OnKey(ctx context.Context, f func(string) error) {
	t.tw.mu.Lock()
	defer t.tw.mu.Unlock()
	t.tw.onKeyCtx = ctx
	t.tw.onKey = f
}

func (t *Terminal) Close() error {
	return t.tw.Close()
}

func (t *Terminal) Read(b []byte) (int, error) {
	return t.tw.Read(b)
}

func (t *Terminal) Write(b []byte) (int, error) {
	return t.vt.Write(b)
}

func (t *Terminal) Print(s string) {
	fmt.Fprint(t, s)
}

func (t *Terminal) Printf(f string, args ...any) {
	fmt.Fprintf(t, f, args...)
}

func (t *Terminal) Errorf(f string, args ...any) {
	s := fmt.Sprintf(f, args...)
	t.Printf("%s%s%s\n", t.vt.Escape.Red, s, t.vt.Escape.Reset)
}

func (t *Terminal) Greenf(f string, args ...any) {
	s := fmt.Sprintf(f, args...)
	t.Printf("%s%s%s", t.vt.Escape.Green, s, t.vt.Escape.Reset)
}

func (t *Terminal) Focus() {
	t.tw.xt.Call("focus")
}

func (t *Terminal) Clear() {
	t.tw.xt.Call("clear")
}

func (t *Terminal) Rows() int {
	return t.tw.xt.Get("rows").Int()
}

func (t *Terminal) Cols() int {
	return t.tw.xt.Get("cols").Int()
}

func (t *Terminal) Prompt(prompt string) (line string, err error) {
	t.Print(prompt)
	t.vt.SetPrompt("")
	line, err = t.ReadLine()
	t.setDefaultPrompt()
	return
}

func (t *Terminal) Confirm(prompt string, defaultYes bool) bool {
	if defaultYes {
		prompt += " [Y/n] "
	} else {
		prompt += " [y/N] "
	}
	line, err := t.Prompt(prompt)
	if err != nil {
		return false
	}
	switch strings.ToUpper(line) {
	case "Y", "YES":
		return true
	case "N", "NO":
		return false
	default:
		return defaultYes
	}
}

func (t *Terminal) ReadLine() (line string, err error) {
	line, err = t.vt.ReadLine()
	line = strings.TrimRight(line, "\r\n")
	return
}

func (t *Terminal) ReadPassword(prompt string) (line string, err error) {
	line, err = t.vt.ReadPassword(prompt)
	line = strings.TrimRight(line, "\r\n")
	return
}
