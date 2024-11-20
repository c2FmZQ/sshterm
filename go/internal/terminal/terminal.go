//go:build wasm

package terminal

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"syscall/js"

	"golang.org/x/term"

	"github.com/c2FmZQ/sshterm/internal/jsutil"
)

var ErrClosed = errors.New("terminal is closed")

func New(ctx context.Context, t js.Value) *Terminal {
	tt := &Terminal{
		ctx:      ctx,
		xt:       t,
		dataCh:   make(chan []byte, 100),
		resizeCh: make(chan resizeEvent, 10),
		closeCh:  make(chan struct{}),
	}
	tt.vt = term.NewTerminal(tt, "")
	tt.vt.SetBracketedPasteMode(true)
	tt.setDefaultPrompt()

	disp := t.Call("onData", js.FuncOf(func(this js.Value, args []js.Value) any {
		select {
		case <-tt.ctx.Done():
			return tt.Close()
		case <-tt.closeCh:
		case tt.dataCh <- []byte(args[0].String()):
		}
		return nil
	}))
	tt.dispose = append(tt.dispose, disp)
	disp = t.Call("onResize", js.FuncOf(func(this js.Value, args []js.Value) any {
		event := args[0]
		select {
		case <-tt.ctx.Done():
		case <-tt.closeCh:
		case tt.resizeCh <- resizeEvent{cols: event.Get("cols").Int(), rows: event.Get("rows").Int()}:
		}
		return nil
	}))
	tt.dispose = append(tt.dispose, disp)

	tt.vt.SetSize(tt.Cols(), tt.Rows())
	go func() {
		for resize := range tt.resizeCh {
			tt.vt.SetSize(resize.cols, resize.rows)
			if tt.onResize != nil {
				tt.onResize(resize.rows, resize.cols)
			}
		}
	}()
	return tt
}

var _ io.Reader = (*Terminal)(nil)
var _ io.Writer = (*Terminal)(nil)
var _ io.Closer = (*Terminal)(nil)

type Terminal struct {
	ctx      context.Context
	xt       js.Value // xterm.Terminal
	vt       *term.Terminal
	dataCh   chan []byte
	resizeCh chan resizeEvent
	closeCh  chan struct{}
	onResize func(h, w int) error
	r        []byte

	dispose []js.Value
}

type resizeEvent struct {
	cols int
	rows int
}

func (t *Terminal) setDefaultPrompt() {
	t.vt.SetPrompt(string(t.vt.Escape.Green) + "sshterm> " + string(t.vt.Escape.Reset))
}

func (t *Terminal) OnResize(f func(h, w int) error) {
	t.onResize = f
}

func (t *Terminal) isClosed() bool {
	select {
	case <-t.closeCh:
		return true
	default:
		return false
	}
}

func (t *Terminal) Close() error {
	for _, d := range t.dispose {
		d.Call("dispose")
	}
	t.dispose = nil
	if !t.isClosed() {
		close(t.resizeCh)
		close(t.closeCh)
	}
	return nil
}

func (t *Terminal) Read(b []byte) (int, error) {
	if t.isClosed() {
		return 0, ErrClosed
	}
	if len(t.r) == 0 {
		select {
		case <-t.ctx.Done():
			return 0, t.ctx.Err()
		case <-t.closeCh:
			return 0, ErrClosed
		case t.r = <-t.dataCh:
		}
	}
	n := copy(b, t.r)
	t.r = t.r[n:]
	return n, nil
}

func (t *Terminal) Write(b []byte) (int, error) {
	if t.isClosed() {
		return 0, ErrClosed
	}
	t.xt.Call("write", jsutil.Uint8ArrayFromBytes(b))
	return len(b), nil
}

func (t *Terminal) Print(s string) {
	t.xt.Call("write", js.ValueOf(s))
}

func (t *Terminal) Printf(f string, args ...any) {
	t.xt.Call("write", js.ValueOf(fmt.Sprintf(f, args...)))
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
	t.xt.Call("focus")
}

func (t *Terminal) Clear() {
	t.xt.Call("clear")
}

func (t *Terminal) Rows() int {
	return t.xt.Get("rows").Int()
}

func (t *Terminal) Cols() int {
	return t.xt.Get("cols").Int()
}

func (t *Terminal) Prompt(prompt string) (line string, err error) {
	t.vt.SetPrompt(prompt)
	line, err = t.ReadLine()
	t.setDefaultPrompt()
	return
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
