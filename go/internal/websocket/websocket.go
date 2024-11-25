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

package websocket

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"syscall/js"
	"time"

	"github.com/c2FmZQ/sshterm/internal/jsutil"
)

var (
	ErrClosed         = errors.New("websocket is closed")
	ErrClosedByServer = errors.New("websocket was closed by server")
)

func New(ctx context.Context, url string, log io.Writer) (*WebSocket, error) {
	jsWS := js.Global().Get("WebSocket").New(url)
	ws := &WebSocket{
		ctx:     ctx,
		ws:      jsWS,
		log:     log,
		ch:      make(chan js.Value, 100),
		closeCh: make(chan struct{}),
	}
	errCh := make(chan error)
	jsWS.Call("addEventListener", "open", js.FuncOf(func(this js.Value, args []js.Value) any {
		select {
		case errCh <- nil:
		default:
		}
		return nil
	}))
	jsWS.Call("addEventListener", "error", js.FuncOf(func(this js.Value, args []js.Value) any {
		select {
		case errCh <- fmt.Errorf("websocket error"):
		default:
		}
		ws.Close()
		return nil
	}))
	jsWS.Call("addEventListener", "close", js.FuncOf(func(this js.Value, args []js.Value) any {
		if !ws.isClosed() {
			ws.err = ErrClosedByServer
		}
		ws.Close()
		return nil
	}))
	jsWS.Call("addEventListener", "message", js.FuncOf(func(this js.Value, args []js.Value) any {
		event := args[0]
		select {
		case <-ws.ctx.Done():
			return ws.Close()
		case ws.ch <- event.Get("data").Call("arrayBuffer"):
		}
		return nil
	}))
	return ws, <-errCh
}

var _ net.Conn = (*WebSocket)(nil)

type WebSocket struct {
	ctx     context.Context
	ws      js.Value // WebSocket
	log     io.Writer
	ch      chan js.Value
	r       []byte
	closeCh chan struct{}
	err     error
}

func (ws *WebSocket) isClosed() bool {
	select {
	case <-ws.closeCh:
		return true
	default:
		return false
	}

}

func (ws *WebSocket) Close() error {
	if !ws.isClosed() {
		if ws.err == nil {
			ws.err = ErrClosed
		}
		close(ws.closeCh)
		ws.ws.Call("close")
	}
	return nil
}

func (ws *WebSocket) readChunk() error {
	select {
	case <-ws.ctx.Done():
		return ws.ctx.Err()
	case p := <-ws.ch:
		data, err := jsutil.Await(p)
		if err != nil {
			return err
		}
		vv := jsutil.Uint8Array.New(data)
		n := len(ws.r)
		ws.r = append(ws.r, make([]byte, vv.Length())...)
		js.CopyBytesToGo(ws.r[n:], vv)
		return nil
	case <-ws.closeCh:
		return ws.err
	}
}

func (ws *WebSocket) Read(b []byte) (int, error) {
	var err error
	for len(ws.r) == 0 || (len(ws.r) < len(b) && len(ws.ch) > 0) {
		if err = ws.readChunk(); err != nil {
			break
		}
	}
	n := copy(b, ws.r)
	ws.r = ws.r[n:]
	return n, err
}

func (ws *WebSocket) Write(b []byte) (int, error) {
	if ws.isClosed() {
		return 0, ws.err
	}
	n := len(b)
	for len(b) > 0 {
		sz := min(len(b), 4096)
		ws.ws.Call("send", jsutil.Uint8ArrayFromBytes(b[:sz]))
		b = b[sz:]
	}
	return n, nil
}

func (ws *WebSocket) LocalAddr() net.Addr {
	return &net.TCPAddr{}
}

func (ws *WebSocket) RemoteAddr() net.Addr {
	return &net.TCPAddr{}
}

func (ws *WebSocket) SetDeadline(t time.Time) error {
	return nil
}

func (ws *WebSocket) SetReadDeadline(t time.Time) error {
	return nil
}

func (ws *WebSocket) SetWriteDeadline(t time.Time) error {
	return nil
}
