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

func (ws *WebSocket) Read(b []byte) (int, error) {
	if ws.isClosed() {
		return 0, ws.err
	}
	if len(ws.r) == 0 {
		select {
		case <-ws.ctx.Done():
			return 0, ws.ctx.Err()
		case <-ws.closeCh:
			return 0, ws.err
		case p, ok := <-ws.ch:
			if !ok {
				return 0, ws.err
			}
			data, err := jsutil.Await(p)
			if err != nil {
				return 0, err
			}
			vv := jsutil.Uint8Array.New(data)
			sz := vv.Length()
			ws.r = make([]byte, sz)
			js.CopyBytesToGo(ws.r, vv)
		}
	}
	n := copy(b, ws.r)
	ws.r = ws.r[n:]
	return n, nil
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
