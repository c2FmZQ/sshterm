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

package jsutil

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"sync"
	"sync/atomic"
	"syscall/js"
	"time"
)

var (
	ReadableStream = js.Global().Get("ReadableStream")
)

func NewStreamReader(stream js.Value) *StreamReader {
	return &StreamReader{
		reader: stream.Call("getReader"),
	}
}

var _ io.ReadCloser = (*StreamReader)(nil)

type StreamReader struct {
	reader js.Value // ReadableStreamDefaultReader
	buf    []byte
}

func (r *StreamReader) Read(b []byte) (int, error) {
	if len(r.buf) == 0 {
		chunk, err := Await(r.reader.Call("read"))
		if err != nil {
			return 0, err
		}
		if chunk.Get("done").Bool() {
			return 0, io.EOF
		}
		r.buf = Uint8ArrayToBytes(chunk.Get("value"))
	}
	n := copy(b, r.buf)
	r.buf = r.buf[n:]
	return n, nil
}

func (r *StreamReader) Close() error {
	Await(r.reader.Call("cancel"))
	return nil
}

func NewReadableStream(r io.Reader, done chan<- error, progress func(int64)) js.Value {
	cancelCh := make(chan struct{})
	allDone := func(err error) {
		select {
		case done <- err:
		default:
		}
	}
	offset := new(atomic.Int64)
	s := Object.New()
	s.Set("pull", js.FuncOf(func(this js.Value, args []js.Value) any {
		return NewPromise(func() (any, error) {
			controller := args[0]
			size := 16384
			if ds := controller.Get("desiredSize"); !ds.IsUndefined() {
				size = max(size, ds.Int())
			}
			buf := make([]byte, size)
			n, err := r.Read(buf)
			if n > 0 {
				select {
				case <-cancelCh:
					return nil, nil
				default:
					controller.Call("enqueue", Uint8ArrayFromBytes(buf[:n]))
					offset.Add(int64(n))
					if progress != nil {
						progress(offset.Load())
					}
				}
			}
			if err == io.EOF {
				controller.Call("close")
				allDone(nil)
			} else if err != nil {
				controller.Call("error", Error.New(err.Error()))
				allDone(err)
			}
			return nil, nil
		})
	}))
	s.Set("cancel", js.FuncOf(func(this js.Value, args []js.Value) any {
		close(cancelCh)
		allDone(errors.New("canceled"))
		return nil
	}))
	return ReadableStream.New(s)
}

func NewStreamHelper() *StreamHelper {
	container := js.Global().Get("navigator").Get("serviceWorker")
	if !container.Truthy() {
		return nil
	}
	registration, err := Await(container.Call("getRegistration"))
	if err != nil || !registration.Truthy() {
		registration, err = Await(container.Call("register", "stream-helper.js"))
	}
	if err != nil || !registration.Truthy() {
		return nil
	}
	// The stream requests must go to this service worker. Until it
	// controls the page, they go to the network instead.
	if !waitForController(container, registration, 10*time.Second) {
		js.Global().Get("console").Call("error", "service worker is not controlling the page")
		return nil
	}

	h := &StreamHelper{
		streams: make(map[string]stream),
	}

	container.Set("onmessage", js.FuncOf(
		func(this js.Value, args []js.Value) (ret any) {
			event := args[0]
			sid := event.Get("data").Get("streamId")
			if !sid.Truthy() {
				return nil
			}
			id := sid.String()
			h.mu.Lock()
			defer h.mu.Unlock()

			s, exists := h.streams[id]
			if !exists {
				event.Get("source").Call("postMessage",
					NewObject(map[string]any{
						"streamId": id},
					),
				)
				return nil
			}
			delete(h.streams, id)
			close(s.started)

			TryCatch(
				// try
				func() {
					rs := NewReadableStream(s.reader, s.done, s.progress)
					event.Get("source").Call("postMessage",
						NewObject(map[string]any{
							"streamId": id,
							"body":     rs,
							"options": NewObject(map[string]any{
								"status":     "200",
								"statusText": "OK",
								"headers":    NewObject(s.headers),
							}),
						}),
						Array.New(rs),
					)
				},
				// catch
				func(e any) {
					err, ok := e.(error)
					if !ok {
						err = fmt.Errorf("panic: %T %v", e, e)
					}
					s.done <- err
					js.Global().Get("console").Call("error", "stream helper failed:", err.Error())
					event.Get("source").Call("postMessage",
						NewObject(map[string]any{
							"streamId": id,
							"body":     "Internal Server Error",
							"options": NewObject(map[string]any{
								"status":     "500",
								"statusText": "Internal Server Error",
								"headers": NewObject(map[string]any{
									"Content-Type": "text/plain",
								}),
							}),
						}),
					)
				},
			)
			return nil
		},
	))

	return h
}

// waitForController waits until the registration's active service worker
// controls the page. A newly registered service worker claims the page when it
// is activated.
func waitForController(container, registration js.Value, timeout time.Duration) bool {
	ch := make(chan struct{}, 1)
	notify := js.FuncOf(func(this js.Value, args []js.Value) any {
		select {
		case ch <- struct{}{}:
		default:
		}
		return nil
	})
	defer notify.Release()
	container.Call("addEventListener", "controllerchange", notify)
	defer container.Call("removeEventListener", "controllerchange", notify)

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		if c := container.Get("controller"); c.Truthy() && c.Equal(registration.Get("active")) {
			return true
		}
		select {
		case <-ch:
		case <-timer.C:
			return false
		}
	}
}

func UnregisterServiceWorker() {
	if c := js.Global().Get("navigator").Get("serviceWorker"); c.Truthy() {
		if r, err := Await(c.Call("getRegistration")); err == nil && r.Truthy() {
			r.Call("unregister")
		}
	}
}

type StreamHelper struct {
	mu      sync.Mutex
	streams map[string]stream
}

type stream struct {
	reader   io.Reader
	headers  map[string]any
	done     chan error
	started  chan struct{}
	progress func(int64)
}

func (h *StreamHelper) addStream(rc io.Reader, headers map[string]any, progress func(int64)) (string, <-chan struct{}, <-chan error, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	b := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", nil, nil, err
	}
	id := hex.EncodeToString(b)
	s := stream{
		reader:   rc,
		headers:  headers,
		done:     make(chan error, 1),
		started:  make(chan struct{}),
		progress: progress,
	}
	h.streams[id] = s
	return id, s.started, s.done, nil
}

// removeStream removes a stream that hasn't started. It returns false if the
// stream already started.
func (h *StreamHelper) removeStream(id string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	_, exists := h.streams[id]
	delete(h.streams, id)
	return exists
}

func (h *StreamHelper) Download(rc io.ReadCloser, filename string, size int64, progress func(int64), hook func(string) error) (err error) {
	defer rc.Close()
	if h == nil {
		return errors.New("streaming download unavailable")
	}
	hdr := map[string]any{
		// FormatMediaType uses RFC 2231 encoding for non-ASCII names.
		// Header values must be ASCII.
		"Content-Disposition": mime.FormatMediaType("attachment", map[string]string{"filename": filename}),
		"Cache-Control":       "no-store",
		"Content-Type":        "application/octet-stream",
	}
	if size > 0 {
		hdr["Content-Length"] = fmt.Sprintf("%d", size)
	}
	id, started, done, err := h.addStream(rc, hdr, progress)
	if err != nil {
		return err
	}
	url := "./stream/" + id
	if hook != nil {
		if err := hook(url); err != nil {
			h.removeStream(id)
			return err
		}
	} else {
		anchor := Document.Call("createElement", "a")
		anchor.Set("href", url)
		Body.Call("appendChild", anchor)
		anchor.Call("click")
		Body.Call("removeChild", anchor)
	}
	// Don't wait forever if the request never reaches the service worker.
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	select {
	case <-started:
	case <-timer.C:
		if h.removeStream(id) {
			return errors.New("download did not start")
		}
	}
	return <-done
}
