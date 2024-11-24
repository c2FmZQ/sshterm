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
	"sync"
	"sync/atomic"
	"syscall/js"
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
	if r, err := Await(container.Call("getRegistration")); err != nil || !r.Truthy() {
		return nil
	}

	h := &StreamHelper{
		streams: make(map[string]stream),
	}

	container.Set("onmessage", js.FuncOf(
		func(this js.Value, args []js.Value) any {
			h.mu.Lock()
			defer h.mu.Unlock()
			event := args[0]
			sid := event.Get("data").Get("streamId")
			if !sid.Truthy() {
				return nil
			}
			n := sid.String()
			if s, exists := h.streams[n]; exists {
				hdr := Object.New()
				for k, v := range s.headers {
					hdr.Set(k, v)
				}
				msg := Object.New()
				msg.Set("streamId", n)
				msg.Set("headers", hdr)
				rs := NewReadableStream(s.reader, s.done, s.progress)
				msg.Set("readableStream", rs)
				event.Get("source").Call("postMessage", msg, Array.New(rs))
				delete(h.streams, n)
			} else {
				msg := Object.New()
				msg.Set("streamId", n)
				event.Get("source").Call("postMessage", msg)
			}
			return nil
		},
	))

	return h
}

type StreamHelper struct {
	mu      sync.Mutex
	streams map[string]stream
}

type stream struct {
	reader   io.Reader
	headers  map[string]string
	done     chan error
	progress func(int64)
}

func (h *StreamHelper) addStream(rc io.Reader, headers map[string]string, progress func(int64)) (string, <-chan error, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	b := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", nil, err
	}
	id := hex.EncodeToString(b)
	ch := make(chan error, 1)
	h.streams[id] = stream{
		reader:   rc,
		headers:  headers,
		done:     ch,
		progress: progress,
	}
	return id, ch, nil
}

func (h *StreamHelper) Download(rc io.ReadCloser, filename string, size int64, progress func(int64)) (err error) {
	defer rc.Close()
	if h == nil {
		return errors.New("streaming download unavailable")
	}
	hdr := map[string]string{
		"Content-Disposition": fmt.Sprintf("attachment; filename=%q", filename),
		"Cache-Control":       "no-store",
		"Content-Type":        "application/octet-stream",
	}
	if size > 0 {
		hdr["Content-Length"] = fmt.Sprintf("%d", size)
	}
	id, done, err := h.addStream(rc, hdr, progress)
	if err != nil {
		return err
	}
	anchor := Document.Call("createElement", "a")
	anchor.Set("href", "./stream/"+id)
	Body.Call("appendChild", anchor)
	anchor.Call("click")
	Body.Call("removeChild", anchor)
	return <-done
}
