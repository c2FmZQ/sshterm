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
	"fmt"
	"io"
	"sync"
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

func NewReadableStream(r io.ReadCloser) js.Value {
	s := Object.New()
	s.Set("pull", js.FuncOf(func(this js.Value, args []js.Value) any {
		controller := args[0]
		size := 4096
		if ds := controller.Get("desiredSize"); !ds.IsUndefined() {
			size = ds.Int()
		}
		buf := make([]byte, size)
		n, err := r.Read(buf)
		if n > 0 {
			controller.Call("enqueue", Uint8ArrayFromBytes(buf[:n]))
		}
		if err == io.EOF {
			controller.Call("close")
			r.Close()
		} else if err != nil {
			controller.Call("error", Error.New(err.Error()))
			r.Close()
		}
		return nil
	}))
	s.Set("cancel", js.FuncOf(func(this js.Value, args []js.Value) any {
		r.Close()
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
		streams: make(map[string]Stream),
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
				for k, v := range s.Headers {
					hdr.Set(k, v)
				}
				msg := Object.New()
				msg.Set("streamId", n)
				msg.Set("headers", hdr)
				rs := NewReadableStream(s.Reader)
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
	streams map[string]Stream
}

type Stream struct {
	Reader  io.ReadCloser
	Headers map[string]string
}

func (h *StreamHelper) AddStream(rc io.ReadCloser, headers map[string]string) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	b := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	id := hex.EncodeToString(b)
	h.streams[id] = Stream{
		Reader:  rc,
		Headers: headers,
	}
	return id, nil
}

func (h *StreamHelper) StartStreamDownload(rc io.ReadCloser, filename, mimeType string) error {
	id, err := h.AddStream(rc, map[string]string{
		"Content-Disposition": fmt.Sprintf("attachment; filename=%q", filename),
		"Content-Type":        mimeType,
		"Cache-Control":       "no-store",
	})
	if err != nil {
		return err
	}
	anchor := Document.Call("createElement", "a")
	anchor.Set("href", "./stream/"+id)
	Body.Call("appendChild", anchor)
	anchor.Call("click")
	Body.Call("removeChild", anchor)
	return nil
}
