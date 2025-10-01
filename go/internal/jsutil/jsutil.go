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
	"fmt"
	"io"
	"regexp"
	"syscall/js"
)

var (
	Uint8Array = js.Global().Get("Uint8Array")
	Error      = js.Global().Get("Error")
	Array      = js.Global().Get("Array")
	Object     = js.Global().Get("Object")
	Promise    = js.Global().Get("Promise")
	Blob       = js.Global().Get("Blob")
	URL        = js.Global().Get("URL")
	Document   = js.Global().Get("document")
	Body       = Document.Get("body")
)

func TryCatch(try func(), catch func(any)) {
	defer func() {
		if e := recover(); e != nil {
			catch(e)
		}
	}()
	try()
}

func NewObject(m map[string]any) js.Value {
	obj := Object.New()
	for k, v := range m {
		obj.Set(k, v)
	}
	return obj
}

func NewArray(a []any) js.Value {
	arr := Array.New()
	for _, v := range a {
		arr.Call("push", v)
	}
	return arr
}

func NewResolvedPromise(v any) js.Value {
	return Promise.Call("resolve", v)
}

func NewPromise(f func() (any, error)) js.Value {
	return Promise.New(js.FuncOf(
		func(this js.Value, args []js.Value) any {
			resolve := args[0]
			reject := args[1]
			go func() {
				v, err := f()
				if err != nil {
					reject.Invoke(Error.New(err.Error()))
					return
				}
				resolve.Invoke(v)
			}()
			return nil
		},
	))
}

func Await(p js.Value) (js.Value, error) {
	if then := p.Get("then"); then.IsUndefined() || then.Type() != js.TypeFunction {
		return p, nil
	}
	v := make(chan js.Value, 1)
	e := make(chan error, 1)
	resolve := func(this js.Value, args []js.Value) any {
		v <- args[0]
		return nil
	}
	reject := func(this js.Value, args []js.Value) any {
		e <- fmt.Errorf("%v", js.Global().Get("JSON").Call("stringify", args[0]).String())
		//e <- fmt.Errorf("%v", args[0])
		return nil
	}
	p.Call("then", js.FuncOf(resolve)).
		Call("catch", js.FuncOf(reject))
	select {
	case value := <-v:
		return value, nil
	case err := <-e:
		return js.Value{}, err
	}
}

func Uint8ArrayFromBytes(in []byte) js.Value {
	out := Uint8Array.New(js.ValueOf(len(in)))
	js.CopyBytesToJS(out, in)
	return out
}

func Uint8ArrayToBytes(v js.Value) []byte {
	buf := make([]byte, v.Length())
	js.CopyBytesToGo(buf, v)
	return buf
}

type ImportedFile struct {
	Name    string
	Type    string
	Size    int64
	Content io.ReadCloser
}

func (f *ImportedFile) ReadAll() ([]byte, error) {
	b, err := io.ReadAll(f.Content)
	if err != nil {
		f.Content.Close()
	}
	return b, err
}

func AcceptFileDrop(event js.Value) []ImportedFile {
	files := event.Get("dataTransfer").Get("files")
	length := files.Length()
	out := make([]ImportedFile, 0, length)
	for i := 0; i < length; i++ {
		f := files.Index(i)
		out = append(out, ImportedFile{
			Name:    f.Get("name").String(),
			Type:    f.Get("type").String(),
			Size:    int64(f.Get("size").Float()),
			Content: NewStreamReader(f.Call("stream")),
		})
	}
	return out
}

func ImportFiles(accept string, multiple bool) []ImportedFile {
	input := Document.Call("createElement", "input")
	input.Set("type", "file")
	input.Set("name", "files")
	if multiple {
		input.Set("multiple", "true")
	}
	if accept != "" {
		input.Set("accept", accept)
	}

	ch := make(chan ImportedFile)
	input.Call("addEventListener", "cancel", js.FuncOf(func(this js.Value, args []js.Value) any {
		close(ch)
		return nil
	}))
	input.Call("addEventListener", "change", js.FuncOf(func(this js.Value, args []js.Value) any {
		event := args[0]
		files := event.Get("target").Get("files")
		length := files.Length()
		for i := 0; i < length; i++ {
			f := files.Index(i)
			ch <- ImportedFile{
				Name:    f.Get("name").String(),
				Type:    f.Get("type").String(),
				Size:    int64(f.Get("size").Float()),
				Content: NewStreamReader(f.Call("stream")),
			}
		}
		close(ch)
		return nil
	}))
	Body.Call("appendChild", input)
	input.Call("click")
	Body.Call("removeChild", input)

	var out []ImportedFile
	for f := range ch {
		out = append(out, f)
	}
	return out
}

func ExportFile(data []byte, filename, mimeType string) error {
	blobOpts := Object.New()
	blobOpts.Set("type", mimeType)
	blob := Blob.New(Array.New(Uint8ArrayFromBytes(data)), blobOpts)

	anchor := Document.Call("createElement", "a")
	anchor.Set("href", URL.Call("createObjectURL", blob))
	anchor.Call("setAttribute", "download", js.ValueOf(filename))
	Body.Call("appendChild", anchor)
	anchor.Call("click")
	Body.Call("removeChild", anchor)
	return nil
}

func TLSProxySID() string {
	re := regexp.MustCompile(`__tlsproxySid=([^;]*)(;|$)`)
	m := re.FindStringSubmatch(Document.Get("cookie").String())
	if len(m) > 1 {
		return m[1]
	}
	return ""
}

func Hostname() string {
	return Document.Get("location").Get("hostname").String()
}
