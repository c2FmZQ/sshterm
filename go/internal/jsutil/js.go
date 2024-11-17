//go:build wasm

package jsutil

import (
	"fmt"
	"syscall/js"
)

var (
	Uint8Array = js.Global().Get("Uint8Array")
	Response   = js.Global().Get("Response")
	Error      = js.Global().Get("Error")
	Promise    = js.Global().Get("Promise")
)

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
		e <- fmt.Errorf("%v", args[0])
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
