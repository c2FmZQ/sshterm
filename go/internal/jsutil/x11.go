//go:build wasm

package jsutil

import (
	"errors"
	"syscall/js"
)

func ReadClipboard() (string, error) {
	nav := js.Global().Get("navigator")
	if nav.IsUndefined() || nav.IsNull() {
		return "", errors.New("navigator is undefined")
	}
	cb := nav.Get("clipboard")
	if cb.IsUndefined() || cb.IsNull() {
		return "", errors.New("navigator.clipboard is undefined")
	}
	p := cb.Call("readText")
	v, err := Await(p)
	if err != nil {
		return "", err
	}
	return v.String(), nil
}

func WriteClipboard(text string) error {
	nav := js.Global().Get("navigator")
	if nav.IsUndefined() || nav.IsNull() {
		return errors.New("navigator is undefined")
	}
	cb := nav.Get("clipboard")
	if cb.IsUndefined() || cb.IsNull() {
		return errors.New("navigator.clipboard is undefined")
	}
	p := cb.Call("writeText", text)
	_, err := Await(p)
	return err
}
