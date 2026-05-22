//go:build wasm

package jsutil

import (
	"syscall/js"
)

func SendMouseEvent(wid uint32, eventType string, x, y int16, buttons uint16) {
	js.Global().Call("sendMouseEvent", wid, eventType, x, y, buttons)
}

func SendKeyboardEvent(wid uint32, eventType string, keyCode uint8, altKey, ctrlKey, shiftKey, metaKey bool) {
	js.Global().Call("sendKeyboardEvent", wid, eventType, keyCode, altKey, ctrlKey, shiftKey, metaKey)
}

func ReadClipboard() (string, error) {
	p := js.Global().Get("x11").Call("readClipboard")
	v, err := Await(p)
	if err != nil {
		return "", err
	}
	return v.String(), nil
}

func WriteClipboard(text string) error {
	p := js.Global().Get("x11").Call("writeClipboard", text)
	_, err := Await(p)
	return err
}
