//go:build wasm

package main

import (
	"syscall/js"

	app "github.com/c2FmZQ/sshterm/internal"
)

func main() {
	sshApp := js.Global().Get("sshApp")
	if sshApp.Type() != js.TypeObject {
		panic("sshApp object not found")
	}
	ready := sshApp.Get("sshIsReady")
	if ready.Type() != js.TypeFunction {
		panic("sshApp.sshIsReady not found")
	}
	sshApp.Set("start", js.FuncOf(app.Start))
	ready.Invoke()
	<-make(chan struct{})
}
