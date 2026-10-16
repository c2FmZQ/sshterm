//go:build x11 && wasm && debug

package x11

import (
	"encoding/json"
	"fmt"
	"syscall/js"
)

func (w *wasmX11Frontend) recordOperation(op CanvasOperation) {
	for i, arg := range op.Args {
		b, err := json.Marshal(arg)
		if err != nil {
			debugf("ERR recordOperation: %v", err)
		}
		var v any
		if err := json.Unmarshal(b, &v); err != nil {
			debugf("ERR recordOperation: %v", err)
		}
		op.Args[i] = fmt.Sprint(v)
	}
	w.canvasOperations = append(w.canvasOperations, op)
}

func uint16SliceToString(s []uint16) string {
	runes := make([]rune, len(s))
	for i, v := range s {
		runes[i] = rune(v)
	}
	return string(runes)
}

func (w *wasmX11Frontend) GetCanvasOperations() []CanvasOperation {
	return w.canvasOperations
}

func (w *wasmX11Frontend) initCanvasOperations() {
	w.canvasOperations = []CanvasOperation{}
	js.Global().Set("getCanvasOperations", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		ops := w.GetCanvasOperations()
		jsOps := make([]interface{}, len(ops))
		for i, op := range ops {
			jsOps[i] = map[string]interface{}{
				"Type":        op.Type,
				"Args":        op.Args,
				"FillStyle":   op.FillStyle,
				"StrokeStyle": op.StrokeStyle,
			}
		}
		return js.ValueOf(jsOps)
	}))
}
