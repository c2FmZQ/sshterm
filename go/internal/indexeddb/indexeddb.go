//go:build wasm

package indexeddb

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"syscall/js"
)

const (
	storeName = "store"
	dbVersion = 2
)

var ErrNotFound = errors.New("not found")

func New(name string, log io.Writer) (*DB, error) {
	req := js.Global().Get("indexedDB").Call("open", js.ValueOf(name), js.ValueOf(dbVersion))

	type result struct {
		v   js.Value
		err error
	}
	resCh := make(chan result, 2)

	req.Set("onupgradeneeded", js.FuncOf(func(this js.Value, args []js.Value) any {
		db := req.Get("result")
		names := db.Get("objectStoreNames")
		var found bool
		for i := 0; i < names.Length(); i++ {
			n := names.Index(i).String()
			if n == storeName {
				found = true
				break
			}
		}
		if !found {
			db.Call("createObjectStore", storeName)
		}
		return nil
	}))
	req.Set("onerror", js.FuncOf(func(this js.Value, args []js.Value) any {
		resCh <- result{err: errors.New("error loading database")}
		return nil
	}))
	req.Set("onsuccess", js.FuncOf(func(this js.Value, args []js.Value) any {
		resCh <- result{v: req.Get("result")}
		return nil
	}))
	r := <-resCh
	if r.err != nil {
		return nil, r.err
	}
	return &DB{
		db:  r.v,
		log: log,
	}, nil
}

type DB struct {
	db  js.Value
	log io.Writer
}

func (db *DB) Close() {
	db.db.Call("close")
}

func (db *DB) Get(key string, value any) error {
	req := db.db.Call("transaction", storeName).Call("objectStore", storeName).Call("get", key)
	errCh := make(chan error, 2)
	req.Set("onerror", js.FuncOf(func(this js.Value, args []js.Value) any {
		errCh <- errors.New("transaction error")
		return nil
	}))
	req.Set("onsuccess", js.FuncOf(func(this js.Value, args []js.Value) any {
		errCh <- nil
		return nil
	}))
	if err := <-errCh; err != nil {
		return err
	}
	v := req.Get("result")
	if v.IsUndefined() {
		return ErrNotFound
	}
	if err := json.Unmarshal([]byte(v.String()), value); err != nil {
		return fmt.Errorf("json.Unmarshal: %w", err)
	}
	return nil
}

func (db *DB) Set(key string, value any) error {
	b, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("json.Marshal: %w", err)
	}
	t := db.db.Call("transaction", storeName, "readwrite")
	req := t.Call("objectStore", storeName).Call("put", string(b), key)
	errCh := make(chan error, 2)
	req.Set("onerror", js.FuncOf(func(this js.Value, args []js.Value) any {
		errCh <- errors.New("transaction error")
		return nil
	}))
	req.Set("onsuccess", js.FuncOf(func(this js.Value, args []js.Value) any {
		errCh <- nil
		return nil
	}))
	return <-errCh
}
