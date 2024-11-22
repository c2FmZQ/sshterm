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

package indexeddb

import (
	"encoding/json"
	"errors"
	"fmt"
	"syscall/js"
)

const (
	storeName = "store"
	dbVersion = 2
)

var ErrNotFound = errors.New("not found")

func Delete(name string) error {
	req := js.Global().Get("indexedDB").Call("deleteDatabase", js.ValueOf(name))
	ch := make(chan error, 1)
	req.Set("onerror", js.FuncOf(func(this js.Value, args []js.Value) any {
		ch <- errors.New("error deleting database")
		return nil
	}))
	req.Set("onsuccess", js.FuncOf(func(this js.Value, args []js.Value) any {
		ch <- nil
		return nil
	}))
	return <-ch
}

func New(name string) (*DB, error) {
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
		db: r.v,
	}, nil
}

type DB struct {
	db js.Value
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
