// MIT License
//
// Copyright (c) 2026 TTBT Enterprises LLC
// Copyright (c) 2026 Robin Thellend <rthellend@rthellend.com>
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

package app

import (
	"io"

	"github.com/c2FmZQ/sshterm/internal/jsutil"
	"github.com/c2FmZQ/sshterm/internal/terminal"
	"github.com/c2FmZQ/sshterm/internal/zmodem"
)

func newZModemFilter(term *terminal.Terminal) (io.Writer, io.Reader) {
	return zmodem.New(term, wasmDownload, wasmUpload)
}

func wasmDownload(name string, size int64, r io.Reader) error {
	helper := jsutil.NewStreamHelper()
	if helper == nil {
		data, err := io.ReadAll(r)
		if err == nil {
			jsutil.ExportFile(data, name, "application/octet-stream")
		}
		return err
	}
	return helper.Download(io.NopCloser(r), name, size, nil, nil)
}

func wasmUpload() ([]*zmodem.File, error) {
	imported := jsutil.ImportFiles("", true)
	var files []*zmodem.File
	for _, imp := range imported {
		files = append(files, &zmodem.File{
			Name: imp.Name,
			Size: imp.Size,
			R:    imp.Content,
		})
	}
	return files, nil
}
