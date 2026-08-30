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
