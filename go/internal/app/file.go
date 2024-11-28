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

package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"sync/atomic"

	"github.com/pkg/sftp"
	"github.com/urfave/cli/v2"

	"github.com/c2FmZQ/sshterm/internal/jsutil"
)

func (a *App) fileCommand() *cli.App {
	return &cli.App{
		Name:            "file",
		Usage:           "Copy files to or from a remote server.",
		UsageText:       "file [-i <keyname>] <upload|download> username@<endpoint>:<path>",
		Description:     "The file command copies files to or from a remote server.",
		HideHelpCommand: true,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "identity",
				Aliases: []string{"i"},
				Usage:   "The key to use for authentication.",
			},
		},
		Commands: []*cli.Command{
			{
				Name:      "upload",
				Aliases:   []string{"up"},
				Usage:     "Copies files to a remote server.",
				UsageText: "file [-i <keyname>] upload username@<endpoint>:<dir>",
				Action:    a.sftpUpload,
			},
			{
				Name:      "download",
				Aliases:   []string{"down"},
				Usage:     "Copies a file from a remote server.",
				UsageText: "file [-i <keyname>] download username@<endpoint>:<file>",
				Action:    a.sftpDownload,
			},
		},
	}
}

func (a *App) sftpUpload(ctx *cli.Context) error {
	t := a.term
	if ctx.Args().Len() != 1 {
		cli.ShowSubcommandHelp(ctx)
		return nil
	}
	targetPath := ctx.Args().Get(0)
	keyName := ctx.String("identity")

	target, p, ok := strings.Cut(targetPath, ":")
	if !ok {
		return fmt.Errorf("invalid target %q", target)
	}

	cctx, cancel := context.WithCancel(ctx.Context)
	defer cancel()

	c, err := a.sshClient(cctx, target, keyName)
	if err != nil {
		return err
	}
	client, err := sftp.NewClient(c)
	if err != nil {
		return err
	}
	defer client.Close()

	st, err := client.Stat(p)
	if err != nil || !st.IsDir() {
		return fmt.Errorf("remote path %q is not a directory", p)
	}

	files := a.importFiles("", true)
	cp := func(f jsutil.ImportedFile) error {
		defer f.Content.Close()
		fn := path.Join(p, f.Name)
		w, err := client.OpenFile(fn, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
		if err != nil {
			return fmt.Errorf("%s: %v", fn, err)
		}
		buf := make([]byte, 16384)
		var total int64
		for loop := 0; ; loop++ {
			n, err := f.Content.Read(buf)
			if n > 0 {
				if nn, err := w.Write(buf[:n]); err != nil {
					w.Close()
					return err
				} else if n != nn {
					w.Close()
					return io.ErrShortWrite
				}
				total += int64(n)
				if loop%100 == 0 {
					t.Printf("%3d%%\b\b\b\b", 100*total/f.Size)
				}
			}
			if err == io.EOF {
				t.Printf("%3d%%\n", 100*total/f.Size)
				break
			}
			if err != nil {
				w.Close()
				return err
			}

		}
		return w.Close()
	}
	for _, f := range files {
		t.Printf("%s ", f.Name)
		if err := cp(f); err != nil {
			return err
		}
	}
	return nil
}

func (a *App) sftpDownload(ctx *cli.Context) error {
	t := a.term
	if ctx.Args().Len() != 1 {
		cli.ShowSubcommandHelp(ctx)
		return nil
	}
	targetPath := ctx.Args().Get(0)
	keyName := ctx.String("identity")

	target, p, ok := strings.Cut(targetPath, ":")
	if !ok {
		return fmt.Errorf("invalid target %q", target)
	}

	if a.streamHelper == nil {
		a.streamHelper = jsutil.NewStreamHelper()
		if a.streamHelper == nil {
			return errors.New("streaming download unavailable")
		}
	}
	cctx, cancel := context.WithCancel(ctx.Context)
	defer cancel()

	c, err := a.sshClient(cctx, target, keyName)
	if err != nil {
		return err
	}
	client, err := sftp.NewClient(c)
	if err != nil {
		return err
	}
	defer client.Close()

	r, err := client.Open(p)
	if err != nil {
		return fmt.Errorf("%s: %v", p, err)
	}
	defer r.Close()
	st, err := r.Stat()
	if err != nil {
		return fmt.Errorf("%s: %v", p, err)
	}
	size := st.Size()
	_, name := path.Split(r.Name())
	calls := new(atomic.Int32)
	progress := func(total int64) {
		if calls.Load()%100 == 0 {
			t.Printf("%3d%%\b\b\b\b", 100*total/size)
		}
		calls.Add(1)
	}
	t.Printf("%s ", name)
	if err := a.streamHelper.Download(r, name, size, progress, a.cfg.StreamHook); err != nil {
		return err
	}
	calls.Store(0)
	progress(size)
	t.Printf("\n")
	return nil
}
