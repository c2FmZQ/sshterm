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

package tests

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sync"
	"syscall/js"
	"testing"
	"time"

	"github.com/c2FmZQ/sshterm/internal/app"
	"github.com/c2FmZQ/sshterm/internal/jsutil"
)

var (
	testingM  *testing.M
	done      chan struct{}
	appConfig *app.Config

	terminalIO     *termIO
	fileUploader   *uploader
	fileDownloader *downloader
)

func TestMain(m *testing.M) {
	flag.Parse()
	flag.Set("test.failfast", "true")
	sshApp := js.Global().Get("sshApp")
	if sshApp.Type() != js.TypeObject {
		panic("sshApp object not found")
	}
	ready := sshApp.Get("sshIsReady")
	if ready.Type() != js.TypeFunction {
		panic("sshApp.sshIsReady not found")
	}
	sshApp.Set("start", js.FuncOf(start))
	done = make(chan struct{})
	testingM = m
	ready.Invoke()
	<-done
}

func start(this js.Value, args []js.Value) any {
	if n := len(args); n != 1 {
		return fmt.Errorf("expected one argument, got %d", n)
	}
	if args[0].Type() != js.TypeObject {
		return errors.New("args[0] should be an Object")
	}
	arg := args[0]

	if t := arg.Get("term"); t.Type() != js.TypeObject {
		return errors.New("term value is missing")
	}

	fileUploader = &uploader{}
	fileDownloader = &downloader{}

	appConfig = &app.Config{
		Term:         arg.Get("term"),
		DBName:       "sshtermtest",
		UploadHook:   fileUploader.upload,
		DownloadHook: fileDownloader.download,
		StreamHook:   fileDownloader.stream,
	}
	terminalIO = newTermIO(appConfig.Term)

	appConfig.Term.Call("writeln", "\x1b[32m╔════════════════╗\x1b[0m")
	appConfig.Term.Call("writeln", "\x1b[32m║ SSH TERM TESTS ║\x1b[0m")
	appConfig.Term.Call("writeln", "\x1b[32m╚════════════════╝\x1b[0m")

	if js.Global().Get("navigator").Get("serviceWorker").IsUndefined() {
		appConfig.Term.Call("writeln", "navigator.serviceWorker is undefined")
	}

	return jsutil.NewPromise(func() (any, error) {
		if _, err := http.Get("/reset"); err != nil {
			appConfig.Term.Call("writeln", "reset: "+err.Error())
		}

		out := "PASS"
		if res := testingM.Run(); res != 0 {
			out = "FAIL"
		}
		terminalIO.Stop()
		appConfig.Term.Call("writeln", out)
		close(done)
		return out, nil
	})
}

type uploader struct {
	mu    sync.Mutex
	files []jsutil.ImportedFile
}

func (u *uploader) enqueue(name string, typ string, size int64, content []byte) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.files = append(u.files, jsutil.ImportedFile{
		Name:    name,
		Type:    typ,
		Size:    size,
		Content: io.NopCloser(bytes.NewReader(content)),
	})
}

func (u *uploader) upload(accept string, multiple bool) []jsutil.ImportedFile {
	u.mu.Lock()
	defer u.mu.Unlock()
	v := u.files
	u.files = nil
	return v
}

type downloader struct {
	mu       sync.Mutex
	receiver chan downloadedFile
}

type downloadedFile struct {
	Name    string
	Type    string
	Content []byte
}

func (d *downloader) wait() <-chan downloadedFile {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.receiver = make(chan downloadedFile, 1)
	return d.receiver
}

func (d *downloader) download(data []byte, filename, mimeType string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.receiver == nil {
		return errors.New("not ready for download")
	}
	d.receiver <- downloadedFile{filename, mimeType, data}
	return nil
}

func (d *downloader) stream(url string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.receiver == nil {
		return errors.New("not ready for download")
	}
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var filename string
	if m := regexp.MustCompile(`^attachment; filename="(.*)"`).FindStringSubmatch(resp.Header.Get("Content-Disposition")); len(m) > 1 {
		filename = m[1]
	}
	d.receiver <- downloadedFile{filename, resp.Header.Get("Content-Type"), body}
	return nil
}

func newTermIO(term js.Value) *termIO {
	t := &termIO{
		term: term,
		buf:  bytes.NewBuffer(nil),
	}

	appConfig.Term.Set("origWrite", appConfig.Term.Get("write"))
	appConfig.Term.Set("write", js.FuncOf(func(this js.Value, args []js.Value) any {
		if args[0].Type() == js.TypeString {
			t.Write([]byte(args[0].String()))
		} else {
			t.Write(jsutil.Uint8ArrayToBytes(args[0]))
		}
		return appConfig.Term.Call("origWrite", args[0])
	}))
	return t
}

type termIO struct {
	mu   sync.Mutex
	buf  *bytes.Buffer
	term js.Value

	expect   *regexp.Regexp
	expectCh chan []string
}

func (t *termIO) Stop() {
	appConfig.Term.Set("write", appConfig.Term.Get("origWrite"))
	appConfig.Term.Delete("origWrite")
}

func (t *termIO) Reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buf.Reset()
}

func (t *termIO) Type(input string) {
	t.buf.Reset()
	for _, c := range input {
		time.Sleep(20 * time.Millisecond)
		if c == '\n' {
			appConfig.Term.Call("input", "\r", true)
		}
		appConfig.Term.Call("input", fmt.Sprintf("%c", c), true)
	}
}

func (t *termIO) Write(b []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	n, err := t.buf.Write(b)
	if t.expect != nil {
		if m := t.expect.FindStringSubmatch(t.buf.String()); len(m) != 0 {
			t.expectCh <- m
		}
	}
	return n, err
}

func (t *termIO) Expect(tt *testing.T, re string) []string {
	r, err := regexp.Compile(re)
	if err != nil {
		tt.Fatalf("%s: %v", re, err)
	}
	t.mu.Lock()
	if m := r.FindStringSubmatch(t.buf.String()); len(m) != 0 {
		t.mu.Unlock()
		return m
	}
	t.expect = r
	t.expectCh = make(chan []string)
	t.mu.Unlock()

	select {
	case result := <-t.expectCh:
		t.mu.Lock()
		defer t.mu.Unlock()
		t.expect = nil
		t.expectCh = nil
		return result
	case <-time.After(5 * time.Second):
		t.mu.Lock()
		defer t.mu.Unlock()
		t.expect = nil
		t.expectCh = nil
		tt.Fatalf("expecting %q, timed out", re)
	}
	return nil
}
