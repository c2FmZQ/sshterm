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
	"net/http"
	"syscall/js"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/c2FmZQ/sshterm/internal/app"
)

const prompt = "sshterm> "

type line struct {
	Type   string
	Expect string
	Reset  bool
	Do     func([]string)
	Wait   time.Duration
}

func script(t *testing.T, lines []line) {
	for _, line := range lines {
		if line.Reset {
			terminalIO.Reset()
		}
		if line.Wait != 0 {
			time.Sleep(line.Wait)
		}
		if line.Type != "" {
			terminalIO.Type(line.Type)
		}
		if line.Expect != "" {
			m := terminalIO.Expect(t, line.Expect)
			if line.Do != nil {
				line.Do(m)
			}
		}
	}
}

func TestHelp(t *testing.T) {
	a, err := app.New(appConfig)
	if err != nil {
		t.Fatalf("app.New: %v", err)
	}
	result := make(chan error)
	go func() {
		result <- a.Run()
	}()

	script(t, []line{
		{Expect: prompt},
		{Type: "help\n", Expect: "(?s)agent.*clear.*db.*file.*keys.*reload.*ssh.*> "},
		{Expect: prompt},
		{Type: "exit\n"},
	})
	if err := <-result; err != nil {
		t.Fatalf("Run(): %v", err)
	}
}

func TestEndpoint(t *testing.T) {
	a, err := app.New(appConfig)
	if err != nil {
		t.Fatalf("app.New: %v", err)
	}
	result := make(chan error)
	go func() {
		result <- a.Run()
	}()

	script(t, []line{
		{Expect: prompt},
		{Type: "db wipe\n", Expect: `Continue\?`},
		{Type: "Y\n", Expect: prompt},
		{Type: "ep list\n", Expect: "<none>"},
		{Type: "ep add test foobar\n", Expect: prompt},
		{Type: "ep list\n", Expect: "test.*foobar.*n/a"},
		{Type: "ep delete test\n", Expect: prompt},
		{Type: "ep list\n", Expect: "<none>"},
		{Expect: prompt},
		{Type: "exit\n"},
	})
	if err := <-result; err != nil {
		t.Fatalf("Run(): %v", err)
	}
}

func TestKeys(t *testing.T) {
	a, err := app.New(appConfig)
	if err != nil {
		t.Fatalf("app.New: %v", err)
	}
	result := make(chan error)
	go func() {
		result <- a.Run()
	}()

	downloadCh := fileDownloader.wait()

	script(t, []line{
		{Expect: prompt},
		{Type: "db wipe\n", Expect: `Continue\?`},
		{Type: "Y\n", Expect: prompt},
		{Type: "keys list\n", Expect: "<none>"},
		{Type: "keys generate test\n", Expect: "Enter passphrase"},
		{Type: "foobar\n", Expect: "Re-enter the same passphrase"},
		{Type: "foobar\n", Expect: prompt},
		{Type: "keys list\n", Expect: "ssh-ed25519 .* test"},
		{Expect: prompt},
		{Type: "keys export --private test\n", Expect: `Continue\?`},
		{Type: "Y\n"},
	})
	file := <-downloadCh
	if got, want := file.Name, "test.key"; got != want {
		t.Errorf("filename = %q, want %q", got, want)
	}

	fileUploader.enqueue(file.Name, file.Type, int64(len(file.Content)), file.Content)

	script(t, []line{
		{Type: "keys import samekey\n", Expect: "Enter passphrase for samekey"},
		{Type: "foobar\n", Expect: prompt},
		{Type: "keys list\n", Expect: "(?s)ssh-ed25519 .* samekey\r\nssh-ed25519 .* test\r\n"},
		{Expect: prompt},
		{Type: "keys delete test\n", Expect: `Continue\?`},
		{Type: "Y\n", Expect: prompt},
		{Type: "keys list\n", Expect: "ssh-ed25519 .* samekey\r\n"},
		{Expect: prompt},
		{Type: "keys delete samekey\n", Expect: `Continue\?`},
		{Type: "Y\n", Expect: prompt},
		{Type: "keys list\n", Expect: "<none>"},
		{Expect: prompt},
		{Type: "exit\n"},
	})

	if err := <-result; err != nil {
		t.Fatalf("Run(): %v", err)
	}
}

func TestDB(t *testing.T) {
	a, err := app.New(appConfig)
	if err != nil {
		t.Fatalf("app.New: %v", err)
	}
	result := make(chan error)
	go func() {
		result <- a.Run()
	}()

	downloadCh := fileDownloader.wait()

	script(t, []line{
		{Expect: prompt},
		{Type: "db wipe\n", Expect: `Continue\?`},
		{Type: "Y\n", Expect: prompt},
		{Type: "ep add test websocket\n", Expect: prompt},
		{Type: "ep list\n", Expect: "test .* websocket"},
		{Type: "keys generate test\n", Expect: "Enter passphrase"},
		{Type: "foobar\n", Expect: "Re-enter the same passphrase"},
		{Type: "foobar\n", Expect: prompt},
		{Type: "keys list\n", Expect: "ssh-ed25519 .* test"},
		{Expect: prompt},
		{Type: "db backup\n", Expect: "Enter a passphrase for the backup:"},
		{Type: "foobar\n", Expect: "Enter the same passphrase:"},
		{Type: "foobar\n", Expect: prompt},
		{Type: "db wipe\n", Expect: `Continue\?`},
		{Type: "Y\n", Expect: prompt},
		{Type: "ep list\n", Expect: "<none>"},
		{Type: "keys list\n", Expect: "<none>"},
		{Expect: prompt},
	})
	file := <-downloadCh

	fileUploader.enqueue(file.Name, file.Type, int64(len(file.Content)), file.Content)

	script(t, []line{
		{Type: "db restore\n", Expect: "Enter the passphrase for the backup:"},
		{Type: "foobar\n", Expect: prompt},
		{Type: "ep list\n", Expect: "test .* websocket"},
		{Type: "keys list\n", Expect: "ssh-ed25519 .* test"},
		{Expect: prompt},
		{Type: "exit\n"},
	})

	if err := <-result; err != nil {
		t.Fatalf("Run(): %v", err)
	}
}

func TestSSH(t *testing.T) {
	a, err := app.New(appConfig)
	if err != nil {
		t.Fatalf("app.New: %v", err)
	}
	result := make(chan error)
	go func() {
		result <- a.Run()
	}()

	txt := []byte("Hello World!")
	fileUploader.enqueue("hello.txt", "text/plain", int64(len(txt)), txt)

	script(t, []line{
		{Expect: prompt},
		{Type: "db wipe\n", Expect: `Continue\?`},
		{Type: "Y\n", Expect: prompt},
		{Type: "ep add test-server websocket\n", Expect: prompt},
		{Type: "ssh testuser@test-server\n", Expect: `(?s)Host key for websocket.*Continue\?`},
		{Type: "Y\n", Expect: "Password: "},
		{Type: "password\n", Expect: "remote> "},
		{Type: "exit\n", Expect: prompt},
		{Wait: time.Second, Type: "\n\n"},

		{Type: "keys generate test\n", Expect: "Enter passphrase"},
		{Type: "foobar\n", Expect: "Re-enter the same passphrase"},
		{Type: "foobar\n", Expect: prompt},
		{Type: "keys list\n", Expect: "ssh-ed25519 .* test\r\n", Do: func(m []string) {
			pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(m[0]))
			if err != nil {
				t.Fatalf("ssh.ParseAuthorizedKey: %v", err)
			}
			if _, err := http.Post("/addkey", "text/pem", bytes.NewReader(pub.Marshal())); err != nil {
				t.Fatalf("http.Post: %v", err)
			}
		}},
		{Type: "ssh -i test testuser@test-server\n", Expect: "Enter passphrase for test:"},
		{Type: "foobar\n", Expect: "remote> "},
		{Type: "exit\n", Expect: prompt},
		{Wait: time.Second, Type: "\n\n"},

		{Type: "agent add test\n", Expect: "Enter passphrase for test:"},
		{Type: "foobar\n", Expect: prompt},
		{Type: "ssh testuser@test-server\n", Expect: "remote> "},
		{Type: "exit\n", Expect: prompt},
		{Wait: time.Second, Type: "\n\n"},
		{Type: "ssh testuser@test-server foo bar\n", Expect: "exec: foo bar"},
		{Wait: time.Second, Type: "\n\n"},

		{Type: "file upload testuser@test-server:.\n", Expect: "100%"},

		{Expect: prompt},
		{Type: "exit\n"},
	})
	if err := <-result; err != nil {
		t.Fatalf("Run(): %v", err)
	}
}

func TestDownload(t *testing.T) {
	if js.Global().Get("navigator").Get("serviceWorker").IsUndefined() {
		t.Skip("Service Worker not available")
	}
	a, err := app.New(appConfig)
	if err != nil {
		t.Fatalf("app.New: %v", err)
	}
	result := make(chan error)
	go func() {
		result <- a.Run()
	}()

	txt := []byte("Hello World!")
	fileUploader.enqueue("hello-again.txt", "text/plain", int64(len(txt)), txt)

	downloadCh := fileDownloader.wait()

	script(t, []line{
		{Expect: prompt},
		{Type: "db wipe\n", Expect: `Continue\?`},
		{Type: "Y\n", Expect: prompt},
		{Type: "ep add test-server websocket\n", Expect: prompt},
		{Type: "file upload testuser@test-server:.\n", Expect: `(?s)Host key for websocket.*Continue\?`},
		{Type: "\n", Expect: "Password: "},
		{Type: "password\n", Expect: "100%"},

		{Type: "file download testuser@test-server:hello-again.txt\n", Expect: "Password: "},
		{Type: "password\n", Expect: "100%"},

		{Expect: prompt},
		{Type: "exit\n"},
	})
	file := <-downloadCh
	if got, want := file.Name, "hello-again.txt"; got != want {
		t.Errorf("filename = %q, want %q", got, want)
	}
	if err := <-result; err != nil {
		t.Fatalf("Run(): %v", err)
	}
}
